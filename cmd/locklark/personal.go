package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"unicode/utf8"
)

var personalUsage = errors.New("usage: locklark personal <init|add-login|list|audit|archived-audit> --file PATH, or backup|restore --file SOURCE --out NEW_PATH, or edit-login --file PATH --id ID --revision REV --field title|username|password|otp, or reveal-login --file PATH --id ID --revision REV --field username|password, or generate-login --file PATH [--length N], or regenerate-password --file PATH --id ID --revision REV [--length N], or otp --file PATH --id ID --revision REV")

// One terminal mode covers the entire interaction; no prompt or inter-field
// gap is visible while echo is enabled.
type console struct {
	reader *bufio.Reader
	skipLF bool
}

func (c *console) field(prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt+": "); err != nil {
		return nil, err
	}
	var value []byte
	for {
		b, err := c.reader.ReadByte()
		if err != nil || b == 3 || b == 4 || b == 27 || len(value) > 64<<10 {
			clear(value)
			return nil, errors.New("terminal input cancelled or too long")
		}
		if c.skipLF {
			c.skipLF = false
			if b == '\n' {
				continue
			}
		}
		switch b {
		case '\r', '\n':
			c.skipLF = b == '\r'
			fmt.Fprint(os.Stderr, "\r\n")
			return value, nil
		case 8, 127:
			_, n := utf8.DecodeLastRune(value)
			clear(value[len(value)-n:])
			value = value[:len(value)-n]
		default:
			value = append(value, b)
		}
	}
}
func confirmIssued(c *console, label, value, prompt string) error {
	if _, err := fmt.Fprintf(os.Stderr, "%s： %s\r\n", label, value); err != nil {
		return err
	}
	typed, err := c.field(prompt)
	defer clear(typed)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(typed, []byte(value)) != 1 {
		return errors.New("confirmation mismatch; no file created")
	}
	return nil
}
func runPersonal(args []string, out io.Writer) (retErr error) {
	if len(args) < 3 || len(args)%2 != 1 {
		return personalUsage
	}
	action := args[0]
	opts := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if args[i+1] == "" || opts[args[i]] != "" {
			return personalUsage
		}
		opts[args[i]] = args[i+1]
	}
	path := opts["--file"]
	if path == "" {
		return personalUsage
	}
	var edit personal.Edit
	var reveal personal.RevealTarget
	length := password.DefaultPolicy().Length
	switch action {
	case "otp":
		edit = personal.Edit{ID: opts["--id"], Revision: opts["--revision"], Field: "otp"}
		if len(opts) != 3 || !personal.ValidEditTarget(edit.ID, edit.Revision, edit.Field) {
			return personalUsage
		}
	case "generate-login", "regenerate-password":
		expected := 1
		if action == "regenerate-password" {
			expected = 3
			if !personal.ValidEditTarget(opts["--id"], opts["--revision"], "password") {
				return personalUsage
			}
		}
		if value, found := opts["--length"]; found {
			var err error
			length, err = strconv.Atoi(value)
			if err != nil || strconv.Itoa(length) != value {
				return personalUsage
			}
			expected++
		}
		if len(opts) != expected {
			return personalUsage
		}
		if _, err := password.Validate(password.Policy{Length: length, Alphabet: password.DefaultAlphabet}); err != nil {
			return err
		}
	case "reveal-login":
		reveal = personal.RevealTarget{ID: opts["--id"], Revision: opts["--revision"], Field: opts["--field"]}
		if len(opts) != 4 || !personal.ValidRevealTarget(reveal.ID, reveal.Revision, reveal.Field) {
			return personalUsage
		}
	case "edit-login":
		edit = personal.Edit{ID: opts["--id"], Revision: opts["--revision"], Field: opts["--field"]}
		if len(opts) != 4 || !personal.ValidEditTarget(edit.ID, edit.Revision, edit.Field) {
			return personalUsage
		}
	case "backup", "restore":
		if len(opts) != 2 || opts["--out"] == "" {
			return personalUsage
		}
	case "init", "add-login", "audit", "list", "archived-audit":
		if len(opts) != 1 {
			return personalUsage
		}
	default:
		return personalUsage
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return errors.New("personal commands require an interactive terminal for input and prompts")
	}
	if action == "init" {
		if _, e := os.Lstat(path); e == nil {
			return errors.New("file already exists; no Secret Key issued")
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errors.New("cannot disable terminal echo")
	}
	var once sync.Once
	var resetErr error
	restore := func() { once.Do(func() { resetErr = term.Restore(fd, state) }) }
	done := make(chan struct{})
	defer func() {
		close(done)
		restore()
		if retErr == nil && resetErr != nil {
			retErr = resetErr
		}
	}()
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	c := console{reader: bufio.NewReader(os.Stdin)}
	consoleField := c.field
	pw, err := consoleField("主密码")
	if err != nil {
		return err
	}
	defer clear(pw)
	var response any
	if action == "init" {
		confirm, e := consoleField("再次输入主密码")
		if e != nil {
			return e
		}
		match := subtle.ConstantTimeCompare(pw, confirm)
		clear(confirm)
		if match != 1 || len(bytes.TrimSpace(pw)) == 0 {
			return errors.New("password empty or confirmation did not match")
		}
		key, e := personal.NewSecret()
		if e != nil {
			return e
		}
		defer clear(key)
		if _, e = fmt.Fprintf(os.Stderr, "请离线保存 Secret Key；丢失它将无法打开此库。 %s\r\n", personal.FormatSecret(key)); e != nil {
			return e
		}
		typed, e := consoleField("重新输入刚保存的 Secret Key")
		if e != nil {
			return e
		}
		verified, e := personal.ParseSecret(string(typed))
		clear(typed)
		match = subtle.ConstantTimeCompare(key, verified)
		clear(verified)
		if e != nil || match != 1 {
			return errors.New("Secret Key confirmation did not match; vault not created")
		}
		if err = personal.Create(path, string(pw), key); err != nil {
			return err
		}
		response = map[string]string{"status": "created"}
	} else {
		input, e := consoleField("Secret Key")
		if e != nil {
			return e
		}
		key, e := personal.ParseSecret(string(input))
		clear(input)
		if e != nil {
			return errors.New("invalid Secret Key")
		}
		defer clear(key)
		switch action {
		case "otp":
			if _, e = fmt.Fprintf(os.Stderr, "将在本终端显示条目 %s（修订 %s）的 TOTP 验证码；请确保本机时间准确，终端历史可能保留验证码。\r\n", edit.ID, edit.Revision); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SHOW 确认显示验证码")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SHOW" {
				return errors.New("OTP disclosure cancelled")
			}
			response, err = personal.RevealOTP(path, string(pw), key, edit.ID, edit.Revision, os.Stderr)
		case "reveal-login":
			if _, e = fmt.Fprintf(os.Stderr, "即将在本终端显示条目 %s（修订 %s）的 %s 字段（JSON 字符串）；终端历史可能保留原值。\r\n", reveal.ID, reveal.Revision, reveal.Field); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SHOW 确认显示")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SHOW" {
				return errors.New("disclosure cancelled")
			}
			response, err = personal.RevealLogin(path, string(pw), key, reveal, os.Stderr)
		case "backup":
			prepared, e := personal.PrepareBackup(path, opts["--out"], string(pw), key)
			if e != nil {
				return e
			}
			defer prepared.Close()
			if e = confirmIssued(&c, "请单独离线保存这份备份的恢复码（含可信检查点）", prepared.Material(), "重新输入恢复码"); e != nil {
				return e
			}
			err = prepared.Publish()
			response = map[string]string{"status": "backed-up"}
		case "restore":
			kit, e := consoleField("此备份的恢复码")
			if e != nil {
				return e
			}
			defer clear(kit)
			prepared, e := personal.PrepareRestore(path, opts["--out"], string(pw), key, string(kit))
			if e != nil {
				return e
			}
			defer prepared.Close()
			fresh, e := personal.NewSecret()
			if e != nil {
				return e
			}
			defer clear(fresh)
			if e = confirmIssued(&c, "恢复库沿用主密码，请离线保存新的 Secret Key", personal.FormatSecret(fresh), "重新输入新 Secret Key"); e != nil {
				return e
			}
			err = prepared.Publish(fresh)
			response = map[string]string{"status": "restored"}
		case "archived-audit":
			response, err = personal.ArchivedAudit(path, string(pw), key)
		case "regenerate-password":
			if _, e = fmt.Fprintf(os.Stderr, "将为条目 %s（修订 %s）生成 %d 位字母数字密码并替换本地保存值。此操作不会修改网站密码；需要时请先备份。\r\n", opts["--id"], opts["--revision"], length); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SAVE 确认替换本地密码")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SAVE" {
				return errors.New("password regeneration cancelled")
			}
			response, err = personal.RegeneratePassword(path, string(pw), key, opts["--id"], opts["--revision"], length)
		case "add-login", "generate-login":
			title, e := consoleField("登录标题")
			if e != nil {
				return e
			}
			defer clear(title)
			username, e := consoleField("用户名（可留空）")
			if e != nil {
				return e
			}
			defer clear(username)
			if action == "generate-login" {
				if _, e = fmt.Fprintf(os.Stderr, "将生成并加密保存 %d 位字母数字密码；需要查看时另用 reveal-login。\r\n", length); e != nil {
					return e
				}
				confirmation, e := consoleField("输入 SAVE 确认生成并保存")
				defer clear(confirmation)
				if e != nil {
					return e
				}
				if string(confirmation) != "SAVE" {
					return errors.New("password generation cancelled")
				}
				response, err = personal.GenerateLogin(path, string(pw), key, string(title), string(username), length)
				break
			}
			value, e := consoleField("登录密码")
			if e != nil {
				return e
			}
			defer clear(value)
			id, e := personal.AddLogin(path, string(pw), key, string(title), string(username), string(value))
			if e != nil {
				return e
			}
			response = map[string]string{"id": id}
		case "edit-login":
			prompt := map[string]string{"title": "新标题", "username": "新用户名（可留空）", "password": "新登录密码", "otp": "新 TOTP 配置（Base32 或 otpauth URI，留空清除）"}[edit.Field]
			value, e := consoleField(prompt)
			if e != nil {
				return e
			}
			defer clear(value)
			if edit.Field == "otp" {
				if _, e = fmt.Fprint(os.Stderr, "此操作只更新本地保存的 TOTP 配置，不会开启或关闭网站的双因素认证。\r\n"); e != nil {
					return e
				}
				confirmation, e := consoleField("输入 SAVE 确认更新 TOTP")
				defer clear(confirmation)
				if e != nil {
					return e
				}
				if string(confirmation) != "SAVE" {
					return errors.New("OTP update cancelled")
				}
			}
			edit.Value = string(value)
			revision, e := personal.EditLogin(path, string(pw), key, edit)
			if e != nil {
				return e
			}
			response = map[string]string{"id": edit.ID, "revision": revision}
		case "list":
			response, err = personal.List(path, string(pw), key)
		case "audit":
			response, err = personal.Audit(path, string(pw), key)
		}
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(response)
}
