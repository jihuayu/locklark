package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jihuayu/locklark/internal/gateway"
	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf8"
)

var personalUsage = errors.New("usage: locklark personal run-cli --file PATH --id ID --revision REV --profile token|gh --name ENV --cwd ABS_DIR --timeout SECONDS [--helper-path ABS_DIR_LIST] -- ABS_PROGRAM [ARG...], or run-env --file PATH --id ID --revision REV --field username|password --name ENV --cwd ABS_DIR --timeout SECONDS -- ABS_PROGRAM [ARG...], or <init|add-login|list|audit|archived-audit|references> --file PATH, or health --file PATH [--hibp true], or add-item --file PATH --input ITEM.json, or backup|restore --file SOURCE --out NEW_PATH, or edit-login --file PATH --id ID --revision REV --field title|username|password|otp|url|notes (hidden single-line replacement; use native editor for multiline notes), or reveal-login --file PATH --id ID --revision REV --field username|password, or generate-login --file PATH [--length N], or regenerate-password --file PATH --id ID --revision REV [--length N], or otp --file PATH --id ID --revision REV, or reveal-ref|otp-ref --file PATH --ref REF --revision REV, or inspect-1pux --file PATH --source ARCHIVE, or plan-import-1pux --file PATH --source ARCHIVE [--model v2], or import-1pux --file PATH --source ARCHIVE --digest PLAN_DIGEST [--model v2], or export-kdbx --file PATH --out NEW_FILE.kdbx, or archive-login|unarchive-login --file PATH --id ID --revision REV, or list|search --file PATH [--state active|archived|trashed|all], or trash-login|restore-login --file PATH --id ID --revision REV, or match-logins --file PATH --origin HTTPS_ORIGIN --frame-origin HTTPS_ORIGIN, or inject-json --file PATH --id ID --revision REV --field username|password --name PROPERTY --out NEW.json, or github-pull --file PATH --id ID --revision REV --repository-id NUMERIC_ID --owner OWNER --repository NAME --number PR --api-ip PUBLIC_IPV4")

// One terminal mode covers the entire interaction; no prompt or inter-field
// gap is visible while echo is enabled.
type console struct {
	reader io.ByteReader
	writer io.Writer
	skipLF bool
}

func (c *console) output() io.Writer {
	if c.writer != nil {
		return c.writer
	}
	return os.Stderr
}

// Interactive child input must remain in the terminal, rather than in a
// prompt reader's read-ahead buffer when the terminal is restored.
type consoleByteReader struct{ input *os.File }

func (r consoleByteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, e := io.ReadFull(r.input, b[:])
	return b[0], e
}

func (c *console) field(prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(c.output(), prompt+": "); err != nil {
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
			fmt.Fprint(c.output(), "\r\n")
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

// personalImportNotice returns the fixed pre-consent warning for the import
// profile. The full v2 mapping is opt-in only; both profiles still refuse every
// unknown or unsupported record as a whole instead of writing partial items.
func personalImportNotice(v2 bool) string {
	if v2 {
		return "显式启用 v2 完整映射：支持受限的类别、分节字段、标签、收藏与附件。\r\n未知或不受支持的类别、字段、历史、标签或附件会整批原子拒绝，不写入部分条目，也不会覆盖已有条目。\r\n来源记录会加密保留，可能保留以后修改前的旧值。\r\n"
	}
	return "仅支持单账户、单库的基本登录；未支持的类别、字段、历史和附件会整批拒绝。\r\n来源记录会加密保留，可能保留以后修改前的旧值；不会覆盖已有条目。\r\n"
}

// personalImportConsent reports the confirmation phrase for the requested step.
func personalImportConsent(action string) (string, string) {
	if action == "import-1pux" {
		return "输入 SAVE 确认整批导入", "SAVE"
	}
	return "输入 PLAN 确认生成导入计划", "PLAN"
}

func runPersonal(args []string, out io.Writer) (retErr error) {
	var processArgs []string
	if len(args) > 0 && (args[0] == "run-env" || args[0] == "run-cli") {
		for i := 1; i < len(args); i++ {
			if args[i] == "--" {
				processArgs = append([]string{}, args[i+1:]...)
				args = args[:i]
				break
			}
		}
		if len(processArgs) == 0 {
			return personalUsage
		}
	}
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
	var pull personal.LivePullRequest
	var run personal.RunRequest
	var runCLI personal.RunCLIRequest
	length := password.DefaultPolicy().Length
	var importV2 bool
	var hibpOptIn bool
	switch action {
	case "run-cli":
		reveal = personal.RevealTarget{ID: opts["--id"], Revision: opts["--revision"], Field: "password"}
		seconds, e := strconv.Atoi(opts["--timeout"])
		runCLI = personal.RunCLIRequest{Program: processArgs[0], Args: processArgs[1:], Directory: opts["--cwd"], Name: opts["--name"], TimeoutSeconds: seconds, Profile: opts["--profile"]}
		expected := 7
		if helperPath, found := opts["--helper-path"]; found {
			runCLI.HelperPath = filepath.SplitList(helperPath)
			expected++
		}
		if len(opts) != expected || e != nil || strconv.Itoa(seconds) != opts["--timeout"] || !personal.ValidRevealTarget(reveal.ID, reveal.Revision, reveal.Field) || runCLI.Validate() != nil {
			return personalUsage
		}
	case "run-env":
		reveal = personal.RevealTarget{ID: opts["--id"], Revision: opts["--revision"], Field: opts["--field"]}
		seconds, e := strconv.Atoi(opts["--timeout"])
		run = personal.RunRequest{Program: processArgs[0], Args: processArgs[1:], Directory: opts["--cwd"], Name: opts["--name"], TimeoutSeconds: seconds}
		if len(opts) != 7 || e != nil || strconv.Itoa(seconds) != opts["--timeout"] || !personal.ValidRevealTarget(reveal.ID, reveal.Revision, reveal.Field) || run.Validate() != nil {
			return personalUsage
		}
	case "github-pull":
		reveal = personal.RevealTarget{ID: opts["--id"], Revision: opts["--revision"], Field: "password"}
		number, e := strconv.Atoi(opts["--number"])
		pull = personal.LivePullRequest{Repository: gateway.Repository{ID: opts["--repository-id"], Owner: opts["--owner"], Name: opts["--repository"]}, Number: number, Address: opts["--api-ip"]}
		if len(opts) != 8 || e != nil || strconv.Itoa(number) != opts["--number"] || !personal.ValidRevealTarget(reveal.ID, reveal.Revision, reveal.Field) || pull.Validate() != nil {
			return personalUsage
		}
	case "inject-json":
		reveal = personal.RevealTarget{ID: opts["--id"], Revision: opts["--revision"], Field: opts["--field"]}
		if len(opts) != 6 || !personal.ValidRevealTarget(reveal.ID, reveal.Revision, reveal.Field) || !personal.ValidInjectionName(opts["--name"]) || opts["--out"] == "" {
			return personalUsage
		}
	case "add-item":
		if len(opts) != 2 || opts["--input"] == "" {
			return personalUsage
		}
	case "plan-import-1pux":
		expected := 2
		if model, found := opts["--model"]; found {
			if model != "v2" {
				return personalUsage
			}
			importV2 = true
			expected++
		}
		if len(opts) != expected || opts["--source"] == "" {
			return personalUsage
		}
	case "import-1pux":
		expected := 3
		if model, found := opts["--model"]; found {
			if model != "v2" {
				return personalUsage
			}
			importV2 = true
			expected++
		}
		if len(opts) != expected || opts["--source"] == "" || !personal.ValidImportDigest(opts["--digest"]) {
			return personalUsage
		}
	case "match-logins":
		if len(opts) != 3 {
			return personalUsage
		}
		if err := personal.ValidateMatchOrigins(opts["--origin"], opts["--frame-origin"]); err != nil {
			return err
		}
	case "archive-login", "unarchive-login", "trash-login", "restore-login":
		if len(opts) != 3 || !personal.ValidEditTarget(opts["--id"], opts["--revision"], "title") {
			return personalUsage
		}
	case "list", "search":
		if len(opts) == 1 {
			opts["--state"] = "active"
		} else if len(opts) != 2 || !personal.ValidStateFilter(opts["--state"]) {
			return personalUsage
		}
	case "export-kdbx":
		if len(opts) != 2 || opts["--out"] == "" {
			return personalUsage
		}
	case "inspect-1pux":
		if len(opts) != 2 || opts["--source"] == "" {
			return personalUsage
		}
	case "reveal-ref", "otp-ref":
		if len(opts) != 3 {
			return personalUsage
		}
		if err := personal.ValidateReferenceInput(opts["--ref"], opts["--revision"]); err != nil {
			return err
		}
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
		if action == "generate-login" {
			if _, err := password.Validate(password.Policy{Length: length, Alphabet: password.DefaultAlphabet}); err != nil {
				return err
			}
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
	case "init", "add-login", "audit", "archived-audit", "references":
		if len(opts) != 1 {
			return personalUsage
		}
	case "health":
		// The local HIBP opt-in is a strict literal: no implicit desktop or
		// environment preference, and no free-form boolean parser.
		if len(opts) == 2 && opts["--hibp"] == "true" {
			hibpOptIn = true
		} else if len(opts) != 1 {
			return personalUsage
		}
	default:
		return personalUsage
	}
	controlInput, controlOutput := os.Stdin, os.Stderr
	if action == "run-cli" {
		var e error
		controlInput, controlOutput, e = openRunCLIConsole()
		if e != nil {
			return errRunCLIConsole
		}
		defer controlInput.Close()
		if controlOutput != controlInput {
			defer controlOutput.Close()
		}
	} else if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
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
	fd := int(controlInput.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errors.New("cannot disable terminal echo")
	}
	var once sync.Once
	var cliRunning atomic.Bool
	childContext, cancelChild := context.WithCancel(context.Background())
	defer cancelChild()
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
			if action == "run-cli" && cliRunning.Load() {
				cancelChild()
				return
			}
			os.Exit(130)
		case <-done:
		}
	}()
	c := console{reader: bufio.NewReader(os.Stdin)}
	if action == "run-cli" {
		c.reader = consoleByteReader{controlInput}
		c.writer = controlOutput
	}
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
		case "add-item":
			response, err = createTypedPersonal(path, opts["--input"], pw, key, consoleField, c.output())
		case "run-cli":
			if e = confirmRunCLI(&c, reveal, runCLI); e != nil {
				return e
			}
			// The child sees the original terminal mode. Signals after this
			// point cancel through RunCLI so its private directory is cleaned.
			cliRunning.Store(true)
			restore()
			if resetErr != nil {
				return errors.New("cannot restore terminal mode; process not started")
			}
			receipt, e := personal.RunCLI(childContext, path, string(pw), key, reveal, runCLI)
			if e != nil {
				return e
			}
			if receipt.ExitCode != 0 {
				return &childExitStatus{code: receipt.ExitCode}
			}
			// No receipt is appended to the child's output stream.
			return nil
		case "run-env":
			if _, e = fmt.Fprintf(os.Stderr, "将条目 %s（修订 %s）的 %s 交给所选可信本地程序的环境变量 %s。\r\n这不是沙箱：程序可联网、写文件和向后代传递值；同用户或管理员也可能读取环境。\r\n参数会显示并出现在进程列表中，不要把秘密写入参数。标准输入/输出/错误接空设备；只返回退出码。\r\n超时仅终止直接子进程，后代可能继续运行；中断后结果可能未知。\r\n程序：%s\r\n目录：%s\r\n超时：%d 秒\r\n参数：\r\n", reveal.ID, reveal.Revision, reveal.Field, run.Name, strconv.QuoteToASCII(run.Program), strconv.QuoteToASCII(run.Directory), run.TimeoutSeconds); e != nil {
				return e
			}
			for i, arg := range run.Args {
				if _, e = fmt.Fprintf(os.Stderr, "  [%d] %s\r\n", i, strconv.QuoteToASCII(arg)); e != nil {
					return e
				}
			}
			consent, e := consoleField("输入 RUN 确认向本地程序披露字段")
			defer clear(consent)
			if e != nil {
				return e
			}
			if string(consent) != "RUN" {
				return errors.New("local process cancelled")
			}
			response, err = personal.RunEnv(context.Background(), path, string(pw), key, reveal, run)
		case "search":
			if _, e = fmt.Fprint(os.Stderr, "仅搜索当前登录标题，不搜索用户名、密码、备注、验证码配置或导入来源旧值。\r\n"); e != nil {
				return e
			}
			query, e := consoleField("搜索标题（隐藏输入）")
			defer clear(query)
			if e != nil {
				return e
			}
			response, err = personal.Search(path, string(pw), key, string(query), opts["--state"])
		case "github-pull":
			if _, e = fmt.Fprintf(os.Stderr, "将条目 %s（修订 %s）的 password 作为 GitHub token，仅发送至 api.github.com。\r\n目标：%s/%s，固定仓库 ID %s，PR #%d；独立确认的 API IPv4：%s。\r\n只读查询状态，不返回 token；此次确认仅授权一次请求，失败或中断后结果可能未知。\r\n", reveal.ID, reveal.Revision, pull.Repository.Owner, pull.Repository.Name, pull.Repository.ID, pull.Number, pull.Address); e != nil {
				return e
			}
			consent, e := consoleField("输入 CALL 确认此次 GitHub 查询")
			defer clear(consent)
			if e != nil {
				return e
			}
			if string(consent) != "CALL" {
				return errors.New("GitHub query cancelled")
			}
			response, err = personal.LivePull(context.Background(), path, string(pw), key, reveal, pull)
		case "inject-json":
			if _, e = fmt.Fprintf(os.Stderr, "将条目 %s（修订 %s）的 %s 写入明文 JSON 属性 %s。\r\n目标文件不会覆盖，采用当前账户的受限文件权限；请妥善保管或删除明文文件。\r\n目标：", reveal.ID, reveal.Revision, reveal.Field, opts["--name"]); e != nil {
				return e
			}
			if _, e = fmt.Fprintf(os.Stderr, "%s\r\n", strconv.QuoteToASCII(opts["--out"])); e != nil {
				return e
			}
			consent, e := consoleField("输入 WRITE 确认写出明文 JSON")
			defer clear(consent)
			if e != nil {
				return e
			}
			if string(consent) != "WRITE" {
				return errors.New("JSON injection cancelled")
			}
			response, err = personal.InjectJSON(path, string(pw), key, reveal, opts["--name"], opts["--out"])
		case "health":
			if hibpOptIn {
				response, err = personalHealthHIBP(path, string(pw), key, consoleField, os.Stderr)
				break
			}
			if _, e = fmt.Fprint(os.Stderr, "仅检查当前活动登录的本地规则，不检查归档、回收站或导入来源旧值。\r\n不会联网查询泄露数据；未发现问题不代表密码安全，未保存 TOTP 不代表网站未启用双因素。\r\n"); e != nil {
				return e
			}
			consent, e := consoleField("输入 SCAN 确认本地体检")
			defer clear(consent)
			if e != nil {
				return e
			}
			if string(consent) != "SCAN" {
				return errors.New("local health check cancelled")
			}
			response, err = personal.Health(path, string(pw), key)
		case "plan-import-1pux", "import-1pux":
			if _, e = fmt.Fprint(os.Stderr, personalImportNotice(importV2)); e != nil {
				return e
			}
			prompt, answer := personalImportConsent(action)
			if action == "import-1pux" {
				if _, e = fmt.Fprintf(os.Stderr, "确认导入计划的来源摘要：%s\r\n", opts["--digest"]); e != nil {
					return e
				}
			}
			consent, e := consoleField(prompt)
			defer clear(consent)
			if e != nil {
				return e
			}
			if string(consent) != answer {
				return errors.New("1PUX import cancelled")
			}
			if action == "plan-import-1pux" {
				if importV2 {
					response, err = personal.PlanImportOnepuxV2(path, string(pw), key, opts["--source"])
				} else {
					response, err = personal.PlanImportOnepux(path, string(pw), key, opts["--source"])
				}
			} else if importV2 {
				response, err = personal.ImportOnepuxV2(path, string(pw), key, opts["--source"], opts["--digest"])
			} else {
				response, err = personal.ImportOnepux(path, string(pw), key, opts["--source"], opts["--digest"])
			}
		case "export-kdbx":
			password, e := consoleField("新导出密码（至少 12 字符）")
			if e != nil {
				return e
			}
			defer clear(password)
			if e = vault.ValidateExportPassword(string(password)); e != nil {
				return e
			}
			confirmation, e := consoleField("再次输入导出密码")
			if e != nil {
				return e
			}
			defer clear(confirmation)
			if subtle.ConstantTimeCompare(password, confirmation) != 1 {
				return errors.New("export passwords did not match")
			}
			if _, e = fmt.Fprint(os.Stderr, "导出包含活动、归档和回收站条目的敏感值，以独立密码加密；不包含账户钥匙、审计或恢复材料。\r\n包含导入来源记录，可能保留修改前的旧值。\r\n其他工具未必识别归档或回收站状态。\r\n"); e != nil {
				return e
			}
			consent, e := consoleField("输入 SAVE 确认加密导出")
			if e != nil {
				return e
			}
			defer clear(consent)
			if string(consent) != "SAVE" {
				return errors.New("encrypted export cancelled")
			}
			response, err = personal.ExportKDBX(path, string(pw), key, string(password), opts["--out"])
		case "inspect-1pux":
			if _, e = fmt.Fprint(os.Stderr, "将只读检查明文 1PUX 归档并记录审计；不会导入条目，报告不包含字段值。\r\n"); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SCAN 确认预检")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SCAN" {
				return errors.New("1PUX inspection cancelled")
			}
			response, err = personal.InspectOnepux(path, string(pw), key, opts["--source"])
		case "references":
			response, err = personal.References(path, string(pw), key)
		case "reveal-ref", "otp-ref":
			kind := "字段值"
			if action == "otp-ref" {
				kind = "TOTP 验证码（请确保本机时间准确）"
			}
			if _, e = fmt.Fprintf(os.Stderr, "将在本终端显示引用 %s（修订 %s）的%s；终端历史可能保留显示值。\r\n", opts["--ref"], opts["--revision"], kind); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SHOW 确认按引用显示")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SHOW" {
				return errors.New("reference disclosure cancelled")
			}
			if action == "otp-ref" {
				response, err = personal.RevealOTPReference(path, string(pw), key, opts["--ref"], opts["--revision"], os.Stderr)
			} else {
				response, err = personal.RevealReference(path, string(pw), key, opts["--ref"], opts["--revision"], os.Stderr)
			}
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
			prompt := map[string]string{"url": "新网站 HTTPS URL（ASCII，留空清除）", "title": "新标题", "username": "新用户名（可留空）", "password": "新登录密码", "otp": "新 TOTP 配置（Base32 或 otpauth URI，留空清除）", "notes": "新备注（隐藏单行输入，留空清除；多行请用原生编辑器）"}[edit.Field]
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
		case "trash-login", "restore-login":
			verb := "移入回收站"
			if action == "restore-login" {
				verb = "从回收站恢复"
			}
			if _, e := fmt.Fprintf(os.Stderr, "将%s登录 %s（修订 %s）。恢复后回到原活动/归档状态；回收站不自动清空。\r\n", verb, opts["--id"], opts["--revision"]); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SAVE 确认更改回收站状态")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SAVE" {
				return errors.New("trash change cancelled")
			}
			revision, e := personal.SetTrashed(path, string(pw), key, opts["--id"], opts["--revision"], action == "trash-login")
			if e != nil {
				return e
			}
			response = map[string]string{"id": opts["--id"], "revision": revision}
		case "archive-login", "unarchive-login":
			verb := "取消归档"
			if action == "archive-login" {
				verb = "归档"
			}
			if _, e := fmt.Fprintf(os.Stderr, "将%s登录 %s（修订 %s）；条目不会删除。\r\n", verb, opts["--id"], opts["--revision"]); e != nil {
				return e
			}
			confirmation, e := consoleField("输入 SAVE 确认更改归档状态")
			defer clear(confirmation)
			if e != nil {
				return e
			}
			if string(confirmation) != "SAVE" {
				return errors.New("archive change cancelled")
			}
			revision, e := personal.SetArchived(path, string(pw), key, opts["--id"], opts["--revision"], action == "archive-login")
			if e != nil {
				return e
			}
			response = map[string]string{"id": opts["--id"], "revision": revision}
		case "match-logins":
			if _, e := fmt.Fprint(os.Stderr, "按调用者提供的来源查询候选；未验证浏览器页面来源，不执行填充。\r\n"); e != nil {
				return e
			}
			response, err = personal.MatchLogins(path, string(pw), key, opts["--origin"], opts["--frame-origin"])
		case "list":
			response, err = personal.ListState(path, string(pw), key, opts["--state"])
		case "audit":
			response, err = personal.Audit(path, string(pw), key)
		}
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(response)
}
