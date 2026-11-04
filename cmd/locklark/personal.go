package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unicode/utf8"
)

var personalUsage = errors.New("usage: locklark personal <init|add-login|list|audit> --file PATH")

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
func runPersonal(args []string, out io.Writer) (retErr error) {
	if len(args) != 3 || args[1] != "--file" || args[2] == "" {
		return personalUsage
	}
	action, path := args[0], args[2]
	switch action {
	case "init", "add-login", "list", "audit":
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
		case "add-login":
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
