package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
	"io"
	"os"
)

var personalUsage = errors.New("usage: locklark personal <init|add-login|list|audit> --file PATH")

func consoleField(prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt+": "); err != nil {
		return nil, err
	}
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(input)
		return nil, errors.New("terminal input cancelled")
	}
	return input, nil
}
func runPersonal(args []string, out io.Writer) error {
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
		if _, e = fmt.Fprintln(os.Stderr, "请离线保存 Secret Key；丢失它将无法打开此库。", personal.FormatSecret(key)); e != nil {
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
