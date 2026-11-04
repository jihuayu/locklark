package main

import (
	"encoding/json"
	"errors"
	"flag"
	"github.com/jihuayu/locklark/internal/preview"
	"io"
)

func runInvoke(args []string, out, diag io.Writer) error {
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(diag)
	var device, bundle, ticket, path, dir, session, id, review, key, pub, host string
	if cmd == "invoke-prepare" {
		f.StringVar(&key, "session-key", "", "agent session key")
		f.StringVar(&pub, "recipient", "", "pinned host inbox public key")
		f.StringVar(&host, "host-sign-key", "", "pinned host receipt verifier")
		f.StringVar(&id, "id", "", "request ID")
		f.StringVar(&review, "review", "", "submitted request digest")
	}
	if cmd == "executions" || cmd == "invoke-prepare" {
		f.StringVar(&session, "session", "", "agent session")
	}
	if cmd == "invoke-result" || cmd == "invoke-prepare" {
		f.StringVar(&dir, "attempt", "", "private attempt directory (new for prepare)")
	} else {
		f.StringVar(&device, "device", "", "trusted device directory")
	}
	if cmd == "invoke-run" || cmd == "invoke-receipt" {
		f.StringVar(&ticket, "ticket", "", "encrypted invocation")
		f.StringVar(&path, "out", "", "new encrypted reply file")
	}
	if cmd == "invoke-run" {
		f.StringVar(&bundle, "bundle", "", "verified local snapshot")
	}
	if cmd == "invoke-result" {
		f.StringVar(&path, "reply", "", "encrypted reply file")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	var result any
	var err error
	switch cmd {
	case "invoke-prepare":
		if dir == "" || key == "" || pub == "" || host == "" {
			return errors.New("attempt directory and pinned key files required")
		}
		err = preview.PrepareInvocation(dir, key, pub, host, session, id, review)
		result = map[string]string{"id": id, "state": "prepared"}
	case "invoke-run", "invoke-receipt":
		if device == "" || path == "" || ticket == "" || (cmd == "invoke-run" && bundle == "") {
			return errors.New("device, ticket, output and (for execution) bundle required")
		}
		var ciphertext []byte
		if cmd == "invoke-run" {
			ciphertext, err = preview.Invoke(device, bundle, ticket)
		} else {
			ciphertext, err = preview.InvocationReceipt(device, ticket)
		}
		if err == nil {
			err = preview.WriteReply(path, ciphertext)
		}
		result = map[string]string{"state": "sealed"}
	case "invoke-result":
		if dir == "" || path == "" {
			return errors.New("attempt directory and reply required")
		}
		result, err = preview.OpenInvocationResult(dir, path)
	case "executions":
		if device == "" {
			return errors.New("device required")
		}
		result, err = preview.Executions(device, session)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
