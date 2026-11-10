package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/preview"
)

func runInvoke(args []string, out, diag io.Writer) error {
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(diag)
	var device, bundle, ticket, path, dir, session, id, review, key, pub, host, reason string
	if cmd == "approval-revoke" {
		f.StringVar(&id, "id", "", "approved request ID to revoke")
		f.StringVar(&review, "review", "", "review digest")
		f.StringVar(&reason, "reason", "", "business reason for revocation")
	}
	if cmd == "invoke-prepare" {
		f.StringVar(&key, "session-key", "", "agent signing seed file")
		f.StringVar(&pub, "recipient", "", "pinned host inbox public key file")
		f.StringVar(&host, "host-sign-key", "", "pinned host receipt verification key file")
		f.StringVar(&id, "id", "", "request ID")
		f.StringVar(&review, "review", "", "submitted request digest")
	}
	if cmd == "executions" || cmd == "invoke-prepare" {
		f.StringVar(&session, "session", "", "agent session identifier")
	}
	if cmd == "invoke-result" || cmd == "invoke-prepare" {
		f.StringVar(&dir, "attempt", "", "private attempt directory (must be new for invoke-prepare)")
	} else {
		f.StringVar(&device, "device", "", "trusted holder device directory")
	}
	if cmd == "invoke-run" || cmd == "invoke-receipt" {
		f.StringVar(&ticket, "ticket", "", "encrypted invocation ticket file")
		f.StringVar(&path, "out", "", "new encrypted reply output file")
	}
	var recording string
	if cmd == "invoke-run" {
		f.StringVar(&recording, "recorded-response", "", "local synthetic upstream JSON file (never contacts GitHub)")
		f.StringVar(&bundle, "bundle", "", "verified local epoch snapshot directory")
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
	case "approval-revoke":
		if device == "" {
			return errors.New("--device is required")
		}
		result, err = preview.RevokeApproval(device, id, review, reason)
	case "invoke-prepare":
		if dir == "" || key == "" || pub == "" || host == "" {
			return errors.New("--attempt, --session-key, --recipient, and --host-sign-key are required")
		}
		err = preview.PrepareInvocation(dir, key, pub, host, session, id, review)
		result = map[string]string{"id": id, "state": "prepared"}
	case "invoke-run", "invoke-receipt":
		if cmd == "invoke-run" && (device == "" || bundle == "" || ticket == "" || path == "") {
			return errors.New("--device, --bundle, --ticket, and --out are required")
		}
		if cmd == "invoke-receipt" && (device == "" || ticket == "" || path == "") {
			return errors.New("--device, --ticket, and --out are required")
		}
		if _, stat := os.Lstat(path); stat == nil {
			return errors.New("output already exists; choose a new path")
		} else if !errors.Is(stat, os.ErrNotExist) {
			return stat
		}
		parent, stat := os.Stat(filepath.Dir(path))
		if stat != nil {
			return stat
		}
		if !parent.IsDir() {
			return errors.New("output parent must be an existing directory")
		}
		var ciphertext []byte
		if cmd == "invoke-run" && recording != "" {
			ciphertext, err = preview.InvokeRecordedPull(device, bundle, ticket, recording)
		} else if cmd == "invoke-run" {
			ciphertext, err = preview.Invoke(device, bundle, ticket)
		} else {
			ciphertext, err = preview.InvocationReceipt(device, ticket)
		}
		if err == nil {
			if err = preview.WriteReply(path, ciphertext); err != nil {
				return fmt.Errorf("encrypted result is recorded; run invoke-receipt with the same --ticket and a new --out path: %w", err)
			}
		}
		result = map[string]string{"state": "sealed"}
	case "invoke-result":
		if dir == "" || path == "" {
			return errors.New("--attempt and --reply are required")
		}
		result, err = preview.InvocationResult(dir, path)
	case "executions":
		if device == "" {
			return errors.New("--device is required")
		}
		result, err = preview.Executions(device, session)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
