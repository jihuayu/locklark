package main

import (
	"encoding/json"
	"errors"
	"flag"
	"github.com/jihuayu/locklark/internal/preview"
	"io"
)

func runSession(args []string, out, diag io.Writer) error {
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(diag)
	var device, session, key, path, reason string
	if cmd == "session-keygen" {
		f.StringVar(&path, "out", "", "new .sessionkey file in a private agent directory")
	} else {
		f.StringVar(&device, "device", "", "owner device")
		f.StringVar(&session, "session", "", "session ID")
	}
	if cmd == "session-enroll" {
		f.StringVar(&key, "public", "", "independently verified Ed25519 public key")
	}
	if cmd == "session-enroll" || cmd == "session-revoke" {
		f.StringVar(&reason, "reason", "", "business reason")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if cmd != "session-keygen" && device == "" {
		return errors.New("--device required")
	}
	var result any
	var err error
	switch cmd {
	case "session-keygen":
		var pub string
		pub, err = preview.NewSessionKey(path)
		result = map[string]string{"public": pub}
	case "session-enroll":
		result, err = preview.EnrollSession(device, session, key, reason)
	case "session-revoke":
		result, err = preview.RevokeSession(device, session, reason)
	case "session-history":
		result, err = preview.SessionHistory(device, session)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
