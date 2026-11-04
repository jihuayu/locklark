package main

import (
	"encoding/json"
	"errors"
	"flag"
	"github.com/jihuayu/locklark/internal/gateway"
	"github.com/jihuayu/locklark/internal/preview"
	"io"
	"strings"
)

func runPull(args []string, out, diag io.Writer) error {
	enroll := args[0] == "pull-enroll"
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(diag)
	var repo gateway.Repository
	var slug, session, reason, device, pub, inbox, recipient, key, plan string
	var n int
	f.StringVar(&slug, "repo", "", "approved owner/name")
	f.StringVar(&repo.ID, "repo-id", "", "stable numeric repository ID")
	f.StringVar(&session, "session", "", "agent session")
	f.StringVar(&reason, "reason", "", "business reason")
	if enroll {
		f.StringVar(&device, "device", "", "owner device")
		f.StringVar(&pub, "public", "", "verified session public key")
	} else {
		f.StringVar(&inbox, "inbox", "", "request directory")
		f.StringVar(&recipient, "recipient", "", "owner inbox public key")
		f.StringVar(&key, "session-key", "", "agent session key")
		f.StringVar(&plan, "proposal", "", "bounded built-in proposal JSON")
		f.IntVar(&n, "pr", 0, "pull request number")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	var ok bool
	repo.Owner, repo.Name, ok = strings.Cut(slug, "/")
	if f.NArg() != 0 || !ok {
		return errors.New("repository must be owner/name")
	}
	var value any
	var err error
	if enroll {
		if device == "" || pub == "" {
			return errors.New("device and session public key required")
		}
		value, err = preview.EnrollPullSession(device, session, pub, reason, repo)
	} else {
		if inbox == "" || recipient == "" || key == "" || plan == "" {
			return errors.New("inbox, recipient, session key and proposal required")
		}
		value, err = preview.SubmitPullFile(inbox, recipient, session, reason, key, repo, n, plan)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(value)
}
