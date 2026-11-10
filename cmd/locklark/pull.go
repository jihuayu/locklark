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
	f.StringVar(&slug, "repo", "", "approved repository in OWNER/NAME format")
	f.StringVar(&repo.ID, "repo-id", "", "stable numeric repository ID")
	f.StringVar(&session, "session", "", "agent session identifier")
	f.StringVar(&reason, "reason", "", "synthetic business reason")
	if enroll {
		f.StringVar(&device, "device", "", "trusted owner device directory")
		f.StringVar(&pub, "public", "", "independently verified session public key (hex)")
	} else {
		f.StringVar(&inbox, "inbox", "", "local request spool directory")
		f.StringVar(&recipient, "recipient", "", "owner inbox public key file")
		f.StringVar(&key, "session-key", "", "agent signing seed file")
		f.StringVar(&plan, "proposal", "", "bounded built-in proposal JSON file")
		f.IntVar(&n, "pr", 0, "pull request number")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	var ok bool
	repo.Owner, repo.Name, ok = strings.Cut(slug, "/")
	if !ok || repo.Owner == "" || repo.Name == "" {
		return errors.New("--repo must be in OWNER/NAME format")
	}
	var value any
	var err error
	if enroll {
		if device == "" || pub == "" {
			return errors.New("--device and --public are required")
		}
		value, err = preview.EnrollPullSession(device, session, pub, reason, repo)
	} else {
		if inbox == "" || recipient == "" || key == "" || plan == "" {
			return errors.New("--inbox, --recipient, --session-key, and --proposal are required")
		}
		value, err = preview.SubmitPullFile(inbox, recipient, session, reason, key, repo, n, plan)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(value)
}
