package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/jihuayu/locklark/internal/agentmcp"
	"github.com/jihuayu/locklark/internal/preview"
	"io"
)

func runBridge(args []string, out, diag io.Writer) error {
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(diag)
	var c agentmcp.Config
	var device, session, path, poll string
	var once bool
	if cmd == "status-serve" {
		f.BoolVar(&once, "once", false, "answer outstanding status queries once and exit")
		f.StringVar(&session, "session", "", "optional enrolled session ID for profile renewal")
		f.StringVar(&path, "profile", "", "managed bridge profile file for renewal")
	}
	if cmd == "bridge-profile" || cmd == "status-answer" || cmd == "status-serve" {
		f.StringVar(&device, "device", "", "trusted holder device directory")
	}
	if cmd == "bridge-profile" {
		f.StringVar(&session, "session", "", "enrolled PR session ID")
		f.StringVar(&path, "out", "", "new public launch profile file")
	}
	if cmd == "mcp-stdio" || cmd == "status-answer" || cmd == "status-serve" {
		f.StringVar(&c.Poll.Exchange, "exchange", "", "status-only courier exchange directory")
		f.StringVar(&c.Inbox, "inbox", "", "local request spool directory")
	}
	if cmd == "status-answer" {
		f.StringVar(&poll, "poll", "", "read-only status query ID")
	}
	if cmd == "mcp-stdio" {
		f.StringVar(&c.Profile, "profile", "", "signed holder-issued launch profile")
		f.StringVar(&c.Poll.Key, "session-key", "", "agent signing seed file")
		f.StringVar(&c.Poll.Recipient, "recipient", "", "pinned holder inbox public key file")
		f.StringVar(&c.Poll.Host, "host-sign-key", "", "pinned holder signing public key file")
		f.StringVar(&c.Poll.Private, "private", "", "private bridge state directory")
		f.StringVar(&c.Bun, "bun", "", "trusted absolute path to Bun executable")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if cmd == "mcp-stdio" {
		return agentmcp.Serve(context.Background(), c)
	}
	var err error
	if cmd == "status-serve" {
		err = preview.ServeStatus(context.Background(), device, c.Inbox, c.Poll.Exchange, session, path, once)
	} else if cmd == "bridge-profile" {
		if device == "" || path == "" {
			return errors.New("--device and --out are required")
		}
		err = preview.ExportBridgeProfile(device, session, path)
	} else {
		err = preview.AnswerStatus(device, c.Inbox, c.Poll.Exchange, poll)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"state": "written"})
}
