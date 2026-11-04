// Command locklark runs the offline, synthetic-only M0 preview.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jihuayu/locklark/internal/preview"
)

const usage = `Locklark · offline preview (synthetic data only)

  demo     --out NEW_DIR --session ID --reason TEXT
  inspect  --bundle EPOCH_DIR --device CLIENT_DIR --epoch N
  fixture-export --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --out NEW_FILE.1pux
  audit    --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --session ID [--checkpoint FILE]
  audit-verify --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --checkpoint FILE
  request  --inbox DIR --recipient PUBLIC_KEY_FILE --session ID --reason TEXT --ref REF
  inbox    --inbox DIR --device CLIENT_B_DIR --session ID [--after CURSOR]

The only allowed request reference is ` + preview.FixtureRef + `.
request records a pending request. It cannot release any credential.
`

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command := args[0]
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(errOut)
	var dir, bundle, device, session, reason, recipient, ref, after, checkpoint string
	var epoch uint64
	switch command {
	case "demo":
		f.StringVar(&dir, "out", "", "new fixture directory")
	case "inspect", "audit", "audit-verify", "fixture-export":
		f.StringVar(&bundle, "bundle", "", "shared epoch directory")
		f.Uint64Var(&epoch, "epoch", 0, "expected epoch, pinned independently")
	case "request", "inbox":
		f.StringVar(&dir, "inbox", "", "local request spool")
	default:
		return errors.New("unknown command; see locklark help")
	}
	if command == "audit" || command == "audit-verify" {
		f.StringVar(&checkpoint, "checkpoint", "", "checkpoint from an independent trusted location")
	}
	if command == "fixture-export" {
		f.StringVar(&dir, "out", "", "new plaintext synthetic .1pux file")
	}
	if command == "inbox" {
		f.StringVar(&after, "after", "", "cursor from the previous page")
	}
	if command == "inspect" || command == "audit" || command == "inbox" || command == "fixture-export" || command == "audit-verify" {
		f.StringVar(&device, "device", "", "private fixture client directory")
	}
	if command != "inspect" && command != "fixture-export" && command != "audit-verify" {
		f.StringVar(&session, "session", "", "agent session identifier")
	}
	if command == "demo" || command == "request" {
		f.StringVar(&reason, "reason", "", "synthetic business reason; never include a credential")
	}
	if command == "request" {
		f.StringVar(&recipient, "recipient", "", "trusted file containing only the owner's public inbox key")
		f.StringVar(&ref, "ref", "", "synthetic field reference")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	requestedWitness := false
	f.Visit(func(opt *flag.Flag) {
		if opt.Name == "checkpoint" {
			requestedWitness = true
		}
	})
	if requestedWitness && checkpoint == "" {
		return errors.New("--checkpoint requires a trusted checkpoint file")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	var result any
	var err error
	switch command {
	case "demo":
		err = preview.Create(dir, session, reason)
		result = map[string]any{"synthetic": true, "epochs": []int{1, 2, 3}, "out": dir}
	case "inspect", "audit", "audit-verify", "fixture-export":
		if bundle == "" || device == "" || epoch == 0 {
			return errors.New("--bundle, --device and --epoch are required")
		}
		if command == "fixture-export" {
			err = preview.ExportFixture(bundle, device, epoch, dir)
			result = map[string]any{"synthetic": true, "exported": dir, "epoch": epoch}
		} else if command == "inspect" {
			result, err = preview.Inspect(bundle, device, epoch)
		} else {
			if command == "audit-verify" {
				result, err = preview.VerifyAudit(bundle, device, epoch, checkpoint)
			} else if checkpoint != "" {
				result, err = preview.AuditWithCheckpoint(bundle, device, epoch, session, checkpoint)
			} else {
				result, err = preview.Audit(bundle, device, epoch, session)
			}
		}
	case "request":
		if dir == "" || recipient == "" {
			return errors.New("--inbox and --recipient are required")
		}
		var id string
		id, err = preview.Submit(dir, recipient, session, reason, ref)
		result = map[string]string{"id": id, "state": "pending"}
	case "inbox":
		if dir == "" || device == "" {
			return errors.New("--inbox and --device are required")
		}
		result, err = preview.InboxPage(dir, device, session, after)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "locklark:", err)
		os.Exit(1)
	}
}
