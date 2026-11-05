// Command locklark runs the personal CLI, a manual GitHub query and synthetic gateway preview.
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

const usage = `Locklark · personal CLI, manual GitHub query and synthetic gateway preview

  plugin init --file NEW_DB
  plugin inspect --package FILE --id ID --publisher HEX_KEY
  plugin install --file DB --parent CHECKPOINT --pins TRUSTED_JSON --package FILE --id ID --publisher HEX_KEY --digest PACKAGE_DIGEST
  plugin list|audit --file DB --anchor CHECKPOINT --pins TRUSTED_JSON
  plugin revoke --file DB --parent CHECKPOINT --pins TRUSTED_JSON --id ID
  Third-party plugin execution is disabled.

  personal edit-login --file PATH --id ID --revision REV --field title|username|password|otp|url
  personal reveal-login --file PATH --id ID --revision REV --field username|password
  personal generate-login --file PATH [--length N]
  personal regenerate-password --file PATH --id ID --revision REV [--length N]
  personal otp --file PATH --id ID --revision REV
  personal references --file PATH
  personal health --file PATH
  personal github-pull --file PATH --id ID --revision REV --repository-id NUMERIC_ID --owner OWNER --repository NAME --number PR --api-ip PUBLIC_IPV4
  personal inject-json --file PATH --id ID --revision REV --field username|password --name PROPERTY --out NEW.json
  personal inspect-1pux --file PATH --source ARCHIVE
  personal plan-import-1pux --file PATH --source ARCHIVE
  personal import-1pux --file PATH --source ARCHIVE --digest PLAN_DIGEST
  personal export-kdbx --file PATH --out NEW_FILE.kdbx
  personal trash-login|restore-login --file PATH --id ID --revision REV
  personal archive-login|unarchive-login --file PATH --id ID --revision REV
  personal list --file PATH [--state active|archived|trashed|all]
  personal match-logins --file PATH --origin HTTPS_ORIGIN --frame-origin HTTPS_ORIGIN
  personal reveal-ref|otp-ref --file PATH --ref REF --revision REV
  personal <init|add-login|list|audit> --file PATH  (interactive local-owner terminal)

  demo     --out NEW_DIR --session ID --reason TEXT
  inspect  --bundle EPOCH_DIR --device CLIENT_DIR --epoch N
  fixture-export --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --out NEW_FILE.1pux
  audit    --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --session ID [--checkpoint FILE]
  audit-verify --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --checkpoint FILE
  request  --inbox DIR --recipient PUBLIC_KEY_FILE --session ID --reason TEXT --ref REF [--session-key FILE]
  inbox    --inbox DIR --device CLIENT_B_DIR --session ID [--after CURSOR]

  approval-revoke --device CLIENT_B_DIR --id ID --review DIGEST --reason TEXT
  invoke-prepare --session-key FILE --recipient FILE --host-sign-key FILE --session ID --id ID --review DIGEST --attempt NEW_DIR
  pull-enroll --device CLIENT_B_DIR --session ID --public PUBLIC_HEX --repo OWNER/NAME --repo-id ID --reason TEXT
  pull-request --inbox DIR --recipient FILE --session-key FILE --session ID --reason TEXT --repo OWNER/NAME --repo-id ID --pr NUMBER --proposal FILE
  invoke-run     --device CLIENT_B_DIR --bundle EPOCH_3_DIR --ticket FILE --out NEW_REPLY [--recorded-response JSON]
  invoke-receipt --device CLIENT_B_DIR --ticket FILE --out NEW_REPLY
  invoke-result  --attempt DIR --reply FILE
  executions     --device CLIENT_B_DIR --session ID
  bridge-profile --device CLIENT_B_DIR --session ID --out NEW_PROFILE
  mcp-stdio --profile FILE --session-key FILE --recipient FILE --host-sign-key FILE --inbox DIR --exchange DIR --private DIR --bun ABSOLUTE_PATH
  status-serve --device CLIENT_B_DIR --inbox DIR --exchange DIR [--once] [--session ID --profile MANAGED_FILE]
  status-answer --device CLIENT_B_DIR --inbox DIR --exchange DIR --poll QUERY_ID
  session-keygen --out NEW_FILE.sessionkey
  session-enroll --device CLIENT_B_DIR --session ID --public PUBLIC_HEX --reason TEXT
  session-revoke --device CLIENT_B_DIR --session ID --reason TEXT
  session-history --device CLIENT_B_DIR --session ID
  decide   --inbox DIR --device CLIENT_B_DIR --id ID --review DIGEST --choice approve|deny --reason TEXT [--bundle EPOCH_3_DIR]
  decisions --device CLIENT_B_DIR --session ID

The metadata request command accepts only ` + preview.FixtureRef + `.
request records a pending request. It cannot release any credential.
`

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command := args[0]
	switch command {
	case "personal":
		return runPersonal(args[1:], out)
	case "plugin":
		return runPlugin(args[1:], out)
	case "mcp-stdio", "bridge-profile", "status-answer", "status-serve":
		return runBridge(args, out, errOut)
	case "pull-enroll", "pull-request":
		return runPull(args, out, errOut)
	case "invoke-prepare", "invoke-run", "invoke-receipt", "invoke-result", "executions", "approval-revoke":
		return runInvoke(args, out, errOut)
	case "session-keygen", "session-enroll", "session-revoke", "session-history":
		return runSession(args, out, errOut)
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(errOut)
	var dir, bundle, device, session, reason, recipient, ref, after, checkpoint, id, review, choice, sessionKey string
	var epoch uint64
	switch command {
	case "demo":
		f.StringVar(&dir, "out", "", "new fixture directory")
	case "inspect", "audit", "audit-verify", "fixture-export":
		f.StringVar(&bundle, "bundle", "", "shared epoch directory")
		f.Uint64Var(&epoch, "epoch", 0, "expected epoch, pinned independently")
	case "decide":
		f.StringVar(&dir, "inbox", "", "request spool")
		f.StringVar(&bundle, "bundle", "", "required to approve the verified fixture target")
		f.StringVar(&id, "id", "", "reviewed request ID")
		f.StringVar(&review, "review", "", "digest shown during inbox review")
		f.StringVar(&choice, "choice", "", "approve or deny")
	case "decisions": // session-filtered local journal
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
	if command == "inspect" || command == "audit" || command == "inbox" || command == "fixture-export" || command == "audit-verify" || command == "decide" || command == "decisions" {
		f.StringVar(&device, "device", "", "private fixture client directory")
	}
	if command != "inspect" && command != "fixture-export" && command != "audit-verify" && command != "decide" {
		f.StringVar(&session, "session", "", "agent session identifier")
	}
	if command == "demo" || command == "request" || command == "decide" {
		f.StringVar(&reason, "reason", "", "synthetic business reason; never include a credential")
	}
	if command == "request" {
		f.StringVar(&sessionKey, "session-key", "", "agent-owned signing seed file")
		f.StringVar(&recipient, "recipient", "", "trusted file containing only the owner's public inbox key")
		f.StringVar(&ref, "ref", "", "synthetic field reference")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	requestedWitness := false
	requestedKey := false
	f.Visit(func(opt *flag.Flag) {
		if opt.Name == "session-key" {
			requestedKey = true
		}
		if opt.Name == "checkpoint" {
			requestedWitness = true
		}
	})
	if requestedKey && sessionKey == "" {
		return errors.New("--session-key requires a file")
	}
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
	case "decide":
		if dir == "" || device == "" {
			return errors.New("--inbox and --device are required")
		}
		result, err = preview.Decide(dir, device, bundle, id, review, choice, reason)
	case "decisions":
		if device == "" {
			return errors.New("--device is required")
		}
		result, err = preview.Decisions(device, session)
	case "request":
		if dir == "" || recipient == "" {
			return errors.New("--inbox and --recipient are required")
		}
		result, err = preview.SubmitReceipt(dir, recipient, session, reason, ref, sessionKey)
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
