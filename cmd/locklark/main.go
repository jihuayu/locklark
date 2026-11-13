// Command locklark runs the personal CLI, a manual GitHub query and synthetic gateway preview.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/preview"
	"github.com/jihuayu/locklark/internal/teambootstrapcli"
)

const usage = `Locklark — Local-first vault CLI, credential wrappers, team bootstrap & synthetic gateway preview

USAGE
  locklark <command> [subcommand] [flags]
  locklark help | --help | -h

COMMAND GROUPS
  personal      Manage an owner-only local vault in an interactive hidden terminal
  cli           Bind and run pinned developer CLIs with ephemeral credentials
  team          Bootstrap and inspect owner team profiles and trust pins
  plugin        Manage signed local plugin catalogs (third-party execution disabled)
  vaultfile     Inspect one sealed vault file without unlocking it

PERSONAL VAULT (locklark personal <action> --file PATH ...)
  Vault & Lifecycle
    personal init|audit|archived-audit|references     --file PATH
    personal backup|restore                           --file SOURCE --out NEW_PATH
    personal list|search                              --file PATH [--state active|archived|trashed|all]
    personal match-logins                             --file PATH --origin HTTPS_ORIGIN --frame-origin HTTPS_ORIGIN
    personal health                                   --file PATH [--hibp true]

  Items & Logins
    personal add-login                                --file PATH
    personal generate-login                           --file PATH [--length N]
    personal add-item                                 --file PATH --input ITEM.json
    personal edit-login                               --file PATH --id ID --revision REV --field title|username|password|otp|url|notes
    personal regenerate-password                      --file PATH --id ID --revision REV [--length N]
    personal archive-login|unarchive-login            --file PATH --id ID --revision REV
    personal trash-login|restore-login                --file PATH --id ID --revision REV

  Secrets & Process Disclosure
    personal reveal-login                             --file PATH --id ID --revision REV --field username|password
    personal otp                                      --file PATH --id ID --revision REV
    personal reveal-ref|otp-ref                       --file PATH --ref REF --revision REV
    personal inject-json                              --file PATH --id ID --revision REV --field username|password --name PROPERTY --out NEW.json
    personal github-pull                              --file PATH --id ID --revision REV --repository-id NUMERIC_ID --owner OWNER --repository NAME --number PR --api-ip PUBLIC_IPV4
    personal run-env                                  --file PATH --id ID --revision REV --field username|password --name ENV --cwd ABS_DIR --timeout SECONDS -- ABS_PROGRAM [ARG...]
    personal run-cli                                  --file PATH --id ID --revision REV --profile token|gh --name ENV --cwd ABS_DIR --timeout SECONDS [--helper-path ABS_DIR_LIST] -- ABS_PROGRAM [ARG...]

  Migration, Export & Passkey Transfer
    personal inspect-1pux                             --file PATH --source ARCHIVE
    personal plan-import-1pux                         --file PATH --source ARCHIVE [--model v2]
    personal import-1pux                              --file PATH --source ARCHIVE --digest PLAN_DIGEST [--model v2]
    personal export-kdbx                              --file PATH --out NEW_FILE.kdbx
    personal passkey-invite                           --file PATH --out NEW --ttl SECONDS
    personal passkey-revoke                           --file PATH --invitation FILE
    personal passkey-list                             --file PATH
    personal passkey-export                           --file PATH --invitation FILE --target-pin HEX64 --selection PRIVATE_JSON --out NEW_PACKET
    personal passkey-plan                             --file PATH --invitation FILE --packet FILE --source-pin HEX64
    personal passkey-import                           --file PATH --invitation FILE --packet FILE --source-pin HEX64 --digest HEX64 --mapping PRIVATE_JSON

  OneDrive OAuth (OS credential store, refresh token only)
    personal onedrive login|refresh                   --client-id ID --tenant TENANT --scopes SCOPE_LIST
    personal onedrive status|logout                   --client-id ID --tenant TENANT

CLI WRAPPERS (locklark cli <command> ...)
  cli profiles
  cli list       [--binding PATH]
  cli init|bind  <tool> --file PATH --program ABS_PROGRAM [--profile PROFILE] [--binding PATH] [--id ID --revision REV] [--slot-<name> ID:REV] [--helper-path ABS_DIR_LIST] [--passthrough ENV_LIST] [--timeout SECONDS] [--name ENV] [--pin-sha256 true|false]
  cli show|remove <tool> [--binding PATH]
  cli shell-init [bash|zsh|fish|powershell|pwsh] [--binding PATH] [--tools TOOL_LIST]
  cli run <tool> [--binding PATH] [--cwd ABS_DIR] [--timeout SECONDS] -- [ARG...]

TEAM BOOTSTRAP (locklark team <command> ...)
  team create|export-initial|fetch-initial|status|reconcile-protection --profile ABS_PATH [flags]
  Run "locklark team --help" for subcommand flags and exit codes.

VAULTFILE INSPECTION (read-only)
  vaultfile inspect --file PATH --checkpoint FILE
    Verify a sealed file against an explicit caller-pinned checkpoint.
    Reports policy/signature status only; does not decrypt the KDBX payload.

PLUGIN CATALOG (locklark plugin <command> ...)
  plugin init        --file NEW_DB
  plugin inspect     --package FILE --id ID --publisher HEX_KEY
  plugin install     --file DB --parent CHECKPOINT --pins TRUSTED_JSON --package FILE --id ID --publisher HEX_KEY --digest PACKAGE_DIGEST
  plugin list|audit  --file DB --anchor CHECKPOINT --pins TRUSTED_JSON
  plugin revoke      --file DB --parent CHECKPOINT --pins TRUSTED_JSON --id ID
  Third-party plugin execution is disabled.

SYNTHETIC GATEWAY PREVIEW & MCP BRIDGE
  Fixtures & Audit
    demo             --out NEW_DIR --session ID --reason TEXT
    inspect          --bundle EPOCH_DIR --device CLIENT_DIR --epoch N
    fixture-export   --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --out NEW_FILE.1pux
    audit            --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --session ID [--checkpoint FILE]
    audit-verify     --bundle EPOCH_DIR --device CLIENT_DIR --epoch N --checkpoint FILE

  Sessions & Approvals
    session-keygen   --out NEW_FILE.sessionkey
    session-enroll   --device CLIENT_B_DIR --session ID --public PUBLIC_HEX --reason TEXT
    session-revoke   --device CLIENT_B_DIR --session ID --reason TEXT
    session-history  --device CLIENT_B_DIR --session ID
    request          --inbox DIR --recipient PUBLIC_KEY_FILE --session ID --reason TEXT --ref REF [--session-key FILE]
    inbox            --inbox DIR --device CLIENT_B_DIR --session ID [--after CURSOR]
    decide           --inbox DIR --device CLIENT_B_DIR --id ID --review DIGEST --choice approve|deny --reason TEXT [--bundle EPOCH_3_DIR]
    decisions        --device CLIENT_B_DIR --session ID
    approval-revoke  --device CLIENT_B_DIR --id ID --review DIGEST --reason TEXT

  Pull Proposals, Invocation & MCP Status Bridge
    pull-enroll      --device CLIENT_B_DIR --session ID --public PUBLIC_HEX --repo OWNER/NAME --repo-id ID --reason TEXT
    pull-request     --inbox DIR --recipient FILE --session-key FILE --session ID --reason TEXT --repo OWNER/NAME --repo-id ID --pr NUMBER --proposal FILE
    invoke-prepare   --session-key FILE --recipient FILE --host-sign-key FILE --session ID --id ID --review DIGEST --attempt NEW_DIR
    invoke-run       --device CLIENT_B_DIR --bundle EPOCH_3_DIR --ticket FILE --out NEW_REPLY [--recorded-response JSON]
    invoke-receipt   --device CLIENT_B_DIR --ticket FILE --out NEW_REPLY
    invoke-result    --attempt DIR --reply FILE
    executions       --device CLIENT_B_DIR --session ID
    bridge-profile   --device CLIENT_B_DIR --session ID --out NEW_PROFILE
    mcp-stdio        --profile FILE --session-key FILE --recipient FILE --host-sign-key FILE --inbox DIR --exchange DIR --private DIR --bun ABSOLUTE_PATH
    status-serve     --device CLIENT_B_DIR --inbox DIR --exchange DIR [--once] [--session ID --profile MANAGED_FILE]
    status-answer    --device CLIENT_B_DIR --inbox DIR --exchange DIR --poll QUERY_ID

NOTES
  - Passwords, Secret Keys, search queries, and consent phrases are read only from an interactive hidden terminal.
  - onedrive login|status|logout store only a OneDrive refresh token, in the OS credential store, never a plaintext fallback.
  - Run "locklark <personal|cli|vaultfile|team|plugin> --help" for detailed group help.
  - vaultfile inspect does not use a profile, session, account, TTY, or unlock path.
  - The metadata request command accepts only ` + preview.FixtureRef + `.
  - request records a pending request. It cannot release any credential.
`

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command := args[0]
	switch command {
	case "team":
		return runTeam(args[1:], out)
	case "personal":
		return runPersonal(args[1:], out)
	case "plugin":
		return runPlugin(args[1:], out)
	case "vaultfile":
		return runVaultfile(args[1:], out)
	case "cli":
		return runCLICommand(args[1:], out)
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
		f.StringVar(&dir, "out", "", "new synthetic fixture directory")
	case "inspect", "audit", "audit-verify", "fixture-export":
		f.StringVar(&bundle, "bundle", "", "shared epoch snapshot directory")
		f.Uint64Var(&epoch, "epoch", 0, "expected epoch number, pinned independently")
	case "decide":
		f.StringVar(&dir, "inbox", "", "local request spool directory")
		f.StringVar(&bundle, "bundle", "", "epoch snapshot directory required to approve the verified fixture target")
		f.StringVar(&id, "id", "", "reviewed request ID")
		f.StringVar(&review, "review", "", "digest shown during inbox review")
		f.StringVar(&choice, "choice", "", "decision choice: approve or deny")
	case "decisions": // session-filtered local journal
	case "request", "inbox":
		f.StringVar(&dir, "inbox", "", "local request spool directory")
	default:
		return errors.New("unknown command; see locklark help")
	}
	if command == "audit" || command == "audit-verify" {
		f.StringVar(&checkpoint, "checkpoint", "", "checkpoint file from an independent trusted location")
	}
	if command == "fixture-export" {
		f.StringVar(&dir, "out", "", "new plaintext synthetic .1pux output file")
	}
	if command == "inbox" {
		f.StringVar(&after, "after", "", "pagination cursor from the previous page")
	}
	if command == "inspect" || command == "audit" || command == "inbox" || command == "fixture-export" || command == "audit-verify" || command == "decide" || command == "decisions" {
		f.StringVar(&device, "device", "", "private fixture client directory")
	}
	if command != "inspect" && command != "fixture-export" && command != "audit-verify" && command != "decide" {
		f.StringVar(&session, "session", "", "agent session identifier")
	}
	if command == "demo" || command == "request" || command == "decide" {
		f.StringVar(&reason, "reason", "", "synthetic business reason (never include a credential)")
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
		return errors.New("--session-key requires a file path")
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
			return errors.New("--bundle, --device, and --epoch are required")
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

// cliErrorText gives capacity refusals a fixed, user-safe message instead of
// the internal personal error. The vault stays unlocked and unchanged;
// malformed snapshot and verification errors keep their own text.
func cliErrorText(err error) string {
	if errors.Is(err, personal.ErrSnapshotCapacity) || errors.Is(err, personal.ErrImportCapacity) {
		return "金库容量不足：此操作加密后将超过金库存储上限，未保存，原金库保持不变。请删除或缩小大型条目或附件后重试"
	}
	return err.Error()
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		var child *childExitStatus
		if errors.As(err, &child) {
			os.Exit(child.code)
		}
		fmt.Fprintln(os.Stderr, "locklark:", cliErrorText(err))
		os.Exit(teambootstrapcli.ExitCode(err))
	}
}
