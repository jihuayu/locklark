package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/internal/vaultfilesync"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

const vaultFileUsage = `USAGE
  locklark vault-file create --config ABS_NEW_MANIFEST --personal-file ABS_PERSONAL --backend-root ABS_DIR --name NAME --journal ABS_JOURNAL --archive ABS_FUTURE_BACKUP
  locklark vault-file create --config ABS_EXISTING_MANIFEST
  locklark vault-file track-existing --config ABS_CONFIG
  locklark vault-file status --config ABS_CONFIG
  locklark vault-file open-baseline --config ABS_CONFIG
  locklark vault-file open-baseline --include-item-ids --config ABS_CONFIG
  locklark vault-file edit-prepared --config ABS_CONFIG --input ABS_PRIVATE_EDIT
  locklark vault-file import-prepared --config ABS_CONFIG --input ABS_SEALED_FILE
  locklark vault-file resume-prepared --config ABS_CONFIG

Create first prepares a private, durable VaultID and local owner and recovery
custody. BACKUP_REQUIRED means run locklark personal backup --file ABS_PERSONAL
--out ABS_FUTURE_BACKUP, confirm its recovery kit on the terminal, and keep
both archive and kit safe. Run create again with the same config path and enter
the kit on the controlling terminal. Create persists one exact G and immutable
local companion before any backend Create, then uses the Dir backend's
claim/readback/Ack path. LOCAL_BASELINE reports a verified local genesis base
with remote_freshness UNVERIFIED, not a current grant or remote head. Status and
open-baseline accept the original create config after that local Ack.
Create reserves config plus ".baseline" and the backend namespace. It rejects
paths differing only by case or canonical Unicode (NFC) normalization, even
on filesystems where those spellings are distinct.

Status reads only the existing configured local journal's contents and prints
exactly one of CLEAN, DIRTY, PREPARED or REVIEW with remote_freshness UNVERIFIED. REVIEW
means a legacy or inconsistent pending local record; it is never repaired.
Missing, corrupt or unsafe local records are refused. Status never opens the
backend store or reads its contents; it checks backend path metadata only to
reject journal or config paths inside its managed namespace. It never verifies
a remote or grant, decrypts, re-signs, merges or edits.

Open-baseline authenticates and decrypts only the existing journal's saved
baseline with the same fully unlocked local personal device and the supplied
checkpoint. It prints bounded title/category summaries, LOCAL_BASELINE and
remote_freshness UNVERIFIED. It does not read backend data or establish a
current grant, remote freshness or complete content history.
The explicit --include-item-ids mode adds only existing item IDs to those
summaries for later selection. An item ID is not authority; the default output
never includes IDs.

Edit-prepared reads a private JSON request with item_id, expected_old_title and
new_title. It requires fresh full-factor local writer authority, saves only a
sealed direct child of the existing local base and prepares that exact proposal.
It does not read backend data; resume-prepared performs the remote read and CAS.
An offline edit is not evidence of remote freshness or a current SaaS grant.

Import one already signed sealed content successor into an existing clean
baseline journal, or resume its prepared operation. Darwin and Linux only.
Import reads a private input file of at most 32 MiB; it never reads or writes the
backend. Config, input and journal must be distinct and outside its namespace.
Track reads one existing remote sealed file, verifies its signatures against
the external checkpoint, then exclusively creates only the configured journal.
Its operator-owned private parent must already exist. Every existing target is
refused. TRACKED proves a signed sealed baseline, not decryptability, payload
correctness, content history or freshness. LOCAL_UNKNOWN leaves the target for
review; tracking never deletes or repairs it and cannot retry an existing path.
Import saves working and prepares in separate
transactions: LOCAL_REVIEW or LOCAL_UNKNOWN may leave saved working/prepared
state. Retry the same exact input; different local edits are preserved.

The independently supplied private JSON configuration requires version=1,
backend_root, name, journal and checkpoint; open-baseline and edit-prepared
also require the explicit absolute personal_file. The complete checkpoint requires
vault_id, owner_root_key_id, owner_root_public_key (64 lowercase hex),
policy_seq (explicitly present; zero is valid) and policy_digest (64 lowercase hex).

The operator configuration supplies local trust. No default configuration is
created, migrated or inferred from a backend response. No command establishes
current SaaS grants or remote freshness.
`

var (
	errVaultFileConfig       = vaultfileclient.ErrConfig
	errVaultFileJournal      = errors.New("JOURNAL_REJECTED")
	errVaultFileBackend      = vaultfileclient.ErrBackend
	errVaultFileVerification = errors.New("VERIFY_REJECTED")
	errVaultFileUnknown      = errors.New("UNKNOWN_REVIEW")
	errVaultFileConflict     = errors.New("CONFLICT")
	errVaultFileCancelled    = errors.New("CANCELLED")
	errVaultFileUnsupported  = errors.New("UNSUPPORTED")
	errVaultFileUnconfirmed  = errors.New("RESUME_UNCONFIRMED")
	errVaultFileInput        = errors.New("INPUT_REJECTED")
	errVaultFileLocalReview  = errors.New("LOCAL_REVIEW")
	errVaultFileLocalUnknown = errors.New("LOCAL_UNKNOWN")
	errVaultFileTargetExists = errors.New("TARGET_EXISTS")
)

type vaultFileCheckpointConfig = vaultfileclient.CheckpointConfig
type vaultFileResumeConfig = vaultfileclient.ResumeConfig

func decodeVaultFileResumeConfig(raw []byte) (vaultFileResumeConfig, vaultfile.PolicyCheckpoint, error) {
	return vaultfileclient.DecodeResumeConfig(raw)
}

func decodeVaultFileHex(value string) ([]byte, bool) {
	return vaultfileclient.DecodeHex(value)
}

func runVaultFile(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "create" {
		return runVaultFileCreate(args[1:], out)
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") ||
		len(args) == 2 && (args[0] == "resume-prepared" || args[0] == "import-prepared" || args[0] == "edit-prepared" || args[0] == "track-existing" || args[0] == "status" || args[0] == "open-baseline") && (args[1] == "--help" || args[1] == "-h") {
		if _, err := io.WriteString(out, vaultFileUsage); err != nil {
			return errVaultFileUnconfirmed
		}
		return nil
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errVaultFileUnsupported
	}
	if len(args) == 0 || args[0] != "resume-prepared" && args[0] != "import-prepared" && args[0] != "edit-prepared" && args[0] != "track-existing" && args[0] != "status" && args[0] != "open-baseline" {
		return errVaultFileConfig
	}
	importing := args[0] == "import-prepared"
	editing := args[0] == "edit-prepared"
	flags := flag.NewFlagSet("vault-file "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "independent operator configuration")
	var inputPath string
	var includeItemIDs bool
	if args[0] == "open-baseline" {
		flags.BoolVar(&includeItemIDs, "include-item-ids", false, "include item selectors in the verified local baseline summary")
	}
	if importing {
		flags.StringVar(&inputPath, "input", "", "existing signed sealed content successor")
	} else if editing {
		flags.StringVar(&inputPath, "input", "", "private title edit request")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !teamfiles.ValidPath(*configPath) {
		return errVaultFileConfig
	}
	if (importing || editing) && !teamfiles.ValidPath(inputPath) {
		return errVaultFileInput
	}
	// Read only this explicit operator-owned-or-root-owned private regular
	// file. No global settings, migration path or environment fallback is used.
	raw, err := teamfiles.Read(*configPath, 64<<10, true)
	if err != nil {
		return errVaultFileConfig
	}
	defer clear(raw)
	cfg, pin, err := decodeVaultFileResumeConfig(raw)
	fromCreate := false
	if err != nil && (args[0] == "status" || args[0] == "open-baseline") {
		cfg, pin, err = resumeConfigFromCreateManifest(*configPath)
		fromCreate = err == nil
	}
	if err != nil {
		return errVaultFileConfig
	}
	paths := []string{*configPath, cfg.Journal}
	if fromCreate {
		companionPath, err := vaultFileCreateCompanionPath(*configPath)
		if err != nil {
			return errVaultFileConfig
		}
		paths = append(paths, companionPath)
	}
	if cfg.PersonalFile != "" {
		paths = append(paths, cfg.PersonalFile)
	}
	if importing || editing {
		paths = append(paths, inputPath)
	}
	if !teamfiles.Distinct(paths...) {
		return errVaultFileConfig
	}
	if args[0] == "open-baseline" {
		if cfg.PersonalFile == "" {
			return errVaultFileConfig
		}
		info, err := os.Lstat(cfg.PersonalFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errVaultFileConfig
		}
		if err := separateVaultFileStatusState(cfg.BackendRoot, paths...); err != nil {
			return err
		}
		return openBaselineVaultFile(out, cfg, pin, includeItemIDs)
	}
	if args[0] == "status" {
		if err := separateVaultFileStatusState(cfg.BackendRoot, paths...); err != nil {
			return err
		}
		return statusVaultFile(out, cfg)
	}
	if editing {
		if cfg.PersonalFile == "" {
			return errVaultFileConfig
		}
		info, err := os.Lstat(cfg.PersonalFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errVaultFileConfig
		}
		if err := separateVaultFileStatusState(cfg.BackendRoot, paths...); err != nil {
			return err
		}
		input, err := teamfiles.Read(inputPath, 4096, true)
		if err != nil {
			return errVaultFileInput
		}
		defer clear(input)
		return editPreparedVaultFile(out, cfg, pin, input)
	}
	if err := separateVaultFileResumeState(cfg.BackendRoot, paths...); err != nil {
		return err
	}
	var input []byte
	if importing {
		input, err = teamfiles.Read(inputPath, vaultfilebackend.MaxValueSize, true)
		if err != nil {
			return errVaultFileInput
		}
		defer clear(input)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if args[0] == "track-existing" {
		if err := trackExistingVaultFile(ctx, cfg, pin); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, `{"status":"TRACKED"}`); err != nil {
			return errVaultFileLocalUnknown
		}
		return nil
	}
	if importing {
		if err := importPreparedVaultFile(ctx, cfg, pin, input); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, `{"status":"PREPARED"}`); err != nil {
			return errVaultFileLocalUnknown
		}
		return nil
	}
	if err := resumeVaultFile(ctx, cfg, pin); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, `{"status":"RESUMED"}`); err != nil {
		return errVaultFileUnconfirmed
	}
	return nil
}

// Keep the CLI call site and its error identities while sharing the strict
// read-only status scope with other vault-file clients.
func separateVaultFileStatusState(backendRoot string, paths ...string) error {
	return vaultfileclient.SeparateStatusState(backendRoot, paths...)
}

// The backend owns its whole documented vaultfile-backend subtree, including
// temporary-file recovery and future version directories. Operator config and
// journal files must stay outside it before either persistent store is opened.
// Resolve existing ancestors, then compare directory identity: lexical prefixes
// miss symlink aliases and case aliases on case-insensitive filesystems.
// This is a read-only scope check; the existing APIs still enforce their own
// owner, mode, link and path-identity checks and same-operator threat model.
func separateVaultFileResumeState(backendRoot string, paths ...string) error {
	root, err := filepath.EvalSymlinks(backendRoot)
	if err != nil {
		return errVaultFileBackend
	}
	namespace, err := os.Lstat(filepath.Join(root, "vaultfile-backend"))
	if err != nil || !namespace.IsDir() {
		return errVaultFileBackend
	}
	for _, path := range paths {
		// Include the namespace directory itself. A missing leaf is left for
		// OpenExisting to reject; resolving its parent never creates it.
		if info, err := os.Stat(path); err == nil && os.SameFile(namespace, info) {
			return errVaultFileConfig
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return errVaultFileConfig
		}
		for {
			info, err := os.Stat(parent)
			if err != nil || !info.IsDir() || os.SameFile(namespace, info) {
				return errVaultFileConfig
			}
			next := filepath.Dir(parent)
			if next == parent {
				break
			}
			parent = next
		}
	}
	return nil
}

func resumeVaultFile(ctx context.Context, cfg vaultFileResumeConfig, pin vaultfile.PolicyCheckpoint) (retErr error) {
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	journal, err := vaultfilejournal.OpenExisting(cfg.Journal)
	if err != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		return errVaultFileJournal
	}
	defer func() {
		if journal.Close() != nil && retErr == nil {
			retErr = errVaultFileUnconfirmed
		}
	}()
	state, err := journal.LoadState()
	if err != nil || len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || state.RemoteRevision == "" {
		return errVaultFileJournal
	}
	prepared, err := journal.LoadPrepared()
	if err != nil || prepared.Proposal.ExpectedRevision != state.RemoteRevision ||
		prepared.WorkingGeneration > state.Generation ||
		prepared.WorkingGeneration == state.Generation && !bytes.Equal(state.WorkingBytes, prepared.Proposal.Bytes) {
		return errVaultFileJournal
	}
	proposalVerifier, err := vaultfilesync.NewContentProposalVerifier(&pin)
	if err != nil || proposalVerifier(ctx, state.BaseBytes, state.RemoteRevision, prepared.Proposal) != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		return errVaultFileVerification
	}
	// Validate the saved operation against the independent pin before opening
	// the backend. Even a stale backend ticket must not be repaired on behalf
	// of a malformed journal or a wrong operator pin.
	backend, err := vaultfilebackend.OpenExistingDir(cfg.BackendRoot)
	if err != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		return errVaultFileBackend
	}
	defer func() {
		if backend.Close() != nil && retErr == nil {
			retErr = errVaultFileUnconfirmed
		}
	}()
	pullVerifier := func(ctx context.Context, data []byte, _ vaultfilebackend.Revision) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := vaultfile.ParseFile(data)
		if err != nil {
			return err
		}
		return vaultfile.VerifyPolicyCheckpoint(file, &pin)
	}
	pulled, err := vaultfilepublish.ReadPulled(ctx, backend, cfg.Name, pullVerifier)
	if err != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		if errors.Is(err, vaultfilepublish.ErrVerification) {
			return errVaultFileVerification
		}
		return errVaultFileBackend
	}
	coordinator, err := vaultfilepublish.NewCoordinator(backend, journal, cfg.Name, proposalVerifier)
	if err != nil {
		return errVaultFileUnconfirmed
	}
	err = coordinator.ResumePrepared(ctx, pulled, pullVerifier)
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return errVaultFileCancelled
	case errors.Is(err, vaultfilepublish.ErrVerification):
		return errVaultFileVerification
	case errors.Is(err, vaultfilepublish.ErrUnknownReview), errors.Is(err, vaultfilepublish.ErrUnknownWrite), errors.Is(err, vaultfilebackend.ErrUnknown):
		return errVaultFileUnknown
	case errors.Is(err, vaultfilepublish.ErrConflict), errors.Is(err, vaultfilebackend.ErrConflict):
		return errVaultFileConflict
	default:
		return errVaultFileUnconfirmed
	}
}
