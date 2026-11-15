package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfilesync"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

const vaultFileUsage = `USAGE
  locklark vault-file import-prepared --config ABS_CONFIG --input ABS_SEALED_FILE
  locklark vault-file resume-prepared --config ABS_CONFIG

Import one already signed sealed content successor into an existing clean
baseline journal, or resume its prepared operation. Darwin and Linux only.
Import reads a private input file of at most 32 MiB; it never reads or writes the
backend. Config, input and journal must be distinct and outside its namespace.
No paths or baseline are created. Import saves working and prepares in separate
transactions: LOCAL_REVIEW or LOCAL_UNKNOWN may leave saved working/prepared
state. Retry the same exact input; different local edits are preserved.

The independently supplied private JSON configuration requires version=1,
backend_root, name, journal and checkpoint. The complete checkpoint requires
vault_id, owner_root_key_id, owner_root_public_key (64 lowercase hex),
policy_seq (explicitly present; zero is valid) and policy_digest (64 lowercase hex).

The operator configuration supplies local trust. No default configuration is
created, migrated or inferred from a backend response. This command does not
decrypt, re-sign, merge, or establish current SaaS grants or remote freshness.
`

var (
	errVaultFileConfig       = errors.New("CONFIG_REJECTED")
	errVaultFileJournal      = errors.New("JOURNAL_REJECTED")
	errVaultFileBackend      = errors.New("BACKEND_REJECTED")
	errVaultFileVerification = errors.New("VERIFY_REJECTED")
	errVaultFileUnknown      = errors.New("UNKNOWN_REVIEW")
	errVaultFileConflict     = errors.New("CONFLICT")
	errVaultFileCancelled    = errors.New("CANCELLED")
	errVaultFileUnsupported  = errors.New("UNSUPPORTED")
	errVaultFileUnconfirmed  = errors.New("RESUME_UNCONFIRMED")
	errVaultFileInput        = errors.New("INPUT_REJECTED")
	errVaultFileLocalReview  = errors.New("LOCAL_REVIEW")
	errVaultFileLocalUnknown = errors.New("LOCAL_UNKNOWN")
)

type vaultFileCheckpointConfig struct {
	VaultID            string  `json:"vault_id"`
	OwnerRootKeyID     string  `json:"owner_root_key_id"`
	OwnerRootPublicKey string  `json:"owner_root_public_key"`
	PolicySeq          *uint64 `json:"policy_seq"`
	PolicyDigest       string  `json:"policy_digest"`
}

type vaultFileResumeConfig struct {
	Version     int                        `json:"version"`
	BackendRoot string                     `json:"backend_root"`
	Name        string                     `json:"name"`
	Journal     string                     `json:"journal"`
	Checkpoint  *vaultFileCheckpointConfig `json:"checkpoint"`
}

func decodeVaultFileResumeConfig(raw []byte) (vaultFileResumeConfig, vaultfile.PolicyCheckpoint, error) {
	var cfg vaultFileResumeConfig
	var pin vaultfile.PolicyCheckpoint
	if teamfiles.JSON(raw, &cfg) != nil || cfg.Version != 1 ||
		!teamfiles.ValidPath(cfg.BackendRoot) || !teamfiles.ValidPath(cfg.Journal) ||
		!vaultfilebackend.ValidName(cfg.Name) || cfg.Checkpoint == nil {
		return cfg, pin, errVaultFileConfig
	}
	cp := cfg.Checkpoint
	if cp.PolicySeq == nil || cp.VaultID == "" || cp.OwnerRootKeyID == "" ||
		len(cp.VaultID) > 4096 || len(cp.OwnerRootKeyID) > 4096 {
		return cfg, pin, errVaultFileConfig
	}
	public, ok := decodeVaultFileHex(cp.OwnerRootPublicKey)
	if !ok {
		return cfg, pin, errVaultFileConfig
	}
	digest, ok := decodeVaultFileHex(cp.PolicyDigest)
	if !ok {
		return cfg, pin, errVaultFileConfig
	}
	pin = vaultfile.PolicyCheckpoint{
		VaultID: cp.VaultID, OwnerRootKeyID: cp.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(public), PolicySeq: *cp.PolicySeq, PolicyDigest: digest,
	}
	return cfg, pin, nil
}

func decodeVaultFileHex(value string) ([]byte, bool) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == 32
}

func runVaultFile(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") ||
		len(args) == 2 && (args[0] == "resume-prepared" || args[0] == "import-prepared") && (args[1] == "--help" || args[1] == "-h") {
		if _, err := io.WriteString(out, vaultFileUsage); err != nil {
			return errVaultFileUnconfirmed
		}
		return nil
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errVaultFileUnsupported
	}
	if len(args) == 0 || args[0] != "resume-prepared" && args[0] != "import-prepared" {
		return errVaultFileConfig
	}
	importing := args[0] == "import-prepared"
	flags := flag.NewFlagSet("vault-file "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "independent operator configuration")
	var inputPath string
	if importing {
		flags.StringVar(&inputPath, "input", "", "existing signed sealed content successor")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !teamfiles.ValidPath(*configPath) {
		return errVaultFileConfig
	}
	if importing && !teamfiles.ValidPath(inputPath) {
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
	if err != nil {
		return errVaultFileConfig
	}
	paths := []string{*configPath, cfg.Journal}
	if importing {
		paths = append(paths, inputPath)
	}
	if !teamfiles.Distinct(paths...) {
		return errVaultFileConfig
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
