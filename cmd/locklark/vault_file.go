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
  locklark vault-file resume-prepared --config ABS_CONFIG

Resume one already prepared operation using an existing local-directory backend
and an existing private journal. Supported on Darwin and Linux only.

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
		len(args) == 2 && args[0] == "resume-prepared" && (args[1] == "--help" || args[1] == "-h") {
		if _, err := io.WriteString(out, vaultFileUsage); err != nil {
			return errVaultFileUnconfirmed
		}
		return nil
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errVaultFileUnsupported
	}
	if len(args) == 0 || args[0] != "resume-prepared" {
		return errVaultFileConfig
	}
	flags := flag.NewFlagSet("vault-file resume-prepared", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "independent operator configuration")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !teamfiles.ValidPath(*configPath) {
		return errVaultFileConfig
	}
	// Read only this explicit operator-owned-or-root-owned private regular
	// file. No global settings, migration path or environment fallback is used.
	raw, err := teamfiles.Read(*configPath, 64<<10, true)
	if err != nil {
		return errVaultFileConfig
	}
	defer clear(raw)
	cfg, pin, err := decodeVaultFileResumeConfig(raw)
	if err != nil || !teamfiles.Distinct(*configPath, cfg.Journal) {
		return errVaultFileConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := resumeVaultFile(ctx, cfg, pin); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, `{"status":"RESUMED"}`); err != nil {
		return errVaultFileUnconfirmed
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
