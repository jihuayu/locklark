package vaultfileclient

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// ErrLocalOwnedBackupRestoreUnconfirmed reports that the destination owner
// import may already be durable although a post-commit context, lock, fresh
// factor or database close check failed. An exact retry is safe and either
// proves the same private owner or reports a real refusal. Callers must not
// assume rollback and must not replace or overwrite the destination store.
var ErrLocalOwnedBackupRestoreUnconfirmed = errors.New("LOCAL_OWNED_BACKUP_RESTORE_UNCONFIRMED")

// RestoreTransferredLocalOwnedBackupOwner performs the owner/recovery custody
// part of one clean-account restore without a source Session, original source
// directory or original database. It reads exactly the independently pinned
// transferred artifact, checks its size and SHA-256 against the trusted producer
// pin, and hands those exact bytes plus the pin's exact source identity, opaque
// revisions and content sequence to the destination Session's owning restore
// operation. That operation authenticates the artifact and separate recovery
// factor, compares every issued source field before any target read or owner
// store transaction, reads the caller-located existing LOCAL backend
// non-creating, requires exact authenticated bytes and opaque revision, and
// inserts only the single private owner/recovery record into the destination's
// encrypted owner store under the recovery-specific action and a fresh
// full-factor check. The target read is a local point-in-time observation; it
// does not fence, stop or prove the absence of remote writers.
//
// Pin.SourceIdentity is the canonical personal VaultFileBackupCustodySourceIdentity
// produced by SaveLocalOwnedBackupCustodyFile and recomputed by the custody
// opener, not the client-local LocalOwnedBackupSource identity digest.
//
// The destination ordinary device identity is not the source identity and is
// never replaced. No config is activated, no vault child or invitation is
// opened, no remote provider is contacted, and no target is created. The
// returned public ownership projection is local metadata only: it is not a
// signed policy, an activated device, a remote freshness proof or authority for
// any later write. A later management write must independently re-check current
// policy and CAS. An exact retry is idempotent. A missing or replaced target is
// ErrLocalOwnedBackupConflict, a wrong artifact/factor/checkpoint/source binding
// or a colliding private owner record is ErrLocalOwnedBackupReview,
// cancellation/lock is ErrLocalOwnedBackupCanceled, and a possibly committed
// but unconfirmed result is ErrLocalOwnedBackupRestoreUnconfirmed.
func RestoreTransferredLocalOwnedBackupOwner(ctx context.Context, custodyPath string,
	pin LocalOwnedBackupRestoreSourcePin, expected vaultfile.PolicyCheckpoint,
	factor *personal.VaultFileBackupRecoveryFactor,
	locator LocalOwnedBackupRestoreBackendLocator,
	destination *personal.Session) (personal.VaultFileOwnershipPublic, error) {
	empty := personal.VaultFileOwnershipPublic{}
	if ctx == nil {
		ctx = context.Background()
	}
	if destination == nil || !pin.valid() || factor == nil || !locator.valid() ||
		!localOwnedBackupCustodyFileCheckpointValid(expected) ||
		pin.VaultID != expected.VaultID ||
		pin.CheckpointDigest != localOwnedBackupCheckpointDigest(expected) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "request")
	}
	if pin.ArtifactSize > localOwnedBackupCustodyFileLimit {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "file size")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	artifact, err := teamfiles.ReadLimited(ctx, custodyPath, localOwnedBackupCustodyFileLimit, true)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			ctx.Err() != nil {
			return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
		}
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "artifact")
	}
	defer clear(artifact)
	if int64(len(artifact)) != pin.ArtifactSize ||
		sha256.Sum256(artifact) != pin.ArtifactSHA256 {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "artifact digest")
	}
	ownership, err := destination.RestoreVaultFileBackupCustodyOwner(ctx, artifact,
		expected, factor, personal.VaultFileBackupCustodyRestoreSourceBinding{
			VaultID:         pin.VaultID,
			SourceIdentity:  pin.SourceIdentity,
			JournalRevision: pin.JournalRevision,
			BackendRevision: pin.BackendRevision,
			OriginRevision:  pin.OriginRevision,
			ContentSeq:      pin.ContentSeq,
		}, personal.VaultFileBackupCustodyRestoreTarget{
			Root: locator.Root, Name: locator.Name,
		})
	if err != nil {
		return empty, mapLocalOwnedBackupOwnerRestoreError(err)
	}
	if ownership.VaultID != pin.VaultID ||
		ownership.VaultID != expected.VaultID ||
		ownership.OwnerRootKeyID != expected.OwnerRootKeyID {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "owner binding")
	}
	return ownership, nil
}

func mapLocalOwnedBackupOwnerRestoreError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, personal.ErrVaultFileBackupCustodyCanceled),
		errors.Is(err, personal.ErrSessionLocked),
		errors.Is(err, personal.ErrVaultFileFullFactorRequired),
		errors.Is(err, personal.ErrFullFactorRequired):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "restore")
	case errors.Is(err, personal.ErrVaultFileBackupCustodyRestoreUnconfirmed):
		return localOwnedBackupError(ErrLocalOwnedBackupRestoreUnconfirmed, "restore")
	case errors.Is(err, personal.ErrVaultFileBackupCustodyTarget):
		if errors.Is(err, vaultfilebackend.ErrUnsupported) {
			return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "target")
		}
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "target")
	case errors.Is(err, personal.ErrVaultFileOwnership), errors.Is(err, personal.ErrArchiveLimit):
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "owner")
	case errors.Is(err, personal.ErrVaultFileBackupCustodyLimit):
		return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "custody")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "restore")
	}
}
