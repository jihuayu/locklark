package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// localOwnedBackupCustodyFileLimit is the existing single-vault custody
// artifact bound. The file helper must not silently shrink the supported
// archive by reusing a narrower transfer-file limit.
const localOwnedBackupCustodyFileLimit = 128 << 20

// ErrLocalOwnedBackupUnknown reports that the final custody file may already be
// visible but its binding, sync or cleanup was not confirmed. The returned pin
// identifies only the intended path and bytes. It does not assert that a fresh
// reopen will succeed or that the directory update is durable; callers must
// verify those with an explicit reopen/reread and must never retry by replacing
// or removing that path.
var ErrLocalOwnedBackupUnknown = errors.New("LOCAL_OWNED_BACKUP_UNKNOWN")

// localCustodyFileSaveHooks is a private per-invocation seam. Production passes
// the zero value; tests may interleave a failure only after the durable file
// publication has completed. It is never a package-global hook and cannot
// inject a success.
type localCustodyFileSaveHooks struct {
	afterDurablePublish func() error
}

// LocalOwnedBackupCustodyFile is the safe public pin for one custody artifact
// saved on disk. It contains only the exact path, bounded size, public digests
// and the authenticated public vault/source bindings. It never contains a
// recovery factor, owner seed, key, plaintext item or checkpoint bytes.
type LocalOwnedBackupCustodyFile struct {
	Path             string
	VaultID          string
	ArtifactSize     int64
	ArtifactSHA256   [sha256.Size]byte
	CheckpointDigest [sha256.Size]byte
	SourceIdentity   [sha256.Size]byte
	JournalRevision  string
	BackendRevision  string
	OriginRevision   string
	ContentSeq       uint64
}

func (f LocalOwnedBackupCustodyFile) valid() bool {
	return teamfiles.ValidPath(f.Path) && f.VaultID != "" && f.ArtifactSize > 0 &&
		f.ArtifactSHA256 != ([sha256.Size]byte{}) &&
		f.CheckpointDigest != ([sha256.Size]byte{}) &&
		f.SourceIdentity != ([sha256.Size]byte{}) &&
		f.JournalRevision != "" && f.BackendRevision != "" &&
		(f.OriginRevision == "") == (f.ContentSeq == 0)
}

// SaveLocalOwnedBackupCustodyFile authenticates one already prepared artifact
// against the exact caller-pinned checkpoint and separately held recovery
// factor through the existing in-memory opener. It then writes exactly those
// artifact bytes, with no factor, checkpoint file or other metadata, to a new
// private regular file using secure path validation, an exact held parent,
// same-directory owned staging, no-replace publication, and the platform's
// file/publication durability barrier. The actual published bytes are
// re-opened and re-verified before any success is reported.
//
// An existing destination, symlink, unsafe parent, parent interchange before
// publication or cancellation before publication is refused without replacing
// it and only the owned staged name is cleaned. If publication became visible
// but its binding, sync or cleanup could not be confirmed, the error is
// ErrLocalOwnedBackupUnknown. The returned pin then identifies the intended
// path and bytes only; it does not prove that a fresh exact reopen will succeed
// or that the final directory update is durable. This call never retries,
// removes or overwrites the visible final file.
func SaveLocalOwnedBackupCustodyFile(ctx context.Context, path string, artifact []byte,
	expected vaultfile.PolicyCheckpoint, factor *personal.VaultFileBackupRecoveryFactor) (file LocalOwnedBackupCustodyFile, retErr error) {
	return saveLocalOwnedBackupCustodyFile(ctx, path, artifact, expected, factor,
		localCustodyFileSaveHooks{})
}

func saveLocalOwnedBackupCustodyFile(ctx context.Context, path string, artifact []byte,
	expected vaultfile.PolicyCheckpoint, factor *personal.VaultFileBackupRecoveryFactor,
	hooks localCustodyFileSaveHooks) (file LocalOwnedBackupCustodyFile, retErr error) {
	empty := LocalOwnedBackupCustodyFile{}
	if ctx == nil {
		ctx = context.Background()
	}
	if !teamfiles.ValidPath(path) || factor == nil ||
		!localOwnedBackupCustodyFileCheckpointValid(expected) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "file request")
	}
	if len(artifact) == 0 || len(artifact) > localOwnedBackupCustodyFileLimit {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "file size")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	if err := teamfiles.CheckNew(path); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "destination")
	}

	opened, err := OpenLocalOwnedBackupCustody(ctx, artifact, expected, factor)
	if err != nil {
		return empty, err
	}
	sourceIdentity := opened.SourceIdentity
	vaultID := opened.Source.VaultID
	journalRevision := string(opened.Source.JournalRevision)
	backendRevision := string(opened.Source.BackendRevision)
	originRevision := string(opened.Source.OriginRevision)
	contentSeq := opened.Source.ContentSeq
	opened.Clear()
	if vaultID != expected.VaultID || sourceIdentity == ([sha256.Size]byte{}) ||
		journalRevision == "" || backendRevision == "" ||
		(originRevision == "") != (contentSeq == 0) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "file scope")
	}

	digest := sha256.Sum256(artifact)
	file = LocalOwnedBackupCustodyFile{
		Path:             path,
		VaultID:          vaultID,
		ArtifactSize:     int64(len(artifact)),
		ArtifactSHA256:   digest,
		CheckpointDigest: localOwnedBackupCheckpointDigest(expected),
		SourceIdentity:   sourceIdentity,
		JournalRevision:  journalRevision,
		BackendRevision:  backendRevision,
		OriginRevision:   originRevision,
		ContentSeq:       contentSeq,
	}

	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	if err := teamfiles.CheckNew(path); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "destination")
	}
	if err := teamfiles.WriteNewLimited(ctx, path, artifact, localOwnedBackupCustodyFileLimit); err != nil {
		if errors.Is(err, teamfiles.ErrPublicationUnknown) {
			return file, fmt.Errorf("%w: publication", ErrLocalOwnedBackupUnknown)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			ctx.Err() != nil {
			return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
		}
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "write")
	}
	if hooks.afterDurablePublish != nil {
		if err := hooks.afterDurablePublish(); err != nil {
			return file, fmt.Errorf("%w: %w", ErrLocalOwnedBackupUnknown, err)
		}
	}

	staged, err := teamfiles.ReadLimited(ctx, path, localOwnedBackupCustodyFileLimit, true)
	if err != nil {
		return file, fmt.Errorf("%w: reopen", ErrLocalOwnedBackupUnknown)
	}
	defer clear(staged)
	if int64(len(staged)) != file.ArtifactSize ||
		sha256.Sum256(staged) != file.ArtifactSHA256 || !bytes.Equal(staged, artifact) {
		return file, fmt.Errorf("%w: staged digest", ErrLocalOwnedBackupUnknown)
	}
	verified, err := OpenLocalOwnedBackupCustody(ctx, staged, expected, factor)
	if err != nil {
		return file, fmt.Errorf("%w: staged verification", ErrLocalOwnedBackupUnknown)
	}
	verifiedIdentity := verified.SourceIdentity
	verifiedVaultID := verified.Source.VaultID
	verified.Clear()
	if verifiedIdentity != file.SourceIdentity || verifiedVaultID != file.VaultID {
		return file, fmt.Errorf("%w: staged scope", ErrLocalOwnedBackupUnknown)
	}
	if err := ctx.Err(); err != nil {
		return file, fmt.Errorf("%w: context", ErrLocalOwnedBackupUnknown)
	}
	return file, nil
}

// OpenLocalOwnedBackupCustodyFile reads one bounded private custody artifact
// and verifies it against the exact pin returned by
// SaveLocalOwnedBackupCustodyFile, the caller-pinned checkpoint and the
// separately held recovery factor. A missing, replaced, oversized, wrong-vault,
// wrong-checkpoint, wrong-factor or tampered file is refused before any source
// is returned. It does not install, restore, activate or write anything.
func OpenLocalOwnedBackupCustodyFile(ctx context.Context, path string,
	expectedFile LocalOwnedBackupCustodyFile, expected vaultfile.PolicyCheckpoint,
	factor *personal.VaultFileBackupRecoveryFactor) (opened LocalOwnedBackupCustodyOpen,
	actual LocalOwnedBackupCustodyFile, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if expectedFile.ArtifactSize > localOwnedBackupCustodyFileLimit {
		return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "file size")
	}
	if !expectedFile.valid() || expectedFile.Path != path || factor == nil ||
		!localOwnedBackupCustodyFileCheckpointValid(expected) {
		return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupReview, "file request")
	}
	if err := ctx.Err(); err != nil {
		return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	artifact, err := teamfiles.ReadLimited(ctx, path, localOwnedBackupCustodyFileLimit, true)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			ctx.Err() != nil {
			return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
		}
		return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupConflict, "read")
	}
	defer clear(artifact)
	if int64(len(artifact)) != expectedFile.ArtifactSize ||
		sha256.Sum256(artifact) != expectedFile.ArtifactSHA256 {
		return opened, actual, localOwnedBackupError(ErrLocalOwnedBackupConflict, "artifact digest")
	}
	opened, err = OpenLocalOwnedBackupCustody(ctx, artifact, expected, factor)
	if err != nil {
		return LocalOwnedBackupCustodyOpen{}, actual, err
	}
	actual = LocalOwnedBackupCustodyFile{
		Path:             path,
		VaultID:          opened.Source.VaultID,
		ArtifactSize:     int64(len(artifact)),
		ArtifactSHA256:   expectedFile.ArtifactSHA256,
		CheckpointDigest: localOwnedBackupCheckpointDigest(expected),
		SourceIdentity:   opened.SourceIdentity,
		JournalRevision:  string(opened.Source.JournalRevision),
		BackendRevision:  string(opened.Source.BackendRevision),
		OriginRevision:   string(opened.Source.OriginRevision),
		ContentSeq:       opened.Source.ContentSeq,
	}
	if actual.VaultID != expectedFile.VaultID ||
		actual.CheckpointDigest != expectedFile.CheckpointDigest ||
		actual.SourceIdentity != expectedFile.SourceIdentity ||
		actual.JournalRevision != expectedFile.JournalRevision ||
		actual.BackendRevision != expectedFile.BackendRevision ||
		actual.OriginRevision != expectedFile.OriginRevision ||
		actual.ContentSeq != expectedFile.ContentSeq {
		opened.Clear()
		return LocalOwnedBackupCustodyOpen{}, actual,
			localOwnedBackupError(ErrLocalOwnedBackupReview, "file binding")
	}
	if err := ctx.Err(); err != nil {
		opened.Clear()
		return LocalOwnedBackupCustodyOpen{}, actual,
			localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	return opened, actual, nil
}

func localOwnedBackupCustodyFileCheckpointValid(checkpoint vaultfile.PolicyCheckpoint) bool {
	return checkpoint.VaultID != "" && checkpoint.OwnerRootKeyID != "" &&
		len(checkpoint.OwnerRootPublicKey) > 0 && len(checkpoint.PolicyDigest) > 0
}
