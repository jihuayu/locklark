package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// This file is the read-only admission step between reopening a transferred
// custody artifact and any future authorized clean-machine install. It does not
// create a target, migrate, adopt, lock, register, revive an invitation, write
// recovery material, activate config, transition policy, call a remote service
// or retry. A successful call proves only that one independently pinned custody
// artifact is authentic and that the exact named current local backend object
// is the authenticated exact-current version. Authorized install, a new local
// identity, remote providers and account-level recovery remain outstanding.

// errLocalOwnedBackupAdmissionTarget tags the one admission refusal that means
// the authenticated source and the exact named target disagreed, as distinct
// from a malformed request or a wrong artifact/factor/pin. It stays private so
// existing admission readers keep their public ErrLocalOwnedBackupReview
// classification and error text.
var errLocalOwnedBackupAdmissionTarget = errors.New("target")

// LocalOwnedBackupRestoreSourcePin is the independently transported source pin
// for one custody artifact. It deliberately has no path field: the transferred
// artifact's new destination path is a separate local argument, while the
// original custody path, original source directory and original database are
// not inputs to admission. ArtifactSize/ArtifactSHA256, VaultID, SourceIdentity,
// checkpoint digest and the three opaque revisions/content sequence must come
// from the trusted producer result (for example the LocalOwnedBackupCustodyFile
// returned by SaveLocalOwnedBackupCustodyFile), never from the transferred file.
type LocalOwnedBackupRestoreSourcePin struct {
	ArtifactSize     int64
	ArtifactSHA256   [sha256.Size]byte
	VaultID          string
	SourceIdentity   [sha256.Size]byte
	CheckpointDigest [sha256.Size]byte
	JournalRevision  string
	BackendRevision  string
	OriginRevision   string
	ContentSeq       uint64
}

// NewLocalOwnedBackupRestoreSourcePin copies only the independently trusted
// binding fields from a saved custody file. The source Path is intentionally
// dropped: a clean-machine caller must supply the transferred file's new local
// path separately and must not treat the original path as a transport input.
func NewLocalOwnedBackupRestoreSourcePin(file LocalOwnedBackupCustodyFile) LocalOwnedBackupRestoreSourcePin {
	return LocalOwnedBackupRestoreSourcePin{
		ArtifactSize:     file.ArtifactSize,
		ArtifactSHA256:   file.ArtifactSHA256,
		VaultID:          file.VaultID,
		SourceIdentity:   file.SourceIdentity,
		CheckpointDigest: file.CheckpointDigest,
		JournalRevision:  file.JournalRevision,
		BackendRevision:  file.BackendRevision,
		OriginRevision:   file.OriginRevision,
		ContentSeq:       file.ContentSeq,
	}
}

func (p LocalOwnedBackupRestoreSourcePin) valid() bool {
	return p.ArtifactSize > 0 && p.ArtifactSHA256 != ([sha256.Size]byte{}) &&
		p.VaultID != "" && p.SourceIdentity != ([sha256.Size]byte{}) &&
		p.CheckpointDigest != ([sha256.Size]byte{}) &&
		p.JournalRevision != "" && p.BackendRevision != "" &&
		(p.OriginRevision == "") == (p.ContentSeq == 0)
}

// LocalOwnedBackupRestoreBackendLocator is the caller's explicit, independently
// trusted locator for the existing LOCAL backend object. Root and Name are not
// read from custody metadata or inferred from the artifact: the caller must
// transport them separately (for example from a local provisioning record).
// The LOCAL provider is opened non-creating; this admission does not cover a
// remote provider or a caller that cannot obtain such a trusted named locator.
type LocalOwnedBackupRestoreBackendLocator struct {
	Root string
	Name string
}

func (l LocalOwnedBackupRestoreBackendLocator) valid() bool {
	return teamfiles.ValidPath(l.Root) && vaultfilebackend.ValidName(l.Name)
}

// LocalOwnedBackupRestoreAdmission is the minimum verified read-only restore
// observation: public digests, the authenticated vault/source binding and the
// exact current opaque backend revision. It contains no plaintext item, factor,
// seed, key, source path or target bytes. It authorizes no install by itself.
type LocalOwnedBackupRestoreAdmission struct {
	VaultID          string
	ArtifactSize     int64
	ArtifactSHA256   [sha256.Size]byte
	SourceIdentity   [sha256.Size]byte
	CheckpointDigest [sha256.Size]byte
	JournalRevision  string
	BackendRevision  string
	OriginRevision   string
	ContentSeq       uint64
	TargetRevision   string
	TargetSHA256     [sha256.Size]byte
}

// String, GoString, MarshalJSON and Format are fixed redactions so an admission
// value can be safely logged without exposing identifiers, revisions, paths or
// digests. Format also covers a nil pointer.
func (LocalOwnedBackupRestoreAdmission) String() string {
	return "[local owned backup restore admission]"
}
func (LocalOwnedBackupRestoreAdmission) GoString() string {
	return "[local owned backup restore admission]"
}
func (LocalOwnedBackupRestoreAdmission) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedBackupRestoreAdmission) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned backup restore admission]"))
}

// AdmitTransferredLocalOwnedBackupForRestore performs the read-only restore
// admission for one custody artifact transported to custodyPath, without a live
// source Session, original source directory or original database.
//
// The caller must transport these independently and must not derive them from
// the transferred file:
//   - pin: the trusted artifact size/digest, vault ID, source identity,
//     source checkpoint digest and exact journal/backend/origin revisions and
//     content sequence from the save result;
//   - expected: the trusted policy checkpoint;
//   - factor: the separately stored recovery factor;
//   - locator: the trusted root and object name of the existing LOCAL backend.
//
// custodyPath is the artifact's explicit new private local path. It is not the
// original custody path; the original path, original absolute directory and
// original personal database are not required or accepted as admission inputs.
//
// The existing secure file opener re-reads and authenticates the exact artifact
// against pin/expected/factor, including the exact authenticated current source
// bytes, their policy/epoch/chain binding and their opaque backend revision. The
// exact named backend object is then read once with the existing-only local
// Dir.Read, using the caller's locator rather than any path or name from the
// artifact. Admission succeeds only when the actual current target bytes and
// its opaque backend revision are byte-for-byte equal to that already
// authenticated source version; the opener has already established that the
// source version's current policy is exactly expected. Because the source bytes
// were cryptographically verified by the opener, that equality proves the
// target has the same properties, so the target is not parsed a second time and
// no read buffer is retained. Bytes are compared by content and revisions only
// for exact equality; no revision ordering is inferred. A successfully read
// different content or revision, a same-bytes republish at a newer revision, a
// foreign policy or an advanced/replaced target is ErrLocalOwnedBackupReview
// and carries no install authorization. A missing target is
// ErrLocalOwnedBackupConflict. An invalid or non-independently-scoped request is
// ErrLocalOwnedBackupReview. Cancellation is ErrLocalOwnedBackupCanceled.
// Unsupported target providers are ErrLocalOwnedBackupUnsupported. The call
// never creates or writes a target and never retries.
func AdmitTransferredLocalOwnedBackupForRestore(ctx context.Context, custodyPath string,
	pin LocalOwnedBackupRestoreSourcePin, expected vaultfile.PolicyCheckpoint,
	factor *personal.VaultFileBackupRecoveryFactor,
	locator LocalOwnedBackupRestoreBackendLocator) (admission LocalOwnedBackupRestoreAdmission, retErr error) {
	empty := LocalOwnedBackupRestoreAdmission{}
	if ctx == nil {
		ctx = context.Background()
	}
	if !pin.valid() || factor == nil || !locator.valid() ||
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

	// The expected file is built entirely from independent trust inputs. Path is
	// the new destination path only; the original custody/source path is absent.
	expectedFile := LocalOwnedBackupCustodyFile{
		Path:             custodyPath,
		VaultID:          pin.VaultID,
		ArtifactSize:     pin.ArtifactSize,
		ArtifactSHA256:   pin.ArtifactSHA256,
		CheckpointDigest: pin.CheckpointDigest,
		SourceIdentity:   pin.SourceIdentity,
		JournalRevision:  pin.JournalRevision,
		BackendRevision:  pin.BackendRevision,
		OriginRevision:   pin.OriginRevision,
		ContentSeq:       pin.ContentSeq,
	}
	opened, actual, err := OpenLocalOwnedBackupCustodyFile(ctx, custodyPath,
		expectedFile, expected, factor)
	if err != nil {
		return empty, err
	}
	defer opened.Clear()

	backend, err := vaultfilebackend.OpenExistingDir(locator.Root)
	if err != nil {
		return empty, mapLocalOwnedBackupRestoreTargetError(err)
	}
	read, readErr := backend.Read(ctx, locator.Name)
	defer clear(read.Bytes)
	closeErr := backend.Close()
	if readErr != nil {
		return empty, mapLocalOwnedBackupRestoreTargetError(readErr)
	}
	if closeErr != nil {
		return empty, mapLocalOwnedBackupRestoreTargetError(closeErr)
	}
	if len(read.Bytes) == 0 || len(read.Bytes) > vaultfilepublish.MaxPulledBytes ||
		len(read.Revision) == 0 || len(read.Revision) > vaultfilepublish.MaxPulledRevisionSize {
		return empty, mapLocalOwnedBackupRestoreTargetError(
			fmt.Errorf("%w: target result", vaultfilepublish.ErrBackendResult))
	}
	// opened.Source.Current was parsed and cryptographically verified by the
	// custody opener against the independent expected checkpoint, including its
	// key epoch, policy proof and, for a settled vault, the genesis-to-current
	// transition. Requiring both exact byte equality and exact opaque revision
	// equality to that authenticated version proves the observed target has the
	// same properties, so the target is deliberately not parsed a second time.
	if read.Revision != opened.Source.BackendRevision ||
		!bytes.Equal(read.Bytes, opened.Source.Current) {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedBackupReview,
			errLocalOwnedBackupAdmissionTarget)
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	return LocalOwnedBackupRestoreAdmission{
		VaultID:          opened.Source.VaultID,
		ArtifactSize:     actual.ArtifactSize,
		ArtifactSHA256:   actual.ArtifactSHA256,
		SourceIdentity:   opened.SourceIdentity,
		CheckpointDigest: opened.Source.CheckpointDigest,
		JournalRevision:  string(opened.Source.JournalRevision),
		BackendRevision:  string(opened.Source.BackendRevision),
		OriginRevision:   string(opened.Source.OriginRevision),
		ContentSeq:       opened.Source.ContentSeq,
		TargetRevision:   string(read.Revision),
		TargetSHA256:     sha256.Sum256(read.Bytes),
	}, nil
}

func mapLocalOwnedBackupRestoreTargetError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, vaultfilebackend.ErrNotFound):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "target absent")
	case errors.Is(err, vaultfilebackend.ErrUnsupported):
		return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "backend")
	case errors.Is(err, vaultfilepublish.ErrVerification):
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "target")
	case errors.Is(err, vaultfilepublish.ErrInvalidArgument):
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "locator")
	case errors.Is(err, vaultfilebackend.ErrDenied):
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "locator")
	case errors.Is(err, vaultfilebackend.ErrConflict), errors.Is(err, vaultfilebackend.ErrCorrupt),
		errors.Is(err, vaultfilebackend.ErrUnknown), errors.Is(err, vaultfilepublish.ErrBackendResult):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "backend")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "backend")
	}
}
