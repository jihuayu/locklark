package vaultfileclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// This file is the explicit post-restore initialization step for the one
// dedicated managed-device successor journal. It fills the gap between the
// owner-only restore (RestoreTransferredLocalOwnedBackupOwner) and the existing
// managed publication entry point (PublishVaultFileManagedDeviceSuccessor),
// which deliberately requires an already initialized generation-zero journal.
//
// It does not import another owner record, prepare or sign a successor, publish
// a backend object, activate a profile, register a child, write recovery
// material or choose a path from transferred content. The sealed base and its
// opaque revision are re-observed locally after a fresh admission and the
// existing journal CreateNewState primitive creates the only new file.

// ErrLocalOwnedBackupManagedJournalUnconfirmed reports that the destination
// managed journal may already be durable although the create operation could
// not confirm its outcome, or that cancellation was observed only after the
// journal had been created. The journal is deliberately preserved for review.
// It is not safe to delete, replace or reinitialize it by guess: inspect the
// exact caller-named path and the exact base pin. A repeated initialization
// call on that path is refused as a pre-existing journal.
var ErrLocalOwnedBackupManagedJournalUnconfirmed = errors.New("LOCAL_OWNED_BACKUP_MANAGED_JOURNAL_UNCONFIRMED")

// LocalOwnedBackupManagedJournalInitialization is the narrow result of one
// explicit generation-zero managed-journal initialization. It carries only
// public selectors and hashes. It is not a signed policy, an activated device,
// a recovered-owner receipt, an install capability or authority for any later
// write. The later managed publication must independently re-check the live
// owner, the exact target and current policy before its CAS.
type LocalOwnedBackupManagedJournalInitialization struct {
	VaultID         string
	OwnerRootKeyID  string
	Generation      uint64
	BaseSHA256      [sha256.Size]byte
	BackendRevision vaultfilebackend.Revision
}

const localOwnedBackupManagedJournalRedacted = "[local owned backup managed journal initialization]"

func (LocalOwnedBackupManagedJournalInitialization) String() string {
	return localOwnedBackupManagedJournalRedacted
}
func (LocalOwnedBackupManagedJournalInitialization) GoString() string {
	return localOwnedBackupManagedJournalRedacted
}
func (LocalOwnedBackupManagedJournalInitialization) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedBackupManagedJournalInitialization) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, localOwnedBackupManagedJournalRedacted)
}

// InitializeTransferredLocalOwnedBackupManagedJournal creates exactly one new
// private managed-device successor journal in the independently named clean
// destination, initialized to the authenticated transferred sealed base at
// generation zero. It is the explicit step after the destination owner restore;
// it never restores an owner itself and never publishes a successor.
//
// The caller must supply, independently of the transferred content:
//   - custodyPath, pin, expected and factor: the same exact transferred
//     artifact, trusted producer pin, policy checkpoint and separate recovery
//     factor accepted by AdmitTransferredLocalOwnedBackupForRestore;
//   - locator: the trusted existing LOCAL backend root and object name;
//   - destination: the already-unlocked destination account whose stored owner
//     record must be the one exact recovered owner for expected;
//   - journalPath: the exact new private journal path. It is never derived from
//     the artifact, target, owner record or destination account.
//
// The call re-runs the read-only admission, so the artifact, its pin,
// checkpoint, factor and exact currently named target bytes and opaque revision
// are authenticated again. It then re-authenticates the destination owner store
// under the existing fresh full-factor check and selects exactly one public
// owner projection for the admitted vault ID and its exact owner-root
// key/public identity. Verified owner records for other vaults in the same
// account are unrelated siblings and do not become authority; a missing,
// duplicated or conflicting record for the requested vault is refused. It does
// not accept a caller-supplied admission or receipt as authority.
//
// The exact target is read once more and must be the same bytes and opaque
// revision already admitted. Only then does the existing O_EXCL
// vaultfilejournal.CreateNewState write BaseBytes/WorkingBytes at generation
// zero with exactly that opaque revision. No backend, account record, original
// backup, old profile, other journal or configuration is changed. A target
// re-read is a local point-in-time observation; no provider read fence is
// available here, so a later managed open/publication must perform its own live
// target and policy checks and CAS. That later path keeps all of its existing
// prerequisites.
//
// Every rejection happens before CreateNewState and writes nothing: malformed
// request/path or a wrong owner scope is ErrLocalOwnedBackupReview, a missing,
// changed or same-bytes-at-a-new-revision target is ErrLocalOwnedBackupConflict,
// cancellation is ErrLocalOwnedBackupCanceled, and an unsupported platform is
// ErrLocalOwnedBackupUnsupported. A pre-existing journal, including an empty,
// corrupt or symlinked file, is ErrLocalOwnedBackupConflict and is never
// opened, truncated, repaired or removed; O_EXCL also decides a concurrent
// create race. A create whose outcome may already be durable is
// ErrLocalOwnedBackupManagedJournalUnconfirmed and the exact journal is
// preserved. A Session lock that is definitely observed after a successful
// create is reported the same way. The last owner check and CreateNewState are
// deliberately not claimed to be one atomic transaction; a later managed
// publication still owns the full independent authority, target and CAS gate.
func InitializeTransferredLocalOwnedBackupManagedJournal(ctx context.Context,
	custodyPath string, pin LocalOwnedBackupRestoreSourcePin,
	expected vaultfile.PolicyCheckpoint,
	factor *personal.VaultFileBackupRecoveryFactor,
	locator LocalOwnedBackupRestoreBackendLocator,
	destination *personal.Session, journalPath string) (
	out LocalOwnedBackupManagedJournalInitialization, retErr error) {
	empty := LocalOwnedBackupManagedJournalInitialization{}
	if ctx == nil {
		ctx = context.Background()
	}
	if destination == nil || factor == nil ||
		!localOwnedBackupManagedJournalPathValid(journalPath) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "request")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	// This advisory observation avoids the more expensive admission for an
	// obvious existing target. CreateNewState's O_EXCL, not this check, decides
	// a concurrent create race.
	if _, err := os.Lstat(journalPath); err == nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal exists")
	} else if !os.IsNotExist(err) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal path")
	}

	admission, err := AdmitTransferredLocalOwnedBackupForRestore(ctx,
		custodyPath, pin, expected, factor, locator)
	if err != nil {
		if errors.Is(err, errLocalOwnedBackupAdmissionTarget) {
			return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "target")
		}
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	// Bind the exact destination account/owner scope with the existing genuine
	// recovered-owner read, which also enforces the fresh full-factor proof. A
	// caller-supplied receipt is never consulted.
	if err := localOwnedBackupManagedJournalCheckOwner(destination, expected,
		admission.VaultID); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	base, err := readLocalOwnedBackupManagedJournalBase(ctx, locator, admission)
	if err != nil {
		return empty, err
	}
	defer clear(base)
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	// Re-check the same exact owner scope and fresh factor at the last moment
	// before the only write. The local target read is point-in-time, so a later
	// managed publication still performs its own live owner/policy/target checks
	// and CAS.
	if err := localOwnedBackupManagedJournalCheckOwner(destination, expected,
		admission.VaultID); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	err = vaultfilejournal.CreateNewState(journalPath, vaultfilejournal.State{
		BaseBytes:      base,
		WorkingBytes:   base,
		RemoteRevision: vaultfilebackend.Revision(admission.TargetRevision),
		Generation:     0,
	})
	switch {
	case errors.Is(err, vaultfilejournal.ErrTargetExists):
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal exists")
	case errors.Is(err, vaultfilejournal.ErrUnsupported):
		return empty, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "journal")
	case errors.Is(err, vaultfilejournal.ErrInvalid):
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal path")
	case err != nil:
		return empty, localOwnedBackupError(ErrLocalOwnedBackupManagedJournalUnconfirmed, "create")
	}
	// The journal is now exactly durable. A Session lock or cancellation that
	// was definitely observed only after that point is reported without
	// pretending the file or authority was rolled back. This is a post-create
	// audit, not an assertion that the create and the last owner check were
	// atomic: the later managed publisher still performs all of its independent
	// owner, policy, target and CAS checks.
	if !destination.Unlocked() {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupManagedJournalUnconfirmed, "session")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupManagedJournalUnconfirmed, "context")
	}
	return LocalOwnedBackupManagedJournalInitialization{
		VaultID:         admission.VaultID,
		OwnerRootKeyID:  expected.OwnerRootKeyID,
		Generation:      0,
		BaseSHA256:      admission.TargetSHA256,
		BackendRevision: vaultfilebackend.Revision(admission.TargetRevision),
	}, nil
}

func localOwnedBackupManagedJournalPathValid(path string) bool {
	return path != "" && len(path) <= 4096 && utf8.ValidString(path) &&
		!strings.ContainsRune(path, 0) && filepath.IsAbs(path) &&
		filepath.Clean(path) == path
}

func localOwnedBackupManagedJournalCheckOwner(destination *personal.Session,
	expected vaultfile.PolicyCheckpoint, vaultID string) error {
	if destination == nil || expected.VaultID == "" || expected.VaultID != vaultID {
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "destination owner")
	}
	owners, err := destination.VaultFileOwnerships()
	if err != nil {
		return mapLocalOwnedBackupManagedJournalOwnerError(err)
	}
	// A dual-vault account legitimately contains several authenticated owner
	// records. Only the one record for the exact admitted vault and owner root
	// may authorize this journal; every other vault is an unrelated sibling.
	root := hex.EncodeToString(expected.OwnerRootPublicKey)
	matches := 0
	for _, owner := range owners {
		if owner.VaultID != vaultID {
			continue
		}
		if owner.OwnerRootKeyID != expected.OwnerRootKeyID ||
			owner.OwnerRootPublicKey != root {
			// A record for the requested vault under another root is a
			// conflicting scope, not an unrelated owner.
			return localOwnedBackupError(ErrLocalOwnedBackupReview, "destination owner")
		}
		matches++
	}
	if matches != 1 {
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "destination owner")
	}
	return nil
}

func readLocalOwnedBackupManagedJournalBase(ctx context.Context,
	locator LocalOwnedBackupRestoreBackendLocator,
	admission LocalOwnedBackupRestoreAdmission) ([]byte, error) {
	backend, err := vaultfilebackend.OpenExistingDir(locator.Root)
	if err != nil {
		return nil, mapLocalOwnedBackupRestoreTargetError(err)
	}
	read, readErr := backend.Read(ctx, locator.Name)
	closeErr := backend.Close()
	if readErr != nil {
		clear(read.Bytes)
		return nil, mapLocalOwnedBackupRestoreTargetError(readErr)
	}
	if closeErr != nil {
		clear(read.Bytes)
		return nil, mapLocalOwnedBackupRestoreTargetError(closeErr)
	}
	if len(read.Bytes) == 0 || len(read.Bytes) > vaultfilepublish.MaxPulledBytes ||
		len(read.Revision) == 0 || len(read.Revision) > vaultfilepublish.MaxPulledRevisionSize {
		clear(read.Bytes)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupConflict, "target")
	}
	if string(read.Revision) != admission.TargetRevision ||
		sha256.Sum256(read.Bytes) != admission.TargetSHA256 {
		clear(read.Bytes)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupConflict, "target")
	}
	if err := ctx.Err(); err != nil {
		clear(read.Bytes)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	return read.Bytes, nil
}

func mapLocalOwnedBackupManagedJournalOwnerError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, personal.ErrSessionLocked),
		errors.Is(err, personal.ErrVaultFileFullFactorRequired),
		errors.Is(err, personal.ErrFullFactorRequired):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "destination owner")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "destination owner")
	}
}
