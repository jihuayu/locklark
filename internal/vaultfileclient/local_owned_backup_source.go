package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/fs"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

var (
	// ErrLocalOwnedBackupReview rejects a selector, factor, account, owner or
	// locator that does not authenticate the one explicitly selected vault.
	ErrLocalOwnedBackupReview = errors.New("LOCAL_OWNED_BACKUP_REVIEW")
	// ErrLocalOwnedBackupConflict reports a missing, pending, replaced or
	// drifted journal/backend observation. No source is returned.
	ErrLocalOwnedBackupConflict = errors.New("LOCAL_OWNED_BACKUP_CONFLICT")
	// ErrLocalOwnedBackupUnsupported reports a state that is newer or outside
	// the current pristine/first-successor producer formats.
	ErrLocalOwnedBackupUnsupported = errors.New("LOCAL_OWNED_BACKUP_UNSUPPORTED")
	// ErrLocalOwnedBackupCanceled reports cancellation, RequestLock or a closed
	// child observed while the capture was in flight.
	ErrLocalOwnedBackupCanceled = errors.New("LOCAL_OWNED_BACKUP_CANCELED")
)

var (
	errLocalOwnedBackupTargetMismatch = errors.New("local owned backup: target mismatch")

	// localOwnedBackupBeforeCloseForTest is nil in production. Tests use it to
	// install the wrapper's existing first-close seam without receiving a
	// factor, key, token or ciphertext. The public entry still makes every
	// decision.
	localOwnedBackupBeforeCloseForTest func(*localGenesisSessionState)
)

// LocalOwnedBackupSource is one exact authenticated encrypted backup input for
// one existing account-owned local vault. Current is always the backend bytes
// observed at the recorded opaque revision. Origin is non-nil only for a
// settled owned first successor and is the authenticated encrypted genesis
// needed by the existing pristine/first-successor verifier. Every byte slice is
// ciphertext; no private seed, device key, VUK or decrypted item is retained.
//
// The value is coherent at the observed journal/backend read. It does not stop
// writers, prove remote durability or authorize a backup/restore acceptance on
// its own. Callers own the copies and must call Clear when finished.
type LocalOwnedBackupSource struct {
	VaultID string
	// Current is the exact encrypted backend value observed at BackendRevision.
	Current []byte
	// Origin is the authenticated encrypted genesis for a settled first
	// successor and nil for a pristine generation-zero source.
	Origin []byte
	// JournalRevision is the exact opaque revision recorded in the verified
	// journal for Current.
	JournalRevision vaultfilebackend.Revision
	// BackendRevision is the exact opaque revision observed for Current and
	// must equal JournalRevision.
	BackendRevision vaultfilebackend.Revision
	// OriginRevision is the exact opaque genesis revision recorded in a settled
	// journal record and empty for a pristine source.
	OriginRevision vaultfilebackend.Revision
	// ContentSeq is the authenticated current content sequence (0 pristine, 1
	// first successor). It is preserved, never recomputed from a projection.
	ContentSeq uint64
	// Checkpoint is the immutable authenticated per-vault policy/owner pin.
	Checkpoint vaultfile.PolicyCheckpoint
	// CheckpointDigest is the stable local identity of Checkpoint for the next
	// recovery/inventory step. It is not a signature or remote freshness proof.
	CheckpointDigest [sha256.Size]byte
	// IdentityDigest binds the checkpoint, revisions, counters and exact
	// encrypted endpoints into one stable local source identity.
	IdentityDigest [sha256.Size]byte
}

// String, GoString, MarshalJSON and Format are fixed redactions. Format also
// covers a nil *LocalOwnedBackupSource and never dereferences retained bytes.
func (LocalOwnedBackupSource) String() string   { return "[local owned backup source]" }
func (LocalOwnedBackupSource) GoString() string { return "[local owned backup source]" }
func (LocalOwnedBackupSource) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedBackupSource) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned backup source]"))
}

// Clear zeroes every retained ciphertext, checkpoint byte and digest. It is
// idempotent and safe on a nil pointer.
func (s *LocalOwnedBackupSource) Clear() {
	if s == nil {
		return
	}
	clear(s.Current)
	clear(s.Origin)
	clear(s.Checkpoint.OwnerRootPublicKey)
	clear(s.Checkpoint.PolicyDigest)
	*s = LocalOwnedBackupSource{}
}

// CaptureLocalOwnedBackupSource captures exactly one existing, explicitly
// selected account-owned local vault. It re-reads the strict manifest and
// companion, proves the supplied full factors and current account/owner through
// the existing owned-child path, authenticates the pristine generation-zero
// state or the settled owned first successor with the existing journal and
// companion proofs, and reads the actual manifest-named local backend object
// exactly. The observed bytes and opaque revision must equal the journal proof
// byte-for-byte; a same-bytes new revision is refused.
//
// The temporary owned child is the only child closed. The parent Session and
// siblings are not locked or closed. Every check is repeated before delivery,
// and explicit cancellation or RequestLock before the final gate fails closed.
// No backend, journal, vault, locator, config, key store or destination is
// written.
func CaptureLocalOwnedBackupSource(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (source LocalOwnedBackupSource, retErr error) {
	empty := LocalOwnedBackupSource{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "request")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	wrapper, initial, err := OpenLocalGenesisSessionForJournal(
		s, configPath, workspaceRoot, vaultID, expectedJournal, password, key)
	clearLocalGenesisItems(initial.Items)
	if err != nil {
		return empty, classifyLocalOwnedBackupRefusal(
			s, configPath, workspaceRoot, vaultID, expectedJournal, err)
	}
	if wrapper == nil || wrapper.state == nil {
		if wrapper != nil {
			_ = wrapper.Close()
		}
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "child")
	}
	wrapperClosed := false
	defer func() {
		if wrapperClosed {
			return
		}
		closeErr := wrapper.Close()
		if retErr != nil {
			source.Clear()
			return
		}
		if closeErr != nil {
			source.Clear()
			retErr = localOwnedBackupError(ErrLocalOwnedBackupReview, "child close")
		}
	}()

	state := wrapper.state
	state.mu.Lock()
	if state.closed || state.parent != s {
		state.mu.Unlock()
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "child closed")
	}
	manifest := state.manifest
	companion := state.companion
	revision := state.revision
	successor := state.successor
	token := state.token
	state.mu.Unlock()

	if manifest.Journal != expectedJournal || manifest.VaultID != vaultID ||
		manifest.BackendRoot != workspaceRoot || manifest.PersonalFile != s.VaultPath() {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupReview, "locator")
	}

	snapshot, err := readLocalOwnedBackupSnapshot(manifest, companion)
	if err != nil {
		return empty, err
	}
	defer snapshot.clear()
	if err := snapshot.bind(successor, revision); err != nil {
		return empty, err
	}

	// Revalidate the frozen locator and the exact owned child through the
	// existing narrow rules before reading the target or disclosing anything.
	if err := state.revalidateLocator(); err != nil {
		return empty, mapLocalOwnedBackupOpenError(err)
	}
	if err := s.RevalidateVaultFileChildOwnership(token); err != nil {
		return empty, mapLocalOwnedBackupOpenError(err)
	}
	if err := state.revalidateLocator(); err != nil {
		return empty, mapLocalOwnedBackupOpenError(err)
	}
	if !s.Unlocked() {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "session")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	pulled, err := readLocalOwnedBackupTarget(ctx, manifest, snapshot.current, snapshot.journalRevision)
	if err != nil {
		return empty, err
	}

	// The source comes from the final target read, so recheck the exact locator
	// after that read. The delivery claim below independently re-proves exact
	// current ownership before it is created.
	if err := state.revalidateLocator(); err != nil {
		return empty, mapLocalOwnedBackupOpenError(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	claim, err := s.BeginVaultFileReadDeliveryClaim(token)
	if err != nil {
		return empty, mapLocalOwnedBackupClaimError(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	// Build every delivered value before any slow close or final arbitration.
	checkpoint := snapshot.checkpoint
	snapshot.checkpoint = nil
	origin := snapshot.origin
	snapshot.origin = nil
	source = LocalOwnedBackupSource{
		VaultID:         manifest.VaultID,
		Current:         pulled.Bytes(),
		Origin:          origin,
		JournalRevision: snapshot.journalRevision,
		BackendRevision: pulled.Revision(),
		OriginRevision:  snapshot.originRevision,
		ContentSeq:      snapshot.contentSeq,
		Checkpoint:      *checkpoint,
	}
	if source.JournalRevision != source.BackendRevision ||
		(source.Origin == nil) != (source.OriginRevision == "") {
		source.Clear()
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "revision")
	}
	source.CheckpointDigest = localOwnedBackupCheckpointDigest(source.Checkpoint)
	source.IdentityDigest = localOwnedBackupIdentityDigest(source)

	// Finish the real child close and its error before the final short gate.
	if localOwnedBackupBeforeCloseForTest != nil {
		localOwnedBackupBeforeCloseForTest(state)
	}
	closeErr := state.closeWith(claim)
	wrapperClosed = true
	if closeErr != nil {
		source.Clear()
		if err := ctx.Err(); err != nil {
			return empty, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
		}
		return empty, localOwnedBackupError(ErrLocalOwnedBackupConflict, "child close")
	}
	if err := claim.Consume(ctx, s); err != nil {
		source.Clear()
		return empty, mapLocalOwnedBackupClaimError(err)
	}
	return source, nil
}

// localOwnedBackupSnapshot is one authenticated pristine or first-successor
// journal observation. It owns its checkpoint and encrypted byte slices.
type localOwnedBackupSnapshot struct {
	pristine        bool
	checkpoint      *vaultfile.PolicyCheckpoint
	origin          []byte
	originRevision  vaultfilebackend.Revision
	current         []byte
	journalRevision vaultfilebackend.Revision
	contentSeq      uint64
	pin             vaultfilejournal.OwnedGenesisPin
}

func (s *localOwnedBackupSnapshot) clear() {
	if s == nil {
		return
	}
	clearLocalGenesisCheckpoint(s.checkpoint)
	clear(s.origin)
	clear(s.current)
	clear(s.pin.Root.OwnerRootPublicKey)
	*s = localOwnedBackupSnapshot{}
}

func (s *localOwnedBackupSnapshot) bind(successor *localGenesisSuccessorLocator, revision string) error {
	if s == nil || s.checkpoint == nil {
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "snapshot")
	}
	if successor == nil {
		if !s.pristine || s.journalRevision != vaultfilebackend.Revision(revision) || s.origin != nil {
			return localOwnedBackupError(ErrLocalOwnedBackupConflict, "state")
		}
		return nil
	}
	if s.pristine || s.journalRevision != vaultfilebackend.Revision(successor.successorRevision) ||
		s.journalRevision != vaultfilebackend.Revision(revision) ||
		s.origin == nil || s.originRevision == "" ||
		!sameLocalGenesisGenesisPin(s.pin, successor.pin) {
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "successor")
	}
	return nil
}

func readLocalOwnedBackupSnapshot(manifest Manifest, companion Companion) (*localOwnedBackupSnapshot, error) {
	if companion.Resume.Checkpoint == nil {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "checkpoint")
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "owner")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "pin")
	}

	record, successorErr := vaultfilejournal.ReadOwnedFirstSuccessor(manifest.Journal, pin)
	if successorErr == nil {
		snapshot, err := localOwnedBackupSettledSnapshot(manifest, companion, pin, record)
		if err == nil {
			// The snapshot now owns both encrypted endpoints.
			record.GenesisBytes = nil
			record.SuccessorBytes = nil
		}
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		return snapshot, err
	}
	clear(record.GenesisBytes)
	clear(record.SuccessorBytes)

	journal, openErr := vaultfilejournal.OpenExisting(manifest.Journal)
	if openErr == nil {
		state, loadErr := journal.LoadGenesisBaseline()
		closeErr := journal.Close()
		if loadErr == nil && closeErr == nil {
			snapshot, err := localOwnedBackupPristineSnapshot(manifest, companion, pin, root, state)
			if err == nil {
				// The snapshot now owns the pristine ciphertext.
				state.BaseBytes = nil
			}
			clear(state.BaseBytes)
			clear(state.WorkingBytes)
			return snapshot, err
		}
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		return nil, classifyLocalOwnedBackupSnapshotFailure(successorErr, openErr, loadErr, closeErr)
	}

	return nil, classifyLocalOwnedBackupSnapshotFailure(successorErr, openErr, nil, nil)
}

func localOwnedBackupSettledSnapshot(manifest Manifest, companion Companion,
	pin vaultfilejournal.OwnedGenesisPin, record vaultfilejournal.OwnedFirstSuccessor) (*localOwnedBackupSnapshot, error) {
	checkpoint, err := verifyLocalGenesisSuccessor(manifest, companion, pin, record)
	if err != nil || checkpoint == nil {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "successor proof")
	}
	successor, err := vaultfile.ParseFile(record.SuccessorBytes)
	if err != nil || !localOwnedBackupSupportedContent(successor, 1) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "successor format")
	}
	origin, err := vaultfile.ParseFile(record.GenesisBytes)
	if err != nil || !localOwnedBackupSupportedContent(origin, 0) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "origin format")
	}
	return &localOwnedBackupSnapshot{
		checkpoint:      checkpoint,
		origin:          record.GenesisBytes,
		originRevision:  record.GenesisRevision,
		current:         record.SuccessorBytes,
		journalRevision: record.SuccessorRevision,
		contentSeq:      successor.Header.ContentSeq,
		pin:             cloneLocalGenesisGenesisPin(pin),
	}, nil
}

func localOwnedBackupPristineSnapshot(manifest Manifest, companion Companion,
	pin vaultfilejournal.OwnedGenesisPin, root []byte, state vaultfilejournal.State) (*localOwnedBackupSnapshot, error) {
	if sha256.Sum256(state.BaseBytes) != pin.SealedSHA256 ||
		state.RemoteRevision == "" || !bytes.Equal(state.BaseBytes, state.WorkingBytes) {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupConflict, "pristine")
	}
	checkpoint, revision, err := verifyLocalGenesisState(manifest.Journal, manifest.VaultID, companion, root)
	if err != nil || checkpoint == nil ||
		!localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "pristine proof")
	}
	if revision == "" || revision != string(state.RemoteRevision) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupConflict, "pristine revision")
	}
	file, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || !localOwnedBackupSupportedContent(file, 0) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "pristine format")
	}
	return &localOwnedBackupSnapshot{
		pristine:        true,
		checkpoint:      checkpoint,
		current:         state.BaseBytes,
		journalRevision: state.RemoteRevision,
		contentSeq:      file.Header.ContentSeq,
		pin:             cloneLocalGenesisGenesisPin(pin),
	}, nil
}

// localOwnedBackupSupportedContent admits only the current proven producer
// formats: genesis and the immediate ordinary-content first successor. Any
// later policy sequence, key epoch or content sequence is refused explicitly.
func localOwnedBackupSupportedContent(file *vaultfile.File, contentSeq uint64) bool {
	return file != nil && file.Header.KeyEpoch == 1 &&
		file.Header.PolicySeq == 0 && file.Header.ContentSeq == contentSeq &&
		len(file.SignedPolicyProofs) == 1
}

func readLocalOwnedBackupTarget(ctx context.Context, manifest Manifest, expected []byte, revision vaultfilebackend.Revision) (vaultfilepublish.Pulled, error) {
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		return vaultfilepublish.Pulled{}, mapLocalOwnedBackupTargetError(err)
	}
	pulled, readErr := vaultfilepublish.ReadPulled(ctx, backend, manifest.Name,
		func(_ context.Context, data []byte, observed vaultfilebackend.Revision) error {
			if observed != revision || !bytes.Equal(data, expected) {
				return errLocalOwnedBackupTargetMismatch
			}
			return nil
		})
	closeErr := backend.Close()
	if readErr != nil {
		return vaultfilepublish.Pulled{}, mapLocalOwnedBackupTargetError(readErr)
	}
	if closeErr != nil {
		return vaultfilepublish.Pulled{}, mapLocalOwnedBackupTargetError(closeErr)
	}
	if pulled.Revision() != revision {
		return vaultfilepublish.Pulled{}, localOwnedBackupError(ErrLocalOwnedBackupConflict, "backend revision")
	}
	return pulled, nil
}

func classifyLocalOwnedBackupRefusal(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, openErr error) error {
	// A factor, owner, cancellation or session refusal is already specific and
	// must not be downgraded by a later journal-state inspection.
	if errors.Is(openErr, personal.ErrVaultFileScopedFactors) ||
		errors.Is(openErr, personal.ErrVaultFileOwnership) ||
		errors.Is(openErr, personal.ErrVaultFileFullFactorRequired) ||
		errors.Is(openErr, personal.ErrSessionLocked) ||
		errors.Is(openErr, context.Canceled) ||
		errors.Is(openErr, context.DeadlineExceeded) {
		return mapLocalOwnedBackupOpenError(openErr)
	}
	manifest, _, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err == nil && manifest.Journal == expectedJournal {
		if snapshot, snapErr := readLocalOwnedBackupSnapshot(manifest, companion); snapErr == nil {
			snapshot.clear()
		} else if errors.Is(snapErr, ErrLocalOwnedBackupConflict) ||
			errors.Is(snapErr, ErrLocalOwnedBackupUnsupported) ||
			errors.Is(snapErr, ErrLocalOwnedBackupCanceled) {
			return snapErr
		}
	}
	return mapLocalOwnedBackupOpenError(openErr)
}

func classifyLocalOwnedBackupSnapshotFailure(successorErr, openErr, loadErr, closeErr error) error {
	switch {
	case errors.Is(successorErr, vaultfilejournal.ErrPendingRecords),
		errors.Is(successorErr, vaultfilejournal.ErrPreparedExists),
		errors.Is(loadErr, vaultfilejournal.ErrPendingRecords),
		errors.Is(loadErr, vaultfilejournal.ErrPreparedExists):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "pending")
	case errors.Is(successorErr, vaultfilejournal.ErrEmpty),
		errors.Is(loadErr, vaultfilejournal.ErrEmpty),
		errors.Is(successorErr, fs.ErrNotExist),
		errors.Is(openErr, fs.ErrNotExist):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "missing")
	case errors.Is(successorErr, vaultfilejournal.ErrCorrupt),
		errors.Is(successorErr, vaultfilejournal.ErrInvalid),
		errors.Is(loadErr, vaultfilejournal.ErrCorrupt),
		errors.Is(loadErr, vaultfilejournal.ErrInvalid):
		return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "state")
	case errors.Is(successorErr, vaultfilejournal.ErrLocked),
		errors.Is(openErr, vaultfilejournal.ErrLocked),
		errors.Is(loadErr, vaultfilejournal.ErrLocked):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "locked")
	case closeErr != nil:
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal close")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal")
	}
}

func mapLocalOwnedBackupClaimError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, personal.ErrSessionLocked), errors.Is(err, personal.ErrVaultFileScopedChild),
		errors.Is(err, personal.ErrFullFactorRequired):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "delivery")
	case errors.Is(err, personal.ErrVaultFileBaselineJournal):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "delivery")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "delivery")
	}
}

func mapLocalOwnedBackupOpenError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, personal.ErrSessionLocked), errors.Is(err, personal.ErrVaultFileScopedChild):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "session")
	case errors.Is(err, personal.ErrVaultFileBaselineJournal):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "journal")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "locator")
	}
}

func mapLocalOwnedBackupTargetError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	case errors.Is(err, vaultfilebackend.ErrUnsupported):
		return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "backend")
	case errors.Is(err, vaultfilebackend.ErrDenied), errors.Is(err, vaultfilepublish.ErrInvalidArgument):
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "target")
	case errors.Is(err, vaultfilebackend.ErrNotFound), errors.Is(err, vaultfilebackend.ErrConflict),
		errors.Is(err, vaultfilebackend.ErrCorrupt), errors.Is(err, vaultfilebackend.ErrUnknown),
		errors.Is(err, vaultfilepublish.ErrVerification), errors.Is(err, vaultfilepublish.ErrBackendResult),
		errors.Is(err, errLocalOwnedBackupTargetMismatch):
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "backend")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupConflict, "backend")
	}
}

func localOwnedBackupError(category error, reason string) error {
	return fmt.Errorf("%w: %s", category, reason)
}

func localOwnedBackupCheckpointDigest(checkpoint vaultfile.PolicyCheckpoint) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-backup/checkpoint/v1\x00"))
	writeLocalOwnedBackupString(h, checkpoint.VaultID)
	writeLocalOwnedBackupString(h, checkpoint.OwnerRootKeyID)
	writeLocalOwnedBackupBytes(h, checkpoint.OwnerRootPublicKey)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], checkpoint.PolicySeq)
	_, _ = h.Write(seq[:])
	writeLocalOwnedBackupBytes(h, checkpoint.PolicyDigest)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func localOwnedBackupIdentityDigest(source LocalOwnedBackupSource) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-backup/identity/v1\x00"))
	writeLocalOwnedBackupString(h, source.VaultID)
	_, _ = h.Write(source.CheckpointDigest[:])
	writeLocalOwnedBackupString(h, string(source.JournalRevision))
	writeLocalOwnedBackupString(h, string(source.BackendRevision))
	writeLocalOwnedBackupString(h, string(source.OriginRevision))
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], source.ContentSeq)
	_, _ = h.Write(seq[:])
	if source.Origin == nil {
		_, _ = h.Write([]byte{0})
	} else {
		_, _ = h.Write([]byte{1})
		writeLocalOwnedBackupBytes(h, source.Origin)
	}
	writeLocalOwnedBackupBytes(h, source.Current)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeLocalOwnedBackupString(h hash.Hash, value string) {
	writeLocalOwnedBackupBytes(h, []byte(value))
}

func writeLocalOwnedBackupBytes(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}
