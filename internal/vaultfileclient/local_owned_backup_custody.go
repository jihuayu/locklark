package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// LocalOwnedBackupCustody is the public result of one in-memory single-vault
// custody preparation. Artifact is the signed, age-sealed ciphertext envelope;
// the independent recovery factor is returned separately and never included.
type LocalOwnedBackupCustody struct {
	Artifact       []byte
	VaultID        string
	Checkpoint     vaultfile.PolicyCheckpoint
	SourceIdentity [sha256.Size]byte
	Ownership      personal.VaultFileOwnershipPublic
}

// Clear zeroes the retained ciphertext, public checkpoint bytes and digest.
func (c *LocalOwnedBackupCustody) Clear() {
	if c == nil {
		return
	}
	clear(c.Artifact)
	clear(c.Checkpoint.OwnerRootPublicKey)
	clear(c.Checkpoint.PolicyDigest)
	*c = LocalOwnedBackupCustody{}
}

// LocalOwnedBackupCustodyOpen is one decrypted and fully verified artifact.
// Source contains only encrypted source bytes and public binding metadata.
type LocalOwnedBackupCustodyOpen struct {
	Source         LocalOwnedBackupSource
	Ownership      personal.VaultFileOwnershipPublic
	SourceIdentity [sha256.Size]byte
}

// Clear zeroes the retained ciphertext and checkpoint bytes.
func (o *LocalOwnedBackupCustodyOpen) Clear() {
	if o == nil {
		return
	}
	o.Source.Clear()
	o.Ownership = personal.VaultFileOwnershipPublic{}
	*o = LocalOwnedBackupCustodyOpen{}
}

var localOwnedBackupCustodyBeforeSealForTest func(*localGenesisSessionState)

// PrepareLocalOwnedBackupCustody opens one freshly verified custody child for
// the selected account-owned vault and seals it before the real child close.
// The exact child, source backend/journal bytes and opaque revisions are read
// by personal custody; the caller cannot supply source bytes, revisions or a
// source identity. The same explicit password/key open the child and load the
// selected owner record, without Session.fullUnlock or a global freshness
// timer. The artifact and factor stay local until the published exclusive close
// and one-shot read-delivery arbitration both succeed.
//
// The expected checkpoint is the caller's external trust pin from the source.
// It must exactly equal the captured checkpoint. No backend, journal, vault,
// database or destination file is written. The returned factor is the only
// plaintext private output and must be stored separately and cleared.
func PrepareLocalOwnedBackupCustody(ctx context.Context, s *personal.Session,
	configPath, workspaceRoot, vaultID, expectedJournal string,
	expected vaultfile.PolicyCheckpoint, password, key []byte) (custody LocalOwnedBackupCustody, factor *personal.VaultFileBackupRecoveryFactor, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	wrapper, initial, err := openLocalGenesisSessionForCustody(s, configPath, workspaceRoot,
		vaultID, expectedJournal, password, key)
	clearLocalGenesisItems(initial.Items)
	if err != nil {
		return custody, nil, classifyLocalOwnedBackupRefusal(s, configPath, workspaceRoot,
			vaultID, expectedJournal, err)
	}
	if wrapper == nil || wrapper.state == nil {
		if wrapper != nil {
			_ = wrapper.Close()
		}
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "child")
	}
	wrapperClosed := false
	defer func() {
		if wrapperClosed {
			return
		}
		closeErr := wrapper.Close()
		if retErr != nil {
			clear(custody.Artifact)
			if factor != nil {
				factor.Clear()
			}
			return
		}
		if closeErr != nil {
			clear(custody.Artifact)
			if factor != nil {
				factor.Clear()
			}
			custody = LocalOwnedBackupCustody{}
			factor = nil
			retErr = localOwnedBackupError(ErrLocalOwnedBackupReview, "child close")
		}
	}()

	state := wrapper.state
	state.mu.Lock()
	if state.closed || state.parent != s {
		state.mu.Unlock()
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "child closed")
	}
	manifest := state.manifest
	companion := state.companion
	revision := state.revision
	successor := state.successor
	token := state.token
	state.mu.Unlock()

	if manifest.Journal != expectedJournal || manifest.VaultID != vaultID ||
		manifest.BackendRoot != workspaceRoot || manifest.PersonalFile != s.VaultPath() {
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "locator")
	}
	snapshot, err := readLocalOwnedBackupSnapshot(manifest, companion)
	if err != nil {
		return custody, nil, err
	}
	defer snapshot.clear()
	if err := snapshot.bind(successor, revision); err != nil {
		return custody, nil, err
	}
	if snapshot.checkpoint == nil || !sameLocalOwnedBackupCustodyCheckpoint(*snapshot.checkpoint, expected) {
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "checkpoint")
	}

	if err := state.revalidateLocator(); err != nil {
		return custody, nil, mapLocalOwnedBackupOpenError(err)
	}
	if err := s.RevalidateVaultFileChildOwnership(token); err != nil {
		return custody, nil, mapLocalOwnedBackupOpenError(err)
	}
	if err := state.revalidateLocator(); err != nil {
		return custody, nil, mapLocalOwnedBackupOpenError(err)
	}
	if err := ctx.Err(); err != nil {
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}
	claim, err := s.BeginVaultFileReadDeliveryClaim(token)
	if err != nil {
		return custody, nil, mapLocalOwnedBackupClaimError(err)
	}
	if err := ctx.Err(); err != nil {
		_ = state.closeWith(claim)
		wrapperClosed = true
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	if localOwnedBackupCustodyBeforeSealForTest != nil {
		localOwnedBackupCustodyBeforeSealForTest(state)
	}
	sealed, err := s.PrepareVaultFileBackupCustodyForChild(ctx, token, claim, expected, password, key)
	if err != nil {
		_ = state.closeWith(claim)
		wrapperClosed = true
		return custody, nil, mapLocalOwnedBackupCustodyError(err)
	}
	if sealed == nil {
		_ = state.closeWith(claim)
		wrapperClosed = true
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "custody result")
	}
	if err := state.revalidateLocator(); err != nil {
		sealed.Clear()
		_ = state.closeWith(claim)
		wrapperClosed = true
		return custody, nil, mapLocalOwnedBackupOpenError(err)
	}
	if err := ctx.Err(); err != nil {
		sealed.Clear()
		_ = state.closeWith(claim)
		wrapperClosed = true
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
	}

	// Precompute the public return metadata before the physical close. The
	// artifact/factor remain inside the bound seal until Take wins the one final
	// arbitration.
	returnedVaultID := manifest.VaultID
	checkpoint := cloneLocalOwnedBackupCustodyCheckpoint(expected)

	if localOwnedBackupBeforeCloseForTest != nil {
		localOwnedBackupBeforeCloseForTest(state)
	}
	closeErr := state.closeWith(claim)
	wrapperClosed = true
	if closeErr != nil {
		sealed.Clear()
		if err := ctx.Err(); err != nil {
			return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupCanceled, "context")
		}
		return custody, nil, localOwnedBackupError(ErrLocalOwnedBackupConflict, "child close")
	}
	artifact, sealedFactor, ownership, sourceIdentity, err := sealed.Take(ctx, s)
	if err != nil {
		sealed.Clear()
		return custody, nil, mapLocalOwnedBackupCustodyError(err)
	}
	return LocalOwnedBackupCustody{
		Artifact:       artifact,
		VaultID:        returnedVaultID,
		Checkpoint:     checkpoint,
		SourceIdentity: sourceIdentity,
		Ownership:      ownership,
	}, sealedFactor, nil
}

// ImportLocalOwnedBackupRecoveryFactor is the standalone canonical import for
// one serialized recovery factor. It needs no live Session or prior in-memory
// factor and is the normal path for opening a saved custody artifact.
func ImportLocalOwnedBackupRecoveryFactor(material []byte) (*personal.VaultFileBackupRecoveryFactor, error) {
	factor, err := personal.ImportVaultFileBackupRecoveryFactor(material)
	if err != nil {
		return nil, mapLocalOwnedBackupCustodyError(err)
	}
	return factor, nil
}

// OpenLocalOwnedBackupCustody decrypts and verifies one exact expected vault and
// caller-pinned checkpoint. It refuses a wrong factor, checkpoint, vault,
// artifact, source identity or owner binding, and recomputes the canonical
// source identity before returning any ciphertext. It does not install or
// restore a vault.
func OpenLocalOwnedBackupCustody(ctx context.Context, artifact []byte,
	expected vaultfile.PolicyCheckpoint, factor *personal.VaultFileBackupRecoveryFactor) (opened LocalOwnedBackupCustodyOpen, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	verified, ownership, err := personal.OpenVaultFileBackupCustody(ctx, artifact, expected, factor)
	if err != nil {
		return opened, mapLocalOwnedBackupCustodyError(err)
	}
	source := LocalOwnedBackupSource{
		VaultID:         verified.VaultID,
		Current:         verified.Current,
		Origin:          verified.Origin,
		JournalRevision: vaultfilebackend.Revision(verified.JournalRevision),
		BackendRevision: vaultfilebackend.Revision(verified.BackendRevision),
		OriginRevision:  vaultfilebackend.Revision(verified.OriginRevision),
		ContentSeq:      verified.ContentSeq,
		Checkpoint:      cloneLocalOwnedBackupCustodyCheckpoint(verified.Checkpoint),
	}
	source.CheckpointDigest = localOwnedBackupCheckpointDigest(source.Checkpoint)
	source.IdentityDigest = localOwnedBackupIdentityDigest(source)
	if source.VaultID != expected.VaultID ||
		!sameLocalOwnedBackupCustodyCheckpoint(source.Checkpoint, expected) ||
		verified.SourceIdentity == ([sha256.Size]byte{}) ||
		ownership.VaultID != expected.VaultID ||
		ownership.OwnerRootKeyID != expected.OwnerRootKeyID ||
		ownership.OwnerRootPublicKey != hex.EncodeToString(expected.OwnerRootPublicKey) {
		source.Clear()
		return opened, localOwnedBackupError(ErrLocalOwnedBackupReview, "custody binding")
	}
	return LocalOwnedBackupCustodyOpen{
		Source: source, Ownership: ownership, SourceIdentity: verified.SourceIdentity,
	}, nil
}

func mapLocalOwnedBackupCustodyError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, personal.ErrVaultFileBackupCustodyCanceled),
		errors.Is(err, personal.ErrSessionLocked),
		errors.Is(err, personal.ErrVaultFileScopedChild):
		return localOwnedBackupError(ErrLocalOwnedBackupCanceled, "custody")
	case errors.Is(err, personal.ErrVaultFileBackupCustodyLimit):
		return localOwnedBackupError(ErrLocalOwnedBackupUnsupported, "custody")
	default:
		return localOwnedBackupError(ErrLocalOwnedBackupReview, "custody")
	}
}

func cloneLocalOwnedBackupCustodyCheckpoint(checkpoint vaultfile.PolicyCheckpoint) vaultfile.PolicyCheckpoint {
	return vaultfile.PolicyCheckpoint{
		VaultID:            checkpoint.VaultID,
		OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(checkpoint.OwnerRootPublicKey),
		PolicySeq:          checkpoint.PolicySeq,
		PolicyDigest:       bytes.Clone(checkpoint.PolicyDigest),
	}
}

func sameLocalOwnedBackupCustodyCheckpoint(a, b vaultfile.PolicyCheckpoint) bool {
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq &&
		bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest)
}
