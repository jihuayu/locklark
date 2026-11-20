package vaultfileclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// LocalManagedRecoverySelector is the explicit, independently trusted locator
// for one already settled managed-successor recovery. Every field is an
// expected value: the destination account, the exact local journal and named
// backend object, the trusted base policy/key/content pin, the settled
// OperationID and the exact opaque successor revision. It carries no factor,
// key, token, ciphertext, summary or authority, and it is never learned from
// the journal or backend it is checked against.
//
// This is a read selector only. The managed production reader still
// reauthenticates the destination owner, the settled journal transition, the
// named backend bytes/revision and the ordinary destination device before a
// child or item projection is returned.
type LocalManagedRecoverySelector struct {
	AccountPath   string
	WorkspaceRoot string
	BackendName   string
	VaultID       string
	JournalPath   string
	Pin           personal.VaultFileManagedDeviceSuccessorPin
	OperationID   string
	SuccessorRev  vaultfilebackend.Revision
}

// LocalManagedRecoveryScope is the public, frozen scope identity of one managed
// recovery query. It is presentation/selection metadata only. ValidateExactQueryHit
// revalidates the live child and compares this exact scope; the fields are never
// authority or proof by themselves.
type LocalManagedRecoveryScope struct {
	AccountPath       string
	WorkspaceRoot     string
	BackendName       string
	VaultID           string
	JournalPath       string
	OperationID       string
	BaseSHA256        [sha256.Size]byte
	BaseRevision      vaultfilebackend.Revision
	SuccessorRevision vaultfilebackend.Revision
}

func cloneLocalManagedCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) *vaultfile.PolicyCheckpoint {
	if checkpoint == nil {
		return &vaultfile.PolicyCheckpoint{}
	}
	return &vaultfile.PolicyCheckpoint{
		VaultID:            checkpoint.VaultID,
		OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(checkpoint.OwnerRootPublicKey)),
		PolicySeq:          checkpoint.PolicySeq,
		PolicyDigest:       bytes.Clone(checkpoint.PolicyDigest),
	}
}

func cloneLocalManagedRecoveryPin(pin personal.VaultFileManagedDeviceSuccessorPin) personal.VaultFileManagedDeviceSuccessorPin {
	pin.Checkpoint.OwnerRootPublicKey = ed25519.PublicKey(bytes.Clone(pin.Checkpoint.OwnerRootPublicKey))
	pin.Checkpoint.PolicyDigest = bytes.Clone(pin.Checkpoint.PolicyDigest)
	return pin
}

func cloneLocalManagedRecoverySelector(selector *LocalManagedRecoverySelector) *LocalManagedRecoverySelector {
	if selector == nil {
		return nil
	}
	out := *selector
	out.Pin = cloneLocalManagedRecoveryPin(selector.Pin)
	return &out
}

func clearLocalManagedRecoverySelector(selector *LocalManagedRecoverySelector) {
	if selector == nil {
		return
	}
	clear(selector.Pin.Checkpoint.OwnerRootPublicKey)
	clear(selector.Pin.Checkpoint.PolicyDigest)
	selector.Pin.Checkpoint.OwnerRootPublicKey = nil
	selector.Pin.Checkpoint.PolicyDigest = nil
	*selector = LocalManagedRecoverySelector{}
}

func sameLocalManagedRecoverySelector(a, b *LocalManagedRecoverySelector) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.AccountPath == b.AccountPath &&
		a.WorkspaceRoot == b.WorkspaceRoot && a.BackendName == b.BackendName &&
		a.VaultID == b.VaultID && a.JournalPath == b.JournalPath &&
		a.OperationID == b.OperationID && a.SuccessorRev == b.SuccessorRev &&
		a.Pin.KeyEpoch == b.Pin.KeyEpoch && a.Pin.ContentSeq == b.Pin.ContentSeq &&
		a.Pin.SealedSHA256 == b.Pin.SealedSHA256 &&
		a.Pin.BackendRevision == b.Pin.BackendRevision &&
		sameLocalManagedCheckpoint(a.Pin.Checkpoint, b.Pin.Checkpoint)
}

func sameLocalManagedCheckpoint(a, b vaultfile.PolicyCheckpoint) bool {
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq &&
		bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest)
}

func validLocalManagedRecoveryPath(path string) bool {
	return path != "" && len(path) <= maxLocalGenesisBatchPath &&
		filepath.IsAbs(path) && filepath.Clean(path) == path
}

// validLocalManagedRecoverySelector validates only fixed shape and bounds. The
// managed production reader independently proves every trust fact.
func validLocalManagedRecoverySelector(selector *LocalManagedRecoverySelector, candidate LocalGenesisBatchCandidate, accountPath string) bool {
	if selector == nil || candidate.ConfigPath != "" {
		return false
	}
	if !validLocalManagedRecoveryPath(selector.AccountPath) ||
		selector.AccountPath != accountPath ||
		!validLocalManagedRecoveryPath(selector.WorkspaceRoot) ||
		selector.WorkspaceRoot != candidate.WorkspaceRoot ||
		!validLocalManagedRecoveryPath(selector.JournalPath) ||
		selector.JournalPath != candidate.JournalPath ||
		selector.VaultID == "" || len(selector.VaultID) > maxLocalGenesisBatchVaultID ||
		selector.VaultID != candidate.VaultID ||
		!vaultfilebackend.ValidName(selector.BackendName) ||
		selector.Pin.Checkpoint.VaultID != selector.VaultID ||
		selector.Pin.Checkpoint.OwnerRootKeyID == "" ||
		len(selector.Pin.Checkpoint.OwnerRootKeyID) > maxLocalGenesisBatchVaultID ||
		len(selector.Pin.Checkpoint.OwnerRootPublicKey) != ed25519.PublicKeySize ||
		len(selector.Pin.Checkpoint.PolicyDigest) != sha256.Size ||
		selector.Pin.KeyEpoch == 0 ||
		selector.Pin.SealedSHA256 == ([sha256.Size]byte{}) ||
		selector.Pin.BackendRevision == "" ||
		len(selector.Pin.BackendRevision) > vaultfilebackend.MaxRevisionSize ||
		selector.OperationID == "" ||
		len(selector.OperationID) > vaultfilejournal.MaxOperationIDBytes ||
		selector.SuccessorRev == "" ||
		len(selector.SuccessorRev) > vaultfilebackend.MaxRevisionSize {
		return false
	}
	return true
}

// localManagedPhysicalIdentity is the opaque stable identity of one exact
// existing local backend instance. It is compared only inside this package and
// is never included in a result, wrapper, error or diagnostic.
type localManagedPhysicalIdentity [sha256.Size]byte

// localManagedPhysicalTarget keys one physical named object. Two selectors with
// the same identity and exact name address the same durable managed target even
// when their caller-supplied workspace roots use different lexical paths or
// ancestor symlinks. Different names remain different legitimate objects.
type localManagedPhysicalTarget struct {
	identity localManagedPhysicalIdentity
	name     string
}

// localManagedBackendIdentity opens only the already existing local backend,
// reads its fixed stable identity and closes it. It never creates, repairs,
// mutates or resolves a stale lock/ticket, and it never reads a journal. The
// returned identity is public-opaque and is not authority by itself.
func localManagedBackendIdentity(root string) (localManagedPhysicalIdentity, error) {
	var zero localManagedPhysicalIdentity
	backend, err := vaultfilebackend.OpenExistingDir(root)
	if err != nil {
		return zero, ErrLocalReview
	}
	identity, identityErr := backend.StableIdentity()
	closeErr := backend.Close()
	if identityErr != nil || closeErr != nil {
		return zero, ErrLocalReview
	}
	return localManagedPhysicalIdentity(identity), nil
}

func (selector *LocalManagedRecoverySelector) target() *personal.OwnedVaultFileManagedSuccessorTarget {
	if selector == nil {
		return nil
	}
	return &personal.OwnedVaultFileManagedSuccessorTarget{
		JournalPath:  selector.JournalPath,
		BackendRoot:  selector.WorkspaceRoot,
		BackendName:  selector.BackendName,
		Pin:          cloneLocalManagedRecoveryPin(selector.Pin),
		OperationID:  selector.OperationID,
		SuccessorRev: selector.SuccessorRev,
	}
}

func (selector *LocalManagedRecoverySelector) scope() LocalManagedRecoveryScope {
	if selector == nil {
		return LocalManagedRecoveryScope{}
	}
	return LocalManagedRecoveryScope{
		AccountPath:       selector.AccountPath,
		WorkspaceRoot:     selector.WorkspaceRoot,
		BackendName:       selector.BackendName,
		VaultID:           selector.VaultID,
		JournalPath:       selector.JournalPath,
		OperationID:       selector.OperationID,
		BaseSHA256:        selector.Pin.SealedSHA256,
		BaseRevision:      selector.Pin.BackendRevision,
		SuccessorRevision: selector.SuccessorRev,
	}
}
