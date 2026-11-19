package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// OwnedVaultFileFirstSuccessorTarget freezes the exact named local backend
// object and the verified origin pin for one settled owned first successor.
// The pin is derived from the caller's already verified account/companion
// locator. This type is a request selector only; the typed journal reader and
// the current Session still establish every trust fact.
type OwnedVaultFileFirstSuccessorTarget struct {
	BackendRoot string
	BackendName string
	Pin         vaultfilejournal.OwnedGenesisPin
}

// vaultFileOwnedSuccessorBinding is the immutable local read identity of one
// settled owned first successor. It retains only hashes, opaque revisions and
// public device identifiers; no successor bytes, VUK or account material.
type vaultFileOwnedSuccessorBinding struct {
	journalPath string
	pin         vaultfilejournal.OwnedGenesisPin

	backendRoot string
	backendName string

	writerDeviceID string
	readerDeviceID string

	genesisHash       [sha256.Size]byte
	genesisRevision   vaultfilebackend.Revision
	successorHash     [sha256.Size]byte
	successorRevision vaultfilebackend.Revision
}

func cloneOwnedVaultFileGenesisPin(pin vaultfilejournal.OwnedGenesisPin) vaultfilejournal.OwnedGenesisPin {
	out := pin
	out.Root.OwnerRootPublicKey = ed25519.PublicKey(bytes.Clone(pin.Root.OwnerRootPublicKey))
	return out
}

func sameOwnedVaultFileGenesisPin(a, b vaultfilejournal.OwnedGenesisPin) bool {
	return a.Root.VaultID == b.Root.VaultID &&
		a.Root.OwnerRootKeyID == b.Root.OwnerRootKeyID &&
		bytes.Equal(a.Root.OwnerRootPublicKey, b.Root.OwnerRootPublicKey) &&
		a.SealedSHA256 == b.SealedSHA256 && a.OperationID == b.OperationID
}

func validOwnedVaultFileFirstSuccessorTarget(target OwnedVaultFileFirstSuccessorTarget) bool {
	pin := target.Pin
	return validVaultFileGenesisPath(target.BackendRoot) &&
		vaultfilebackend.ValidName(target.BackendName) &&
		pin.Root.VaultID != "" && len(pin.Root.VaultID) <= maxOwnedVaultFileBatchVaultID &&
		pin.Root.OwnerRootKeyID != "" && len(pin.Root.OwnerRootKeyID) <= maxOwnedVaultFileBatchRootID &&
		len(pin.Root.OwnerRootPublicKey) == ed25519.PublicKeySize &&
		pin.OperationID != "" && len(pin.OperationID) <= 256 &&
		pin.SealedSHA256 != ([sha256.Size]byte{})
}

func cloneOwnedVaultFileFirstSuccessorTarget(target OwnedVaultFileFirstSuccessorTarget) OwnedVaultFileFirstSuccessorTarget {
	target.Pin = cloneOwnedVaultFileGenesisPin(target.Pin)
	return target
}

func sameOwnedVaultFileFirstSuccessorTarget(a, b *OwnedVaultFileFirstSuccessorTarget) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.BackendRoot == b.BackendRoot && a.BackendName == b.BackendName &&
		sameOwnedVaultFileGenesisPin(a.Pin, b.Pin)
}

func ownedVaultFileFirstSuccessorMatchesCheckpoint(target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint) bool {
	return checkpoint != nil && checkpoint.VaultID == target.Pin.Root.VaultID &&
		checkpoint.OwnerRootKeyID == target.Pin.Root.OwnerRootKeyID &&
		bytes.Equal(checkpoint.OwnerRootPublicKey, target.Pin.Root.OwnerRootPublicKey)
}

func sameVaultFilePolicyCheckpoint(a, b *vaultfile.PolicyCheckpoint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq &&
		bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest)
}

func clearVaultFilePolicyCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) {
	if checkpoint == nil {
		return
	}
	clear(checkpoint.OwnerRootPublicKey)
	clear(checkpoint.PolicyDigest)
	checkpoint.OwnerRootPublicKey = nil
	checkpoint.PolicyDigest = nil
}

// verifyOwnedVaultFileSuccessorRead is the single bound-Read comparison. It
// requires both the exact expected ciphertext bytes and the exact opaque
// revision; a valid revision with different bytes is rejected. The returned
// buffer is always cleared.
func verifyOwnedVaultFileSuccessorRead(result vaultfilebackend.ReadResult, readErr, closeErr error, expected []byte, expectedRevision vaultfilebackend.Revision) error {
	failed := readErr != nil || closeErr != nil ||
		!bytes.Equal(result.Bytes, expected) || result.Revision != expectedRevision
	clear(result.Bytes)
	if failed {
		return ErrVaultFileBaselineJournal
	}
	return nil
}

// readOwnedVaultFileSuccessorBackend performs the one atomic backend read used
// by one verification operation. The bytes and opaque revision must both name
// the exact acknowledged journal successor that the caller already verified.
func readOwnedVaultFileSuccessorBackend(target OwnedVaultFileFirstSuccessorTarget, expected []byte, expectedRevision vaultfilebackend.Revision) error {
	return readOwnedVaultFileSuccessorBackendContext(context.Background(), target, expected, expectedRevision)
}

func readOwnedVaultFileSuccessorBackendContext(ctx context.Context, target OwnedVaultFileFirstSuccessorTarget, expected []byte, expectedRevision vaultfilebackend.Revision) error {
	if ctx == nil {
		ctx = context.Background()
	}
	backend, err := vaultfilebackend.OpenExistingDir(target.BackendRoot)
	if err != nil {
		return ErrVaultFileBaselineJournal
	}
	result, readErr := backend.Read(ctx, target.BackendName)
	return verifyOwnedVaultFileSuccessorRead(result, readErr, backend.Close(), expected, expectedRevision)
}

// loadOwnedFirstSuccessor authenticates one settled v2 journal through the
// typed reader, binds the immediate successor author to the current personal
// account device using the existing writer authority, and reads the named
// local backend object exactly once. It returns owned genesis and successor
// byte slices so the caller can open the same authenticated content.
func loadOwnedFirstSuccessor(journalPath string, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, recipient string, signingKey ed25519.PublicKey) (*vaultFileOwnedSuccessorBinding, []byte, []byte, error) {
	if journalPath == "" || !validOwnedVaultFileFirstSuccessorTarget(target) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(journalPath, target.Pin)
	if err != nil {
		return nil, nil, nil, ErrVaultFileBaselineJournal
	}
	genesis, successor := record.GenesisBytes, record.SuccessorBytes
	record.GenesisBytes, record.SuccessorBytes = nil, nil
	ok := false
	defer func() {
		if !ok {
			clear(genesis)
			clear(successor)
		}
	}()

	origin, err := vaultfile.VerifyGenesis(genesis, &target.Pin.Root)
	if err != nil || !sameVaultFilePolicyCheckpoint(origin, checkpoint) {
		clearVaultFilePolicyCheckpoint(origin)
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}
	clearVaultFilePolicyCheckpoint(origin)

	genesisFile, err := vaultfile.ParseFile(genesis)
	if err != nil || len(genesisFile.SignedPolicyProofs) == 0 {
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}
	policy := &genesisFile.SignedPolicyProofs[len(genesisFile.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != genesisFile.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), genesisFile.Header.PolicyDigest) {
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}
	readerID, readerOK := localVaultFileReaderDevice(policy, recipient, signingKey)
	writerID, writerOK := localVaultFileWriterDevice(policy, recipient, signingKey)
	if !readerOK || !writerOK || readerID != writerID {
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}

	successorFile, err := vaultfile.ParseFile(successor)
	if err != nil || successorFile.Header.AuthorDeviceID != writerID ||
		successorFile.Header.VaultID != checkpoint.VaultID ||
		successorFile.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(successorFile.Header.PolicyDigest, checkpoint.PolicyDigest) {
		return nil, nil, nil, ErrVaultFileBaselineVerification
	}
	if err := readOwnedVaultFileSuccessorBackend(target, successor, record.SuccessorRevision); err != nil {
		return nil, nil, nil, err
	}

	binding := &vaultFileOwnedSuccessorBinding{
		journalPath:       journalPath,
		pin:               cloneOwnedVaultFileGenesisPin(target.Pin),
		backendRoot:       target.BackendRoot,
		backendName:       target.BackendName,
		writerDeviceID:    writerID,
		readerDeviceID:    readerID,
		genesisHash:       sha256.Sum256(genesis),
		genesisRevision:   record.GenesisRevision,
		successorHash:     sha256.Sum256(successor),
		successorRevision: record.SuccessorRevision,
	}
	ok = true
	return binding, genesis, successor, nil
}

// verifyOwnedFirstSuccessorBinding re-reads the exact settled journal and the
// named backend object once, compares both bytes and the opaque revision, and
// returns the fresh successor bytes. A replaced, advanced, pending, missing or
// ambiguous state fails closed without exposing the previous observation.
func verifyOwnedFirstSuccessorBinding(binding *vaultFileOwnedSuccessorBinding, checkpoint *vaultfile.PolicyCheckpoint) ([]byte, error) {
	genesis, successor, _, _, err := readVerifiedOwnedFirstSuccessor(context.Background(), binding, checkpoint)
	clear(genesis)
	if err != nil {
		clear(successor)
		return nil, err
	}
	return successor, nil
}

// readVerifiedOwnedFirstSuccessor is the shared settled-source read used by
// both the existing successor child path and backup custody. It re-reads the
// exact typed journal and the named backend object, requires both the recorded
// bytes and opaque revisions, and returns the authenticated genesis and
// successor ciphertext. It never returns private material.
func readVerifiedOwnedFirstSuccessor(ctx context.Context, binding *vaultFileOwnedSuccessorBinding,
	checkpoint *vaultfile.PolicyCheckpoint) (genesis, successor []byte,
	genesisRevision, successorRevision vaultfilebackend.Revision, err error) {
	if binding == nil || checkpoint == nil ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: binding.backendRoot, BackendName: binding.backendName, Pin: binding.pin,
		}, checkpoint) {
		return nil, nil, "", "", ErrVaultFileBaselineVerification
	}
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(binding.journalPath, binding.pin)
	if err != nil {
		return nil, nil, "", "", ErrVaultFileBaselineJournal
	}
	genesis, successor = record.GenesisBytes, record.SuccessorBytes
	record.GenesisBytes, record.SuccessorBytes = nil, nil
	genesisRevision, successorRevision = record.GenesisRevision, record.SuccessorRevision
	ok := false
	defer func() {
		if !ok {
			clear(genesis)
			clear(successor)
		}
	}()
	if sha256.Sum256(genesis) != binding.genesisHash ||
		genesisRevision != binding.genesisRevision ||
		sha256.Sum256(successor) != binding.successorHash ||
		successorRevision != binding.successorRevision {
		return nil, nil, "", "", ErrVaultFileBaselineJournal
	}
	origin, err := vaultfile.VerifyGenesis(genesis, &binding.pin.Root)
	if err != nil || !sameVaultFilePolicyCheckpoint(origin, checkpoint) {
		clearVaultFilePolicyCheckpoint(origin)
		return nil, nil, "", "", ErrVaultFileBaselineVerification
	}
	clearVaultFilePolicyCheckpoint(origin)

	successorFile, err := vaultfile.ParseFile(successor)
	if err != nil || successorFile.Header.AuthorDeviceID != binding.writerDeviceID ||
		successorFile.Header.VaultID != checkpoint.VaultID ||
		successorFile.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(successorFile.Header.PolicyDigest, checkpoint.PolicyDigest) {
		return nil, nil, "", "", ErrVaultFileBaselineVerification
	}
	target := OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: binding.backendRoot, BackendName: binding.backendName, Pin: binding.pin,
	}
	if err := readOwnedVaultFileSuccessorBackendContext(ctx, target, successor, binding.successorRevision); err != nil {
		return nil, nil, "", "", err
	}
	ok = true
	return genesis, successor, genesisRevision, successorRevision, nil
}

// OpenOwnedFirstSuccessorVaultFileChild is the settled-v2 companion of
// OpenOwnedVaultFileChild. It proves the same fresh factors and owned target
// authority, then adopts only the exact settled first successor as a read-only
// local child. The just-registered child is revalidated against the exact
// journal, named backend object and current account/owner authority before any
// initial summary or token is returned. It never writes the backend, journal or
// account store.
func (s *Session) OpenOwnedFirstSuccessorVaultFileChild(journalPath string, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte, options VaultFileChildOptions) (VaultFileChildToken, []VaultFileBaselineItem, error) {
	if journalPath == "" || !validOwnedVaultFileFirstSuccessorTarget(target) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}
	target = cloneOwnedVaultFileFirstSuccessorTarget(target)
	return s.openVaultFileChild(journalPath, checkpoint, password, key, options,
		vaultFileChildOpenMode{owned: true, successor: &target})
}

// The helpers above intentionally map every failed typed read, missing or
// ambiguous backend read, byte mismatch and revision mismatch to the same
// bounded journal error. Signature, policy, device or checkpoint failures use
// the bounded verification error. None of them returns a partial item view.
