package vaultfileclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// LocalGenesisBaseline is a bounded view of one authenticated local content
// baseline: either a pristine genesis or one settled owned first successor. It
// says nothing about the current remote file or a service-side grant.
type LocalGenesisBaseline struct {
	VaultID string
	Items   []personal.VaultFileBaselineItem
}

// OpenLocalGenesisBaseline binds a navigation selector to this personal
// identity, its independent owner root, the immutable create metadata and the
// sole local generation-zero journal before disclosing item summaries.
func OpenLocalGenesisBaseline(s *personal.Session, configPath, workspaceRoot, vaultID string) (LocalGenesisBaseline, error) {
	if s == nil || !s.Unlocked() || vaultID == "" {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	manifest, exists, err := ReadManifest(configPath)
	if err != nil || !exists || manifest.VaultID != vaultID ||
		manifest.PersonalFile != s.VaultPath() || manifest.BackendRoot != workspaceRoot {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	manifestDigest, err := ReadManifestDigest(configPath, manifest)
	if err != nil {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	companion, exists, err := ReadCompanion(configPath, manifest)
	if err != nil || !exists || companion.ManifestSHA256 != manifestDigest {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	owners, err := s.VaultFileOwnerships()
	if err != nil {
		return LocalGenesisBaseline{}, err
	}
	var owner personal.VaultFileOwnershipPublic
	count := 0
	for _, candidate := range owners {
		if candidate.VaultID == vaultID {
			owner = candidate
			count++
		}
	}
	if count != 1 || companion.Resume.Checkpoint == nil ||
		owner.OwnerRootKeyID != companion.Resume.Checkpoint.OwnerRootKeyID ||
		owner.OwnerRootPublicKey != companion.Resume.Checkpoint.OwnerRootPublicKey {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	root, ok := DecodeHex(owner.OwnerRootPublicKey)
	if !ok {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	defer clear(root)
	checkpoint, revision, err := verifyLocalGenesisState(manifest.Journal, manifest.VaultID, companion, root)
	if err != nil {
		return LocalGenesisBaseline{}, err
	}
	defer clear(checkpoint.OwnerRootPublicKey)
	defer clear(checkpoint.PolicyDigest)
	items, err := s.OpenVaultFileBaseline(manifest.Journal, checkpoint)
	if err != nil {
		return LocalGenesisBaseline{}, err
	}
	// A journal or selector replaced while the Session was opening must never
	// release the resulting projection. This is a cooperating-writer gate, not
	// a claim against arbitrary same-UID filesystem races.
	if digest, e := ReadManifestDigest(configPath, manifest); e != nil || digest != manifestDigest {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	if current, ok, e := ReadCompanion(configPath, manifest); e != nil || !ok || !SameCompanion(current, companion) {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	verifiedAgain, currentRevision, e := verifyLocalGenesisState(manifest.Journal, manifest.VaultID, companion, root)
	if verifiedAgain != nil {
		clear(verifiedAgain.OwnerRootPublicKey)
		clear(verifiedAgain.PolicyDigest)
	}
	if e != nil || currentRevision != revision || !s.Unlocked() {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	currentOwners, e := s.VaultFileOwnerships()
	if e != nil {
		return LocalGenesisBaseline{}, e
	}
	matching := 0
	for _, candidate := range currentOwners {
		if candidate.VaultID == vaultID {
			matching++
			if candidate != owner {
				return LocalGenesisBaseline{}, ErrLocalReview
			}
		}
	}
	if matching != 1 {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	return LocalGenesisBaseline{VaultID: vaultID, Items: items}, nil
}

func verifyLocalGenesisState(journalPath, vaultID string, companion Companion, root []byte) (*vaultfile.PolicyCheckpoint, string, error) {
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return nil, "", ErrLocalReview
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil {
		return nil, "", ErrLocalReview
	}
	gHash := sha256.Sum256(state.BaseBytes)
	if hex.EncodeToString(gHash[:]) != companion.GenesisSHA256 {
		return nil, "", ErrLocalReview
	}
	file, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || file.Header.OpID != companion.OperationID {
		return nil, "", ErrLocalReview
	}
	pin := vaultfile.GenesisRootPin{VaultID: vaultID, OwnerRootKeyID: companion.Resume.Checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(root)}
	checkpoint, err := vaultfile.VerifyGenesis(state.BaseBytes, &pin)
	if err != nil || checkpoint == nil {
		return nil, "", ErrLocalReview
	}
	if !localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		clear(checkpoint.OwnerRootPublicKey)
		clear(checkpoint.PolicyDigest)
		return nil, "", ErrLocalReview
	}
	return checkpoint, string(state.RemoteRevision), nil
}

func localGenesisOwnedGenesisPin(manifest Manifest, companion Companion, root []byte) (vaultfilejournal.OwnedGenesisPin, bool) {
	if companion.Resume.Checkpoint == nil || len(root) != ed25519.PublicKeySize {
		return vaultfilejournal.OwnedGenesisPin{}, false
	}
	digest, err := hex.DecodeString(companion.GenesisSHA256)
	if err != nil || len(digest) != sha256.Size {
		return vaultfilejournal.OwnedGenesisPin{}, false
	}
	defer clear(digest)
	var sealed [sha256.Size]byte
	copy(sealed[:], digest)
	return vaultfilejournal.OwnedGenesisPin{
		Root: vaultfile.GenesisRootPin{
			VaultID:            manifest.VaultID,
			OwnerRootKeyID:     companion.Resume.Checkpoint.OwnerRootKeyID,
			OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(root)),
		},
		SealedSHA256: sealed,
		OperationID:  companion.OperationID,
	}, true
}

// verifyLocalGenesisSuccessor authenticates the retained genesis against the
// companion checkpoint. The typed journal reader has already authenticated the
// sealed genesis hash, the genesis operation and the immediate transition.
func verifyLocalGenesisSuccessor(manifest Manifest, companion Companion, pin vaultfilejournal.OwnedGenesisPin, record vaultfilejournal.OwnedFirstSuccessor) (*vaultfile.PolicyCheckpoint, error) {
	checkpoint, err := vaultfile.VerifyGenesis(record.GenesisBytes, &pin.Root)
	if err != nil || checkpoint == nil || checkpoint.VaultID != manifest.VaultID ||
		!localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, ErrLocalReview
	}
	return checkpoint, nil
}

// localGenesisSuccessorLocator is the immutable public locator identity of one
// settled owned first successor. It carries the verified origin pin, the named
// local backend object and the opaque backend revision; it never carries
// successor bytes, account material or authorization.
type localGenesisSuccessorLocator struct {
	pin               vaultfilejournal.OwnedGenesisPin
	backendRoot       string
	backendName       string
	successorRevision string
}

// localGenesisVerifiedState is the internal result of binding a strict
// manifest/companion to either a pristine generation-zero journal or one
// settled owned first successor. checkpoint is caller-owned after return.
type localGenesisVerifiedState struct {
	checkpoint *vaultfile.PolicyCheckpoint
	revision   string
	successor  *localGenesisSuccessorLocator
}

func localGenesisCheckpointMatchesCompanion(checkpoint *vaultfile.PolicyCheckpoint, want *CheckpointConfig) bool {
	return checkpoint != nil && want != nil && want.PolicySeq != nil &&
		checkpoint.VaultID == want.VaultID &&
		checkpoint.OwnerRootKeyID == want.OwnerRootKeyID &&
		hex.EncodeToString(checkpoint.OwnerRootPublicKey) == want.OwnerRootPublicKey &&
		checkpoint.PolicySeq == *want.PolicySeq &&
		hex.EncodeToString(checkpoint.PolicyDigest) == want.PolicyDigest
}

func cloneLocalGenesisGenesisPin(pin vaultfilejournal.OwnedGenesisPin) vaultfilejournal.OwnedGenesisPin {
	out := pin
	out.Root.OwnerRootPublicKey = ed25519.PublicKey(bytes.Clone(pin.Root.OwnerRootPublicKey))
	return out
}

func sameLocalGenesisGenesisPin(a, b vaultfilejournal.OwnedGenesisPin) bool {
	return a.Root.VaultID == b.Root.VaultID &&
		a.Root.OwnerRootKeyID == b.Root.OwnerRootKeyID &&
		bytes.Equal(a.Root.OwnerRootPublicKey, b.Root.OwnerRootPublicKey) &&
		a.SealedSHA256 == b.SealedSHA256 && a.OperationID == b.OperationID
}

func cloneLocalGenesisSuccessor(locator *localGenesisSuccessorLocator) *localGenesisSuccessorLocator {
	if locator == nil {
		return nil
	}
	out := *locator
	out.pin = cloneLocalGenesisGenesisPin(locator.pin)
	return &out
}

func sameLocalGenesisSuccessor(a, b *localGenesisSuccessorLocator) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.backendRoot == b.backendRoot && a.backendName == b.backendName &&
		a.successorRevision == b.successorRevision && sameLocalGenesisGenesisPin(a.pin, b.pin)
}

func clearLocalGenesisSuccessor(locator *localGenesisSuccessorLocator) {
	if locator == nil {
		return
	}
	clear(locator.pin.Root.OwnerRootPublicKey)
	locator.pin.Root.OwnerRootPublicKey = nil
	*locator = localGenesisSuccessorLocator{}
}

func clearLocalGenesisVerified(state *localGenesisVerifiedState) {
	if state == nil {
		return
	}
	clearLocalGenesisCheckpoint(state.checkpoint)
	clearLocalGenesisSuccessor(state.successor)
	*state = localGenesisVerifiedState{}
}
