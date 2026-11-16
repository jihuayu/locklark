package vaultfileclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// LocalGenesisBaseline is a bounded view of one authenticated local genesis.
// It says nothing about the current remote file or a service-side grant.
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
	want := companion.Resume.Checkpoint
	if want == nil || want.PolicySeq == nil || checkpoint.VaultID != want.VaultID ||
		checkpoint.OwnerRootKeyID != want.OwnerRootKeyID ||
		hex.EncodeToString(checkpoint.OwnerRootPublicKey) != want.OwnerRootPublicKey ||
		checkpoint.PolicySeq != *want.PolicySeq || hex.EncodeToString(checkpoint.PolicyDigest) != want.PolicyDigest {
		clear(checkpoint.OwnerRootPublicKey)
		clear(checkpoint.PolicyDigest)
		return nil, "", ErrLocalReview
	}
	return checkpoint, string(state.RemoteRevision), nil
}
