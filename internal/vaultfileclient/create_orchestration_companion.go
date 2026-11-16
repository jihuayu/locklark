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

func expectedCreateResume(manifest Manifest, public personal.VaultFileGenesisPublic) (ResumeConfig, error) {
	if public.Ownership.VaultID != manifest.VaultID || public.PolicyDigest == "" {
		return ResumeConfig{}, ErrLocalReview
	}
	seq := uint64(0)
	return ResumeConfig{Version: 1, BackendRoot: manifest.BackendRoot, Name: manifest.Name,
		Journal: manifest.Journal, PersonalFile: manifest.PersonalFile,
		Checkpoint: &CheckpointConfig{VaultID: manifest.VaultID,
			OwnerRootKeyID:     public.Ownership.OwnerRootKeyID,
			OwnerRootPublicKey: public.Ownership.OwnerRootPublicKey,
			PolicySeq:          &seq, PolicyDigest: public.PolicyDigest}}, nil
}

func validateCreateCompanionPublic(companion Companion, manifest Manifest, public personal.VaultFileGenesisPublic) error {
	want, err := expectedCreateResume(manifest, public)
	if err != nil || !SameResume(companion.Resume, want) {
		return ErrLocalReview
	}
	return nil
}

// ensureCreateCompanion binds one independently verified producer intent to
// the exact manifest bytes before publishing a private O_EXCL companion.
func (c *CreationContext) ensureCreateCompanion(password, key, kit []byte) (Companion, error) {
	var zero Companion
	manifest := c.manifest
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := c.session.PrepareVaultFileGenesis(req, password, key, kit)
	if err != nil {
		return zero, err
	}
	digest, err := c.checkManifest()
	if err != nil {
		return zero, err
	}
	j, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
	if err != nil {
		return zero, ErrLocalReview
	}
	intent, loadErr := j.Load()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		clear(intent.SealedBytes)
		return zero, ErrLocalReview
	}
	defer clear(intent.SealedBytes)
	rootPublic, ok := DecodeHex(public.Ownership.OwnerRootPublicKey)
	if !ok {
		return zero, ErrLocalReview
	}
	pin := &vaultfile.GenesisRootPin{VaultID: manifest.VaultID,
		OwnerRootKeyID: public.Ownership.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootPublic)}
	checkpoint, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin)
	file, parseErr := vaultfile.ParseFile(intent.SealedBytes)
	if err != nil || parseErr != nil || intent.Name != manifest.Name || intent.VaultID != manifest.VaultID ||
		intent.OwnerRootKeyID != pin.OwnerRootKeyID || !bytes.Equal(intent.OwnerRootPublicKey, pin.OwnerRootPublicKey) ||
		intent.PolicySeq != 0 || checkpoint.PolicySeq != 0 || !bytes.Equal(intent.PolicyDigest, checkpoint.PolicyDigest) ||
		public.PolicyDigest != hex.EncodeToString(checkpoint.PolicyDigest) || intent.OperationID != file.Header.OpID {
		return zero, ErrLocalReview
	}
	gHash := sha256.Sum256(intent.SealedBytes)
	resume, err := expectedCreateResume(manifest, public)
	if err != nil {
		return zero, err
	}
	want := Companion{Version: 1, Kind: CompanionKind,
		ManifestSHA256: digest, GenesisSHA256: hex.EncodeToString(gHash[:]),
		OperationID: intent.OperationID, Resume: resume}
	current, exists, err := ReadCompanion(c.configPath, manifest)
	if err != nil {
		return zero, err
	}
	if exists {
		if !SameCompanion(current, want) {
			return zero, ErrLocalReview
		}
		return current, nil
	}
	return WriteCompanionNew(c.configPath, manifest, want)
}
