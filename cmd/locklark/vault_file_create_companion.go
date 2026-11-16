package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// The CLI keeps its existing type and function names while the strict local
// metadata codec lives in the shared client package.
type vaultFileCreateCompanion = vaultfileclient.Companion

const vaultFileCreateCompanionKind = vaultfileclient.CompanionKind

func vaultFileCreateCompanionPath(configPath string) (string, error) {
	return vaultfileclient.CompanionPath(configPath)
}

func readVaultFileCreateManifestDigest(path string, expected vaultFileCreateManifest) (string, error) {
	return vaultfileclient.ReadManifestDigest(path, expected)
}

func expectedVaultFileCreateResume(manifest vaultFileCreateManifest, public personal.VaultFileGenesisPublic) (vaultFileResumeConfig, error) {
	if public.Ownership.VaultID != manifest.VaultID || public.PolicyDigest == "" {
		return vaultFileResumeConfig{}, errVaultFileLocalReview
	}
	seq := uint64(0)
	return vaultFileResumeConfig{Version: 1, BackendRoot: manifest.BackendRoot, Name: manifest.Name,
		Journal: manifest.Journal, PersonalFile: manifest.PersonalFile,
		Checkpoint: &vaultFileCheckpointConfig{VaultID: manifest.VaultID,
			OwnerRootKeyID:     public.Ownership.OwnerRootKeyID,
			OwnerRootPublicKey: public.Ownership.OwnerRootPublicKey,
			PolicySeq:          &seq, PolicyDigest: public.PolicyDigest}}, nil
}

func sameVaultFileCreateResume(a, b vaultFileResumeConfig) bool {
	return vaultfileclient.SameResume(a, b)
}

func readVaultFileCreateCompanion(configPath string, manifest vaultFileCreateManifest) (vaultFileCreateCompanion, bool, error) {
	return vaultfileclient.ReadCompanion(configPath, manifest)
}

func validateVaultFileCreateCompanionPublic(companion vaultFileCreateCompanion, manifest vaultFileCreateManifest, public personal.VaultFileGenesisPublic) error {
	want, err := expectedVaultFileCreateResume(manifest, public)
	if err != nil || !sameVaultFileCreateResume(companion.Resume, want) {
		return errVaultFileLocalReview
	}
	return nil
}

// ensureVaultFileCreateCompanion revalidates the exact producer intent with
// the live Session before writing a private O_EXCL companion. An existing
// candidate is accepted only after strict reread and exact comparison; it is
// never renamed over, replaced or treated as a trust anchor by itself.
func ensureVaultFileCreateCompanion(configPath string, manifest vaultFileCreateManifest, session *personal.Session, password, key, kit []byte) (vaultFileCreateCompanion, error) {
	var zero vaultFileCreateCompanion
	req := personal.VaultFileGenesisRequest{VaultID: manifest.VaultID, Name: manifest.Name,
		IntentPath: manifest.Journal, ArchivePath: manifest.Archive}
	public, err := session.PrepareVaultFileGenesis(req, password, key, kit)
	if err != nil {
		return zero, err
	}
	digest, err := readVaultFileCreateManifestDigest(configPath, manifest)
	if err != nil {
		return zero, err
	}
	j, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
	if err != nil {
		return zero, errVaultFileLocalReview
	}
	intent, loadErr := j.Load()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		clear(intent.SealedBytes)
		return zero, errVaultFileLocalReview
	}
	defer clear(intent.SealedBytes)
	rootPublic, ok := decodeVaultFileHex(public.Ownership.OwnerRootPublicKey)
	if !ok {
		return zero, errVaultFileLocalReview
	}
	pin := &vaultfile.GenesisRootPin{VaultID: manifest.VaultID,
		OwnerRootKeyID: public.Ownership.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootPublic)}
	checkpoint, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin)
	file, parseErr := vaultfile.ParseFile(intent.SealedBytes)
	if err != nil || parseErr != nil || intent.Name != manifest.Name || intent.VaultID != manifest.VaultID ||
		intent.OwnerRootKeyID != pin.OwnerRootKeyID || !bytes.Equal(intent.OwnerRootPublicKey, pin.OwnerRootPublicKey) ||
		intent.PolicySeq != 0 || checkpoint.PolicySeq != 0 || !bytes.Equal(intent.PolicyDigest, checkpoint.PolicyDigest) ||
		public.PolicyDigest != hex.EncodeToString(checkpoint.PolicyDigest) || intent.OperationID != file.Header.OpID {
		return zero, errVaultFileLocalReview
	}
	gHash := sha256.Sum256(intent.SealedBytes)
	resume, err := expectedVaultFileCreateResume(manifest, public)
	if err != nil {
		return zero, err
	}
	want := vaultFileCreateCompanion{Version: 1, Kind: vaultFileCreateCompanionKind,
		ManifestSHA256: digest, GenesisSHA256: hex.EncodeToString(gHash[:]),
		OperationID: intent.OperationID, Resume: resume}
	current, exists, err := readVaultFileCreateCompanion(configPath, manifest)
	if err != nil {
		return zero, err
	}
	if exists {
		if !sameVaultFileCreateCompanion(current, want) {
			return zero, errVaultFileLocalReview
		}
		return current, nil
	}
	return vaultfileclient.WriteCompanionNew(configPath, manifest, want)
}

func sameVaultFileCreateCompanion(a, b vaultFileCreateCompanion) bool {
	return vaultfileclient.SameCompanion(a, b)
}
