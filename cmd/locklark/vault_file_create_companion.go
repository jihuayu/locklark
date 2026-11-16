package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// A companion is an immutable local proposal binding, created before any
// backend Create. It cannot prove publication or freshness. Its nested resume
// config is used only after live Session verification of the same G and pin.
type vaultFileCreateCompanion struct {
	Version        int                   `json:"version"`
	Kind           string                `json:"kind"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	GenesisSHA256  string                `json:"genesis_sha256"`
	OperationID    string                `json:"operation_id"`
	Resume         vaultFileResumeConfig `json:"resume"`
}

const vaultFileCreateCompanionKind = "vault_file_create_baseline"

func vaultFileCreateCompanionPath(configPath string) (string, error) {
	path := configPath + ".baseline"
	if !teamfiles.ValidPath(path) {
		return "", errVaultFileConfig
	}
	return path, nil
}

func readVaultFileCreateManifestDigest(path string, expected vaultFileCreateManifest) (string, error) {
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return "", errVaultFileLocalReview
	}
	defer clear(raw)
	var actual vaultFileCreateManifest
	if teamfiles.JSON(raw, &actual) != nil || actual != expected || !validVaultFileCreateManifestPhase(path, actual, true, false) {
		return "", errVaultFileLocalReview
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
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
	if a.Version != b.Version || a.BackendRoot != b.BackendRoot || a.Name != b.Name ||
		a.Journal != b.Journal || a.PersonalFile != b.PersonalFile || a.Checkpoint == nil || b.Checkpoint == nil {
		return false
	}
	x, y := a.Checkpoint, b.Checkpoint
	return x.VaultID == y.VaultID && x.OwnerRootKeyID == y.OwnerRootKeyID &&
		x.OwnerRootPublicKey == y.OwnerRootPublicKey && x.PolicySeq != nil && y.PolicySeq != nil &&
		*x.PolicySeq == *y.PolicySeq && x.PolicyDigest == y.PolicyDigest
}

func readVaultFileCreateCompanion(configPath string, manifest vaultFileCreateManifest) (vaultFileCreateCompanion, bool, error) {
	var companion vaultFileCreateCompanion
	path, err := vaultFileCreateCompanionPath(configPath)
	if err != nil {
		return companion, false, err
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return companion, false, nil
	} else if err != nil {
		return companion, false, errVaultFileLocalReview
	}
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return companion, true, errVaultFileLocalReview
	}
	defer clear(raw)
	if teamfiles.JSON(raw, &companion) != nil || companion.Version != 1 || companion.Kind != vaultFileCreateCompanionKind ||
		!validVaultFileCreateHex32(companion.ManifestSHA256) || !validVaultFileCreateHex32(companion.GenesisSHA256) ||
		!validVaultFileCreateID(companion.OperationID) || !teamfiles.Distinct(path, configPath, manifest.PersonalFile, manifest.Journal, manifest.Archive, manifest.BackendRoot) {
		return vaultFileCreateCompanion{}, true, errVaultFileLocalReview
	}
	digest, err := readVaultFileCreateManifestDigest(configPath, manifest)
	if err != nil || digest != companion.ManifestSHA256 {
		return vaultFileCreateCompanion{}, true, errVaultFileLocalReview
	}
	resumeBytes, err := json.Marshal(companion.Resume)
	if err != nil {
		return vaultFileCreateCompanion{}, true, errVaultFileLocalReview
	}
	defer clear(resumeBytes)
	parsed, _, err := decodeVaultFileResumeConfig(resumeBytes)
	if err != nil || !sameVaultFileCreateResume(parsed, companion.Resume) ||
		parsed.BackendRoot != manifest.BackendRoot || parsed.Name != manifest.Name || parsed.Journal != manifest.Journal ||
		parsed.PersonalFile != manifest.PersonalFile || parsed.Checkpoint.VaultID != manifest.VaultID || *parsed.Checkpoint.PolicySeq != 0 {
		return vaultFileCreateCompanion{}, true, errVaultFileLocalReview
	}
	return companion, true, nil
}

func validVaultFileCreateHex32(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func validVaultFileCreateID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
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
	encoded, err := json.Marshal(want)
	if err != nil {
		return zero, errVaultFileLocalUnknown
	}
	defer clear(encoded)
	path, err := vaultFileCreateCompanionPath(configPath)
	if err != nil {
		return zero, err
	}
	if err := teamfiles.WriteNew(path, encoded); err != nil {
		if errors.Is(err, teamfiles.ErrPublicationUnknown) {
			return zero, errVaultFileLocalUnknown
		}
		return zero, errVaultFileLocalReview
	}
	current, exists, err = readVaultFileCreateCompanion(configPath, manifest)
	if err != nil || !exists || !sameVaultFileCreateCompanion(current, want) {
		return zero, errVaultFileLocalUnknown
	}
	return current, nil
}

func sameVaultFileCreateCompanion(a, b vaultFileCreateCompanion) bool {
	return a.Version == b.Version && a.Kind == b.Kind && a.ManifestSHA256 == b.ManifestSHA256 &&
		a.GenesisSHA256 == b.GenesisSHA256 && a.OperationID == b.OperationID && sameVaultFileCreateResume(a.Resume, b.Resume)
}
