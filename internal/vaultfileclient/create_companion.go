package vaultfileclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/jihuayu/locklark/internal/teamfiles"
)

// Companion is an immutable local proposal binding, created before any
// backend Create. It cannot prove publication or freshness. A caller must
// independently verify the live Session and exact genesis before using it.
type Companion struct {
	Version        int          `json:"version"`
	Kind           string       `json:"kind"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	GenesisSHA256  string       `json:"genesis_sha256"`
	OperationID    string       `json:"operation_id"`
	Resume         ResumeConfig `json:"resume"`
}

const CompanionKind = "vault_file_create_baseline"

func CompanionPath(configPath string) (string, error) {
	path := configPath + ".baseline"
	if !teamfiles.ValidPath(path) {
		return "", ErrConfig
	}
	return path, nil
}

func ReadManifestDigest(path string, expected Manifest) (string, error) {
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return "", ErrLocalReview
	}
	defer clear(raw)
	var actual Manifest
	if teamfiles.JSON(raw, &actual) != nil || actual != expected || !ValidManifestPhase(path, actual, true, false) {
		return "", ErrLocalReview
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func SameResume(a, b ResumeConfig) bool {
	if a.Version != b.Version || a.BackendRoot != b.BackendRoot || a.Name != b.Name ||
		a.Journal != b.Journal || a.PersonalFile != b.PersonalFile || a.Checkpoint == nil || b.Checkpoint == nil {
		return false
	}
	x, y := a.Checkpoint, b.Checkpoint
	return x.VaultID == y.VaultID && x.OwnerRootKeyID == y.OwnerRootKeyID &&
		x.OwnerRootPublicKey == y.OwnerRootPublicKey && x.PolicySeq != nil && y.PolicySeq != nil &&
		*x.PolicySeq == *y.PolicySeq && x.PolicyDigest == y.PolicyDigest
}

func ReadCompanion(configPath string, manifest Manifest) (Companion, bool, error) {
	var companion Companion
	path, err := CompanionPath(configPath)
	if err != nil {
		return companion, false, err
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return companion, false, nil
	} else if err != nil {
		return companion, false, ErrLocalReview
	}
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return companion, true, ErrLocalReview
	}
	defer clear(raw)
	if teamfiles.JSON(raw, &companion) != nil || companion.Version != 1 || companion.Kind != CompanionKind ||
		!ValidHex32(companion.ManifestSHA256) || !ValidHex32(companion.GenesisSHA256) ||
		!ValidID(companion.OperationID) || !teamfiles.Distinct(path, configPath, manifest.PersonalFile, manifest.Journal, manifest.Archive, manifest.BackendRoot) {
		return Companion{}, true, ErrLocalReview
	}
	digest, err := ReadManifestDigest(configPath, manifest)
	if err != nil || digest != companion.ManifestSHA256 {
		return Companion{}, true, ErrLocalReview
	}
	resumeBytes, err := json.Marshal(companion.Resume)
	if err != nil {
		return Companion{}, true, ErrLocalReview
	}
	defer clear(resumeBytes)
	parsed, _, err := DecodeResumeConfig(resumeBytes)
	if err != nil || !SameResume(parsed, companion.Resume) ||
		parsed.BackendRoot != manifest.BackendRoot || parsed.Name != manifest.Name || parsed.Journal != manifest.Journal ||
		parsed.PersonalFile != manifest.PersonalFile || parsed.Checkpoint.VaultID != manifest.VaultID || *parsed.Checkpoint.PolicySeq != 0 {
		return Companion{}, true, ErrLocalReview
	}
	return companion, true, nil
}

func ValidHex32(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func ValidID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

// WriteCompanionNew exclusively writes a caller-supplied metadata proposal.
// It does not authenticate that proposal; callers must first validate the
// exact G and live Session and then re-read the resulting binding.
func WriteCompanionNew(configPath string, manifest Manifest, want Companion) (Companion, error) {
	encoded, err := json.Marshal(want)
	if err != nil {
		return Companion{}, ErrLocalUnknown
	}
	defer clear(encoded)
	path, err := CompanionPath(configPath)
	if err != nil {
		return Companion{}, err
	}
	if err := teamfiles.WriteNew(path, encoded); err != nil {
		if errors.Is(err, teamfiles.ErrPublicationUnknown) {
			return Companion{}, ErrLocalUnknown
		}
		return Companion{}, ErrLocalReview
	}
	current, exists, err := ReadCompanion(configPath, manifest)
	if err != nil || !exists || !SameCompanion(current, want) {
		return Companion{}, ErrLocalUnknown
	}
	return current, nil
}

func SameCompanion(a, b Companion) bool {
	return a.Version == b.Version && a.Kind == b.Kind && a.ManifestSHA256 == b.ManifestSHA256 &&
		a.GenesisSHA256 == b.GenesisSHA256 && a.OperationID == b.OperationID && SameResume(a.Resume, b.Resume)
}
