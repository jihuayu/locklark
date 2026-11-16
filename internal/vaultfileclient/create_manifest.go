package vaultfileclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"golang.org/x/text/unicode/norm"
)

// Manifest is a provisional local create record. It is not a resume config,
// current remote head or authorization to read/write a vault file.
type Manifest struct {
	Version      int    `json:"version"`
	Kind         string `json:"kind"`
	VaultID      string `json:"vault_id"`
	PersonalFile string `json:"personal_file"`
	BackendRoot  string `json:"backend_root"`
	Name         string `json:"name"`
	Journal      string `json:"journal"`
	Archive      string `json:"archive"`
}

const CreateKind = "vault_file_create"

var ErrLocalReview = errors.New("LOCAL_REVIEW")
var ErrLocalUnknown = errors.New("LOCAL_UNKNOWN")

// ReadManifest authenticates only the strict local file shape and path scope.
// The VaultID is a selector; this method does not prove any live Session.
func ReadManifest(path string) (Manifest, bool, error) {
	var manifest Manifest
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return manifest, false, nil
	} else if err != nil {
		return manifest, false, err
	}
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return manifest, true, err
	}
	defer clear(raw)
	if teamfiles.JSON(raw, &manifest) != nil || !ValidManifestPhase(path, manifest, true, false) {
		return Manifest{}, true, ErrLocalReview
	}
	return manifest, true, nil
}

// ReserveManifest persists one random VaultID before caller custody work.
// Exact concurrent retries may use the winner; foreign or unknown outcomes
// are never overwritten. The encoding retains the original v1 field order.
func ReserveManifest(path string, input Manifest) (Manifest, error) {
	return reserveManifestWithWriter(path, input, nil)
}

// The package-private writer seam is nil in production. Tests can make the
// publication result unknown after a real WriteNew without altering disk I/O.
func reserveManifestWithWriter(path string, input Manifest, writeNew func(string, []byte) error) (Manifest, error) {
	if !ValidManifestPhase(path, input, false, false) {
		return Manifest{}, ErrConfig
	}
	if teamfiles.CheckNew(input.Journal) != nil {
		return Manifest{}, ErrLocalReview
	}
	var selector [16]byte
	if _, err := rand.Read(selector[:]); err != nil {
		return Manifest{}, ErrLocalUnknown
	}
	input.VaultID = hex.EncodeToString(selector[:])
	encoded, err := json.Marshal(input)
	if err != nil {
		return Manifest{}, ErrLocalUnknown
	}
	defer clear(encoded)
	if writeNew == nil {
		writeNew = teamfiles.WriteNew
	}
	if err := writeNew(path, encoded); err != nil {
		// A visible inode after publication-unknown is not durable proof.
		// Only a definite pre-publication refusal may name another winner.
		if errors.Is(err, teamfiles.ErrPublicationUnknown) || !errors.Is(err, teamfiles.ErrFile) {
			return Manifest{}, ErrLocalUnknown
		}
		manifest, exists, readErr := ReadManifest(path)
		if readErr != nil || !exists || manifest.PersonalFile != input.PersonalFile ||
			manifest.BackendRoot != input.BackendRoot || manifest.Name != input.Name ||
			manifest.Journal != input.Journal || manifest.Archive != input.Archive {
			return Manifest{}, ErrLocalUnknown
		}
		return manifest, nil
	}
	return input, nil
}

func ValidManifestPhase(path string, manifest Manifest, requireID, journalMustBeNew bool) bool {
	companionPath, err := CompanionPath(path)
	if err != nil {
		return false
	}
	if manifest.Version != 1 || manifest.Kind != CreateKind ||
		!teamfiles.ValidPath(path) || !teamfiles.ValidPath(manifest.PersonalFile) ||
		!teamfiles.ValidPath(manifest.BackendRoot) || !teamfiles.ValidPath(manifest.Journal) ||
		!teamfiles.ValidPath(manifest.Archive) || !vaultfilebackend.ValidName(manifest.Name) ||
		!privateCreateParent(filepath.Dir(path)) || !privateCreateParent(filepath.Dir(manifest.Journal)) ||
		!teamfiles.Distinct(path, companionPath, manifest.PersonalFile, manifest.BackendRoot, manifest.Journal, manifest.Archive) ||
		!normalizedCreateSeparate(manifest.BackendRoot, path, companionPath, manifest.PersonalFile, manifest.BackendRoot, manifest.Journal, manifest.Archive) {
		return false
	}
	if requireID {
		id, err := hex.DecodeString(manifest.VaultID)
		if err != nil || len(id) != 16 || hex.EncodeToString(id) != manifest.VaultID {
			return false
		}
	} else if manifest.VaultID != "" {
		return false
	}
	info, err := os.Lstat(manifest.PersonalFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	if SeparateStatusState(manifest.BackendRoot, path, companionPath, manifest.PersonalFile, manifest.Journal, manifest.Archive) != nil {
		return false
	}
	if journalMustBeNew && teamfiles.CheckNew(manifest.Journal) != nil {
		return false
	}
	return true
}

// Missing leaves cannot be compared with os.SameFile. Reserve case-only and
// canonically equivalent Unicode names on every filesystem, after resolving
// each existing parent. This also reserves the backend namespace before its
// first directory exists.
func normalizedCreateSeparate(backendRoot string, paths ...string) bool {
	canonical := make([]string, 0, len(paths))
	for _, path := range paths {
		resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return false
		}
		leaf := norm.NFC.String(filepath.Join(resolvedParent, filepath.Base(path)))
		for _, prior := range canonical {
			if strings.EqualFold(leaf, prior) {
				return false
			}
		}
		canonical = append(canonical, leaf)
	}
	resolvedRootParent, err := filepath.EvalSymlinks(filepath.Dir(backendRoot))
	if err != nil {
		return false
	}
	namespace := norm.NFC.String(filepath.Join(resolvedRootParent, filepath.Base(backendRoot), "vaultfile-backend"))
	for _, leaf := range canonical {
		for ancestor := leaf; ; ancestor = filepath.Dir(ancestor) {
			if strings.EqualFold(ancestor, namespace) {
				return false
			}
			if ancestor == filepath.Dir(ancestor) {
				break
			}
		}
	}
	return true
}

func privateCreateParent(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm()&0077 == 0
}
