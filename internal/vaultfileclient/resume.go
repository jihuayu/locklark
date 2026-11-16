// Package vaultfileclient holds the local, non-secret metadata boundaries used
// by vault-file clients. A decoded checkpoint is supplied local trust, never
// evidence of a current remote head or account grant.
package vaultfileclient

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

var ErrConfig = errors.New("CONFIG_REJECTED")
var ErrBackend = errors.New("BACKEND_REJECTED")

type CheckpointConfig struct {
	VaultID            string  `json:"vault_id"`
	OwnerRootKeyID     string  `json:"owner_root_key_id"`
	OwnerRootPublicKey string  `json:"owner_root_public_key"`
	PolicySeq          *uint64 `json:"policy_seq"`
	PolicyDigest       string  `json:"policy_digest"`
}

type ResumeConfig struct {
	Version      int               `json:"version"`
	BackendRoot  string            `json:"backend_root"`
	Name         string            `json:"name"`
	Journal      string            `json:"journal"`
	PersonalFile string            `json:"personal_file,omitempty"`
	Checkpoint   *CheckpointConfig `json:"checkpoint"`
}

// DecodeResumeConfig retains the strict v1 decoder, including its legacy
// optional personal_file and explicit policy_seq semantics.
func DecodeResumeConfig(raw []byte) (ResumeConfig, vaultfile.PolicyCheckpoint, error) {
	var cfg ResumeConfig
	var pin vaultfile.PolicyCheckpoint
	if teamfiles.JSON(raw, &cfg) != nil || cfg.Version != 1 ||
		!teamfiles.ValidPath(cfg.BackendRoot) || !teamfiles.ValidPath(cfg.Journal) ||
		cfg.PersonalFile != "" && !teamfiles.ValidPath(cfg.PersonalFile) ||
		!vaultfilebackend.ValidName(cfg.Name) || cfg.Checkpoint == nil {
		return cfg, pin, ErrConfig
	}
	cp := cfg.Checkpoint
	if cp.PolicySeq == nil || cp.VaultID == "" || cp.OwnerRootKeyID == "" ||
		len(cp.VaultID) > 4096 || len(cp.OwnerRootKeyID) > 4096 {
		return cfg, pin, ErrConfig
	}
	public, ok := DecodeHex(cp.OwnerRootPublicKey)
	if !ok {
		return cfg, pin, ErrConfig
	}
	digest, ok := DecodeHex(cp.PolicyDigest)
	if !ok {
		return cfg, pin, ErrConfig
	}
	pin = vaultfile.PolicyCheckpoint{
		VaultID: cp.VaultID, OwnerRootKeyID: cp.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(public), PolicySeq: *cp.PolicySeq, PolicyDigest: digest,
	}
	return cfg, pin, nil
}

func DecodeHex(value string) ([]byte, bool) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == 32
}
