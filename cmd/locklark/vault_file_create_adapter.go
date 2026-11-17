package main

import (
	"encoding/json"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// This adapter gives the user's original create config path to the existing
// status and open-baseline commands. It only checks immutable local config
// binding; those commands retain their LOCAL/UNVERIFIED semantics. It never
// turns the companion into a current remote head or a grant.
func resumeConfigFromCreateManifest(configPath string) (vaultFileResumeConfig, vaultfile.PolicyCheckpoint, error) {
	var zero vaultFileResumeConfig
	var pin vaultfile.PolicyCheckpoint
	manifest, exists, err := readVaultFileCreateManifest(configPath)
	if err != nil || !exists {
		return zero, pin, errVaultFileConfig
	}
	companion, exists, err := readVaultFileCreateCompanion(configPath, manifest)
	if err != nil || !exists {
		return zero, pin, errVaultFileConfig
	}
	raw, err := json.Marshal(companion.Resume)
	if err != nil {
		return zero, pin, errVaultFileConfig
	}
	defer clear(raw)
	return decodeVaultFileResumeConfig(raw)
}
