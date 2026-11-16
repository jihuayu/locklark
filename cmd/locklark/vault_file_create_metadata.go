package main

import (
	"errors"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

type vaultFileCreateCompanion = vaultfileclient.Companion

func vaultFileCreateCompanionPath(configPath string) (string, error) {
	return vaultfileclient.CompanionPath(configPath)
}

func readVaultFileCreateCompanion(configPath string, manifest vaultFileCreateManifest) (vaultFileCreateCompanion, bool, error) {
	return vaultfileclient.ReadCompanion(configPath, manifest)
}

func sameVaultFileCreateCompanion(a, b vaultFileCreateCompanion) bool {
	return vaultfileclient.SameCompanion(a, b)
}

func mapVaultFileCreateContextError(err error) error {
	switch {
	case errors.Is(err, vaultfileclient.ErrCreateVerification):
		return errVaultFileVerification
	case errors.Is(err, vaultfileclient.ErrCreateUnknown):
		return errVaultFileUnknown
	case errors.Is(err, vaultfileclient.ErrCreateCancelled):
		return errVaultFileCancelled
	case errors.Is(err, vaultfileclient.ErrCreateUnsupported):
		return errVaultFileUnsupported
	default:
		return err
	}
}
