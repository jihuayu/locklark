package main

import (
	"context"
	"errors"
	"os"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

func trackExistingVaultFile(ctx context.Context, cfg vaultFileResumeConfig, pin vaultfile.PolicyCheckpoint) (retErr error) {
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	// This advisory refusal avoids a backend read for an existing target.
	// CreateNewState's O_EXCL, not this observation, decides the create race.
	if _, err := os.Lstat(cfg.Journal); err == nil {
		return errVaultFileTargetExists
	} else if !os.IsNotExist(err) {
		return errVaultFileJournal
	}
	backend, err := vaultfilebackend.OpenExistingDir(cfg.BackendRoot)
	if err != nil {
		return errVaultFileBackend
	}
	defer func() {
		if backend.Close() != nil && retErr == nil {
			retErr = errVaultFileLocalUnknown
		}
	}()
	pulled, err := vaultfilepublish.ReadPulled(ctx, backend, cfg.Name, func(ctx context.Context, data []byte, _ vaultfilebackend.Revision) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := vaultfile.ParseFile(data)
		if err != nil {
			return err
		}
		return vaultfile.VerifyPolicyCheckpoint(file, &pin)
	})
	if err != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		if errors.Is(err, vaultfilepublish.ErrVerification) {
			return errVaultFileVerification
		}
		return errVaultFileBackend
	}
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	remote := pulled.Bytes()
	defer clear(remote)
	err = vaultfilejournal.CreateNewState(cfg.Journal, vaultfilejournal.State{
		BaseBytes: remote, WorkingBytes: remote, RemoteRevision: pulled.Revision(), Generation: 0,
	})
	switch {
	case errors.Is(err, vaultfilejournal.ErrTargetExists):
		return errVaultFileTargetExists
	case errors.Is(err, vaultfilejournal.ErrUnsupported):
		return errVaultFileUnsupported
	case errors.Is(err, vaultfilejournal.ErrInvalid):
		return errVaultFileJournal
	case err != nil || ctx.Err() != nil:
		return errVaultFileLocalUnknown
	}
	return nil
}
