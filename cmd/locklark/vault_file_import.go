package main

import (
	"bytes"
	"context"
	"errors"
	"math"

	"github.com/jihuayu/locklark/internal/vaultfilesync"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// This private interface is only the import command's journal boundary. The
// production caller always supplies its exclusively opened real Journal;
// negative unit tests can classify lost results without a product fault hook.
type vaultFileImportJournal interface {
	LoadState() (vaultfilejournal.State, error)
	Load() (vaultfilejournal.Proposal, error)
	LoadPrepared() (vaultfilejournal.PreparedProposal, error)
	UpdateWorking(uint64, []byte) error
	Prepare(uint64, vaultfilejournal.Proposal) error
}

func importPreparedVaultFile(ctx context.Context, cfg vaultFileResumeConfig, pin vaultfile.PolicyCheckpoint, input []byte) (retErr error) {
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	journal, err := vaultfilejournal.OpenExisting(cfg.Journal)
	if err != nil {
		return errVaultFileJournal
	}
	defer func() {
		if journal.Close() != nil && retErr == nil {
			retErr = errVaultFileLocalUnknown
		}
	}()
	return prepareImportedVaultFile(ctx, journal, pin, input)
}

// Import has two durable steps. After UpdateWorking an error or cancellation
// never means "unchanged". No readback turns an unclassified commit error into
// success: the caller can reopen and retry the exact input against full state.
func prepareImportedVaultFile(ctx context.Context, journal vaultFileImportJournal, pin vaultfile.PolicyCheckpoint, input []byte) error {
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	state, err := journal.LoadState()
	if err != nil || len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || state.RemoteRevision == "" {
		return errVaultFileJournal
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	update := bytes.Equal(state.WorkingBytes, state.BaseBytes)
	if !update && !bytes.Equal(state.WorkingBytes, input) {
		return errVaultFileLocalReview
	}
	generation := state.Generation
	if update {
		if generation == math.MaxUint64 {
			return errVaultFileLocalReview
		}
		generation++
	} else if generation == 0 {
		return errVaultFileLocalReview
	}
	file, err := vaultfile.ParseFile(input)
	if err != nil {
		return errVaultFileVerification
	}
	proposal := vaultfilejournal.Proposal{Generation: generation, OperationID: file.Header.OpID,
		ExpectedRevision: state.RemoteRevision, Bytes: input}
	verifier, err := vaultfilesync.NewContentProposalVerifier(&pin)
	if err != nil || verifier(ctx, state.BaseBytes, state.RemoteRevision, proposal) != nil {
		if ctx.Err() != nil {
			return errVaultFileCancelled
		}
		return errVaultFileVerification
	}
	if err := checkVaultFileImportState(journal, state, proposal, !update); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errVaultFileCancelled
	}
	if update {
		if err := journal.UpdateWorking(state.Generation, input); err != nil {
			return vaultFileImportWriteError(err)
		}
		state.Generation = generation
		clear(state.WorkingBytes)
		state.WorkingBytes = bytes.Clone(input)
		defer clear(state.WorkingBytes)
	}
	// Re-read the complete expected tuple and both pending records before the
	// second write. Prepare itself re-checks generation/revision/bytes/pending
	// in its transaction; it does not inspect the legacy proposal record.
	if err := checkVaultFileImportState(journal, state, proposal, true); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errVaultFileLocalReview
	}
	// Exact prepared retries also take this real synchronous DB.Update path.
	// LoadPrepared is never a shortcut to a durable-success response.
	if err := journal.Prepare(generation, proposal); err != nil {
		return vaultFileImportWriteError(err)
	}
	if ctx.Err() != nil {
		return errVaultFileLocalReview
	}
	return nil
}

func checkVaultFileImportState(journal vaultFileImportJournal, expected vaultfilejournal.State, proposal vaultfilejournal.Proposal, allowPrepared bool) error {
	current, err := journal.LoadState()
	if err != nil {
		return errVaultFileLocalReview
	}
	defer clear(current.BaseBytes)
	defer clear(current.WorkingBytes)
	if current.Generation != expected.Generation || current.RemoteRevision != expected.RemoteRevision ||
		!bytes.Equal(current.BaseBytes, expected.BaseBytes) || !bytes.Equal(current.WorkingBytes, expected.WorkingBytes) {
		return errVaultFileLocalReview
	}
	legacy, err := journal.Load()
	clear(legacy.Bytes)
	if err != vaultfilejournal.ErrEmpty {
		return errVaultFileLocalReview
	}
	prepared, err := journal.LoadPrepared()
	defer clear(prepared.Proposal.Bytes)
	if err == vaultfilejournal.ErrEmpty {
		return nil
	}
	if err != nil || !allowPrepared || prepared.WorkingGeneration != expected.Generation ||
		prepared.Proposal.Generation != proposal.Generation || prepared.Proposal.OperationID != proposal.OperationID ||
		prepared.Proposal.ExpectedRevision != proposal.ExpectedRevision || !bytes.Equal(prepared.Proposal.Bytes, proposal.Bytes) {
		return errVaultFileLocalReview
	}
	return nil
}

func vaultFileImportWriteError(err error) error {
	for _, rejected := range []error{vaultfilejournal.ErrInvalid, vaultfilejournal.ErrEmpty, vaultfilejournal.ErrCorrupt,
		vaultfilejournal.ErrClosed, vaultfilejournal.ErrStateGenerationMismatch, vaultfilejournal.ErrStateGenerationOverflow,
		vaultfilejournal.ErrPreparedExists, vaultfilejournal.ErrPreparedMismatch} {
		if errors.Is(err, rejected) {
			return errVaultFileLocalReview
		}
	}
	return errVaultFileLocalUnknown
}
