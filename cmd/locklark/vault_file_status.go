package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// vaultFileLocalState is the complete finite set of local journal states this
// read-only command reports. It is deliberately not a remote or authorization
// state.
type vaultFileLocalState string

const (
	vaultFileStateClean    vaultFileLocalState = "CLEAN"
	vaultFileStateDirty    vaultFileLocalState = "DIRTY"
	vaultFileStatePrepared vaultFileLocalState = "PREPARED"
	vaultFileStateReview   vaultFileLocalState = "REVIEW"
)

func (s vaultFileLocalState) valid() bool {
	switch s {
	case vaultFileStateClean, vaultFileStateDirty, vaultFileStatePrepared, vaultFileStateReview:
		return true
	}
	return false
}

// vaultFileStatusJournal is the read-only journal boundary of status. The
// product always supplies an exclusively opened existing Journal. It has no
// write, backend, decryption or signature method.
type vaultFileStatusJournal interface {
	LoadState() (vaultfilejournal.State, error)
	Load() (vaultfilejournal.Proposal, error)
	LoadPrepared() (vaultfilejournal.PreparedProposal, error)
}

// classifyVaultFileStatus reads only local durable records. A legacy proposal
// or a prepared record that no longer agrees with the current state is
// decodable but unresolved, so it is reported as REVIEW rather than clean,
// dirty or prepared. Malformed, missing and truncated records are refused.
func classifyVaultFileStatus(journal vaultFileStatusJournal) (vaultFileLocalState, error) {
	state, err := journal.LoadState()
	if err != nil {
		return "", errVaultFileJournal
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	// The product commands require a complete baseline. A state record that
	// merely decodes but lacks a base, working file or revision is not a
	// configured journal and is never guessed at.
	if len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || len(state.RemoteRevision) == 0 {
		return "", errVaultFileJournal
	}
	legacy, err := journal.Load()
	switch {
	case err == nil:
		clear(legacy.Bytes)
		return vaultFileStateReview, nil
	case errors.Is(err, vaultfilejournal.ErrEmpty):
	default:
		return "", errVaultFileJournal
	}
	prepared, err := journal.LoadPrepared()
	switch {
	case errors.Is(err, vaultfilejournal.ErrEmpty):
		if bytes.Equal(state.BaseBytes, state.WorkingBytes) {
			return vaultFileStateClean, nil
		}
		return vaultFileStateDirty, nil
	case err != nil:
		return "", errVaultFileJournal
	}
	defer clear(prepared.Proposal.Bytes)
	// This is the same local agreement the resume command requires before it
	// opens a backend. A prepared proposal based on an older generation may
	// have a newer working edit; only an equal-generation record must still
	// carry the exact working bytes.
	if prepared.Proposal.ExpectedRevision != state.RemoteRevision ||
		prepared.WorkingGeneration > state.Generation ||
		prepared.WorkingGeneration == state.Generation && !bytes.Equal(state.WorkingBytes, prepared.Proposal.Bytes) {
		return vaultFileStateReview, nil
	}
	return vaultFileStatePrepared, nil
}

func writeVaultFileStatus(out io.Writer, state vaultFileLocalState) error {
	if !state.valid() {
		return errVaultFileLocalUnknown
	}
	if _, err := fmt.Fprintf(out, "{\"status\":\"%s\",\"remote_freshness\":\"UNVERIFIED\"}\n", state); err != nil {
		return errVaultFileLocalUnknown
	}
	return nil
}

// statusVaultFile opens only the existing configured journal. It never opens,
// reads or writes a backend, never verifies a remote or a current grant, and
// never decrypts or re-signs content. Close is completed before any success
// line is written so an unconfirmed close cannot look like a status result.
func statusVaultFile(out io.Writer, cfg vaultFileResumeConfig) error {
	journal, err := vaultfilejournal.OpenExisting(cfg.Journal)
	if err != nil {
		return errVaultFileJournal
	}
	state, statusErr := classifyVaultFileStatus(journal)
	closeErr := journal.Close()
	if statusErr != nil {
		return statusErr
	}
	if closeErr != nil {
		return errVaultFileJournal
	}
	return writeVaultFileStatus(out, state)
}
