//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// Every test using this double must reject. Runtime positives use the real
// root product, private files, and bbolt in vault_file_import_product_unix_test.
type importNegativeJournal struct {
	state                                vaultfilejournal.State
	prepared                             *vaultfilejournal.PreparedProposal
	legacyError, preparedError           error
	updateError, prepareError            error
	updateThenError, prepareThenError    bool
	loadCalls, updateCalls, prepareCalls int
	afterUpdate, afterPrepare            func(*importNegativeJournal)
}

func (j *importNegativeJournal) LoadState() (vaultfilejournal.State, error) {
	j.loadCalls++
	s := j.state
	s.BaseBytes, s.WorkingBytes = bytes.Clone(s.BaseBytes), bytes.Clone(s.WorkingBytes)
	return s, nil
}

func (j *importNegativeJournal) Load() (vaultfilejournal.Proposal, error) {
	return vaultfilejournal.Proposal{}, j.legacyError
}

func (j *importNegativeJournal) LoadPrepared() (vaultfilejournal.PreparedProposal, error) {
	if j.preparedError != nil {
		return vaultfilejournal.PreparedProposal{}, j.preparedError
	}
	if j.prepared == nil {
		return vaultfilejournal.PreparedProposal{}, vaultfilejournal.ErrEmpty
	}
	p := *j.prepared
	p.Proposal.Bytes = bytes.Clone(p.Proposal.Bytes)
	return p, nil
}

func (j *importNegativeJournal) UpdateWorking(expected uint64, input []byte) error {
	j.updateCalls++
	if j.updateError != nil && !j.updateThenError {
		return j.updateError
	}
	if j.state.Generation != expected {
		return vaultfilejournal.ErrStateGenerationMismatch
	}
	j.state.Generation++
	j.state.WorkingBytes = bytes.Clone(input)
	if j.afterUpdate != nil {
		j.afterUpdate(j)
	}
	return j.updateError
}

func (j *importNegativeJournal) Prepare(generation uint64, p vaultfilejournal.Proposal) error {
	j.prepareCalls++
	if j.prepareError != nil && !j.prepareThenError {
		return j.prepareError
	}
	p.Bytes = bytes.Clone(p.Bytes)
	j.prepared = &vaultfilejournal.PreparedProposal{WorkingGeneration: generation, Proposal: p}
	if j.afterPrepare != nil {
		j.afterPrepare(j)
	}
	return j.prepareError
}

func importNegativeFixture(material resumeProductMaterial) *importNegativeJournal {
	return &importNegativeJournal{state: vaultfilejournal.State{BaseBytes: bytes.Clone(material.r),
		WorkingBytes: bytes.Clone(material.r), RemoteRevision: "owned-revision"}, legacyError: vaultfilejournal.ErrEmpty}
}

func TestVaultFileImportNegativeWriteBoundaries(t *testing.T) {
	material := newResumeProductMaterial(t)
	_, pin, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, map[string]any{
		"version": 1, "backend_root": t.TempDir(), "name": "owned.locklark", "journal": t.TempDir(), "checkpoint": material.config,
	}))
	if err != nil {
		t.Fatal("NEGATIVE_CONFIG_FIXTURE_FAILED")
	}
	// The independent creator supplies the same public checkpoint as for the
	// real product. The double never substitutes a signature verifier.
	unknown := errors.New("owned negative commit failure")
	for _, name := range []string{
		"STALE_UPDATE", "UNKNOWN_UPDATE_BEFORE", "UNKNOWN_UPDATE_AFTER", "CHANGED_WORKING", "GENERATION_GREW_SAME_BYTES",
		"BASE_CHANGED", "REVISION_CHANGED", "LEGACY_ARRIVED", "OTHER_PREPARED_ARRIVED", "UNKNOWN_PREPARE_BEFORE",
		"UNKNOWN_PREPARE_AFTER", "EXACT_PREPARED_RETRY_FAILURE", "CANCEL_AFTER_UPDATE", "CANCEL_AFTER_PREPARE",
		"LEGACY_READ_FAILURE", "LEGACY_PRESENT", "LEGACY_EMPTY_JOINED", "PREPARED_READ_FAILURE",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			j := importNegativeFixture(material)
			want := errVaultFileLocalReview
			switch name {
			case "STALE_UPDATE":
				j.updateError = vaultfilejournal.ErrStateGenerationMismatch
			case "UNKNOWN_UPDATE_BEFORE", "UNKNOWN_UPDATE_AFTER":
				want, j.updateError = errVaultFileLocalUnknown, unknown
				j.updateThenError = name == "UNKNOWN_UPDATE_AFTER"
			case "CHANGED_WORKING":
				j.afterUpdate = func(j *importNegativeJournal) { j.state.Generation++; j.state.WorkingBytes = bytes.Clone(material.s) }
			case "GENERATION_GREW_SAME_BYTES":
				j.afterUpdate = func(j *importNegativeJournal) { j.state.Generation++ }
			case "BASE_CHANGED":
				j.afterUpdate = func(j *importNegativeJournal) { j.state.BaseBytes = bytes.Clone(material.s) }
			case "REVISION_CHANGED":
				j.afterUpdate = func(j *importNegativeJournal) { j.state.RemoteRevision = "changed-revision" }
			case "LEGACY_ARRIVED":
				j.afterUpdate = func(j *importNegativeJournal) { j.legacyError = nil }
			case "OTHER_PREPARED_ARRIVED":
				j.afterUpdate = func(j *importNegativeJournal) {
					j.prepared = &vaultfilejournal.PreparedProposal{WorkingGeneration: j.state.Generation,
						Proposal: vaultfilejournal.Proposal{Generation: j.state.Generation, OperationID: "other-operation",
							ExpectedRevision: j.state.RemoteRevision, Bytes: bytes.Clone(material.p)}}
				}
			case "UNKNOWN_PREPARE_BEFORE", "UNKNOWN_PREPARE_AFTER", "EXACT_PREPARED_RETRY_FAILURE":
				want, j.prepareError = errVaultFileLocalUnknown, unknown
				j.prepareThenError = name == "UNKNOWN_PREPARE_AFTER"
				if name == "EXACT_PREPARED_RETRY_FAILURE" {
					j.state.Generation, j.state.WorkingBytes = 1, bytes.Clone(material.p)
					j.prepared = &vaultfilejournal.PreparedProposal{WorkingGeneration: 1,
						Proposal: vaultfilejournal.Proposal{Generation: 1, OperationID: "prepared-operation",
							ExpectedRevision: j.state.RemoteRevision, Bytes: bytes.Clone(material.p)}}
				}
			case "CANCEL_AFTER_UPDATE":
				j.afterUpdate = func(*importNegativeJournal) { cancel() }
			case "CANCEL_AFTER_PREPARE":
				j.afterPrepare = func(*importNegativeJournal) { cancel() }
			case "LEGACY_READ_FAILURE":
				j.legacyError = unknown
			case "LEGACY_PRESENT":
				j.legacyError = nil
			case "LEGACY_EMPTY_JOINED":
				j.legacyError = errors.Join(vaultfilejournal.ErrEmpty, unknown)
			case "PREPARED_READ_FAILURE":
				j.preparedError = unknown
			}
			if got := prepareImportedVaultFile(ctx, j, pin, material.p); got != want {
				t.Fatal("NEGATIVE_IMPORT_CLASSIFICATION_FAILED")
			}
			if j.prepareCalls > 1 || j.updateCalls > 1 {
				t.Fatal("NEGATIVE_IMPORT_RETRIED_WRITE")
			}
			if name == "UNKNOWN_UPDATE_BEFORE" || name == "UNKNOWN_UPDATE_AFTER" {
				if j.loadCalls != 2 || j.prepareCalls != 0 {
					t.Fatal("UNKNOWN_UPDATE_WAS_READ_BACK_AS_SUCCESS")
				}
			}
			if name == "UNKNOWN_PREPARE_BEFORE" || name == "UNKNOWN_PREPARE_AFTER" || name == "EXACT_PREPARED_RETRY_FAILURE" {
				if j.loadCalls != 3 || j.prepareCalls != 1 {
					t.Fatal("UNKNOWN_PREPARE_WAS_READ_BACK_OR_SKIPPED")
				}
			}
			if name == "CHANGED_WORKING" && (!bytes.Equal(j.state.WorkingBytes, material.s) || j.prepareCalls != 0) {
				t.Fatal("CONCURRENT_WORKING_WAS_OVERWRITTEN")
			}
			if name == "LEGACY_ARRIVED" && (j.legacyError != nil || j.prepareCalls != 0) {
				t.Fatal("CONCURRENT_LEGACY_WAS_CONSUMED")
			}
			if name == "OTHER_PREPARED_ARRIVED" && (j.prepared == nil || j.prepared.Proposal.OperationID != "other-operation" || j.prepareCalls != 0) {
				t.Fatal("CONCURRENT_PREPARED_WAS_OVERWRITTEN")
			}
			if (name == "UNKNOWN_UPDATE_AFTER" || name == "UNKNOWN_PREPARE_AFTER") && !bytes.Equal(j.state.WorkingBytes, material.p) {
				t.Fatal("UNKNOWN_LOCAL_WRITE_WAS_CLEARED")
			}
			if (name == "UNKNOWN_PREPARE_AFTER" || name == "CANCEL_AFTER_PREPARE") &&
				(j.prepared == nil || !bytes.Equal(j.prepared.Proposal.Bytes, material.p)) {
				t.Fatal("COMMITTED_PREPARED_WAS_CLEARED")
			}
		})
	}
}

func TestVaultFileImportNegativePreparedTuple(t *testing.T) {
	material := newResumeProductMaterial(t)
	_, pin, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, map[string]any{
		"version": 1, "backend_root": t.TempDir(), "name": "owned.locklark", "journal": t.TempDir(), "checkpoint": material.config,
	}))
	if err != nil {
		t.Fatal("NEGATIVE_TUPLE_CONFIG_FAILED")
	}
	for _, name := range []string{"WORKING_GENERATION", "PROPOSAL_GENERATION", "OPERATION", "REVISION", "BYTES"} {
		t.Run(name, func(t *testing.T) {
			j := importNegativeFixture(material)
			j.state.Generation, j.state.WorkingBytes = 1, bytes.Clone(material.p)
			j.prepared = &vaultfilejournal.PreparedProposal{WorkingGeneration: 1,
				Proposal: vaultfilejournal.Proposal{Generation: 1, OperationID: "prepared-operation",
					ExpectedRevision: j.state.RemoteRevision, Bytes: bytes.Clone(material.p)}}
			switch name {
			case "WORKING_GENERATION":
				j.prepared.WorkingGeneration++
			case "PROPOSAL_GENERATION":
				j.prepared.Proposal.Generation++
			case "OPERATION":
				j.prepared.Proposal.OperationID = "other-operation"
			case "REVISION":
				j.prepared.Proposal.ExpectedRevision = "other-revision"
			case "BYTES":
				j.prepared.Proposal.Bytes = bytes.Clone(material.s)
			}
			before := *j.prepared
			if got := prepareImportedVaultFile(context.Background(), j, pin, material.p); got != errVaultFileLocalReview || j.updateCalls != 0 || j.prepareCalls != 0 {
				t.Fatal("MISMATCHED_PREPARED_TUPLE_WAS_ACCEPTED")
			}
			if j.prepared.WorkingGeneration != before.WorkingGeneration || j.prepared.Proposal.Generation != before.Proposal.Generation ||
				j.prepared.Proposal.OperationID != before.Proposal.OperationID || j.prepared.Proposal.ExpectedRevision != before.Proposal.ExpectedRevision ||
				!bytes.Equal(j.prepared.Proposal.Bytes, before.Proposal.Bytes) {
				t.Fatal("MISMATCHED_PREPARED_TUPLE_WAS_CHANGED")
			}
		})
	}
}
