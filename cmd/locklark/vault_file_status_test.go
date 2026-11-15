package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// stubVaultFileStatusJournal returns deep copies exactly like the durable
// Journal load APIs. The classifier clears what it reads; a shared backing
// slice here would make one table case corrupt another.
type stubVaultFileStatusJournal struct {
	state       vaultfilejournal.State
	stateErr    error
	legacy      vaultfilejournal.Proposal
	legacyErr   error
	prepared    vaultfilejournal.PreparedProposal
	preparedErr error
}

func (s stubVaultFileStatusJournal) LoadState() (vaultfilejournal.State, error) {
	state := s.state
	state.BaseBytes = bytes.Clone(state.BaseBytes)
	state.WorkingBytes = bytes.Clone(state.WorkingBytes)
	return state, s.stateErr
}

func (s stubVaultFileStatusJournal) Load() (vaultfilejournal.Proposal, error) {
	proposal := s.legacy
	proposal.Bytes = bytes.Clone(proposal.Bytes)
	return proposal, s.legacyErr
}

func (s stubVaultFileStatusJournal) LoadPrepared() (vaultfilejournal.PreparedProposal, error) {
	prepared := s.prepared
	prepared.Proposal.Bytes = bytes.Clone(prepared.Proposal.Bytes)
	return prepared, s.preparedErr
}

func TestVaultFileStatusClassification(t *testing.T) {
	base := []byte("sealed-baseline")
	preparedBytes := []byte("sealed-prepared")
	newerWorking := []byte("sealed-newer-working")
	state := func(working []byte, generation uint64) vaultfilejournal.State {
		return vaultfilejournal.State{BaseBytes: base, WorkingBytes: working, RemoteRevision: "opaque-revision", Generation: generation}
	}
	prepared := func(expected string, workingGeneration, generation uint64, b []byte) vaultfilejournal.PreparedProposal {
		return vaultfilejournal.PreparedProposal{
			WorkingGeneration: workingGeneration,
			Proposal: vaultfilejournal.Proposal{
				Generation: generation, OperationID: "operation", ExpectedRevision: vaultfilebackend.Revision(expected), Bytes: b,
			},
		}
	}
	cases := []struct {
		name    string
		journal stubVaultFileStatusJournal
		want    vaultFileLocalState
		wantErr error
	}{
		{name: "CLEAN", journal: stubVaultFileStatusJournal{state: state(base, 0), legacyErr: vaultfilejournal.ErrEmpty, preparedErr: vaultfilejournal.ErrEmpty}, want: vaultFileStateClean},
		{name: "DIRTY", journal: stubVaultFileStatusJournal{state: state(preparedBytes, 1), legacyErr: vaultfilejournal.ErrEmpty, preparedErr: vaultfilejournal.ErrEmpty}, want: vaultFileStateDirty},
		{name: "PREPARED", journal: stubVaultFileStatusJournal{state: state(preparedBytes, 1), legacyErr: vaultfilejournal.ErrEmpty, prepared: prepared("opaque-revision", 1, 1, preparedBytes)}, want: vaultFileStatePrepared},
		{name: "PREPARED_OLDER_GENERATION", journal: stubVaultFileStatusJournal{state: state(newerWorking, 2), legacyErr: vaultfilejournal.ErrEmpty, prepared: prepared("opaque-revision", 1, 1, preparedBytes)}, want: vaultFileStatePrepared},
		{name: "LEGACY_PENDING", journal: stubVaultFileStatusJournal{state: state(base, 0), legacy: vaultfilejournal.Proposal{Generation: 1, OperationID: "legacy", ExpectedRevision: "opaque-revision", Bytes: preparedBytes}, preparedErr: vaultfilejournal.ErrEmpty}, want: vaultFileStateReview},
		{name: "PREPARED_REVISION_MISMATCH", journal: stubVaultFileStatusJournal{state: state(preparedBytes, 1), legacyErr: vaultfilejournal.ErrEmpty, prepared: prepared("other-revision", 1, 1, preparedBytes)}, want: vaultFileStateReview},
		{name: "PREPARED_NEWER_GENERATION", journal: stubVaultFileStatusJournal{state: state(preparedBytes, 1), legacyErr: vaultfilejournal.ErrEmpty, prepared: prepared("opaque-revision", 2, 2, preparedBytes)}, want: vaultFileStateReview},
		{name: "PREPARED_BYTES_MISMATCH", journal: stubVaultFileStatusJournal{state: state(newerWorking, 1), legacyErr: vaultfilejournal.ErrEmpty, prepared: prepared("opaque-revision", 1, 1, preparedBytes)}, want: vaultFileStateReview},
		{name: "STATE_READ_FAILURE", journal: stubVaultFileStatusJournal{stateErr: vaultfilejournal.ErrCorrupt}, wantErr: errVaultFileJournal},
		{name: "STATE_WITHOUT_BASE", journal: stubVaultFileStatusJournal{state: vaultfilejournal.State{WorkingBytes: base}, legacyErr: vaultfilejournal.ErrEmpty, preparedErr: vaultfilejournal.ErrEmpty}, wantErr: errVaultFileJournal},
		{name: "STATE_WITHOUT_WORKING", journal: stubVaultFileStatusJournal{state: vaultfilejournal.State{BaseBytes: base, RemoteRevision: "opaque-revision"}, legacyErr: vaultfilejournal.ErrEmpty, preparedErr: vaultfilejournal.ErrEmpty}, wantErr: errVaultFileJournal},
		{name: "CORRUPT_LEGACY", journal: stubVaultFileStatusJournal{state: state(base, 0), legacyErr: vaultfilejournal.ErrCorrupt, preparedErr: vaultfilejournal.ErrEmpty}, wantErr: errVaultFileJournal},
		{name: "CORRUPT_PREPARED", journal: stubVaultFileStatusJournal{state: state(base, 0), legacyErr: vaultfilejournal.ErrEmpty, preparedErr: vaultfilejournal.ErrCorrupt}, wantErr: errVaultFileJournal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyVaultFileStatus(tc.journal)
			if tc.wantErr != nil {
				if err != tc.wantErr || got != "" {
					t.Fatal("STATUS_FAILCLOSED_CLASSIFICATION_MISMATCH")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatal("STATUS_LOCAL_CLASSIFICATION_MISMATCH")
			}
		})
	}
}

func TestVaultFileStatusOutputBounded(t *testing.T) {
	for _, state := range []vaultFileLocalState{vaultFileStateClean, vaultFileStateDirty, vaultFileStatePrepared, vaultFileStateReview} {
		var out bytes.Buffer
		if err := writeVaultFileStatus(&out, state); err != nil {
			t.Fatal("STATUS_FIXED_OUTPUT_FAILED")
		}
		want := "{\"status\":\"" + string(state) + "\",\"remote_freshness\":\"UNVERIFIED\"}\n"
		if out.String() != want {
			t.Fatal("STATUS_FIXED_OUTPUT_MISMATCH")
		}
		if strings.Contains(out.String(), "SYNCED") || strings.Contains(out.String(), "CURRENT") || strings.Contains(out.String(), "GRANT") {
			t.Fatal("STATUS_MADE_REMOTE_OR_GRANT_CLAIM")
		}
	}
	var out bytes.Buffer
	if err := writeVaultFileStatus(&out, vaultFileLocalState("raw-value")); err != errVaultFileLocalUnknown || out.Len() != 0 {
		t.Fatal("STATUS_UNBOUNDED_VALUE_WAS_PRINTED")
	}
	if err := writeVaultFileStatus(errorWriter{}, vaultFileStateClean); err != errVaultFileLocalUnknown {
		t.Fatal("STATUS_OUTPUT_FAILURE_WAS_IGNORED")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("owned output failure") }

func TestVaultFileStatusHelpPreservesOriginalCommands(t *testing.T) {
	for _, args := range [][]string{{"vault-file", "--help"}, {"vault-file", "status", "--help"}} {
		var out bytes.Buffer
		if err := run(args, &out, &out); err != nil {
			t.Fatal("STATUS_HELP_FAILED")
		}
		text := out.String()
		for _, required := range []string{
			"locklark vault-file track-existing --config ABS_CONFIG",
			"locklark vault-file status --config ABS_CONFIG",
			"locklark vault-file import-prepared --config ABS_CONFIG --input ABS_SEALED_FILE",
			"locklark vault-file resume-prepared --config ABS_CONFIG",
			"CLEAN, DIRTY, PREPARED or REVIEW",
			"remote_freshness UNVERIFIED",
		} {
			if !strings.Contains(text, required) {
				t.Fatal("STATUS_HELP_MISSING_REQUIRED_CONTRACT")
			}
		}
	}
}
