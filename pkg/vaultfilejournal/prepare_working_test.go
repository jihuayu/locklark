package vaultfilejournal

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func cleanPrepareWorkingFixture(t *testing.T) (*Journal, State, Proposal) {
	t.Helper()
	j := openAt(t, privateDir(t))
	base := opaque(211, 71)
	state := State{BaseBytes: base, WorkingBytes: bytes.Clone(base), RemoteRevision: vaultfilebackend.Revision("owned-base")}
	if err := j.InitializeState(state); err != nil {
		t.Fatal("PREPARE_WORKING_INIT_FAILED")
	}
	proposal := Proposal{Generation: 1, OperationID: "owned-next-operation", ExpectedRevision: state.RemoteRevision,
		Bytes: opaque(233, 72)}
	return j, state, proposal
}

func TestPrepareWorkingIfStateRealBoltMinimum(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	j, err := Open(path)
	if err != nil {
		t.Fatal("PREPARE_WORKING_OPEN_FAILED")
	}
	base := opaque(211, 71)
	state := State{BaseBytes: base, WorkingBytes: bytes.Clone(base), RemoteRevision: vaultfilebackend.Revision("owned-base")}
	if err := j.InitializeState(state); err != nil {
		t.Fatal("PREPARE_WORKING_INIT_FAILED")
	}
	proposal := Proposal{Generation: 1, OperationID: "owned-next-operation", ExpectedRevision: state.RemoteRevision,
		Bytes: opaque(233, 72)}
	if err := j.PrepareWorkingIfState(state, proposal); err != nil {
		t.Fatal("PREPARE_WORKING_COMMIT_FAILED")
	}
	if j.Close() != nil {
		t.Fatal("PREPARE_WORKING_CLOSE_FAILED")
	}
	j, err = OpenExisting(path)
	if err != nil {
		t.Fatal("PREPARE_WORKING_REOPEN_FAILED")
	}
	defer j.Close()
	want := State{BaseBytes: base, WorkingBytes: proposal.Bytes, RemoteRevision: state.RemoteRevision, Generation: 1}
	if !sameState(mustLoadState(t, j), want) ||
		!samePrepared(mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: 1, Proposal: proposal}) {
		t.Fatal("PREPARE_WORKING_DURABLE_TUPLE_MISMATCH")
	}
}

func TestPrepareWorkingIfStateRealBoltRefusals(t *testing.T) {
	t.Run("same-generation-ack-aba", func(t *testing.T) {
		j, initial, proposal := cleanPrepareWorkingFixture(t)
		if j.PrepareWorkingIfState(initial, proposal) != nil {
			t.Fatal("PREPARE_WORKING_SETUP_FAILED")
		}
		beforeAck := mustLoadState(t, j)
		if j.Ack(proposal.OperationID, proposal.Bytes, vaultfilebackend.Revision("owned-after-ack")) != nil {
			t.Fatal("PREPARE_WORKING_ACK_SETUP_FAILED")
		}
		current := mustLoadState(t, j)
		if current.Generation != beforeAck.Generation || sameState(current, beforeAck) {
			t.Fatal("PREPARE_WORKING_ABA_FIXTURE_INVALID")
		}
		if err := j.PrepareWorkingIfState(beforeAck, proposal); !errors.Is(err, ErrStateMismatch) {
			t.Fatal("PREPARE_WORKING_ADOPTED_ACK_BASE")
		}
		if !sameState(mustLoadState(t, j), current) {
			t.Fatal("PREPARE_WORKING_ABA_REJECTION_MUTATED")
		}
	})
	t.Run("legacy-pending", func(t *testing.T) {
		j, state, proposal := cleanPrepareWorkingFixture(t)
		if j.Save(baseProposal()) != nil {
			t.Fatal("PREPARE_WORKING_LEGACY_SETUP_FAILED")
		}
		if err := j.PrepareWorkingIfState(state, proposal); !errors.Is(err, ErrPendingRecords) {
			t.Fatal("PREPARE_WORKING_LEGACY_NOT_REFUSED")
		}
		if !sameState(mustLoadState(t, j), state) {
			t.Fatal("PREPARE_WORKING_LEGACY_REJECTION_MUTATED")
		}
	})
	t.Run("exact-replay-and-different-pending", func(t *testing.T) {
		j, state, proposal := cleanPrepareWorkingFixture(t)
		if j.PrepareWorkingIfState(state, proposal) != nil {
			t.Fatal("PREPARE_WORKING_SETUP_FAILED")
		}
		dirty := mustLoadState(t, j)
		beforeState := rawKey(t, j, stateKey)
		beforePrepared := rawKey(t, j, preparedKey)
		if j.PrepareWorkingIfState(dirty, proposal) != nil {
			t.Fatal("PREPARE_WORKING_EXACT_REPLAY_FAILED")
		}
		other := proposal
		other.OperationID = "other-operation"
		if err := j.PrepareWorkingIfState(dirty, other); !errors.Is(err, ErrPreparedExists) {
			t.Fatal("PREPARE_WORKING_DIFFERENT_PENDING_ACCEPTED")
		}
		if !bytes.Equal(rawKey(t, j, stateKey), beforeState) ||
			!bytes.Equal(rawKey(t, j, preparedKey), beforePrepared) {
			t.Fatal("PREPARE_WORKING_REPLAY_OR_REFUSAL_MUTATED")
		}
	})
	t.Run("precommit-fault-not-committed", func(t *testing.T) {
		j, state, proposal := cleanPrepareWorkingFixture(t)
		fault := errors.New("owned precommit fault")
		if err := j.prepareWorkingIfStateWithHook(state, proposal, func() error { return fault }); !errors.Is(err, fault) {
			t.Fatal("PREPARE_WORKING_FAULT_NOT_REPORTED")
		}
		if !sameState(mustLoadState(t, j), state) {
			t.Fatal("PREPARE_WORKING_PRECOMMIT_FAULT_MUTATED")
		}
		if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
			t.Fatal("PREPARE_WORKING_PRECOMMIT_FAULT_PREPARED")
		}
	})
}
