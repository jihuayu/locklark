//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

func managedBindingFixture(t *testing.T) (string, State, Proposal, ManagedSuccessorBinding) {
	t.Helper()
	state := State{
		BaseBytes:      opaque(333, 71),
		WorkingBytes:   opaque(333, 71),
		RemoteRevision: vaultfilebackend.Revision(`"managed-base-rev"`),
		Generation:     0,
	}
	proposal := Proposal{
		Generation:       1,
		OperationID:      "op-managed:binding.1",
		ExpectedRevision: state.RemoteRevision,
		Bytes:            opaque(777, 72),
	}
	binding := ManagedSuccessorBinding{
		Generation:   1,
		OperationID:  proposal.OperationID,
		TargetDigest: sha256.Sum256([]byte("protected exact target")),
	}
	path := filepath.Join(privateDir(t), "journal.db")
	if err := CreateNewState(path, state); err != nil {
		t.Fatal("MANAGED_BINDING_CREATE_FAILED")
	}
	return path, state, proposal, binding
}

func TestManagedSuccessorBindingAtomicAndRetained(t *testing.T) {
	path, origin, proposal, binding := managedBindingFixture(t)
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("MANAGED_BINDING_OPEN_FAILED")
	}
	if _, err := j.LoadManagedSuccessorBinding(); !errors.Is(err, ErrEmpty) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_PRISTINE_NOT_EMPTY")
	}
	if err := j.RebaseAndPrepareManagedSuccessor(origin, origin.BaseBytes,
		origin.RemoteRevision, proposal, binding); err != nil {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_PREPARE_FAILED")
	}
	got, err := j.LoadManagedSuccessorBinding()
	state, stateErr := j.LoadState()
	prepared, preparedErr := j.LoadPrepared()
	audit, auditErr := j.LoadRebaseAudit(1)
	if err != nil || stateErr != nil || preparedErr != nil || auditErr != nil ||
		got != binding || state.Generation != 1 ||
		!bytes.Equal(state.WorkingBytes, proposal.Bytes) ||
		!sameProposal(prepared.Proposal, proposal) ||
		!sameProposal(audit.Proposal, proposal) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_PREPARE_RELATION_FAILED")
	}
	if err := j.Ack(proposal.OperationID, proposal.Bytes, `"managed-successor-rev"`); err != nil {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_ACK_FAILED")
	}
	got, err = j.LoadManagedSuccessorBinding()
	state, stateErr = j.LoadState()
	_, preparedErr = j.LoadPrepared()
	closeErr := j.Close()
	if err != nil || stateErr != nil || closeErr != nil ||
		got != binding || state.Generation != 1 ||
		state.RemoteRevision != `"managed-successor-rev"` ||
		!bytes.Equal(state.BaseBytes, proposal.Bytes) ||
		!errors.Is(preparedErr, ErrEmpty) {
		t.Fatal("MANAGED_BINDING_SETTLEMENT_LOST")
	}
}

func TestManagedSuccessorBindingRejectsOverwriteAndMalformed(t *testing.T) {
	path, origin, proposal, binding := managedBindingFixture(t)
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("MANAGED_BINDING_NEGATIVE_OPEN_FAILED")
	}
	if err := j.RebaseAndPrepareManagedSuccessor(origin, origin.BaseBytes,
		origin.RemoteRevision, proposal, binding); err != nil {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_NEGATIVE_PREPARE_FAILED")
	}
	next := Proposal{
		Generation:       2,
		OperationID:      "op-managed:binding.2",
		ExpectedRevision: origin.RemoteRevision,
		Bytes:            opaque(444, 73),
	}
	state, err := j.LoadState()
	if err != nil {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_NEGATIVE_STATE_FAILED")
	}
	if err := j.RebaseAndPrepare(state, state.BaseBytes, state.RemoteRevision, next); !errors.Is(err, ErrPendingRecords) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_GENERIC_REBASE_OVERWROTE_BINDING")
	}
	if err := j.RebaseAndPrepareManagedSuccessor(state, state.BaseBytes,
		state.RemoteRevision, next, ManagedSuccessorBinding{
			Generation: 2, OperationID: next.OperationID, TargetDigest: binding.TargetDigest,
		}); !errors.Is(err, ErrPendingRecords) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_PREPARE_OVERWROTE_BINDING")
	}
	if err := j.RebaseAndPrepareManagedSuccessor(origin, origin.BaseBytes,
		origin.RemoteRevision, proposal, ManagedSuccessorBinding{
			Generation: 2, OperationID: proposal.OperationID, TargetDigest: binding.TargetDigest,
		}); !errors.Is(err, ErrInvalid) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_WRONG_GENERATION_ACCEPTED")
	}
	j.mu.Lock()
	err = j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte(managedBindingKey), []byte("malformed"))
	})
	j.mu.Unlock()
	if err != nil {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_MALFORMED_WRITE_FAILED")
	}
	if _, err := j.LoadManagedSuccessorBinding(); !errors.Is(err, ErrCorrupt) {
		_ = j.Close()
		t.Fatal("MANAGED_BINDING_MALFORMED_ACCEPTED")
	}
	if err := j.Close(); err != nil {
		t.Fatal("MANAGED_BINDING_NEGATIVE_CLOSE_FAILED")
	}
}
