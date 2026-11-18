package vaultfilejournal

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// LoadOwnedFirstPending returns the exact first owned-successor preparation
// left by PrepareWorkingIfState, but only when the entire durable application
// shape is the generation-1 dirty State plus its one prepared proposal. The
// legacy proposal record, a genesis intent, any other key and every other
// state/prepared relation is refused without changing anything.
//
// The returned State is the pending state: BaseBytes is the original sealed
// genesis, WorkingBytes is the exact prepared successor and Generation is 1.
// Prepared is the same durable record AckOwnedFirstSuccessor expects. This
// method does not authenticate either file, bind an owner pin or grant any
// write authority; those remain the caller's responsibility.
func (j *Journal) LoadOwnedFirstPending() (State, PreparedProposal, error) {
	var (
		state    State
		prepared PreparedProposal
	)
	if j == nil {
		return State{}, PreparedProposal{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return State{}, PreparedProposal{}, ErrClosed
	}
	err := j.db.View(func(tx *bolt.Tx) error {
		b, err := ownedFirstSuccessorBucket(tx, true)
		if err != nil {
			return err
		}
		state, err = decodeState(b.Get([]byte(stateKey)))
		if err != nil {
			return err
		}
		stored, found, err := readPreparedTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		prepared = stored
		if state.Generation != 1 || prepared.WorkingGeneration != 1 ||
			prepared.Proposal.Generation != 1 ||
			prepared.Proposal.ExpectedRevision != state.RemoteRevision ||
			!bytes.Equal(prepared.Proposal.Bytes, state.WorkingBytes) ||
			bytes.Equal(state.BaseBytes, state.WorkingBytes) {
			return ErrPreparedMismatch
		}
		return nil
	})
	if err != nil {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return State{}, PreparedProposal{}, err
	}
	return state, prepared, nil
}
