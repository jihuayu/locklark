package vaultfilejournal

import (
	"bytes"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// PrepareWorkingIfState atomically prepares a locally sealed successor against
// one frozen, complete journal state. It never reads a backend. A clean state
// becomes working=proposal with generation+1 and the exact proposal prepared;
// a dirty state can only prepare or replay its exact existing working bytes.
// A changed base or revision at the same generation is a mismatch, not an
// invitation to adopt the new state. Unknown write errors remain unknown.
func (j *Journal) PrepareWorkingIfState(expected State, proposal Proposal) error {
	return j.prepareWorkingIfState(expected, proposal, nil)
}

// prepareWorkingIfStateWithHook injects a pre-commit failure in tests only.
func (j *Journal) prepareWorkingIfStateWithHook(expected State, proposal Proposal, hook func() error) error {
	return j.prepareWorkingIfState(expected, proposal, hook)
}

func (j *Journal) prepareWorkingIfState(expected State, proposal Proposal, hook func() error) error {
	if !validStateGeneration(expected) || len(expected.BaseBytes) == 0 ||
		!validProposal(proposal) || proposal.ExpectedRevision != expected.RemoteRevision {
		return ErrInvalid
	}
	fresh := bytes.Equal(expected.BaseBytes, expected.WorkingBytes)
	targetGeneration := expected.Generation
	if fresh {
		if expected.Generation == math.MaxUint64 || proposal.Generation != expected.Generation+1 {
			return ErrInvalid
		}
		targetGeneration++
	} else if expected.Generation == 0 || proposal.Generation != expected.Generation ||
		!bytes.Equal(expected.WorkingBytes, proposal.Bytes) {
		return ErrInvalid
	}
	expected = State{BaseBytes: bytes.Clone(expected.BaseBytes),
		RemoteRevision: vaultfilebackend.Revision(bytes.Clone([]byte(expected.RemoteRevision))),
		WorkingBytes:   bytes.Clone(expected.WorkingBytes), Generation: expected.Generation}
	defer clear(expected.BaseBytes)
	defer clear(expected.WorkingBytes)
	proposal = Proposal{Generation: proposal.Generation, OperationID: string(bytes.Clone([]byte(proposal.OperationID))),
		ExpectedRevision: vaultfilebackend.Revision(bytes.Clone([]byte(proposal.ExpectedRevision))), Bytes: bytes.Clone(proposal.Bytes)}
	defer clear(proposal.Bytes)
	target := PreparedProposal{WorkingGeneration: targetGeneration, Proposal: proposal}

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		current, found, err := readStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		if !sameState(current, expected) {
			return ErrStateMismatch
		}
		bucket := tx.Bucket([]byte(bucketName))
		key, _ := bucket.Cursor().Seek([]byte(recordKey))
		if bytes.Equal(key, []byte(recordKey)) {
			return ErrPendingRecords
		}
		prior, prepared, err := readPreparedTx(tx)
		if err != nil {
			return err
		}
		if prepared {
			if fresh || !samePrepared(prior, target) {
				return ErrPreparedExists
			}
			return nil // exact replay still crosses the real DB.Update boundary
		}
		if fresh {
			next := State{BaseBytes: current.BaseBytes, RemoteRevision: current.RemoteRevision,
				WorkingBytes: proposal.Bytes, Generation: targetGeneration}
			if err := bucket.Put([]byte(stateKey), encodeState(next)); err != nil {
				return err
			}
		}
		if err := bucket.Put([]byte(preparedKey), encodePrepared(target)); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		return wrapPreparedErr("prepare working", err)
	}
	return nil
}
