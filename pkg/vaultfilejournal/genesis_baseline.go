package vaultfilejournal

import (
	"bytes"

	bolt "go.etcd.io/bbolt"
)

// LoadGenesisBaseline reads only a journal whose entire application shape is
// the single generation-0 State left by AckGenesis. It does not authenticate
// sealed bytes, establish a remote publication or grant, or modify the DB.
// The returned state owns its byte slices. A normal later edit, any pending
// record, or an unknown key/bucket requires a different caller path.
func (j *Journal) LoadGenesisBaseline() (State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return State{}, ErrClosed
	}
	var state State
	err := j.db.View(func(tx *bolt.Tx) error {
		buckets := 0
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if !bytes.Equal(name, []byte(bucketName)) {
				return ErrCorrupt
			}
			buckets++
			return nil
		}); err != nil || buckets != 1 {
			return ErrCorrupt
		}
		b := tx.Bucket([]byte(bucketName))
		keys := 0
		if err := b.ForEach(func(key, value []byte) error {
			if !bytes.Equal(key, []byte(stateKey)) || value == nil {
				return ErrCorrupt
			}
			keys++
			return nil
		}); err != nil || keys != 1 {
			return ErrCorrupt
		}
		var found bool
		var err error
		state, found, err = readStateTx(tx)
		if err != nil || !found || state.Generation != 0 || len(state.BaseBytes) == 0 ||
			len(state.RemoteRevision) == 0 || len(state.RemoteRevision) > MaxStateRevisionBytes ||
			!bytes.Equal(state.BaseBytes, state.WorkingBytes) {
			return ErrCorrupt
		}
		return nil
	})
	if err != nil {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		return State{}, err
	}
	return state, nil
}
