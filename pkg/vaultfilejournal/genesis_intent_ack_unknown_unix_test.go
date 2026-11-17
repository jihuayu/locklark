//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// These tests inject lost results around a real Bolt Update. They do not
// simulate a physical crash or an external backend acknowledgement.
func TestGenesisAckRollbackErrorReopensExactIntent(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	want := genesisIntentFixture()
	if CreateNewGenesisIntent(path, want) != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_CREATE_FAILED")
	}
	g, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_OPEN_FAILED")
	}
	injected := errors.New("owned rollback result")
	reached := false
	update := func(body func(*bolt.Tx) error) error {
		return g.journal.db.Update(func(tx *bolt.Tx) error {
			if err := body(tx); err != nil {
				return err
			}
			reached = true
			return injected
		})
	}
	err = g.ackGenesisWithUpdate(want, want.SealedBytes, "owned-revision", update)
	if !reached || !errors.Is(err, injected) || g.Close() != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_NOT_OBSERVED")
	}
	reopened, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_INTENT_LOST")
	}
	got, err := reopened.Load()
	if err != nil || !sameGenesisIntent(got, want) || reopened.Close() != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_INTENT_CHANGED")
	}
	if j, err := OpenExisting(path); !errors.Is(err, ErrPendingGenesisIntent) || j != nil {
		t.Fatal("GENESIS_ACK_ROLLBACK_INFERRED_ACK")
	}
}

func TestGenesisAckCommittedButErrorReopensExactState(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	want := genesisIntentFixture()
	revision := vaultfilebackend.Revision("owned-committed-revision")
	if CreateNewGenesisIntent(path, want) != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_CREATE_FAILED")
	}
	g, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_OPEN_FAILED")
	}
	injected := errors.New("owned lost completion")
	reached := false
	update := func(body func(*bolt.Tx) error) error {
		if err := g.journal.db.Update(body); err != nil {
			return err
		}
		reached = true
		return injected
	}
	err = g.ackGenesisWithUpdate(want, want.SealedBytes, revision, update)
	if !reached || !errors.Is(err, injected) || g.Close() != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_ERROR_NOT_OBSERVED")
	}
	if pending, err := OpenExistingIntent(path); err == nil || pending != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_STILL_PENDING")
	}
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_STATE_MISSING")
	}
	defer j.Close()
	state, err := j.LoadState()
	if err != nil || state.Generation != 0 || state.RemoteRevision != revision ||
		!bytes.Equal(state.BaseBytes, want.SealedBytes) || !bytes.Equal(state.WorkingBytes, want.SealedBytes) {
		t.Fatal("GENESIS_ACK_COMMITTED_STATE_CHANGED")
	}
	if err := j.db.View(func(tx *bolt.Tx) error {
		roots := 0
		if err := tx.ForEach(func(k []byte, _ *bolt.Bucket) error {
			roots++
			if !bytes.Equal(k, []byte(bucketName)) {
				return ErrCorrupt
			}
			return nil
		}); err != nil || roots != 1 {
			return ErrCorrupt
		}
		keys := 0
		return tx.Bucket([]byte(bucketName)).ForEach(func(k, v []byte) error {
			keys++
			if !bytes.Equal(k, []byte(stateKey)) || v == nil || keys != 1 {
				return ErrCorrupt
			}
			return nil
		})
	}); err != nil {
		t.Fatal("GENESIS_ACK_COMMITTED_EXTRA_RECORD")
	}
}
