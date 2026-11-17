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

func ackedGenesisBaselineFixture(t *testing.T) (string, GenesisIntent) {
	t.Helper()
	path := filepath.Join(privateDir(t), "journal.db")
	intent := genesisIntentFixture()
	if CreateNewGenesisIntent(path, intent) != nil {
		t.Fatal("GENESIS_BASELINE_INTENT_CREATE_FAILED")
	}
	j, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_INTENT_OPEN_FAILED")
	}
	if err := j.AckGenesis(intent, intent.SealedBytes, vaultfilebackend.Revision("opaque-revision")); err != nil || j.Close() != nil {
		t.Fatal("GENESIS_BASELINE_ACK_FAILED")
	}
	return path, intent
}

func TestLoadGenesisBaselineOnlyExactAckShape(t *testing.T) {
	path, intent := ackedGenesisBaselineFixture(t)
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("GENESIS_BASELINE_OPEN_FAILED")
	}
	state, err := j.LoadGenesisBaseline()
	if err != nil || state.Generation != 0 || state.RemoteRevision != "opaque-revision" ||
		!bytes.Equal(state.BaseBytes, intent.SealedBytes) || !bytes.Equal(state.WorkingBytes, intent.SealedBytes) {
		t.Fatal("GENESIS_BASELINE_EXACT_ACK_REJECTED")
	}
	state.BaseBytes[0] ^= 1
	again, err := j.LoadGenesisBaseline()
	if err != nil || !bytes.Equal(again.BaseBytes, intent.SealedBytes) || j.Close() != nil {
		t.Fatal("GENESIS_BASELINE_ALIASED_STORAGE")
	}
}

func TestLoadGenesisBaselineRejectsLaterAndForeignRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*bolt.Tx) error
	}{
		{name: "generation-one", change: func(tx *bolt.Tx) error {
			s, _, err := readStateTx(tx)
			if err != nil {
				return err
			}
			s.Generation = 1
			return tx.Bucket([]byte(bucketName)).Put([]byte(stateKey), encodeState(s))
		}},
		{name: "dirty-working", change: func(tx *bolt.Tx) error {
			s, _, err := readStateTx(tx)
			if err != nil {
				return err
			}
			s.WorkingBytes[0] ^= 1
			return tx.Bucket([]byte(bucketName)).Put([]byte(stateKey), encodeState(s))
		}},
		{name: "legacy-proposal", change: func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(bucketName)).Put([]byte(recordKey), []byte("unknown"))
		}},
		{name: "prepared-proposal", change: func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(bucketName)).Put([]byte(preparedKey), []byte("unknown"))
		}},
		{name: "unknown-key", change: func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(bucketName)).Put([]byte("foreign"), []byte("unknown"))
		}},
		{name: "unknown-bucket", change: func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte("foreign"))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := ackedGenesisBaselineFixture(t)
			db, err := bolt.Open(path, 0600, nil)
			if err != nil {
				t.Fatal("GENESIS_BASELINE_MUTATION_OPEN_FAILED")
			}
			if err := db.Update(tc.change); err != nil || db.Close() != nil {
				t.Fatal("GENESIS_BASELINE_MUTATION_FAILED")
			}
			j, err := OpenExisting(path)
			if err != nil {
				t.Fatal("GENESIS_BASELINE_REOPEN_FAILED")
			}
			if _, err := j.LoadGenesisBaseline(); !errors.Is(err, ErrCorrupt) || j.Close() != nil {
				t.Fatal("GENESIS_BASELINE_FOREIGN_SHAPE_ACCEPTED")
			}
		})
	}
}
