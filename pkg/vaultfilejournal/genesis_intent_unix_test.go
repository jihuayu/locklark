//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

func genesisIntentFixture() GenesisIntent {
	return GenesisIntent{
		Name: "owned-vault", VaultID: "owned-vault-id", OwnerRootKeyID: "owned-root-id",
		OwnerRootPublicKey: bytes.Repeat([]byte{0x31}, 32), PolicySeq: 0,
		PolicyDigest: bytes.Repeat([]byte{0x42}, 32), OperationID: "owned-genesis-op",
		SealedBytes: []byte("owned opaque sealed genesis bytes"),
	}
}

func TestGenesisIntentRealBoltCreateReadAck(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	input := genesisIntentFixture()
	want := cloneGenesisIntent(input)
	if err := CreateNewGenesisIntent(path, input); err != nil {
		t.Fatal("GENESIS_CREATE_FAILED")
	}
	input.SealedBytes[0] ^= 1
	input.OwnerRootPublicKey[0] ^= 1
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("GENESIS_INODE_MODE_FAILED")
	}
	if j, err := Open(path); !errors.Is(err, ErrPendingGenesisIntent) || j != nil {
		t.Fatal("GENESIS_LEGACY_OPEN_ACCEPTED")
	}
	if j, err := OpenExisting(path); !errors.Is(err, ErrPendingGenesisIntent) || j != nil {
		t.Fatal("GENESIS_EXISTING_STATE_OPEN_ACCEPTED")
	}
	g, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_REOPEN_FAILED")
	}
	got, err := g.Load()
	if err != nil || !sameGenesisIntent(got, want) {
		t.Fatal("GENESIS_LOADED_INTENT_CHANGED")
	}
	got.SealedBytes[0] ^= 1
	got.PolicyDigest[0] ^= 1
	again, err := g.Load()
	if err != nil || !sameGenesisIntent(again, want) {
		t.Fatal("GENESIS_LOAD_ALIASED_STORAGE")
	}
	if err := g.AckGenesis(want, bytes.Clone(want.SealedBytes), vaultfilebackend.Revision("owned-remote-revision")); err != nil {
		t.Fatal("GENESIS_ACK_FAILED")
	}
	if err := g.Close(); err != nil {
		t.Fatal("GENESIS_CLOSE_FAILED")
	}
	if g, err := OpenExistingIntent(path); err == nil || g != nil {
		t.Fatal("GENESIS_ACK_LEFT_INTENT")
	}
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("GENESIS_STATE_REOPEN_FAILED")
	}
	state, err := j.LoadState()
	if err != nil || state.Generation != 0 || state.RemoteRevision != "owned-remote-revision" ||
		!bytes.Equal(state.BaseBytes, want.SealedBytes) || !bytes.Equal(state.WorkingBytes, want.SealedBytes) {
		t.Fatal("GENESIS_ACK_STATE_MISMATCH")
	}
	if _, err := j.Load(); !errors.Is(err, ErrEmpty) {
		t.Fatal("GENESIS_ACK_LEFT_LEGACY")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) || j.Close() != nil {
		t.Fatal("GENESIS_ACK_LEFT_PREPARED")
	}
}

func TestGenesisIntentAckRefusalsKeepExactIntent(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	want := genesisIntentFixture()
	if CreateNewGenesisIntent(path, want) != nil {
		t.Fatal("GENESIS_NEG_CREATE_FAILED")
	}
	g, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_NEG_OPEN_FAILED")
	}
	defer g.Close()
	foreign := cloneGenesisIntent(want)
	foreign.Name = "foreign-vault"
	wrongPin := cloneGenesisIntent(want)
	wrongPin.PolicyDigest[0] ^= 1
	wrongOp := cloneGenesisIntent(want)
	wrongOp.OperationID = "other-genesis-op"
	wrongBytes := cloneGenesisIntent(want)
	wrongBytes.SealedBytes[0] ^= 1
	for _, c := range []struct {
		name string
		i    GenesisIntent
		b    []byte
		r    vaultfilebackend.Revision
		err  error
	}{
		{"wrong-name", foreign, want.SealedBytes, "r", ErrGenesisMismatch},
		{"wrong-pin", wrongPin, want.SealedBytes, "r", ErrGenesisMismatch},
		{"wrong-op", wrongOp, want.SealedBytes, "r", ErrGenesisMismatch},
		{"wrong-intent-bytes", wrongBytes, want.SealedBytes, "r", ErrGenesisMismatch},
		{"wrong-readback", want, []byte("different"), "r", ErrGenesisMismatch},
		{"empty-revision", want, want.SealedBytes, "", ErrInvalid},
		{"long-revision", want, want.SealedBytes, vaultfilebackend.Revision(bytes.Repeat([]byte{'r'}, MaxStateRevisionBytes+1)), ErrInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := g.AckGenesis(c.i, c.b, c.r); !errors.Is(err, c.err) {
				t.Fatal("GENESIS_NEG_ACK_CLASSIFICATION")
			}
			got, err := g.Load()
			if err != nil || !sameGenesisIntent(got, want) {
				t.Fatal("GENESIS_NEG_ACK_CHANGED_INTENT")
			}
		})
	}
}

func TestGenesisIntentRejectsForeignRecordsAndMalformedEncoding(t *testing.T) {
	for _, name := range []string{"state", "prepared", "proposal", "other-key", "other-bucket"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "journal.db")
			if CreateNewGenesisIntent(path, genesisIntentFixture()) != nil {
				t.Fatal("GENESIS_FOREIGN_CREATE_FAILED")
			}
			db, err := bolt.Open(path, 0600, nil)
			if err != nil {
				t.Fatal("GENESIS_FOREIGN_DB_OPEN_FAILED")
			}
			err = db.Update(func(tx *bolt.Tx) error {
				if name == "other-bucket" {
					_, err := tx.CreateBucket([]byte("foreign"))
					return err
				}
				return tx.Bucket([]byte(bucketName)).Put([]byte(name), []byte("foreign"))
			})
			if err != nil || db.Close() != nil {
				t.Fatal("GENESIS_FOREIGN_FIXTURE_FAILED")
			}
			if g, err := OpenExistingIntent(path); err == nil || g != nil {
				t.Fatal("GENESIS_FOREIGN_INTENT_ACCEPTED")
			}
			if j, err := Open(path); !errors.Is(err, ErrPendingGenesisIntent) || j != nil {
				t.Fatal("GENESIS_FOREIGN_LEGACY_OPEN_ACCEPTED")
			}
		})
	}
	want := genesisIntentFixture()
	raw := encodeGenesisIntent(want)
	if _, err := decodeGenesisIntent(raw[:len(raw)-1]); !errors.Is(err, ErrCorrupt) {
		t.Fatal("GENESIS_TRUNCATION_ACCEPTED")
	}
	if _, err := decodeGenesisIntent(append(bytes.Clone(raw), 0)); !errors.Is(err, ErrCorrupt) {
		t.Fatal("GENESIS_TRAILING_BYTES_ACCEPTED")
	}
	oversize := bytes.Clone(raw)
	binary.BigEndian.PutUint32(oversize[19:23], uint32(MaxProposalBytes+1))
	if _, err := decodeGenesisIntent(oversize); !errors.Is(err, ErrCorrupt) {
		t.Fatal("GENESIS_DECLARED_OVERFLOW_ACCEPTED")
	}
	changed := bytes.Clone(raw)
	changed[genesisIntentPrefix] ^= 1
	if _, err := decodeGenesisIntent(changed); !errors.Is(err, ErrCorrupt) {
		t.Fatal("GENESIS_CHECKSUM_ACCEPTED")
	}
}

func TestGenesisIntentAckRefusesLateForeignState(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	want := genesisIntentFixture()
	if CreateNewGenesisIntent(path, want) != nil {
		t.Fatal("GENESIS_LATE_CREATE_FAILED")
	}
	g, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_LATE_OPEN_FAILED")
	}
	defer g.Close()
	if err := g.journal.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte(stateKey), encodeState(newStateFixture()))
	}); err != nil {
		t.Fatal("GENESIS_LATE_FIXTURE_FAILED")
	}
	if err := g.AckGenesis(want, want.SealedBytes, "remote-revision"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("GENESIS_LATE_STATE_ACKED")
	}
	if err := g.journal.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get([]byte(genesisIntentKey)) == nil || !bytes.Equal(b.Get([]byte(stateKey)), encodeState(newStateFixture())) {
			return ErrCorrupt
		}
		return nil
	}); err != nil {
		t.Fatal("GENESIS_LATE_STATE_MUTATED")
	}
}

func TestGenesisIntentCreateCollisionAndUnknownRetainInode(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	fixture := []byte("owned foreign target")
	if os.WriteFile(path, fixture, 0600) != nil {
		t.Fatal("GENESIS_COLLISION_FIXTURE_FAILED")
	}
	if err := CreateNewGenesisIntent(path, genesisIntentFixture()); !errors.Is(err, ErrTargetExists) {
		t.Fatal("GENESIS_COLLISION_ACCEPTED")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, fixture) {
		t.Fatal("GENESIS_COLLISION_CHANGED_TARGET")
	}
	unknownPath := filepath.Join(privateDir(t), "unknown.db")
	fault := errors.New("owned create fault")
	err := createNewJournalWith(unknownPath, func(j *Journal) error { return j.initializeGenesisIntent(genesisIntentFixture()) }, func(stage newStateStage) error {
		if stage == newStateCommitted {
			return fault
		}
		return nil
	})
	if !errors.Is(err, ErrCreateUnknown) {
		t.Fatal("GENESIS_UNKNOWN_CLASSIFICATION")
	}
	before, err := os.ReadFile(unknownPath)
	if err != nil {
		t.Fatal("GENESIS_UNKNOWN_TARGET_REMOVED")
	}
	if err := CreateNewGenesisIntent(unknownPath, genesisIntentFixture()); !errors.Is(err, ErrTargetExists) {
		t.Fatal("GENESIS_UNKNOWN_RETRY_OVERWROTE")
	}
	after, err := os.ReadFile(unknownPath)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(before) {
		t.Fatal("GENESIS_UNKNOWN_RETRY_CHANGED_TARGET")
	}
	g, err := OpenExistingIntent(unknownPath)
	if err != nil || g.Close() != nil {
		t.Fatal("GENESIS_UNKNOWN_COMMITTED_INTENT_LOST")
	}
}

func TestGenesisIntentOversizeAndLockedNameReplacement(t *testing.T) {
	oversizePath := filepath.Join(privateDir(t), "oversize.db")
	oversize := genesisIntentFixture()
	oversize.SealedBytes = make([]byte, MaxProposalBytes+1)
	if err := CreateNewGenesisIntent(oversizePath, oversize); !errors.Is(err, ErrInvalid) {
		t.Fatal("GENESIS_OVERSIZE_ACCEPTED")
	}
	if _, err := os.Lstat(oversizePath); !os.IsNotExist(err) {
		t.Fatal("GENESIS_OVERSIZE_CREATED_TARGET")
	}
	path := filepath.Join(privateDir(t), "journal.db")
	if CreateNewGenesisIntent(path, genesisIntentFixture()) != nil {
		t.Fatal("GENESIS_REPLACEMENT_CREATE_FAILED")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("GENESIS_REPLACEMENT_READ_FAILED")
	}
	parked := filepath.Join(filepath.Dir(path), "parked.db")
	sentinel := []byte("owned replacement")
	mutated := false
	j, err := openExistingOnlyDatabaseKindWith(path, func() {
		mutated = os.Rename(path, parked) == nil && os.WriteFile(path, sentinel, 0600) == nil
	}, true)
	if !mutated || j != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("GENESIS_REPLACED_NAME_ACCEPTED")
	}
	old, oldErr := os.ReadFile(parked)
	newValue, newErr := os.ReadFile(path)
	if oldErr != nil || newErr != nil || !bytes.Equal(old, before) || !bytes.Equal(newValue, sentinel) {
		t.Fatal("GENESIS_REPLACEMENT_CHANGED_INODES")
	}
}
