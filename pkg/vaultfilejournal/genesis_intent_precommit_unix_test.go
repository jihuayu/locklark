//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// A precommit failure reserves the inode even if no journal marker was
// written. Neither legacy Open nor intent reopening may initialize it later.
func TestGenesisPrecommitUnknownInodeCannotBeTakenOver(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage newStateStage
	}{
		{"file-created", newStateFileCreated},
		{"database-locked", newStateDatabaseLocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "journal.db")
			intent := genesisIntentFixture()
			fault := errors.New("owned precommit fault")
			reached := false
			err := createNewJournalWith(path, func(j *Journal) error {
				return j.initializeGenesisIntent(intent)
			}, func(at newStateStage) error {
				if at == tc.stage {
					reached = true
					return fault
				}
				return nil
			})
			if !reached || !errors.Is(err, ErrCreateUnknown) {
				t.Fatal("PRECOMMIT_UNKNOWN_NOT_REACHED")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("PRECOMMIT_INODE_MISSING")
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("PRECOMMIT_INODE_INVALID")
			}
			if tc.stage == newStateFileCreated && len(before) != 0 || tc.stage == newStateDatabaseLocked && len(before) == 0 {
				t.Fatal("PRECOMMIT_STAGE_SHAPE_INVALID")
			}
			assertRetained := func() {
				t.Helper()
				after, err := os.ReadFile(path)
				current, statErr := os.Lstat(path)
				if err != nil || statErr != nil || !os.SameFile(info, current) || !bytes.Equal(before, after) {
					t.Fatal("PRECOMMIT_INODE_CHANGED")
				}
			}
			if j, err := Open(path); j != nil || !errors.Is(err, ErrInvalid) {
				if j != nil {
					_ = j.Close()
				}
				t.Fatal("PRECOMMIT_LEGACY_OPEN_ACCEPTED")
			}
			assertRetained()
			if g, err := OpenExistingIntent(path); g != nil || err == nil {
				if g != nil {
					_ = g.Close()
				}
				t.Fatal("PRECOMMIT_INTENT_REOPEN_ACCEPTED")
			}
			assertRetained()
			if err := CreateNewGenesisIntent(path, intent); !errors.Is(err, ErrTargetExists) {
				t.Fatal("PRECOMMIT_CREATE_COLLISION_MISCLASSIFIED")
			}
			assertRetained()
		})
	}
}

func TestJournalOpenCloseCreatesEmptyNamespace(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	j, err := Open(path)
	if err != nil {
		t.Fatal("JOURNAL_NEW_OPEN_FAILED")
	}
	if err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil || b.Stats().KeyN != 0 {
			return ErrInvalid
		}
		return nil
	}); err != nil || j.Close() != nil {
		t.Fatal("JOURNAL_NEW_NAMESPACE_MISSING")
	}
	j, err = Open(path)
	if err != nil {
		t.Fatal("JOURNAL_EMPTY_REOPEN_FAILED")
	}
	if _, err := j.Load(); !errors.Is(err, ErrEmpty) {
		t.Fatal("JOURNAL_EMPTY_REOPEN_CHANGED")
	}
	if err := j.InitializeEmptyState(newStateFixture()); err != nil || j.Close() != nil {
		t.Fatal("JOURNAL_EMPTY_STATE_INIT_FAILED")
	}
	j, err = OpenExisting(path)
	if err != nil || j.Close() != nil {
		t.Fatal("JOURNAL_STATE_REOPEN_FAILED")
	}
}

func TestBareBoltWithoutJournalNamespaceIsRefused(t *testing.T) {
	path := filepath.Join(privateDir(t), "journal.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil || db.Close() != nil {
		t.Fatal("BARE_BOLT_FIXTURE_FAILED")
	}
	before, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || len(before) == 0 {
		t.Fatal("BARE_BOLT_FIXTURE_INVALID")
	}
	if j, err := Open(path); j != nil || !errors.Is(err, ErrInvalid) {
		if j != nil {
			_ = j.Close()
		}
		t.Fatal("BARE_BOLT_LEGACY_OPEN_ACCEPTED")
	}
	after, err := os.ReadFile(path)
	current, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, current) || !bytes.Equal(before, after) {
		t.Fatal("BARE_BOLT_REFUSAL_CHANGED_INODE")
	}
	db, err = bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal("BARE_BOLT_REOPEN_FAILED")
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte(bucketName)); return err }); err != nil || db.Close() != nil {
		t.Fatal("BARE_BOLT_NAMESPACE_FIXTURE_FAILED")
	}
	j, err := Open(path)
	if err != nil || j.Close() != nil {
		t.Fatal("BARE_BOLT_VALID_EMPTY_NAMESPACE_REFUSED")
	}
}
