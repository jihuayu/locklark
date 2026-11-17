//go:build darwin || linux || windows

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func existingFixture(t *testing.T, state bool, noFreelistSync bool) string {
	t.Helper()
	path := filepath.Join(privateDir(t), "journal.db")
	j, err := Open(path)
	if err != nil {
		t.Fatal("FIXTURE_OPEN_FAILED")
	}
	j.db.NoFreelistSync = noFreelistSync
	if state {
		if err := j.InitializeState(baseState()); err != nil {
			j.Close()
			t.Fatal("FIXTURE_STATE_FAILED")
		}
	} else {
		// Commit a valid bbolt file with no journal state. In no-freelist
		// mode a normal write-mode bolt.Open would otherwise repair it.
		if err := j.db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte("uninitialized"))
			return err
		}); err != nil {
			j.Close()
			t.Fatal("FIXTURE_EMPTY_STATE_FAILED")
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal("FIXTURE_CLOSE_FAILED")
	}
	return path
}

func existingBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("FIXTURE_READ_FAILED")
	}
	return raw
}

// The minimum real-file gate: an existing state/prepared pair survives an
// unchanged open, and later explicit commits remain durable across reopen.
func TestOpenExistingMinimum(t *testing.T) {
	path := existingFixture(t, true, false)
	j, err := Open(path)
	if err != nil {
		t.Fatal("PREPARE_OPEN_FAILED")
	}
	s := baseState()
	p := Proposal{Generation: 1, OperationID: "existing-resume", ExpectedRevision: s.RemoteRevision, Bytes: s.WorkingBytes}
	if err := j.Prepare(s.Generation, p); err != nil {
		j.Close()
		t.Fatal("PREPARE_FAILED")
	}
	if err := j.Close(); err != nil {
		t.Fatal("PREPARE_CLOSE_FAILED")
	}
	before := existingBytes(t, path)
	j, err = OpenExisting(path)
	if err != nil {
		t.Fatal("EXISTING_OPEN_FAILED")
	}
	got, err := j.LoadState()
	if err != nil || !sameState(got, s) {
		j.Close()
		t.Fatal("STATE_CHANGED_ON_OPEN")
	}
	prepared, err := j.LoadPrepared()
	if err != nil || !sameProposal(prepared.Proposal, p) || prepared.WorkingGeneration != s.Generation {
		j.Close()
		t.Fatal("PREPARED_CHANGED_ON_OPEN")
	}
	if err := j.Close(); err != nil {
		t.Fatal("EXISTING_CLOSE_FAILED")
	}
	if !bytes.Equal(before, existingBytes(t, path)) {
		t.Fatal("OPEN_WROTE_JOURNAL")
	}
	j, err = OpenExisting(path)
	if err != nil {
		t.Fatal("SECOND_EXISTING_OPEN_FAILED")
	}
	newWorking := opaque(300, 47)
	if err := j.UpdateWorking(s.Generation, newWorking); err != nil {
		j.Close()
		t.Fatal("EXPLICIT_UPDATE_FAILED")
	}
	if err := j.Close(); err != nil {
		t.Fatal("EXPLICIT_CLOSE_FAILED")
	}
	j, err = OpenExisting(path)
	if err != nil {
		t.Fatal("DURABLE_REOPEN_FAILED")
	}
	defer j.Close()
	got, err = j.LoadState()
	if err != nil || !bytes.Equal(got.WorkingBytes, newWorking) || got.Generation != s.Generation+1 {
		t.Fatal("EXPLICIT_UPDATE_NOT_DURABLE")
	}
}

func TestOpenExistingDoesNotRepairFreelist(t *testing.T) {
	for _, state := range []bool{true, false} {
		name := "STATE_ABSENT"
		if state {
			name = "STATE_PRESENT"
		}
		t.Run(name, func(t *testing.T) {
			path := existingFixture(t, state, true)
			before := existingBytes(t, path)
			j, err := OpenExisting(path)
			if state {
				if err != nil || j == nil {
					t.Fatal("EXISTING_OPEN_FAILED")
				}
				if err := j.Close(); err != nil {
					t.Fatal("EXISTING_CLOSE_FAILED")
				}
			} else if j != nil || !errors.Is(err, ErrEmpty) {
				t.Fatal("MISSING_STATE_NOT_REFUSED")
			}
			if !bytes.Equal(before, existingBytes(t, path)) {
				t.Fatal("OPEN_REPAIRED_FREELIST")
			}
		})
	}
}

func TestOpenExistingRefusesMissingEmptyCorrupt(t *testing.T) {
	t.Run("MISSING", func(t *testing.T) {
		path := filepath.Join(privateDir(t), "missing.db")
		j, err := OpenExisting(path)
		if j != nil || err == nil {
			t.Fatal("MISSING_JOURNAL_NOT_REFUSED")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("MISSING_JOURNAL_CREATED")
		}
	})
	for _, contents := range [][]byte{nil, []byte("not-a-journal")} {
		name := "CORRUPT_FILE"
		if len(contents) == 0 {
			name = "ZERO_LENGTH"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "journal.db")
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal("INVALID_FIXTURE_CREATE_FAILED")
			}
			j, err := OpenExisting(path)
			if j != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("INVALID_JOURNAL_NOT_REFUSED")
			}
			if !bytes.Equal(contents, existingBytes(t, path)) {
				t.Fatal("INVALID_JOURNAL_CHANGED")
			}
		})
	}
	t.Run("CORRUPT_STATE", func(t *testing.T) {
		path := existingFixture(t, true, true)
		j, err := Open(path)
		if err != nil {
			t.Fatal("CORRUPT_FIXTURE_OPEN_FAILED")
		}
		j.db.NoFreelistSync = true
		writeRawState(t, j, []byte("invalid-state"))
		if j.Close() != nil {
			t.Fatal("CORRUPT_FIXTURE_CLOSE_FAILED")
		}
		before := existingBytes(t, path)
		j, err = OpenExisting(path)
		if j != nil || !errors.Is(err, ErrCorrupt) {
			t.Fatal("CORRUPT_STATE_NOT_REFUSED")
		}
		if !bytes.Equal(before, existingBytes(t, path)) {
			t.Fatal("CORRUPT_STATE_REPAIRED")
		}
	})
}
