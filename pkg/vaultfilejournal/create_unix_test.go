//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newStateFixture() State {
	return State{BaseBytes: []byte("owned sealed base"), WorkingBytes: []byte("owned sealed base"), RemoteRevision: "owned-revision"}
}

func TestCreateNewStateMinimum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	s := newStateFixture()
	if CreateNewState(path, s) != nil {
		t.Fatal("CREATE_NEW_STATE_FAILED")
	}
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("CREATE_NEW_STATE_REOPEN_FAILED")
	}
	got, err := j.LoadState()
	if err != nil || got.Generation != 0 || got.RemoteRevision != s.RemoteRevision || !bytes.Equal(got.BaseBytes, s.BaseBytes) || !bytes.Equal(got.WorkingBytes, s.WorkingBytes) {
		t.Fatal("CREATE_NEW_STATE_MISMATCH")
	}
	if _, err := j.Load(); err != ErrEmpty {
		t.Fatal("CREATE_NEW_STATE_HAS_LEGACY")
	}
	if _, err := j.LoadPrepared(); err != ErrEmpty || j.Close() != nil {
		t.Fatal("CREATE_NEW_STATE_HAS_PREPARED")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("CREATE_NEW_STATE_MODE_MISMATCH")
	}
}

func TestCreateNewStateRefusals(t *testing.T) {
	for _, name := range []string{"EXISTING_EMPTY", "EXISTING_CORRUPT", "EXISTING_EDIT", "INVALID_STATE", "MISSING_PARENT", "SHARED_PARENT"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "journal.db")
			state := newStateFixture()
			want := ErrTargetExists
			switch name {
			case "EXISTING_EMPTY", "EXISTING_CORRUPT":
				data := []byte{}
				if name == "EXISTING_CORRUPT" {
					data = []byte("owned corrupt file")
				}
				if os.WriteFile(path, data, 0600) != nil {
					t.Fatal("CREATE_REFUSAL_FIXTURE_FAILED")
				}
			case "EXISTING_EDIT":
				j, err := Open(path)
				if err != nil || j.InitializeEmptyState(state) != nil || j.UpdateWorking(0, []byte("owned newer working")) != nil || j.Close() != nil {
					t.Fatal("CREATE_EDIT_FIXTURE_FAILED")
				}
			case "INVALID_STATE":
				state.WorkingBytes, want = []byte("different"), ErrInvalid
			case "MISSING_PARENT":
				path, want = filepath.Join(root, "missing", "journal.db"), ErrInvalid
			case "SHARED_PARENT":
				parent := filepath.Join(root, "shared")
				if os.Mkdir(parent, 0700) != nil || os.Chmod(parent, 0755) != nil {
					t.Fatal("CREATE_PARENT_FIXTURE_FAILED")
				}
				path, want = filepath.Join(parent, "journal.db"), ErrInvalid
			}
			before, beforeErr := os.ReadFile(path)
			if CreateNewState(path, state) != want {
				t.Fatal("CREATE_REFUSAL_CLASSIFICATION_FAILED")
			}
			after, afterErr := os.ReadFile(path)
			if beforeErr == nil && (afterErr != nil || !bytes.Equal(before, after)) || os.IsNotExist(beforeErr) && !os.IsNotExist(afterErr) {
				t.Fatal("CREATE_REFUSAL_CHANGED_TARGET")
			}
		})
	}
}

func TestCreateNewStateParentBinding(t *testing.T) {
	for _, stage := range []newStateStage{newStateParentBound, newStateFileCreated, newStateDatabaseLocked, newStateCommitted, newStateBeforeParentSync} {
		t.Run([]string{"PARENT_BOUND", "FILE_CREATED", "DATABASE_LOCKED", "COMMITTED", "BEFORE_PARENT_SYNC"}[int(stage)], func(t *testing.T) {
			root := t.TempDir()
			parent, moved := filepath.Join(root, "parent"), filepath.Join(root, "moved")
			if os.Mkdir(parent, 0700) != nil {
				t.Fatal("PARENT_BINDING_FIXTURE_FAILED")
			}
			path := filepath.Join(parent, "journal.db")
			sentinel := []byte("owned replacement target")
			called := false
			err := createNewStateWith(path, newStateFixture(), func(at newStateStage) error {
				if at == stage {
					called = true
					if os.Rename(parent, moved) != nil || os.Mkdir(parent, 0700) != nil || os.WriteFile(path, sentinel, 0600) != nil {
						t.Fatal("PARENT_SWAP_FIXTURE_FAILED")
					}
				}
				return nil
			})
			want := ErrCreateUnknown
			if stage == newStateParentBound {
				want = ErrInvalid
			}
			if !called || err != want {
				t.Fatal("PARENT_SWAP_CLASSIFICATION_FAILED")
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, sentinel) {
				t.Fatal("PARENT_SWAP_TOUCHED_REPLACEMENT")
			}
			_, err = os.Lstat(filepath.Join(moved, "journal.db"))
			if stage == newStateParentBound && !os.IsNotExist(err) || stage != newStateParentBound && err != nil {
				t.Fatal("PARENT_FD_CREATE_BINDING_FAILED")
			}
		})
	}
}

func TestCreateNewStateUnknownPreservesTarget(t *testing.T) {
	for _, stage := range []newStateStage{newStateFileCreated, newStateDatabaseLocked, newStateCommitted, newStateBeforeParentSync, newStateDatabaseClosed} {
		t.Run([]string{"FILE_CREATED", "DATABASE_LOCKED", "COMMITTED", "BEFORE_PARENT_SYNC", "DATABASE_CLOSED"}[int(stage)-1], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.db")
			fault := errors.New("owned negative stage failure")
			err := createNewStateWith(path, newStateFixture(), func(at newStateStage) error {
				if at == stage {
					return fault
				}
				return nil
			})
			if err != ErrCreateUnknown {
				t.Fatal("CREATE_UNKNOWN_WAS_NOT_PRESERVED")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("CREATE_UNKNOWN_DELETED_TARGET")
			}
			digest := sha256.Sum256(before)
			if CreateNewState(path, newStateFixture()) != ErrTargetExists {
				t.Fatal("CREATE_UNKNOWN_WAS_REINITIALIZED")
			}
			after, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(after) != digest {
				t.Fatal("CREATE_UNKNOWN_RETRY_CHANGED_TARGET")
			}
			if stage >= newStateCommitted {
				j, err := OpenExisting(path)
				if err != nil || j.Close() != nil {
					t.Fatal("CREATE_UNKNOWN_COMMITTED_STATE_LOST")
				}
			}
		})
	}
}
