package teamsync

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

func TestFileAnchorCreateInitializationFailureNeverPublishes(t *testing.T) {
	for _, phase := range []string{"before-write", "partial-write", "after-initialization"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			if os.Chmod(parent, 0700) != nil {
				t.Fatal("private parent setup failed")
			}
			path := filepath.Join(parent, "anchor.db")
			cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
			injected := errors.New("injected initialization failure")
			store, err := createFileAnchorStore(path, cp, func(name string, initial directory.Checkpoint) error {
				if phase == "partial-write" {
					if os.WriteFile(name, []byte("partial private anchor"), 0600) != nil {
						t.Fatal("partial initialization setup failed")
					}
				}
				if phase == "after-initialization" && initializeFileAnchor(name, initial) != nil {
					t.Fatal("complete initialization setup failed")
				}
				return injected
			})
			if store != nil || !errors.Is(err, ErrAnchor) {
				t.Fatal("failed initialization returned a store")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("failed initialization published a final anchor")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed initialization retained an owned temporary file")
			}
		})
	}
}

func TestFileAnchorCreateExistingFilesRemainUntouched(t *testing.T) {
	for _, contents := range [][]byte{nil, []byte("malformed anchor")} {
		t.Run(fmt.Sprintf("size-%d", len(contents)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.db")
			if os.WriteFile(path, contents, 0600) != nil {
				t.Fatal("existing file setup failed")
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
			if store, err := CreateFileAnchorStore(path, cp); store != nil || !errors.Is(err, ErrAnchor) {
				t.Fatal("existing file adopted as an anchor")
			}
			after, err := os.Lstat(path)
			raw, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(raw, contents) {
				t.Fatal("existing anchor file changed")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("existing-file refusal left temporary files")
			}
		})
	}
}

func TestFileAnchorCreateRejectsIncompleteOrDifferentStagedCheckpoint(t *testing.T) {
	for _, phase := range []string{"empty", "different-checkpoint"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.db")
			cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
			store, err := createFileAnchorStore(path, cp, func(tmp string, _ directory.Checkpoint) error {
				if phase == "different-checkpoint" {
					return initializeFileAnchor(tmp, directory.Checkpoint{Scope: strings.Repeat("b", 64)})
				}
				return nil
			})
			if store != nil || !errors.Is(err, ErrAnchor) {
				t.Fatal("incomplete or different checkpoint was published")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected staged checkpoint retained temporary or final files")
			}
		})
	}
}

func TestFileAnchorCreateStagesCompleteCheckpointBeforePublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.db")
	cp := directory.Checkpoint{Scope: strings.Repeat("a", 64), Version: 7, Hash: strings.Repeat("b", 64)}
	store, err := createFileAnchorStore(path, cp, func(tmp string, initial directory.Checkpoint) error {
		if tmp == path || filepath.Dir(tmp) != filepath.Dir(path) {
			return errors.New("anchor did not stage in the publication directory")
		}
		if err := initializeFileAnchor(tmp, initial); err != nil {
			return err
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("anchor final name exists before publication")
		}
		staged, err := OpenFileAnchorStore(tmp)
		if err != nil {
			return err
		}
		loaded, err := staged.Load()
		if err != nil || loaded != initial {
			return errors.New("staged checkpoint incomplete")
		}
		return nil
	})
	if err != nil || store == nil {
		t.Fatal("complete anchor publication failed")
	}
	reopened, err := OpenFileAnchorStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load()
	if err != nil || loaded != cp {
		t.Fatal("published anchor checkpoint is incomplete")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("successful publication retained a temporary file")
	}
}

func TestFileAnchorCreateConcurrentPublishHasOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.db")
	const count = 12
	var workers sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, count)
	checkpoints := make([]directory.Checkpoint, count)
	for i := range checkpoints {
		checkpoints[i] = directory.Checkpoint{Scope: strings.Repeat("a", 64), Version: 1, Hash: fmt.Sprintf("%064x", i+1)}
		workers.Add(1)
		go func(i int) { defer workers.Done(); <-start; _, errs[i] = CreateFileAnchorStore(path, checkpoints[i]) }(i)
	}
	close(start)
	workers.Wait()
	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner >= 0 {
				t.Fatal("multiple creators published")
			}
			winner = i
		} else if !errors.Is(err, ErrAnchor) {
			t.Fatal("unexpected creation failure")
		}
	}
	if winner < 0 {
		t.Fatal("no creator published")
	}
	store, err := OpenFileAnchorStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded != checkpoints[winner] {
		t.Fatal("published checkpoint differs from sole winner")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("concurrent creators retained temporary files")
	}
}

func TestFileAnchorCreateLosingPublishPreservesRacingFinal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.db")
	cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
	contents := []byte("another creator owns this final name")
	store, err := createFileAnchorStore(path, cp, func(tmp string, initial directory.Checkpoint) error {
		if err := initializeFileAnchor(tmp, initial); err != nil {
			return err
		}
		return os.WriteFile(path, contents, 0600)
	})
	if store != nil || !errors.Is(err, ErrAnchor) {
		t.Fatal("racing final name was overwritten")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, contents) {
		t.Fatal("racing final file changed")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("losing publisher retained its temporary file")
	}
}

func TestFileAnchorCreateCleanupPreservesReplacedTemporaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.db")
	cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
	contents := []byte("replacement file is not the creator's temporary file")
	var replaced string
	store, err := createFileAnchorStore(path, cp, func(tmp string, _ directory.Checkpoint) error {
		replaced = tmp
		if err := os.Rename(tmp, tmp+"-moved"); err != nil {
			return err
		}
		if err := os.WriteFile(tmp, contents, 0600); err != nil {
			return err
		}
		return errors.New("injected initialization failure after replacement")
	})
	if store != nil || !errors.Is(err, ErrAnchor) {
		t.Fatal("replaced temporary file accepted")
	}
	raw, err := os.ReadFile(replaced)
	if err != nil || !bytes.Equal(raw, contents) {
		t.Fatal("cleanup removed or changed another file")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed initialization published a final name")
	}
}
