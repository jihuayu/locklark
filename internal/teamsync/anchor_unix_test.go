//go:build unix

package teamsync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

func TestFileAnchorPublishDirectorySyncFailureKeepsCompleteFinal(t *testing.T) {
	parent := t.TempDir()
	tmp, path := filepath.Join(parent, "staged.db"), filepath.Join(parent, "anchor.db")
	cp := directory.Checkpoint{Scope: strings.Repeat("a", 64), Version: 2, Hash: strings.Repeat("b", 64)}
	if _, err := CreateFileAnchorStore(tmp, cp); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory sync failure")
	if err := publishAnchorFileWithSync(tmp, path, func(*os.File) error { return injected }); !errors.Is(err, injected) {
		t.Fatal("directory sync failure was ignored")
	}
	store, err := OpenFileAnchorStore(path)
	if err != nil {
		t.Fatal("sync failure left an incomplete final file")
	}
	loaded, err := store.Load()
	if err != nil || loaded != cp {
		t.Fatal("sync failure changed the complete published checkpoint")
	}
	if _, err := CreateFileAnchorStore(path, cp); !errors.Is(err, ErrAnchor) {
		t.Fatal("published final was adopted after sync failure")
	}
	called := false
	if err := publishAnchorFileWithSync(tmp, path, func(*os.File) error { called = true; return nil }); err == nil || called {
		t.Fatal("existing final was replaced or synced as a new publication")
	}
}

func TestFileAnchorCreateRefusesSymlinkFinalAndUnsafeParent(t *testing.T) {
	parent := t.TempDir()
	target, path := filepath.Join(parent, "target"), filepath.Join(parent, "anchor.db")
	if os.WriteFile(target, []byte("untouched"), 0600) != nil || os.Symlink(target, path) != nil {
		t.Fatal("symlink setup failed")
	}
	cp := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
	if _, err := CreateFileAnchorStore(path, cp); !errors.Is(err, ErrAnchor) {
		t.Fatal("symlink final accepted")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "untouched" {
		t.Fatal("symlink target changed")
	}
	if st, err := os.Lstat(path); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink final was replaced")
	}
	if os.Chmod(parent, 0777) != nil {
		t.Fatal("unsafe parent setup failed")
	}
	if _, err := CreateFileAnchorStore(filepath.Join(parent, "other.db"), cp); !errors.Is(err, ErrAnchor) {
		t.Fatal("untrusted parent accepted")
	}
}
