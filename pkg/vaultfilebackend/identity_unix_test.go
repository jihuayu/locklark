//go:build darwin || linux

package vaultfilebackend

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func newIdentityBackend(t *testing.T, root string) *Dir {
	t.Helper()
	backend, err := OpenDir(root)
	if err != nil {
		t.Fatal("IDENTITY_BACKEND_OPEN_FAILED")
	}
	if err := backend.CreateIfAbsent(context.Background(), "protected", []byte("sealed-target")); err != nil {
		_ = backend.Close()
		t.Fatal("IDENTITY_BACKEND_CREATE_FAILED")
	}
	return backend
}

func copyIdentityRoot(t *testing.T, src, dst string) {
	t.Helper()
	if err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(target, info.Mode().Perm())
	}); err != nil {
		t.Fatal("IDENTITY_BACKEND_COPY_FAILED")
	}
}

func TestDirStableIdentityReopenAndCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "backend")
	first := newIdentityBackend(t, root)
	identity, err := first.StableIdentity()
	if err != nil {
		_ = first.Close()
		t.Fatal("IDENTITY_BACKEND_FIRST_FAILED")
	}
	if err := first.Close(); err != nil {
		t.Fatal("IDENTITY_BACKEND_FIRST_CLOSE_FAILED")
	}
	reopened, err := OpenExistingDir(root)
	if err != nil {
		t.Fatal("IDENTITY_BACKEND_REOPEN_FAILED")
	}
	again, err := reopened.StableIdentity()
	if err != nil || again != identity {
		_ = reopened.Close()
		t.Fatal("IDENTITY_BACKEND_REOPEN_CHANGED")
	}
	read, readErr := reopened.Read(context.Background(), "protected")
	closeErr := reopened.Close()
	defer clear(read.Bytes)
	if readErr != nil || closeErr != nil || !bytes.Equal(read.Bytes, []byte("sealed-target")) {
		t.Fatal("IDENTITY_BACKEND_REOPEN_CONTENT_FAILED")
	}

	copyRoot := filepath.Join(t.TempDir(), "backend-copy")
	copyIdentityRoot(t, root, copyRoot)
	copied, err := OpenExistingDir(copyRoot)
	if err != nil {
		t.Fatal("IDENTITY_BACKEND_COPY_OPEN_FAILED")
	}
	copiedIdentity, err := copied.StableIdentity()
	copiedRead, copiedReadErr := copied.Read(context.Background(), "protected")
	closeErr = copied.Close()
	defer clear(copiedRead.Bytes)
	if err != nil || copiedIdentity == identity ||
		copiedReadErr != nil || !bytes.Equal(copiedRead.Bytes, read.Bytes) ||
		copiedRead.Revision != read.Revision || closeErr != nil {
		t.Fatal("IDENTITY_BACKEND_COPY_NOT_DISTINGUISHED")
	}
}

func TestDirStableIdentityRejectsSamePathReplacement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "backend")
	original := newIdentityBackend(t, root)
	identity, err := original.StableIdentity()
	if err != nil {
		_ = original.Close()
		t.Fatal("IDENTITY_BACKEND_ORIGINAL_FAILED")
	}
	if err := original.Close(); err != nil {
		t.Fatal("IDENTITY_BACKEND_ORIGINAL_CLOSE_FAILED")
	}
	copyRoot := filepath.Join(t.TempDir(), "backend-copy")
	copyIdentityRoot(t, root, copyRoot)
	moved := filepath.Join(t.TempDir(), "backend-original")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal("IDENTITY_BACKEND_MOVE_FAILED")
	}
	if err := os.Rename(copyRoot, root); err != nil {
		t.Fatal("IDENTITY_BACKEND_REPLACE_FAILED")
	}
	replacement, err := OpenExistingDir(root)
	if err != nil {
		t.Fatal("IDENTITY_BACKEND_REPLACEMENT_OPEN_FAILED")
	}
	replacementIdentity, err := replacement.StableIdentity()
	read, readErr := replacement.Read(context.Background(), "protected")
	closeErr := replacement.Close()
	defer clear(read.Bytes)
	if err != nil || replacementIdentity == identity ||
		readErr != nil || !bytes.Equal(read.Bytes, []byte("sealed-target")) || closeErr != nil {
		t.Fatal("IDENTITY_BACKEND_SAME_PATH_REPLACEMENT_ACCEPTED")
	}
}

func TestDirStableIdentityClosedFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "backend")
	backend := newIdentityBackend(t, root)
	if err := backend.Close(); err != nil {
		t.Fatal("IDENTITY_BACKEND_CLOSE_FAILED")
	}
	if _, err := backend.StableIdentity(); !errors.Is(err, ErrDenied) {
		t.Fatal("IDENTITY_BACKEND_CLOSED_ACCEPTED")
	}
}
