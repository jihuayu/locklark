//go:build darwin || linux

package vaultfilebackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

type existingTreeEntry struct {
	mode   fs.FileMode
	digest [sha256.Size]byte
	link   string
}

func existingTree(t *testing.T, root string) map[string]existingTreeEntry {
	t.Helper()
	entries := make(map[string]existingTreeEntry)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		key, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		item := existingTreeEntry{mode: info.Mode()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.digest = sha256.Sum256(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			item.link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		entries[key] = item
		return nil
	})
	if err != nil {
		t.Fatal("TREE_INSPECTION_FAILED")
	}
	return entries
}

func existingDirFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "backend")
	dir, err := OpenDir(root)
	if err != nil {
		t.Fatal("DIRECTORY_FIXTURE_OPEN_FAILED")
	}
	if err := dir.CreateIfAbsent(context.Background(), "vault", []byte("existing-value")); err != nil {
		dir.Close()
		t.Fatal("DIRECTORY_FIXTURE_WRITE_FAILED")
	}
	if dir.Close() != nil {
		t.Fatal("DIRECTORY_FIXTURE_CLOSE_FAILED")
	}
	return root
}

func TestOpenExistingDirMinimum(t *testing.T) {
	root := existingDirFixture(t)
	before := existingTree(t, root)
	dir, err := OpenExistingDir(root)
	if err != nil {
		t.Fatal("EXISTING_DIRECTORY_OPEN_FAILED")
	}
	if dir.Close() != nil {
		t.Fatal("EXISTING_DIRECTORY_CLOSE_FAILED")
	}
	if !maps.Equal(before, existingTree(t, root)) {
		t.Fatal("DIRECTORY_OPEN_CHANGED_DISK")
	}
	dir, err = OpenExistingDir(root)
	if err != nil {
		t.Fatal("EXISTING_DIRECTORY_REOPEN_FAILED")
	}
	read, err := dir.Read(context.Background(), "vault")
	if err != nil || !bytes.Equal(read.Bytes, []byte("existing-value")) {
		dir.Close()
		t.Fatal("EXISTING_VALUE_READ_FAILED")
	}
	if err := dir.ReplaceIfVersion(context.Background(), "vault", read.Revision, []byte("explicit-cas")); err != nil {
		dir.Close()
		t.Fatal("EXPLICIT_CAS_FAILED")
	}
	if dir.Close() != nil {
		t.Fatal("CAS_CLOSE_FAILED")
	}
	dir, err = OpenExistingDir(root)
	if err != nil {
		t.Fatal("CAS_REOPEN_FAILED")
	}
	defer dir.Close()
	read, err = dir.Read(context.Background(), "vault")
	if err != nil || !bytes.Equal(read.Bytes, []byte("explicit-cas")) {
		t.Fatal("EXPLICIT_CAS_NOT_DURABLE")
	}
}

func TestOpenExistingDirMissingResources(t *testing.T) {
	for _, name := range []string{"ROOT", "NAMESPACE", "VERSION", "TMP", "DATA", "LOCK"} {
		t.Run(name, func(t *testing.T) {
			root := existingDirFixture(t)
			base := filepath.Join(root, dirSubdir, dirVer)
			missing := map[string]string{
				"ROOT": root, "NAMESPACE": filepath.Join(root, dirSubdir), "VERSION": base,
				"TMP": filepath.Join(base, tmpName), "DATA": filepath.Join(base, dataName), "LOCK": filepath.Join(base, lockName),
			}[name]
			if os.RemoveAll(missing) != nil {
				t.Fatal("MISSING_RESOURCE_FIXTURE_FAILED")
			}
			before := existingTree(t, root)
			dir, err := OpenExistingDir(root)
			if dir != nil || err == nil {
				t.Fatal("MISSING_RESOURCE_NOT_REFUSED")
			}
			if !maps.Equal(before, existingTree(t, root)) {
				t.Fatal("MISSING_RESOURCE_WAS_CREATED")
			}
		})
	}
}

func TestOpenExistingDirDoesNotResolveOrRepair(t *testing.T) {
	for _, name := range []string{"STALE_HOLDER", "ORPHAN_TEMP", "MALFORMED_TICKET"} {
		t.Run(name, func(t *testing.T) {
			root := existingDirFixture(t)
			base := filepath.Join(root, dirSubdir, dirVer)
			id := "00112233445566778899aabbccddeeff"
			if name != "MALFORMED_TICKET" {
				if os.WriteFile(filepath.Join(base, tmpName, "op-"+id), []byte("staged"), 0600) != nil {
					t.Fatal("TEMP_FIXTURE_FAILED")
				}
			}
			if name == "STALE_HOLDER" {
				if os.WriteFile(filepath.Join(base, lockName), []byte(ticketHolder+" "+id+"\n"), 0600) != nil {
					t.Fatal("HOLDER_FIXTURE_FAILED")
				}
			} else if name == "MALFORMED_TICKET" {
				if os.WriteFile(filepath.Join(base, lockName), []byte("not-a-ticket"), 0600) != nil {
					t.Fatal("TICKET_FIXTURE_FAILED")
				}
			}
			before := existingTree(t, root)
			dir, err := OpenExistingDir(root)
			if err != nil {
				t.Fatal("NONMUTATING_OPEN_FAILED")
			}
			if dir.Close() != nil {
				t.Fatal("NONMUTATING_CLOSE_FAILED")
			}
			if !maps.Equal(before, existingTree(t, root)) {
				t.Fatal("OPEN_RESOLVED_OR_REPAIRED")
			}
		})
	}
}

func TestOpenExistingDirUnsafeResources(t *testing.T) {
	for _, name := range []string{"SYMLINK_ROOT", "SHARED_NAMESPACE", "SYMLINK_LOCK", "HARDLINK_LOCK", "SHARED_LOCK"} {
		t.Run(name, func(t *testing.T) {
			root := existingDirFixture(t)
			argument := root
			base := filepath.Join(root, dirSubdir, dirVer)
			lock := filepath.Join(base, lockName)
			switch name {
			case "SYMLINK_ROOT":
				argument = filepath.Join(filepath.Dir(root), "alias")
				if os.Symlink(root, argument) != nil {
					t.Fatal("ROOT_ALIAS_FIXTURE_FAILED")
				}
			case "SHARED_NAMESPACE":
				if os.Chmod(filepath.Join(root, dirSubdir), 0755) != nil {
					t.Fatal("NAMESPACE_MODE_FIXTURE_FAILED")
				}
			case "SYMLINK_LOCK":
				parked := filepath.Join(filepath.Dir(root), "parked-lock")
				if os.Rename(lock, parked) != nil || os.Symlink(parked, lock) != nil {
					t.Fatal("LOCK_ALIAS_FIXTURE_FAILED")
				}
			case "HARDLINK_LOCK":
				if os.Link(lock, filepath.Join(filepath.Dir(root), "linked-lock")) != nil {
					t.Fatal("LOCK_LINK_FIXTURE_FAILED")
				}
			case "SHARED_LOCK":
				if os.Chmod(lock, 0644) != nil {
					t.Fatal("LOCK_MODE_FIXTURE_FAILED")
				}
			}
			before := existingTree(t, filepath.Dir(root))
			dir, err := OpenExistingDir(argument)
			if dir != nil || err == nil {
				t.Fatal("UNSAFE_RESOURCE_NOT_REFUSED")
			}
			if !maps.Equal(before, existingTree(t, filepath.Dir(root))) {
				t.Fatal("UNSAFE_RESOURCE_REPAIRED")
			}
		})
	}
}
