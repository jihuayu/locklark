//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenExistingUnsafeUnix(t *testing.T) {
	for _, name := range []string{"SYMLINK", "HARDLINK", "SHARED_FILE", "SHARED_PARENT", "FIFO", "DIRECTORY"} {
		t.Run(name, func(t *testing.T) {
			path := existingFixture(t, true, false)
			before := existingBytes(t, path)
			argument := path
			switch name {
			case "SYMLINK":
				argument = filepath.Join(filepath.Dir(path), "alias")
				if os.Symlink(path, argument) != nil {
					t.Fatal("SYMLINK_FIXTURE_FAILED")
				}
			case "HARDLINK":
				if os.Link(path, filepath.Join(filepath.Dir(path), "alias")) != nil {
					t.Fatal("HARDLINK_FIXTURE_FAILED")
				}
			case "SHARED_FILE":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("MODE_FIXTURE_FAILED")
				}
			case "SHARED_PARENT":
				if os.Chmod(filepath.Dir(path), 0755) != nil {
					t.Fatal("PARENT_FIXTURE_FAILED")
				}
			case "FIFO":
				argument = filepath.Join(filepath.Dir(path), "fifo")
				if unix.Mkfifo(argument, 0600) != nil {
					t.Fatal("FIFO_FIXTURE_FAILED")
				}
			case "DIRECTORY":
				argument = filepath.Join(filepath.Dir(path), "directory")
				if os.Mkdir(argument, 0700) != nil {
					t.Fatal("DIRECTORY_FIXTURE_FAILED")
				}
			}
			j, err := OpenExisting(argument)
			if j != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("UNSAFE_JOURNAL_NOT_REFUSED")
			}
			if !bytes.Equal(before, existingBytes(t, path)) {
				t.Fatal("UNSAFE_JOURNAL_CHANGED")
			}
		})
	}
}

func TestOpenExistingChecksLockedIdentity(t *testing.T) {
	for _, name := range []string{"REPLACED", "REMOVED", "SYMLINKED", "TRUNCATED"} {
		t.Run(name, func(t *testing.T) {
			path := existingFixture(t, true, true)
			original := existingBytes(t, path)
			replacement := existingFixture(t, true, true)
			replacementBytes := existingBytes(t, replacement)
			parked := filepath.Join(filepath.Dir(path), "parked.db")
			mutationOK := true
			j, err := openExistingOnlyDatabaseWith(path, func() {
				if name == "TRUNCATED" {
					mutationOK = os.Truncate(path, 0) == nil
					return
				}
				if os.Rename(path, parked) != nil {
					mutationOK = false
					return
				}
				switch name {
				case "REPLACED":
					mutationOK = os.Rename(replacement, path) == nil
				case "SYMLINKED":
					mutationOK = os.Symlink(replacement, path) == nil
				}
			})
			if !mutationOK {
				t.Fatal("IDENTITY_FIXTURE_MUTATION_FAILED")
			}
			if j != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("CHANGED_IDENTITY_NOT_REFUSED")
			}
			if name == "TRUNCATED" {
				if len(existingBytes(t, path)) != 0 {
					t.Fatal("ZERO_FILE_INITIALIZED")
				}
				return
			}
			if !bytes.Equal(original, existingBytes(t, parked)) {
				t.Fatal("HELD_INODE_WAS_REPAIRED")
			}
			if name == "REMOVED" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("REMOVED_JOURNAL_RECREATED")
				}
			} else if !bytes.Equal(replacementBytes, existingBytes(t, path)) {
				t.Fatal("REPLACEMENT_WAS_CHANGED")
			}
		})
	}
}
