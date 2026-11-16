//go:build !windows

package main

// Unix creation and verification of the passkey-transfer fixture files.
//
// Unix expresses privacy with an owner-only mode, so a normal write plus an
// explicit chmod is enough: 0600 is the private class the transfer CLI requires
// of every private input and produces for every private output, and 0644 is the
// deliberately shared class the negatives must be refused for.

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// passkeyTransferWritePrivate writes one private transfer fixture file.
func passkeyTransferWritePrivate(t *testing.T, path string, content []byte) {
	t.Helper()
	passkeyTransferWriteMode(t, path, content, 0o600)
}

// passkeyTransferWriteShared writes the same bytes but grants group and other
// read access, the Unix equivalent of the Windows Everyone-read negative.
func passkeyTransferWriteShared(t *testing.T, path string, content []byte) {
	t.Helper()
	passkeyTransferWriteMode(t, path, content, 0o644)
}

func passkeyTransferWriteMode(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
	// Restore the requested mode independently of the process umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("fixture file mode: %v", err)
	}
}

// passkeyTransferPrivateFileError reports whether path is a regular file with
// the owner-only mode the transfer CLI requires of private inputs/outputs.
func passkeyTransferPrivateFileError(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("transfer fixture unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("transfer fixture is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("transfer fixture mode is %v, want owner-only 0600", info.Mode().Perm())
	}
	return nil
}

// passkeyTransferAssertOwnerPrivate fails the test unless the path is an
// owner-only regular file. It never prints file content.
func passkeyTransferAssertOwnerPrivate(t *testing.T, path string) {
	t.Helper()
	if err := passkeyTransferPrivateFileError(path); err != nil {
		t.Fatalf("output is not an owner-private regular file: %v", err)
	}
}
