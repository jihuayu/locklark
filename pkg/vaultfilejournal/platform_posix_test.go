//go:build !windows

package vaultfilejournal

import (
	"os"
	"testing"
)

// makeParentShared widens the directory's POSIX mode so it grants group and
// other access. The journal must reject it, never tighten it.
func makeParentShared(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// makeDBPrivate gives an existing file owner-only permissions.
func makeDBPrivate(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mustLinkDir creates a symbolic link to a directory.
func mustLinkDir(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// mustLinkFile creates a symbolic link to a file.
func mustLinkFile(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// posixModeChecks reports that permission mode bits govern this platform.
const posixModeChecks = true

// checkLocalPermissions requires the database file (0600) and its parent
// directory (no group or other bits) to be private by mode.
func checkLocalPermissions(t *testing.T, dbPath, parent string) {
	t.Helper()
	if fi, err := os.Lstat(dbPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %v, want regular 0600", fi)
	}
	if fi, err := os.Lstat(parent); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("parent mode is not private: %v, %v", fi, err)
	}
}
