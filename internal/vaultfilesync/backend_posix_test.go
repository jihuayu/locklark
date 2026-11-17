//go:build darwin || linux

package vaultfilesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// newFixtureBackend opens the real local directory backend at a fresh
// 0700 directory below the test's temp root.
func newFixtureBackend(t *testing.T) vaultfilebackend.Backend {
	t.Helper()
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, err := vaultfilebackend.OpenDir(store)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	return backend
}

// newJournalDir returns a fresh empty 0700 directory below the test's temp
// root, the shape vaultfilejournal.Open requires of a journal's parent.
func newJournalDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
