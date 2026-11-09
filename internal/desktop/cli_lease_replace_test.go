//go:build !windows

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestHashCLIProgramRefusesPathReplacementAfterRead pauses after the descriptor
// was read and stat'ed, atomically replaces the caller-visible path, and proves
// the hasher fails closed instead of returning the digest of bytes the path no
// longer names. This is the desktop lease evidence race.
func TestHashCLIProgramRefusesPathReplacementAfterRead(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "program")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldSeam := cliHashProgramBeforeFinalLstat
	replaced := false
	cliHashProgramBeforeFinalLstat = func() {
		if replaced {
			t.Fatal("final-lstat seam ran twice")
		}
		replaced = true
		if err := os.Remove(program); err != nil {
			t.Fatalf("remove hashed path: %v", err)
		}
		if err := os.Rename(replacement, program); err != nil {
			t.Fatalf("replace hashed path: %v", err)
		}
	}
	t.Cleanup(func() { cliHashProgramBeforeFinalLstat = oldSeam })

	if _, err := hashCLIProgram(program); !errors.Is(err, errCLILeaseStale) {
		t.Fatalf("replaced path hash error = %v, want stale refusal", err)
	}
	if !replaced {
		t.Fatal("path replacement was not exercised")
	}
	cliHashProgramBeforeFinalLstat = oldSeam
	if _, err := hashCLIProgram(program); err != nil {
		t.Fatalf("replacement program should hash normally after the seam: %v", err)
	}
}
