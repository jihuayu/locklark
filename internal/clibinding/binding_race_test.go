//go:build !windows

package clibinding

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestComputeProgramSHA256RefusesPathReplacementAfterOpen pauses after the
// descriptor read and before the final path identity check, then atomically
// replaces the path. The shared hasher used by VerifyProgram must fail closed
// rather than return a pin for an inode the path no longer names.
func TestComputeProgramSHA256RefusesPathReplacementAfterOpen(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "tool")
	if err := os.WriteFile(program, []byte("old image"), 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new image"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldSeam := computeProgramBeforeFinalCheck
	replaced := false
	computeProgramBeforeFinalCheck = func() {
		if replaced {
			t.Fatal("final check seam ran twice")
		}
		replaced = true
		if err := os.Remove(program); err != nil {
			t.Fatalf("remove hashed path: %v", err)
		}
		if err := os.Rename(replacement, program); err != nil {
			t.Fatalf("replace hashed path: %v", err)
		}
	}
	t.Cleanup(func() { computeProgramBeforeFinalCheck = oldSeam })

	if _, err := ComputeProgramSHA256(program); !errors.Is(err, ErrBinding) {
		t.Fatalf("replaced path digest error = %v, want ErrBinding", err)
	}
	if !replaced {
		t.Fatal("path replacement was not exercised")
	}
}
