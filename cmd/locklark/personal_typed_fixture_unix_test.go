//go:build !windows

package main

// OS-specific creation of the private typed-input fixture.
//
// Unix enforces privacy with owner-only mode 0600, so a normal write is
// sufficient. Windows cannot express a private DACL through os.WriteFile or
// os.Chmod, so it uses personal_typed_fixture_windows_test.go instead. Shared
// here so later typed attachment tests can create input files the same way.

import (
	"os"
	"testing"
)

func writePrivateTypedFixture(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write private input: %v", err)
	}
	// Restore owner-only mode independently of the process umask.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("private input mode: %v", err)
	}
}
