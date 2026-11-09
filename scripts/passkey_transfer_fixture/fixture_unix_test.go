//go:build !windows

package main

// Unix private-root fixtures for TestPrivateRoot: a real 0700 directory and a
// deliberately group/other-readable one.

import (
	"os"
	"testing"
)

func passkeyTransferPrivateRootFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("private root mode: %v", err)
	}
	return root
}

func passkeyTransferMakeRootShared(t *testing.T, root string) {
	t.Helper()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("shared root mode: %v", err)
	}
}
