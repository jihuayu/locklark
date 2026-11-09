//go:build !windows

package main

// Unix private-root policy for the passkey transfer acceptance fixture.
//
// The owned acceptance harness (scripts/passkey_transfer_acceptance.py) is a
// POSIX PTY driver, so on Unix the root is a real 0700 directory that must have
// no group/other bits. Windows cannot express that with mode bits; see
// root_windows.go.

import (
	"os"
	"path/filepath"
)

// privateRoot requires an absolute, clean, owner-private 0700 directory. It
// follows no symlink and rejects group/other access.
func privateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errFixtureRefused
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errFixtureRefused
	}
	return nil
}
