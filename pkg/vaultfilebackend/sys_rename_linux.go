//go:build linux

package vaultfilebackend

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames tmp to final with an atomic exchange, replacing
// final in one step and leaving the previous record at tmp for the caller to
// drop. When final does not exist the exchange fails with os.ErrNotExist and
// nothing is published, so a concurrently created final is never clobbered.
// File systems without RENAME_EXCHANGE support fall back to rename(2); the
// shared lock still serializes every cooperating writer there.
func renameNoReplace(tmp, final string) error {
	err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, unix.RENAME_EXCHANGE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ENOENT):
		return &os.LinkError{Op: "rename", Old: tmp, New: final, Err: os.ErrNotExist}
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP):
		return os.Rename(tmp, final)
	default:
		return &os.LinkError{Op: "rename", Old: tmp, New: final, Err: err}
	}
}
