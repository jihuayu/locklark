//go:build darwin

package vaultfilebackend

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames tmp to final with an atomic exchange. It replaces
// final in one step and moves the previous record to tmp, so the caller can
// drop it; when final does not exist the exchange fails with os.ErrNotExist and
// nothing is published. A concurrently created final is therefore never
// clobbered by a rename that did not compare it.
func renameNoReplace(tmp, final string) error {
	err := unix.RenamexNp(tmp, final, unix.RENAME_SWAP)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ENOENT):
		return &os.LinkError{Op: "rename", Old: tmp, New: final, Err: os.ErrNotExist}
	default:
		return &os.LinkError{Op: "rename", Old: tmp, New: final, Err: err}
	}
}
