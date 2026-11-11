package vaultfilejournal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// checkRegular fails unless fi names a regular, non-symlinked file.
func checkRegular(fi os.FileInfo) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: database path is a symlink", ErrInvalid)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: database path is not a regular file", ErrInvalid)
	}
	return nil
}

// removeOwnFile removes a file this package alone created (a uniquely named
// temporary) after the caller has closed it.
func removeOwnFile(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
