package vaultfilejournal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// checkPrivateDir requires dir to be a real (non-symlinked) directory with no
// group or other permission bits: 0700 or stricter. A filesystem-backed temp
// directory (for example /var/folders/... on macOS, 0755) is rejected rather
// than tightened, because changing another component's directory mode would be
// an unrelated side effect.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: parent directory: %v", ErrInvalid, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: parent is not a real directory", ErrInvalid)
	}
	return checkPrivateMode(dir, fi.Mode())
}

// checkPrivateMode rejects group and other access; a directory readable by
// other accounts is rejected even if it is owned by the caller.
func checkPrivateMode(dir string, mode fs.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("%w: parent directory %s has mode %04o, want no group or other access", ErrInvalid, dir, mode.Perm())
	}
	return nil
}

// checkDBPath requires path to name a regular, non-symlinked file, or nothing.
// A missing file is reported missing=true; it is not created here.
func checkDBPath(path string) (missing bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: database file: %v", ErrInvalid, err)
	}
	if err := checkRegular(fi); err != nil {
		return false, err
	}
	return false, nil
}

// verifyDBFile re-checks the path after bbolt opened it, guarding against a
// symlink or special file swapped in between the check and the open.
func verifyDBFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: database file: %v", ErrInvalid, err)
	}
	return checkRegular(fi)
}

func checkRegular(fi os.FileInfo) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: database path is a symlink", ErrInvalid)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: database path is not a regular file", ErrInvalid)
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
