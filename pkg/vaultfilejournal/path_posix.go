//go:build !windows

package vaultfilejournal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	bolt "go.etcd.io/bbolt"
)

// checkPrivateDir requires dir to be a real (non-symlinked) directory with no
// group or other permission bits: 0700 or stricter. Open never creates or
// tightens the directory, so one whose mode grants group or other access is
// rejected as is.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: parent directory: %v", ErrInvalid, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: parent is not a real directory", ErrInvalid)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: parent directory %s has mode %04o, want no group or other access", ErrInvalid, dir, mode)
	}
	return nil
}

// checkExistingDBFile requires an existing database file to have no group or
// other permission bits. It never chmods the file: a caller-owned file with a
// wider mode is rejected and left untouched.
func checkExistingDBFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: database file: %v", ErrInvalid, err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: database file %s has mode %04o, want no group or other access", ErrInvalid, path, mode)
	}
	return nil
}

// openDatabase opens the bbolt database after the path checks. A new file is
// checkpointed by syncing its parent directory; an existing file never gains
// group or other access, so it is rejected rather than repaired.
func openDatabase(path, parent string, missingHint bool) (*Journal, error) {
	if !missingHint {
		if err := checkExistingDBFile(path); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{NoSync: false, Timeout: lockTimeout})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrLocked, err)
		}
		return nil, fmt.Errorf("vault file journal: open: %w", err)
	}
	// bolt creates only the main file; checkpoint it so the 0600 inode is
	// durable rather than depending on a later rename. If the file already
	// existed, skip the extra sync.
	if missingHint {
		if err := syncDir(parent); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("vault file journal: sync directory: %w", err)
		}
	}
	if err := verifyDBFile(path); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Re-check the permission bits now that the file is open, so the
	// no-group-or-other promise covers the read boundary too. A file widened
	// in between is rejected as is, never chmodded.
	if !missingHint {
		if err := checkExistingDBFile(path); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &Journal{db: db}, nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
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

// checkDBPath requires path to name a regular, non-symlinked file, or nothing.
// A missing file is reported missing=true; it is not created here.
func checkDBPath(path string) (missing bool, err error) {
	fi, statErr := os.Lstat(path)
	if errors.Is(statErr, fs.ErrNotExist) {
		return true, nil
	}
	if statErr != nil {
		return false, fmt.Errorf("%w: database file: %v", ErrInvalid, statErr)
	}
	if err := checkRegular(fi); err != nil {
		return false, err
	}
	return false, nil
}
