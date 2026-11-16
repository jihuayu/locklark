//go:build !windows

package vaultfilejournal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
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
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return fmt.Errorf("%w: existing database is not a nonempty regular file", ErrInvalid)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: database file %s has mode %04o, want no group or other access", ErrInvalid, path, mode)
	}
	return nil
}

// openDatabase lets only the descriptor this call created with O_EXCL enter
// bbolt at zero length. An existing zero-length file can be a failed genesis
// intent creation, so it is never handed to bbolt for initialization.
func openDatabase(path, parent string, missingHint bool) (*Journal, error) {
	if !missingHint {
		if err := checkExistingDBFile(path); err != nil {
			return nil, err
		}
	}
	var opened *os.File
	db, err := bolt.Open(path, 0o600, &bolt.Options{NoSync: false, NoFreelistSync: !missingHint, Timeout: lockTimeout,
		OpenFile: func(name string, flags int, _ os.FileMode) (*os.File, error) {
			if opened != nil || name != path || flags&os.O_TRUNC != 0 || flags&(os.O_WRONLY|os.O_RDWR) != os.O_RDWR {
				return nil, ErrInvalid
			}
			openFlags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
			if missingHint {
				openFlags |= unix.O_CREAT | unix.O_EXCL
			}
			fd, err := unix.Open(path, openFlags, 0600)
			if err != nil {
				return nil, fmt.Errorf("%w: database descriptor: %v", ErrInvalid, err)
			}
			file := os.NewFile(uintptr(fd), "vaultfile-journal")
			if file == nil {
				_ = unix.Close(fd)
				return nil, ErrInvalid
			}
			info, err := file.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
				(!missingHint && info.Size() == 0) {
				_ = file.Close()
				return nil, ErrInvalid
			}
			if missingHint && unix.Fchmod(fd, 0600) != nil {
				_ = file.Close()
				return nil, ErrInvalid
			}
			opened = file
			return file, nil
		},
	})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrLocked, err)
		}
		return nil, fmt.Errorf("vault file journal: open: %w", err)
	}
	refuse := func(err error) (*Journal, error) {
		_ = db.Close()
		return nil, err
	}
	if opened == nil {
		return refuse(ErrInvalid)
	}
	held, err := opened.Stat()
	named, nameErr := os.Lstat(path)
	if err != nil || nameErr != nil || !named.Mode().IsRegular() || !os.SameFile(held, named) {
		return refuse(ErrInvalid)
	}
	if missingHint {
		// A real Journal.Open/Close has an empty journal namespace. Bare bbolt
		// initialization has none and cannot later take over a reserved inode.
		if err := db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte(bucketName))
			return err
		}); err != nil {
			return refuse(err)
		}
	}
	// Checkpoint a newly created inode; existing files are never repaired.
	if missingHint {
		if err := syncDir(parent); err != nil {
			return refuse(fmt.Errorf("vault file journal: sync directory: %w", err))
		}
	}
	named, nameErr = os.Lstat(path)
	if nameErr != nil || !named.Mode().IsRegular() || !os.SameFile(held, named) {
		return refuse(ErrInvalid)
	}
	// Re-check the permission bits now that the file is open, so the
	// no-group-or-other promise covers the read boundary too. A file widened
	// in between is rejected as is, never chmodded.
	if !missingHint {
		if err := checkExistingDBFile(path); err != nil {
			return refuse(err)
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
