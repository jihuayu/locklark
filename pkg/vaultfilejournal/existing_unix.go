//go:build darwin || linux

package vaultfilejournal

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openExistingOnlyDatabase(path string) (*Journal, error) {
	return openExistingOnlyDatabaseWith(path, nil)
}

// beforeBolt is a private deterministic seam for name-replacement tests. It
// runs after the only descriptor open and before bbolt acquires its lock.
func openExistingOnlyDatabaseWith(path string, beforeBolt func()) (*Journal, error) {
	return openExistingOnlyDatabaseKindWith(path, beforeBolt, false)
}

func openExistingIntentOnlyDatabase(path string) (*Journal, error) {
	return openExistingOnlyDatabaseKindWith(path, nil, true)
}

func openExistingOnlyDatabaseKindWith(path string, beforeBolt func(), wantIntent bool) (*Journal, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), "vaultfile-existing-journal")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalid
	}
	if _, err := existingFileInfo(file); err != nil {
		_ = file.Close()
		return nil, ErrInvalid
	}
	if beforeBolt != nil {
		beforeBolt()
	}
	return openExistingValidatedKind(path, file, func() error {
		// This runs only after bbolt's exclusive lock has been acquired.
		// Rechecking just the pathname before Open would not bind that lock
		// or the database reads to the configured journal's inode.
		held, err := existingFileInfo(file)
		if err != nil {
			return ErrInvalid
		}
		current, err := os.Lstat(path)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(held, current) {
			return ErrInvalid
		}
		return nil
	}, wantIntent)
}

func existingFileInfo(file *os.File) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, ErrInvalid
	}
	return info, nil
}
