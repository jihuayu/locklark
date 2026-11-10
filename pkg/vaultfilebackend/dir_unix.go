//go:build darwin || linux

package vaultfilebackend

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openLockFile opens the dedicated lock file without following a symlink and
// without blocking on a FIFO or device planted in the directory. It refuses a
// non-regular, symlinked, multiply-linked or group/world-writable file: every
// process shares only this inode for locking, so it must never be swapped.
func openLockFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, deniedMsg(nil, "lock file is a symlink or has multiple links")
		}
		if st, statErr := os.Lstat(path); statErr == nil && !st.Mode().IsRegular() {
			return nil, deniedMsg(nil, "lock file is not a regular file")
		}
		return nil, deniedMsg(err, "open lock file")
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !privateFile(st) {
		f.Close()
		return nil, deniedMsg(nil, "lock file is not a private regular file")
	}
	return f, nil
}

// tryLock takes a whole-file OS advisory record lock without blocking and
// reports whether it was granted. POSIX record locks are released
// automatically when the process exits or dies.
func tryLock(f *os.File) (bool, error) {
	err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(os.SEEK_SET)})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
		return false, nil
	}
	return false, err
}

func unlock(f *os.File) error {
	return unix.FcntlFlock(f.Fd(), unix.F_SETLK, &unix.Flock_t{Type: unix.F_UNLCK, Whence: int16(os.SEEK_SET)})
}

// readLockFile reads at most size bytes from offset 0. It is only used while
// the lock is held.
func readLockFile(f *os.File, size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// writeLockFile replaces the lock file contents.
func writeLockFile(f *os.File, b []byte) error {
	if _, err := f.WriteAt(b, 0); err != nil {
		return err
	}
	return f.Truncate(int64(len(b)))
}

// privateFile reports whether the file is a regular file owned by the current
// user, with link count one and exactly 0600 permissions. Any looser mode
// (group/other access, including execute bits) or a hard link is refused.
func privateFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0600
}

// ownedByEUID reports whether info is owned by the effective user. Unlike
// privateDir, which also accepts trusted ancestors such as /usr owned by root,
// this is required of every protected namespace directory.
func ownedByEUID(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == uint32(os.Geteuid())
}

// privateDir reports whether the directory is not group/world writable, or is
// a system sticky directory such as /tmp.
func privateDir(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		return stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	}
	return true
}

// openPrivateFile opens an existing data file read-only without following
// symlinks and without blocking on special files.
func openPrivateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, deniedMsg(nil, "data path is a symlink")
		}
		return nil, deniedMsg(err, "open data file")
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil || !privateFile(st) {
		f.Close()
		return nil, deniedMsg(nil, "data file is not a private 0600 regular file")
	}
	return f, nil
}

// linkNoReplace publishes tmp under final, failing if final exists (a hard
// link creation is atomic and never replaces an existing name).
func linkNoReplace(tmp, final string) error {
	return os.Link(tmp, final)
}
