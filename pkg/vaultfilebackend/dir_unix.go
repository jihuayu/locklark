//go:build darwin || linux

package vaultfilebackend

import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// openLockFile is the test-facing convenience wrapper around
// openLockFileOwned. A validation rejection returns a descriptor still owned by
// the opener, so the wrapper closes it only through the identity-aware
// rejection path; a descriptor whose identity cannot be determined is retained
// by the bounded quarantine instead of being closed blindly.
func openLockFile(path string) (*os.File, error) {
	f, info, err := openLockFileOwned(path)
	if err != nil {
		closeRejectedLockFile(f, info, time.Now())
		return nil, err
	}
	return f, nil
}

// openLockFileOwned opens or creates the dedicated lock file without following
// a symlink and without blocking on a FIFO or device planted in the directory.
// A successfully opened descriptor and the identity obtained from it are
// returned even when validation rejects the file: the caller owns the
// descriptor and must close it through closeRejectedLockFile, under its actual
// identity semaphore. The returned info is nil when f.Stat itself failed; in
// that case the descriptor has already been retained by the bounded unknown
// identity quarantine and must not be closed.
func openLockFileOwned(path string) (*os.File, os.FileInfo, error) {
	if err := reserveLockFileOpen(); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if errors.Is(err, unix.EEXIST) {
		releaseLockFileOpen()
		return openExistingLockFileOwned(path)
	}
	if err != nil {
		releaseLockFileOpen()
		return nil, nil, lockOpenError(path, err)
	}
	return lockFileFromFD(path, fd)
}

// openExistingLockFileOwned is the existing-only form of openLockFileOwned. It
// never creates a lock file, so a lock file removed after OpenDir is refused
// rather than silently recreated as a different inode. Its descriptor and
// validation-rejection ownership contract is the same as openLockFileOwned.
func openExistingLockFileOwned(path string) (*os.File, os.FileInfo, error) {
	if err := reserveLockFileOpen(); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		releaseLockFileOpen()
		return nil, nil, lockOpenError(path, err)
	}
	return lockFileFromFD(path, fd)
}

// openExistingLockFile is the test-facing convenience wrapper around
// openExistingLockFileOwned, with the same rejection ownership policy as
// openLockFile.
func openExistingLockFile(path string) (*os.File, error) {
	f, info, err := openExistingLockFileOwned(path)
	if err != nil {
		closeRejectedLockFile(f, info, time.Now())
		return nil, err
	}
	return f, nil
}

// lockOpenError classifies a failed lock open with the same refusals as a
// successfully opened but unacceptable entry.
func lockOpenError(path string, err error) error {
	if errors.Is(err, unix.ENOENT) {
		return deniedMsg(err, "lock file is missing")
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
		return deniedMsg(nil, "lock file is a symlink or has multiple links")
	}
	if st, statErr := os.Lstat(path); statErr == nil && !st.Mode().IsRegular() {
		return deniedMsg(nil, "lock file is not a regular file")
	}
	return deniedMsg(err, "open lock file")
}

// lockFileRejected is a test-only deterministic point after an opened lock
// descriptor failed validation and before its owner can close it. Production
// builds leave it nil.
var lockFileRejected func(path string)

// lockFileFromFD wraps an opened descriptor after checking it is a private
// regular file. Its identity is taken from the descriptor itself, never from a
// later pathname stat, so it describes exactly the inode that was opened. The
// descriptor is not closed on a validation rejection: closing it there could
// release a POSIX record lock another operation of this process holds on the
// same inode. The caller closes a rejected descriptor only after acquiring the
// semaphore for the identity returned here.
func lockFileFromFD(path string, fd int) (*os.File, os.FileInfo, error) {
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		releaseLockFileOpen()
		return nil, nil, deniedMsg(nil, "lock file descriptor is invalid")
	}
	st, err := f.Stat()
	if err != nil {
		// The descriptor is valid enough to exist but its identity cannot be
		// determined. Retaining it keeps a possible shared lock descriptor open
		// rather than risking an unchecked close; the bounded quarantine refuses
		// further opens rather than accumulating without limit.
		retainUnknownLockFile(f)
		return f, nil, deniedMsg(err, "lock file")
	}
	releaseLockFileOpen()
	if !st.Mode().IsRegular() || !privateFile(st) {
		if lockFileRejected != nil {
			lockFileRejected(path)
		}
		return f, st, deniedMsg(nil, "lock file is not a private regular file")
	}
	return f, st, nil
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

// lockInodeKey reduces a Stat to the stable platform identity of the inode.
// It is the key for process-local lock coordination: unlike a pathname, it is
// shared by every alias that reaches the same lock inode.
func lockInodeKey(info os.FileInfo) (inProcKey, bool) {
	if info == nil {
		return inProcKey{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return inProcKey{}, false
	}
	return inProcKey{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}, true
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
