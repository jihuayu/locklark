//go:build unix

package teamfiles

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func chain(path string, file, private bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return ErrFile
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0 {
			return ErrFile
		}
		if first {
			mask := os.FileMode(0022)
			if private {
				mask = 0077
			}
			if !st.Mode().IsRegular() || owner.Nlink != 1 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&mask != 0 {
				return ErrFile
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return ErrFile
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedParent(path string) error {
	if chain(path, false, true) != nil {
		return ErrFile
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ErrFile
	}
	return chain(resolved, false, true)
}
func trustedFile(path string, private bool) error {
	if chain(path, true, private) != nil {
		return ErrFile
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ErrFile
	}
	return chain(resolved, true, private)
}
func createLocalFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}
func openLocalFile(path string, private bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, ErrFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrFile
	}
	f := os.NewFile(uintptr(fd), path)
	after, err := f.Stat()
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&mask != 0 {
		f.Close()
		return nil, ErrFile
	}
	return f, nil
}
func publishLocalFile(tmp, path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = os.Link(tmp, path); err != nil {
		return err
	}
	return dir.Sync()
}
func equalPath(a, b string) bool    { return a == b }
func validPlatformPath(string) bool { return true }
