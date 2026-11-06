//go:build unix

package teamclient

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func profileChain(path string, file bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil {
			return ErrProfile
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0 {
			return ErrProfile
		}
		if first {
			if !st.Mode().IsRegular() || owner.Nlink != 1 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 || st.Size() > 32<<20 {
				return ErrProfile
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return ErrProfile
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedProfileParent(path string) error {
	if profileChain(path, false) != nil {
		return ErrProfile
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return ErrProfile
	}
	return profileChain(resolved, false)
}
func trustedProfileFile(path string) error {
	if profileChain(path, true) != nil {
		return ErrProfile
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return ErrProfile
	}
	return profileChain(resolved, true)
}
func createProfileFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}
func openProfileFile(path string, flags int) (*os.File, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, ErrProfile
	}
	fd, e := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrProfile
	}
	f := os.NewFile(uintptr(fd), path)
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || !profileUniqueFile(path, after) || after.Mode().Perm()&0077 != 0 || after.Size() > 32<<20 {
		f.Close()
		return nil, ErrProfile
	}
	return f, nil
}

// The independent identity lease is never removed by product cleanup.
func lockProfileIdentity(f *os.File) error {
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrProfile
	}
	return nil
}

func equalProfilePath(a, b string) bool { return a == b }
func profileUniqueFile(_ string, st os.FileInfo) bool {
	info, ok := st.Sys().(*syscall.Stat_t)
	return ok && info.Nlink == 1
}
