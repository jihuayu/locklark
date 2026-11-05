//go:build unix

package browserhost

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Files and both the spelled/resolved ancestor chains must be owned by this
// user or root. Root-owned sticky temporary roots cannot replace another user's
// protected child; other group/world-writable directories are refused.
func registrationChain(path string, file bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil {
			return ErrProtocol
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrProtocol
		}
		if stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
			return ErrProtocol
		}
		if first {
			if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
				return ErrProtocol
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return ErrProtocol
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedRegistrationParent(dir string) error {
	if registrationChain(dir, false) != nil {
		return ErrProtocol
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return ErrProtocol
	}
	return registrationChain(resolved, false)
}
func trustedRegistrationFile(path string, executable bool) error {
	if registrationChain(path, true) != nil {
		return ErrProtocol
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || registrationChain(resolved, true) != nil {
		return ErrProtocol
	}
	before, e := os.Lstat(resolved)
	if e != nil {
		return ErrProtocol
	}
	fd, e := unix.Open(resolved, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return ErrProtocol
	}
	f := os.NewFile(uintptr(fd), resolved)
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Mode().Perm()&0022 != 0 || executable && after.Mode().Perm()&0111 == 0 {
		return ErrProtocol
	}
	return nil
}
func createRegistrationDirectory(path string) error { return os.Mkdir(path, 0700) }
func privateRegistrationTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".locklark-native-*")
}
func publishRegistrationTemp(temp, target string, replace bool) error {
	if replace {
		if e := os.Rename(temp, target); e != nil {
			return e
		}
	} else {
		if e := os.Link(temp, target); e != nil {
			return e
		}
		if e := os.Remove(temp); e != nil {
			return e
		}
	}
	dir, e := os.Open(filepath.Dir(target))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
