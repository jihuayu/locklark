//go:build unix

package management

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

// Validate both spelling and resolved path. Root-owned system symlinks (such as
// macOS /var) are allowed; another user's writable ancestor is not trusted.
func trustedChain(path string) error { return trustedPathChain(path, true) }
func trustedPathChain(path string, first bool) error {
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil {
			return ErrUnavailable
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnavailable
		}
		own := stat.Uid == uint32(os.Geteuid())
		if first {
			if !own || !st.Mode().IsRegular() || st.Size() > 64<<10 || st.Mode().Perm()&0022 != 0 {
				return ErrUnavailable
			}
		} else {
			if !own && stat.Uid != 0 {
				return ErrUnavailable
			}
			if st.Mode()&os.ModeSymlink == 0 {
				if !st.IsDir() || st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0 {
					return ErrUnavailable
				}
			}
		}
		first = false
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
func openTrustedConfiguration(path string) (*os.File, error) {
	absolute, e := filepath.Abs(path)
	if e != nil || trustedChain(absolute) != nil {
		return nil, ErrUnavailable
	}
	resolved, e := filepath.EvalSymlinks(absolute)
	if e != nil || trustedChain(resolved) != nil {
		return nil, ErrUnavailable
	}
	before, e := os.Lstat(resolved)
	if e != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open(resolved, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), resolved)
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrUnavailable
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || after.Mode().Perm()&0022 != 0 || after.Size() > 64<<10 {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func trustedConnectionParent(path string) error {
	absolute, e := filepath.Abs(filepath.Dir(path))
	if e != nil || trustedPathChain(absolute, false) != nil {
		return ErrUnavailable
	}
	resolved, e := filepath.EvalSymlinks(absolute)
	if e != nil {
		return ErrUnavailable
	}
	return trustedPathChain(resolved, false)
}
func privateConnectionFile(f *os.File) error {
	st, e := f.Stat()
	if e != nil || st.Mode().Perm()&0077 != 0 {
		return ErrUnavailable
	}
	return nil
}
