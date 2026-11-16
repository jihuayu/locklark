//go:build unix

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func configChain(path string, file, private bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil {
			return errCommand
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 && owner.Uid != uint32(os.Geteuid()) {
			return errCommand
		}
		if first {
			mask := os.FileMode(0022)
			if private {
				mask = 0077
			}
			if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&mask != 0 {
				return errCommand
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return errCommand
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func readLocalFile(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || configChain(path, true, private) != nil {
		return nil, errCommand
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || configChain(resolved, true, private) != nil {
		return nil, errCommand
	}
	before, e := os.Lstat(path)
	if e != nil || before.Size() > limit {
		return nil, errCommand
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errCommand
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > limit {
		return nil, errCommand
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, errCommand
	}
	return raw, nil
}
