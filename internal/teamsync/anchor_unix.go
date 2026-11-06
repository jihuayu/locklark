//go:build unix

package teamsync

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func anchorChain(path string, file bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil {
			return ErrAnchor
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0 {
			return ErrAnchor
		}
		if first {
			if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 || st.Size() > 8<<20 {
				return ErrAnchor
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return ErrAnchor
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedAnchorParent(path string) error {
	if anchorChain(path, false) != nil {
		return ErrAnchor
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return ErrAnchor
	}
	return anchorChain(resolved, false)
}
func trustedAnchorFile(path string) error {
	if anchorChain(path, true) != nil {
		return ErrAnchor
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return ErrAnchor
	}
	return anchorChain(resolved, true)
}
func createAnchorFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}
func publishAnchorFile(tmp, path string) error {
	return publishAnchorFileWithSync(tmp, path, (*os.File).Sync)
}
func publishAnchorFileWithSync(tmp, path string, syncDir func(*os.File) error) error {
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	// A hard link cannot replace an existing name. On directory-sync failure
	// the complete final file remains, but Create returns no store.
	if e := os.Link(tmp, path); e != nil {
		return e
	}
	return syncDir(dir)
}
func openAnchorFile(path string, flags int) (*os.File, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, ErrAnchor
	}
	fd, e := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAnchor
	}
	f := os.NewFile(uintptr(fd), path)
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || after.Size() > 8<<20 {
		f.Close()
		return nil, ErrAnchor
	}
	return f, nil
}
