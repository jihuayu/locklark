//go:build unix

package localpath

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// TrustedTemporaryParent resolves symlinks once and validates the entire
// canonical ancestor chain. The caller must use the returned path, rather than
// the potentially replaceable original alias. Other users must not be able to
// rename any ancestor; the current user and administrators are not isolated.
func TrustedTemporaryParent(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrUntrusted
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", ErrUntrusted
	}
	canonical = filepath.Clean(canonical)
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(canonical, current), string(filepath.Separator))
	check := func(name string, final bool) error {
		info, e := os.Lstat(name)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUntrusted
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUntrusted
		}
		uid := uint32(os.Geteuid())
		if stat.Uid != 0 && stat.Uid != uid {
			return ErrUntrusted
		}
		stickyRoot := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if info.Mode().Perm()&0022 != 0 && !stickyRoot {
			return ErrUntrusted
		}
		if final && !(stat.Uid == uid && info.Mode().Perm()&0077 == 0) && !stickyRoot {
			return ErrUntrusted
		}
		return nil
	}
	if e = check(current, canonical == current); e != nil {
		return "", e
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if e = check(current, i == len(parts)-1); e != nil {
			return "", e
		}
	}
	return canonical, nil
}
