//go:build unix

package teamfiles

import (
	"errors"
	"os"
	"path/filepath"
)

func privateDirectory(path string, exact bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrFile
	}
	if exact {
		if info.Mode().Perm() != 0700 {
			return ErrFile
		}
	} else if info.Mode().Perm()&0077 != 0 {
		return ErrFile
	}
	return nil
}

func validatePrivateParent(path string) error {
	return privateDirectory(path, false)
}

func validatePrivateWorkspace(path string) error {
	return privateDirectory(path, true)
}

func validatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return ErrFile
	}
	return nil
}

func ensurePrivateWorkspace(path string) error {
	if validatePrivateWorkspace(path) == nil {
		return nil
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrFile
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return ErrFile
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrFile
	}
	return validatePrivateWorkspace(path)
}
