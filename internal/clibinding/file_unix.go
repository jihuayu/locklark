//go:build !windows

package clibinding

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// trustedBindingParent accepts a real, existing directory owned by this user or
// root that unrelated users cannot write to. A root-owned sticky directory such
// as /tmp may be group/other writable because only the owner of an existing
// child can replace it.
func trustedBindingParent(dir string) error {
	if !filepath.IsAbs(dir) {
		return ErrBinding
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrBinding
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrBinding
	}
	if sys.Uid != uint32(os.Geteuid()) && sys.Uid != 0 {
		return ErrBinding
	}
	if info.Mode().Perm()&0022 != 0 && !(sys.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
		return ErrBinding
	}
	return nil
}

// readPrivateBindingFile reads a 0600 file below a trusted directory without
// following a symlink and revalidates the opened descriptor after Lstat.
func readPrivateBindingFile(path string) ([]byte, error) {
	if err := trustedBindingParent(filepath.Dir(path)); err != nil {
		return nil, ErrBinding
	}
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, ErrBinding
	}
	beforeSys, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() > maxBindingFileSize || before.Mode().Perm()&0077 != 0 ||
		beforeSys.Uid != uint32(os.Geteuid()) {
		return nil, ErrBinding
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrBinding
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrBinding
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() ||
		after.Mode().Perm()&0077 != 0 || after.Size() > maxBindingFileSize {
		return nil, ErrBinding
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBindingFileSize+1))
	if err != nil || len(raw) > maxBindingFileSize {
		clear(raw)
		return nil, ErrBinding
	}
	return raw, nil
}

// writePrivateBindingFile replaces path atomically with a 0600 temporary file
// created in the same trusted directory. Chmod is explicit so a permissive
// caller umask cannot widen the mode.
func writePrivateBindingFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := trustedBindingParent(dir); err != nil {
		return ErrBinding
	}
	if before, err := os.Lstat(path); err == nil {
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
			return ErrBinding
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrBinding
	}
	var temp string
	var file *os.File
	var err error
	for attempt := 0; attempt < 16; attempt++ {
		suffix, suffixErr := randomTempSuffix()
		if suffixErr != nil {
			return suffixErr
		}
		temp = filepath.Join(dir, ".locklark-cli-"+suffix+".tmp")
		file, err = os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		break
	}
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			file.Close()
			os.Remove(temp)
		}
	}()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	published = true
	if directory, openErr := os.Open(dir); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
