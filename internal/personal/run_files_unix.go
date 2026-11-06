//go:build !windows

package personal

import (
	"os"
	"syscall"
)

// writePrivateRunFile creates a new owner-only file and refuses to follow a
// symlink at the final component. Chmod applies the requested mode regardless
// of the caller's umask.
func writePrivateRunFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode&0700)
	if err != nil {
		return err
	}
	if err = file.Chmod(mode & 0700); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
