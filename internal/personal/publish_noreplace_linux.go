//go:build linux

package personal

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishRenameNoReplace(tmp, path string) error {
	return publishRenameNoReplaceWith(tmp, path, unix.Renameat2, (*os.File).Sync)
}

// The caller has fsynced and closed the complete temporary file. There is no
// replacing-rename, placeholder or hard-link fallback if the kernel/filesystem
// does not support RENAME_NOREPLACE. A directory-sync failure leaves the complete
// published file for inspection, matching the existing publication contract.
func publishRenameNoReplaceWith(tmp, path string, rename func(int, string, int, string, uint) error, syncDir func(*os.File) error) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = rename(unix.AT_FDCWD, tmp, int(dir.Fd()), filepath.Base(path), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}
