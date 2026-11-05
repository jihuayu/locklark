//go:build !windows

package directory

import (
	"os"
	"path/filepath"
)

// The temporary file was fsynced and closed. Commit a new name only; fsync
// its directory before reporting success, including on filesystems that defer
// directory updates. On sync failure keep the complete link for inspection.
func publishDirectory(tmp, path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = os.Link(tmp, path); err != nil {
		return err
	}
	return dir.Sync()
}
