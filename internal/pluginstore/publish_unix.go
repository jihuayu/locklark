//go:build !windows

package pluginstore

import (
	"os"
	"path/filepath"
)

func publish(tmp, path string) error {
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = os.Link(tmp, path); e != nil {
		return e
	}
	return dir.Sync()
}
