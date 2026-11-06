//go:build linux || darwin

package desktop

import (
	"github.com/jihuayu/locklark/internal/personal"
	"os"
	"path/filepath"
	"syscall"
)

func openSSHImport(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, personal.ErrSSHKey
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, personal.ErrSSHKey
	}
	return f, nil
}
