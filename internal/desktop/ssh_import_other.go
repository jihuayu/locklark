//go:build !linux && !darwin && !windows

package desktop

import (
	"github.com/jihuayu/locklark/internal/personal"
	"os"
)

func openSSHImport(string) (*os.File, error) { return nil, personal.ErrSSHKey }
