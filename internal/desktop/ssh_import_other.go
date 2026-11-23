//go:build !linux && !darwin && !windows

package desktop

import (
	"github.com/jihuayu/passme/internal/personal"
	"os"
)

func openSSHImport(string) (*os.File, error) { return nil, personal.ErrSSHKey }
