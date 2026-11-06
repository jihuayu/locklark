//go:build !unix && !windows

package teambootstrapcli

import (
	"errors"
	"os/exec"
)

func configureDetached(*exec.Cmd) {}
func detachChildConsole() error   { return errors.New("unsupported console") }
