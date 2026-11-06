//go:build unix

package teambootstrapcli

import (
	"os/exec"
	"syscall"
)

func configureDetached(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func detachChildConsole() error       { return nil }
