package teambootstrapcli

import (
	"errors"
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

func configureDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}
func detachChildConsole() error {
	_, _, _ = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole").Call()
	cp, _ := windows.GetConsoleCP()
	if cp != 0 {
		return errors.New("console still attached")
	}
	return nil
}
