package main

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func detachRunCLIConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}

func prepareRunCLIConsoleProbe() (bool, error) {
	before, _ := windows.GetConsoleCP()
	// Establish a real native no-console precondition in this test child;
	// do not infer it from window visibility or process creation flags.
	free := windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
	if free.Find() != nil {
		return before != 0, errors.New("native console detach unavailable")
	}
	free.Call()
	after, _ := windows.GetConsoleCP()
	if after != 0 {
		return before != 0, errors.New("native console remains attached")
	}
	return before != 0, nil
}
