//go:build !windows

package main

import (
	"os"

	"golang.org/x/term"
)

func openRunCLIConsole() (*os.File, *os.File, error) {
	// /dev/tty is this process's controlling terminal, not an inherited
	// standard-stream descriptor. Opening it fails for a detached session.
	control, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return nil, nil, errRunCLIConsole
	}
	if !term.IsTerminal(int(control.Fd())) {
		control.Close()
		return nil, nil, errRunCLIConsole
	}
	return control, control, nil
}
