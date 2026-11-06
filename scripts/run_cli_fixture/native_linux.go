//go:build linux

package main

import (
	"golang.org/x/sys/unix"
	"syscall"
)

func terminalEcho() bool {
	fd, e := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if e != nil {
		return false
	}
	defer unix.Close(fd)
	state, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	return e == nil && state.Lflag&unix.ECHO != 0
}
func execControllingTTY(terminal, program string, args, env []string) {
	fd, e := unix.Open(terminal, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if e != nil {
		panic("controlling terminal unavailable")
	}
	if unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0) != nil {
		unix.Close(fd)
		panic("controlling terminal ownership failed")
	}
	unix.Close(fd)
	if syscall.Exec(program, args, env) != nil {
		panic("normal CLI exec failed")
	}
}
func execGH(program string, args, env []string) {
	if syscall.Exec(program, args, env) != nil {
		panic("actual gh exec failed")
	}
}
