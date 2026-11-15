//go:build unix

package main

import (
	"context"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func terminalSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} }
func prepareTerminalInput(console *os.File) (func(context.Context) (byte, error), func() error, error) {
	fd := int(console.Fd())
	flags, e := unix.FcntlInt(console.Fd(), unix.F_GETFL, 0)
	if e != nil {
		return nil, nil, errCommand
	}
	if unix.SetNonblock(fd, true) != nil {
		return nil, nil, errCommand
	}
	restore := func() error { _, e := unix.FcntlInt(console.Fd(), unix.F_SETFL, flags); return e }
	read := func(ctx context.Context) (byte, error) {
		var input [1]byte
		defer clear(input[:])
		for ctx.Err() == nil {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, e := unix.Poll(fds, 100)
			if e == unix.EINTR {
				continue
			}
			if e != nil {
				return 0, errCommand
			}
			if n == 0 {
				continue
			}
			if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return 0, errCommand
			}
			if ctx.Err() != nil {
				return 0, errCommand
			}
			n, e = unix.Read(fd, input[:])
			if e == unix.EINTR || e == unix.EAGAIN {
				continue
			}
			if e != nil || n != 1 {
				return 0, errCommand
			}
			return input[0], nil
		}
		return 0, errCommand
	}
	return read, restore, nil
}
