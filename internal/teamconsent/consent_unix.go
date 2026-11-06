//go:build unix

package teamconsent

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
)

func openTerminal() (*os.File, *os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, ErrTrust
	}
	return f, f, nil
}
func prepareInput(f *os.File) (func(context.Context) (byte, error), func() error, error) {
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return nil, nil, ErrTrust
	}
	if unix.SetNonblock(int(f.Fd()), true) != nil {
		return nil, nil, ErrTrust
	}
	restore := func() error { _, err := unix.FcntlInt(f.Fd(), unix.F_SETFL, flags); return err }
	read := func(ctx context.Context) (byte, error) {
		var b [1]byte
		for ctx.Err() == nil {
			fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 100)
			if err == unix.EINTR {
				continue
			}
			if err != nil || fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return 0, ErrTrust
			}
			if n == 0 {
				continue
			}
			n, err = unix.Read(int(f.Fd()), b[:])
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			if err != nil || n != 1 {
				return 0, ErrTrust
			}
			return b[0], nil
		}
		return 0, ErrTrust
	}
	return read, restore, nil
}
