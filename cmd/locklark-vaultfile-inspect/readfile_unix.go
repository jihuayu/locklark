//go:build unix

package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// readRegular opens one final-component no-follow descriptor with O_NOCTTY
// and O_NONBLOCK, fstats that exact handle as a regular file, and only then
// performs a bounded read. O_NOFOLLOW is intentionally final-component only:
// legitimate intermediate directory symlinks (for example /tmp or /var on
// macOS) remain usable. The explicit path grants no policy authority; the
// caller-pinned checkpoint is the trust input.
func readRegular(path string, max int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.New("input")
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("input")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > max {
		return nil, errors.New("input")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		clear(raw)
		return nil, errors.New("input")
	}
	return raw, nil
}
