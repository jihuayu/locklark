//go:build !windows

package main

// Bounded, owner-only read of `personal add-item --input`.
//
// The descriptor is opened without following a final symlink and without
// blocking on a FIFO. Every post-open check runs on the same descriptor that is
// read, so a path swap cannot redirect the read. The only accepted file is a
// regular file owned by the effective user with no group/other permission bits.
// Any refusal is the fixed errTypedInputRefused and clears a partially read
// buffer; no path, errno or file content is returned in the error.

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readTypedPersonalFile(path string) ([]byte, error) {
	// O_NONBLOCK makes opening a FIFO return immediately; the regular-file check
	// below then refuses it without waiting for a writer.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errTypedInputRefused
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errTypedInputRefused
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, errTypedInputRefused
	}
	if !validPrivateTypedStat(uint32(stat.Mode), uint32(stat.Uid), stat.Size, unix.Geteuid()) {
		return nil, errTypedInputRefused
	}

	raw, err := io.ReadAll(io.LimitReader(file, int64(maxTypedInputBytes)+1))
	if err != nil || len(raw) > maxTypedInputBytes {
		clear(raw)
		return nil, errTypedInputRefused
	}
	return raw, nil
}

// validPrivateTypedStat is deliberately pure so the ownership, regular-file,
// permission and size rules can be unit-tested without privileged filesystem
// setup. mode is the raw st_mode value and includes the file type bits.
func validPrivateTypedStat(mode, uid uint32, size int64, euid int) bool {
	if mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	if uid != uint32(euid) {
		return false
	}
	if mode&0077 != 0 {
		return false
	}
	return size >= 0 && size <= maxTypedInputBytes
}
