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

	"github.com/jihuayu/locklark/internal/vault"
)

// readTypedPersonalFile bounds the JSON input document at the historic 1 MiB.
func readTypedPersonalFile(path string) ([]byte, error) {
	return readPrivateTypedFile(path, maxTypedInputBytes)
}

// readTypedAttachmentFile bounds one explicit attachment at the native
// per-attachment limit. Binary bodies are not required to be UTF-8 and a
// zero-length file is accepted.
func readTypedAttachmentFile(path string) ([]byte, error) {
	return readPrivateTypedFile(path, vault.MaxAttachmentSize)
}

// readPrivateTypedFile is the single owner-only descriptor reader shared by the
// JSON document and binary attachment paths. O_NONBLOCK makes opening a FIFO
// return immediately; the regular-file check below then refuses it without
// waiting for a writer.
func readPrivateTypedFile(path string, limit int64) ([]byte, error) {
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
	if !validPrivateTypedStatBound(uint32(stat.Mode), uint32(stat.Uid), stat.Size, unix.Geteuid(), limit) {
		return nil, errTypedInputRefused
	}

	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, errTypedInputRefused
	}
	return raw, nil
}

// validPrivateTypedStat is the historic 1 MiB JSON bound retained for tests
// and callers of the document reader.
func validPrivateTypedStat(mode, uid uint32, size int64, euid int) bool {
	return validPrivateTypedStatBound(mode, uid, size, euid, maxTypedInputBytes)
}

// validPrivateTypedStatBound is deliberately pure so the ownership,
// regular-file, permission and size rules can be unit-tested without
// privileged filesystem setup. mode is the raw st_mode value and includes the
// file type bits; limit is the same byte bound the reader enforces.
func validPrivateTypedStatBound(mode, uid uint32, size int64, euid int, limit int64) bool {
	if mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	if uid != uint32(euid) {
		return false
	}
	if mode&0077 != 0 {
		return false
	}
	return size >= 0 && size <= limit
}
