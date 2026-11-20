//go:build darwin || linux

package vaultfilebackend

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"syscall"
)

const stableIdentityDomain = "locklark vaultfilebackend dir stable identity v1\x00"

// StableIdentity returns a fixed, non-revealing digest of the exact established
// local backend instance this Dir was opened with. It re-validates every
// protected component against the identities captured by OpenDir and then
// hashes only those device/inode identities plus the lock file identity. It
// never returns a pathname or any raw filesystem identity value.
//
// The digest changes when the configured root, namespace, version, temporary or
// data directory is physically replaced, including by a same-content copy at a
// different path. Renaming the same directory in place keeps its identity, as
// it keeps os.SameFile. A closed backend is refused.
func (d *Dir) StableIdentity() ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if d == nil {
		return zero, ErrDenied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return zero, ErrDenied
	}
	if _, err := d.dir(); err != nil {
		return zero, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(stableIdentityDomain))
	parts := []struct {
		label string
		info  os.FileInfo
	}{
		{"root", d.identity.root},
		{"namespace", d.identity.ns},
		{"version", d.identity.v1},
		{"temporary", d.identity.tmp},
		{"data", d.identity.data},
		{"lock", d.lockID},
	}
	var buf [16]byte
	for _, part := range parts {
		if part.info == nil {
			return zero, ErrDenied
		}
		stat, ok := part.info.Sys().(*syscall.Stat_t)
		if !ok {
			return zero, ErrDenied
		}
		_, _ = h.Write([]byte(part.label))
		_, _ = h.Write([]byte{0})
		binary.BigEndian.PutUint64(buf[0:8], uint64(stat.Dev))
		binary.BigEndian.PutUint64(buf[8:16], stat.Ino)
		_, _ = h.Write(buf[:])
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
