//go:build !darwin && !linux

package vaultfilebackend

import "crypto/sha256"

// StableIdentity is unsupported on platforms without the local directory
// backend. It always fails closed and never invents an identity.
func (d *Dir) StableIdentity() ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	return zero, ErrUnsupported
}
