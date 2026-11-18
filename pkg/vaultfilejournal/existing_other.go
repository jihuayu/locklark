//go:build !darwin && !linux && !windows

package vaultfilejournal

import bolt "go.etcd.io/bbolt"

func openExistingOnlyDatabase(string, func(*bolt.Tx) error) (*Journal, error) {
	return nil, ErrUnsupported
}
