//go:build !darwin && !linux && !windows

package vaultfilejournal

func openExistingOnlyDatabase(string) (*Journal, error) { return nil, ErrUnsupported }
