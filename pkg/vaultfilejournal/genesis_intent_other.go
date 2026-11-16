//go:build !darwin && !linux

package vaultfilejournal

func openExistingIntentOnlyDatabase(string) (*Journal, error) { return nil, ErrUnsupported }
