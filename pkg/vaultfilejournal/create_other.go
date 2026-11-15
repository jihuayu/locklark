//go:build !darwin && !linux

package vaultfilejournal

func createNewState(string, State) error { return ErrUnsupported }
