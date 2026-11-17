//go:build !darwin && !linux

package vaultfilejournal

func createNewState(string, State) error                 { return ErrUnsupported }
func createNewGenesisIntent(string, GenesisIntent) error { return ErrUnsupported }
