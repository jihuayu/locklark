//go:build !darwin && !linux

package vaultfilejournal

import (
	"path/filepath"
	"testing"
)

func TestCreateNewStateUnsupported(t *testing.T) {
	if CreateNewState(filepath.Join(t.TempDir(), "new.db"), State{}) != ErrUnsupported {
		t.Fatal("CREATE_UNSUPPORTED_TARGET_ACCEPTED")
	}
}
