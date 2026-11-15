//go:build !darwin && !linux

package vaultfilebackend

import (
	"errors"
	"testing"
)

func TestOpenExistingDirUnsupported(t *testing.T) {
	dir, err := OpenExistingDir("")
	if dir != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("UNSUPPORTED_DIRECTORY_PLATFORM_ACCEPTED")
	}
}
