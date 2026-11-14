//go:build unix

package vaultfileinspect

import (
	"os"
	"testing"
)

func createPrivateOutput(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private output creation failed")
	}
	return f
}

func assertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("output is not private 0600")
	}
}
