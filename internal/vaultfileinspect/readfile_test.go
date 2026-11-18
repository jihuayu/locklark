package vaultfileinspect

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularOwnedRegularBoundedUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	want := []byte("safe")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(want)
	got, err := readRegular(path, int64(len(want)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("regular read = %q, %v", got, err)
	}
	if after := sha256.Sum256(mustRead(t, path)); after != before {
		t.Fatal("read changed the input")
	}
	if _, err := readRegular(path, int64(len(want)-1)); err == nil {
		t.Fatal("oversized regular input was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readRegular(empty, 0); err != nil || len(got) != 0 {
		t.Fatalf("empty regular read = %q, %v", got, err)
	}
}
