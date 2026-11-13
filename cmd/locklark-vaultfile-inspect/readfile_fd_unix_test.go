//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularClosesOwnFDs(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	// Warm every path once before counting; failures intentionally include a
	// final symlink and a non-regular input.
	if _, err := readRegular(regular, 1); err != nil {
		t.Fatal(err)
	}
	_, _ = readRegular(link, 1)

	count := func() int {
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Fatal("open descriptor count failed")
		}
		return len(entries)
	}
	before := count()
	for i := 0; i < 32; i++ {
		if _, err := readRegular(regular, 1); err != nil {
			t.Fatal(err)
		}
		_, _ = readRegular(link, 1)
	}
	after := count()
	if before != after {
		t.Fatalf("reader leaked descriptors: %d -> %d", before, after)
	}
}
