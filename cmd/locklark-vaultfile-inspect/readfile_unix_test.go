//go:build unix

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadRegularRejectsSymlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(mustRead(t, target))
	if _, err := readRegular(link, 64); err == nil {
		t.Fatal("symlink input was accepted")
	}
	if after := sha256.Sum256(mustRead(t, target)); after != before {
		t.Fatal("symlink read changed the target")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readRegular(fifo, 64)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO input was accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO input blocked")
	}
}
