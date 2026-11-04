package preview

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRejectIdleFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "manifest.json"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := read(dir, "manifest.json", 2048); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a snapshot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("untrusted FIFO stalled the read before file type validation")
	}
}
