package personal

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInspectionRejectsIdleFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{fifo, link, "/dev/null"} {
		done := make(chan error, 1)
		go func() { _, err := readInspectionSource(source); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrInspectionSource) {
				t.Fatal("special source not refused", err)
			}
		case <-time.After(2 * time.Second):
			peer, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			peer.Close()
			t.Fatal("source read blocked on idle FIFO")
		}
	}
}
