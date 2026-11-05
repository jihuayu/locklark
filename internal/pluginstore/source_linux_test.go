package pluginstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPackageFIFORefusedWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if e := syscall.Mkfifo(path, 0600); e != nil {
		t.Fatal(e)
	}
	link := path + "-link"
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	for _, source := range []string{path, link} {
		if _, e := ReadPackage(source); e != ErrInvalid {
			t.Fatal("FIFO package source", e)
		}
		if _, e := ReadPins(source); e != ErrInvalid {
			t.Fatal("FIFO pins source", e)
		}
	}
}
