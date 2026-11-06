//go:build linux || darwin

package desktop

import (
	"github.com/jihuayu/locklark/internal/personal"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNativeSSHImportDoesNotBlockOnFIFOOrFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("FIFO fixture failed")
	}
	done := make(chan error, 1)
	go func() { value, e := readSSHImport(fifo); clear(value); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("nonregular import accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("private key importer blocked on FIFO")
	}
	path := filepath.Join(dir, "ordinary")
	if os.WriteFile(path, []byte("public invalid fixture"), 0600) != nil {
		t.Fatal("ordinary fixture failed")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink fixture failed")
	}
	if value, e := readSSHImport(link); e == nil {
		clear(value)
		t.Fatal("private importer followed a symlink")
	}
	if os.WriteFile(path, make([]byte, personal.MaxSSHImport+1), 0600) != nil {
		t.Fatal("oversized fixture failed")
	}
	if value, e := readSSHImport(path); e == nil {
		clear(value)
		t.Fatal("private importer accepted an oversized file")
	}
}
