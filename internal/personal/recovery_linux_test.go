package personal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRestoreRejectsIdleFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "untrusted-backup")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"direct", "symlink"} {
		t.Run(name, func(t *testing.T) {
			source := fifo
			if name == "symlink" {
				source = filepath.Join(dir, "link")
				if err := os.Symlink(fifo, source); err != nil {
					t.Fatal(err)
				}
			}
			dest := filepath.Join(dir, "restored")
			done := make(chan error, 1)
			go func() {
				r, err := PrepareRestore(source, dest, "synthetic", bytes.Repeat([]byte{1}, 16), "synthetic-material")
				if r != nil {
					r.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrArchiveType) {
					t.Fatal("FIFO not rejected as a nonregular backup", err)
				}
			case <-time.After(2 * time.Second):
				// Unblock the old implementation so a failing regression test
				// does not strand a goroutine or leak a file descriptor.
				peer, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("FIFO reader did not exit after unblocking")
				}
				t.Fatal("untrusted FIFO blocked restore before file type validation")
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatal("rejected source left a restored vault")
			}
		})
	}
}

func TestRestoreAcceptsRegularFileThroughSymlink(t *testing.T) {
	archive, pw, key, kit := recoveryFixture(t)
	dir := t.TempDir()
	link, dest := filepath.Join(dir, "backup-link"), filepath.Join(dir, "restored")
	if err := os.Symlink(archive, link); err != nil {
		t.Fatal(err)
	}
	r, err := PrepareRestore(link, dest, pw, key, kit)
	if err != nil {
		t.Fatal("regular backup link rejected", err)
	}
	defer r.Close()
	fresh := bytes.Repeat([]byte{5}, 16)
	if err = r.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	events, err := Audit(dest, pw, fresh)
	if err != nil || len(events) != 2 || events[0].Action != "vault.restore" {
		t.Fatal("regular backup restore did not retain its audited lifecycle", err)
	}
}
