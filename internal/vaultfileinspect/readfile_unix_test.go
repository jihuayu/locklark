//go:build unix

package vaultfileinspect

import (
	"crypto/sha256"
	"errors"
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
		t.Fatal("final symlink input was accepted")
	}
	if after := sha256.Sum256(mustRead(t, target)); after != before {
		t.Fatal("symlink read changed the target")
	}

	realDir := filepath.Join(dir, "real-dir")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(realDir, "file")
	if err := os.WriteFile(inside, []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	got, err := readRegular(filepath.Join(linkDir, "file"), 6)
	if err != nil || string(got) != "inside" {
		t.Fatalf("intermediate directory symlink was not allowed: %v", err)
	}
	if after := sha256.Sum256(mustRead(t, inside)); after != sha256.Sum256([]byte("inside")) {
		t.Fatal("intermediate symlink read changed the file")
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

func TestReadRegularObserverProvesFDClosed(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("four"), 0600); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(dir, "oversize")
	if err := os.WriteFile(oversize, []byte("fives"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	assertClosed := func(fd int) {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("opened descriptor was not closed")
		}
	}
	read := func(path string, max int64, wantErr bool) {
		var fds []int
		_, err := readRegularWithObserver(path, max, func(fd int) { fds = append(fds, fd) })
		if (err != nil) != wantErr || len(fds) != 1 {
			t.Fatalf("observer result mismatch for %s", path)
		}
		assertClosed(fds[0])
	}
	read(regular, 4, false)
	read(fifo, 4, true)
	read(oversize, 4, true)
}
