//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireRefusedFile(t *testing.T, path string) {
	t.Helper()
	raw, err := readTypedPersonalFile(path)
	if !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("expected fixed refusal for %s, got %v", filepath.Base(path), err)
	}
	if raw != nil {
		t.Fatalf("refusal returned a buffer for %s", filepath.Base(path))
	}
	if text := err.Error(); strings.Contains(text, path) || strings.Contains(text, "canary") {
		t.Fatalf("refusal echoed path or content: %q", text)
	}
}

func TestReadTypedPersonalFilePrivateRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json")
	want := []byte(`{"category":"identity","title":"private canary"}`)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readTypedPersonalFile(path)
	if err != nil {
		t.Fatalf("read private file: %v", err)
	}
	defer clear(got)
	if string(got) != string(want) {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestReadTypedPersonalFileRefusesPublicMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json")
	if err := os.WriteFile(path, []byte(`{"title":"canary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	requireRefusedFile(t, path)
}

func TestReadTypedPersonalFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"title":"canary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	requireRefusedFile(t, link)
}

func TestReadTypedPersonalFileRefusesFIFOWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readTypedPersonalFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errTypedInputRefused) {
			t.Fatalf("expected fixed FIFO refusal, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO read waited for a writer")
	}
}

func TestReadTypedPersonalFileRefusesOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "item.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(maxTypedInputBytes) + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	requireRefusedFile(t, path)
}

func TestReadTypedPersonalFileRefusesDirectory(t *testing.T) {
	requireRefusedFile(t, t.TempDir())
}

func TestValidPrivateTypedStat(t *testing.T) {
	const euid = 1000
	regularPrivate := uint32(unix.S_IFREG) | 0600
	for _, test := range []struct {
		name string
		mode uint32
		uid  uint32
		size int64
		want bool
	}{
		{"private regular", regularPrivate, euid, 0, true},
		{"read-only private", uint32(unix.S_IFREG) | 0400, euid, maxTypedInputBytes, true},
		{"directory", uint32(unix.S_IFDIR) | 0600, euid, 0, false},
		{"fifo", uint32(unix.S_IFIFO) | 0600, euid, 0, false},
		{"symlink stat", uint32(unix.S_IFLNK) | 0600, euid, 0, false},
		{"foreign owner", regularPrivate, euid + 1, 0, false},
		{"group read", regularPrivate | 0040, euid, 0, false},
		{"group write", regularPrivate | 0020, euid, 0, false},
		{"other read", regularPrivate | 0004, euid, 0, false},
		{"other write", regularPrivate | 0002, euid, 0, false},
		{"other execute", regularPrivate | 0001, euid, 0, false},
		{"too large", regularPrivate, euid, maxTypedInputBytes + 1, false},
		{"negative size", regularPrivate, euid, -1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validPrivateTypedStat(test.mode, test.uid, test.size, euid); got != test.want {
				t.Fatalf("validPrivateTypedStat = %v, want %v", got, test.want)
			}
		})
	}
}
