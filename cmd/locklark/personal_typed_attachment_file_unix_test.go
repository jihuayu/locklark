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

	"github.com/jihuayu/locklark/internal/vault"
)

func requireRefusedAttachment(t *testing.T, path string) {
	t.Helper()
	raw, err := readTypedAttachmentFile(path)
	if !errors.Is(err, errTypedInputRefused) || raw != nil {
		t.Fatalf("expected fixed attachment refusal for %s, got raw=%x err=%v", filepath.Base(path), raw, err)
	}
	if text := err.Error(); strings.Contains(text, path) || strings.Contains(text, "canary") {
		t.Fatalf("refusal echoed path or content: %q", text)
	}
}

func TestReadTypedAttachmentFileRefusesUnsafeSources(t *testing.T) {
	t.Run("public-mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary.bin")
		writePrivateTypedFixture(t, path, []byte("canary\x00body"))
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		requireRefusedAttachment(t, path)
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.bin")
		writePrivateTypedFixture(t, target, []byte("canary\x00body"))
		link := filepath.Join(dir, "link.bin")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		requireRefusedAttachment(t, link)
	})
	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "canary.fifo")
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Skipf("FIFO unavailable: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := readTypedAttachmentFile(path)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, errTypedInputRefused) {
				t.Fatalf("expected fixed FIFO refusal, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("attachment FIFO read waited for a writer")
		}
	})
}

func TestValidPrivateTypedStatAttachmentBound(t *testing.T) {
	const euid = 1000
	regularPrivate := uint32(unix.S_IFREG) | 0600
	if !validPrivateTypedStatBound(regularPrivate, euid, vault.MaxAttachmentSize, euid, vault.MaxAttachmentSize) {
		t.Fatal("exact per-attachment limit must be accepted")
	}
	if validPrivateTypedStatBound(regularPrivate, euid, vault.MaxAttachmentSize+1, euid, vault.MaxAttachmentSize) {
		t.Fatal("per-attachment limit must be enforced")
	}
	if validPrivateTypedStatBound(regularPrivate, euid, maxTypedInputBytes+1, euid, maxTypedInputBytes) {
		t.Fatal("document limit must stay at 1 MiB")
	}
}
