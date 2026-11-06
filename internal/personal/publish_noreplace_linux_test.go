//go:build linux

package personal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func publishFixtureFile(t *testing.T, dir string, value byte) string {
	t.Helper()
	f, e := os.CreateTemp(dir, "publish-staging-")
	if e != nil {
		t.Fatal("create publish fixture failed")
	}
	if _, e = f.Write(bytes.Repeat([]byte{value}, 4096)); e != nil {
		f.Close()
		t.Fatal("write publish fixture failed")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		t.Fatal("sync publish fixture failed")
	}
	if e = f.Close(); e != nil {
		t.Fatal("close publish fixture failed")
	}
	return f.Name()
}

func TestRenameNoReplaceKeepsExistingTargetUnchanged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "vault.ll")
	if e := os.WriteFile(target, bytes.Repeat([]byte{7}, 4096), 0600); e != nil {
		t.Fatal("existing target setup failed")
	}
	source := publishFixtureFile(t, dir, 9)
	if e := publishRenameNoReplace(source, target); !errors.Is(e, os.ErrExist) {
		t.Fatal("existing target was not refused")
	}
	value, e := os.ReadFile(target)
	if e != nil || !bytes.Equal(value, bytes.Repeat([]byte{7}, 4096)) {
		t.Fatal("existing target was changed")
	}
	if _, e = os.Stat(source); e != nil {
		t.Fatal("refused source was unexpectedly removed")
	}
}

func TestRenameNoReplaceConcurrentPublishHasOneCompleteWinner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "vault.ll")
	sources := []string{publishFixtureFile(t, dir, 11), publishFixtureFile(t, dir, 13)}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, source := range sources {
		workers.Add(1)
		go func(path string) { defer workers.Done(); <-start; results <- publishRenameNoReplace(path, target) }(source)
	}
	close(start)
	workers.Wait()
	close(results)
	won, refused := 0, 0
	for e := range results {
		if e == nil {
			won++
		} else if errors.Is(e, os.ErrExist) {
			refused++
		} else {
			t.Fatal("concurrent publication failed unexpectedly")
		}
	}
	if won != 1 || refused != 1 {
		t.Fatal("concurrent publication did not have exactly one winner")
	}
	value, e := os.ReadFile(target)
	if e != nil || !bytes.Equal(value, bytes.Repeat([]byte{11}, 4096)) && !bytes.Equal(value, bytes.Repeat([]byte{13}, 4096)) {
		t.Fatal("published winner was incomplete or mixed")
	}
}

func TestRenameNoReplaceSyncFailureLeavesCompletePublishedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "vault.ll")
	source := publishFixtureFile(t, dir, 17)
	e := publishRenameNoReplaceWith(source, target, unix.Renameat2, func(dir *os.File) error { _ = dir.Close(); return dir.Sync() })
	if e == nil {
		t.Fatal("directory sync failure reported success")
	}
	value, e := os.ReadFile(target)
	if e != nil || !bytes.Equal(value, bytes.Repeat([]byte{17}, 4096)) {
		t.Fatal("sync failure lost the complete published file")
	}
	if _, e = os.Stat(source); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("successful publication did not consume staging name")
	}
}

func TestRenameNoReplaceUnsupportedKernelFailsClosed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "vault.ll")
	source := publishFixtureFile(t, dir, 19)
	called := 0
	e := publishRenameNoReplaceWith(source, target, func(int, string, int, string, uint) error { called++; return unix.ENOSYS }, (*os.File).Sync)
	if !errors.Is(e, unix.ENOSYS) || called != 1 {
		t.Fatal("unsupported rename was not reported")
	}
	if _, e = os.Stat(target); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unsupported rename used an unsafe publication fallback")
	}
	if _, e = os.Stat(source); e != nil {
		t.Fatal("unsupported rename lost the staging file")
	}
}
