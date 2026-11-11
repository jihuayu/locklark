//go:build linux || darwin

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestValidateSettingsFilePathRejectsSpecialFiles proves that an existing
// non-regular settings path (a FIFO that would block LoadSettings, or a device
// such as /dev/zero that would read unbounded data) fails closed before
// startup with the fixed ErrSettingsPath. It never touches the GUI or the
// per-user settings file.
func TestValidateSettingsFilePathRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "settings.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	link := filepath.Join(dir, "settings.link")
	if err := os.Symlink(filepath.Join(dir, "settings.json"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	regular := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	rejected := map[string]string{"fifo": fifo, "dangling symlink": link, "directory": dir}
	if fi, err := os.Lstat("/dev/zero"); err == nil && !fi.Mode().IsRegular() {
		rejected["device"] = "/dev/zero"
	}
	for name, path := range rejected {
		got, err := validateSettingsFilePath(path)
		if got != "" || !errors.Is(err, ErrSettingsPath) || strings.Contains(err.Error(), path) {
			t.Errorf("%s: validateSettingsFilePath(%q) = %q, %v; want path-free ErrSettingsPath", name, path, got, err)
		}
		if err := RunWithSettingsPath(path); !errors.Is(err, ErrSettingsPath) {
			t.Errorf("%s: RunWithSettingsPath did not refuse the path before startup: %v", name, err)
		}
	}
	if got, err := validateSettingsFilePath(regular); err != nil || got != regular {
		t.Errorf("validateSettingsFilePath(%q) = %q, %v; want the regular file accepted", regular, got, err)
	}
}
