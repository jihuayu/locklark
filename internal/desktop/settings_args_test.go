package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDesktopArgsDefaultSelection proves that no arguments select the existing
// default settings path and that a new App keeps that default untouched.
func TestDesktopArgsDefaultSelection(t *testing.T) {
	path, err := parseDesktopArgs(nil)
	if err != nil || path != "" {
		t.Fatalf("parseDesktopArgs(nil) = %q, %v; want the default", path, err)
	}
	a := New()
	if a.settingsPath != SettingsPath() {
		t.Fatalf("New settings path = %q, want SettingsPath() %q", a.settingsPath, SettingsPath())
	}
	if a.settings != DefaultSettings() {
		t.Fatal("New must start from DefaultSettings before LoadSettings")
	}
}

// TestDesktopArgsAcceptsExplicitSettingsPath proves the one supported option
// selects exactly the clean absolute path and does not touch the file.
func TestDesktopArgsAcceptsExplicitSettingsPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	got, err := parseDesktopArgs([]string{"--settings", path})
	if err != nil || got != path {
		t.Fatalf("parseDesktopArgs = %q, %v; want %q", got, err, path)
	}
	if got := SettingsPath(); got == path {
		t.Fatalf("SettingsPath() unexpectedly equals the explicit path %q", path)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parsing must not read or create the settings file: %v", err)
	}
}

// TestDesktopArgsRejectsInvalidArguments proves every unsupported form fails
// closed before startup with a fixed message that never echoes the argument.
func TestDesktopArgsRejectsInvalidArguments(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "settings.json")
	usage := []struct {
		name string
		args []string
	}{
		{"missing value", []string{"--settings"}},
		{"duplicate", []string{"--settings", abs, "--settings", abs}},
		{"duplicate different", []string{"--settings", abs, "--settings", filepath.Join(t.TempDir(), "settings.json")}},
		{"equals form", []string{"--settings=" + abs}},
		{"unknown option", []string{"--verbose"}},
		{"unknown positional", []string{"settings.json"}},
		{"trailing argument", []string{"--settings", abs, "extra"}},
	}
	for _, c := range usage {
		got, err := parseDesktopArgs(c.args)
		var usageErr *UsageError
		if got != "" || !errors.As(err, &usageErr) || err.Error() != desktopSettingsUsage {
			t.Errorf("%s: parseDesktopArgs(%q) = %q, %v; want UsageError", c.name, c.args, got, err)
			continue
		}
		if strings.Contains(err.Error(), abs) || strings.Contains(strings.ToLower(err.Error()), "verbose") {
			t.Errorf("%s: usage message echoed the argument: %q", c.name, err)
		}
		if err := RunDesktopArgs(c.args); !errors.As(err, &usageErr) {
			t.Errorf("%s: RunDesktopArgs did not refuse the arguments before startup", c.name)
		}
	}
	// Bad paths fail before startup with ErrSettingsPath.
	for name, path := range map[string]string{"relative": "settings.json", "relative dot": "./settings.json", "non-clean": abs + "/", "dot segments": filepath.Dir(abs) + "/./settings.json", "nul": abs + "\x00", "empty value": ""} {
		args := []string{"--settings", path}
		got, err := parseDesktopArgs(args)
		if got != "" || !errors.Is(err, ErrSettingsPath) || strings.Contains(err.Error(), abs) {
			t.Errorf("%s: parseDesktopArgs(%q) = %q, %v; want path-free ErrSettingsPath", name, args, got, err)
		}
		if err := RunDesktopArgs(args); !errors.Is(err, ErrSettingsPath) {
			t.Errorf("%s: RunDesktopArgs did not refuse the path before startup", name)
		}
	}
}

// TestValidateSettingsFilePath proves the path-only validation used by
// RunWithSettingsPath and RunDesktopArgs.
func TestValidateSettingsFilePath(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "settings.json")
	for _, path := range []string{abs, filepath.Join(dir, "nested", ".settings.json"), "/settings.json"} {
		if got, err := validateSettingsFilePath(path); err != nil || got != path {
			t.Errorf("validateSettingsFilePath(%q) = %q, %v", path, got, err)
		}
	}
	for _, path := range []string{"", "settings.json", "./settings.json", "../settings.json", abs + "/..", abs + "/.", abs + "/", "/", dir, abs + "\x00"} {
		if _, err := validateSettingsFilePath(path); !errors.Is(err, ErrSettingsPath) {
			t.Errorf("validateSettingsFilePath(%q) error = %v, want ErrSettingsPath", path, err)
		}
	}
	if _, err := parseDesktopArgs([]string{"--settings", ".."}); err == nil {
		t.Fatal("parseDesktopArgs accepted a relative parent path")
	}
	// RunWithSettingsPath must reject before opening the GUI, with a fixed,
	// path-free error.
	for _, path := range []string{"settings.json", "./settings.json", abs + "\x00", abs + "/"} {
		if err := RunWithSettingsPath(path); !errors.Is(err, ErrSettingsPath) || strings.Contains(err.Error(), filepath.Dir(abs)) {
			t.Errorf("RunWithSettingsPath(%q) = %v, want path-free ErrSettingsPath", path, err)
		}
	}
}
