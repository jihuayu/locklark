//go:build windows

package vaultfileclient

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStatusPathWindowsVolumes(t *testing.T) {
	for _, tt := range []struct {
		path, volume, root string
		components         []string
	}{
		{path: `C:\one\two`, volume: `C:`, root: `C:\`, components: []string{"one", "two"}},
		{path: `\\server\share\one`, volume: `\\server\share`, root: `\\server\share\`, components: []string{"one"}},
	} {
		if filepath.VolumeName(tt.path) != tt.volume {
			t.Fatal("STATUS_SCOPE_WINDOWS_VOLUME_FAILED")
		}
		root, components := statusPathRootComponents(tt.path, filepath.VolumeName(tt.path), string(os.PathSeparator))
		if root != tt.root || !reflect.DeepEqual(components, tt.components) {
			t.Fatal("STATUS_SCOPE_WINDOWS_WALK_ROOT_FAILED")
		}
	}
}

func TestStatusExistingDirStartsAtDriveRoot(t *testing.T) {
	dir := t.TempDir()
	resolved, absent, err := statusExistingDir(dir)
	if err != nil || absent {
		t.Fatal("STATUS_SCOPE_WINDOWS_EXISTING_DRIVE_PATH_REJECTED")
	}
	want, err := os.Stat(dir)
	if err != nil {
		t.Fatal("STATUS_SCOPE_WINDOWS_FIXTURE_STAT_FAILED")
	}
	got, err := os.Stat(resolved)
	if err != nil || !os.SameFile(want, got) {
		t.Fatal("STATUS_SCOPE_WINDOWS_WRONG_DRIVE_PATH")
	}
	_, absent, err = statusExistingDir(filepath.Join(dir, "absent"))
	if err != nil || !absent {
		t.Fatal("STATUS_SCOPE_WINDOWS_ABSENT_CHILD_REJECTED")
	}
}
