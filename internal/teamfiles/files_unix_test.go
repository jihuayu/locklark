//go:build unix

package teamfiles

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteNewRestrictiveUmaskChild(t *testing.T) {
	const helper = "LOCKLARK_TEAMFILES_RESTRICTIVE_UMASK_TEST"
	if os.Getenv(helper) == "1" {
		// Only this short-lived subprocess changes umask. The parent made
		// the private directory before starting the child.
		syscall.Umask(0777)
		path := os.Getenv("LOCKLARK_TEAMFILES_RESTRICTIVE_UMASK_PATH")
		want := []byte("private create manifest")
		if WriteNew(path, want) != nil {
			t.Fatal("WRITE_NEW_RESTRICTIVE_UMASK_FAILED")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("WRITE_NEW_PUBLISHED_NON_0600_FILE")
		}
		got, err := Read(path, 1024, true)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("WRITE_NEW_PUBLISHED_UNREADABLE_FILE")
		}
		if WriteNew(path, []byte("replacement")) == nil {
			t.Fatal("WRITE_NEW_REPLACED_EXISTING_FILE")
		}
		return
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal("PRIVATE_FIXTURE_FAILED")
	}
	path := filepath.Join(parent, "manifest")
	cmd := exec.Command(os.Args[0], "-test.run=^TestWriteNewRestrictiveUmaskChild$")
	cmd.Env = append(os.Environ(), helper+"=1", "LOCKLARK_TEAMFILES_RESTRICTIVE_UMASK_PATH="+path)
	if err := cmd.Run(); err != nil {
		t.Fatal("RESTRICTIVE_UMASK_CHILD_FAILED")
	}
}

func TestTransferRejectsSymlinksHardlinksAndUnsafeModes(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "record")
	if WriteNew(path, []byte("public")) != nil {
		t.Fatal("transfer setup")
	}
	alias := filepath.Join(parent, "alias")
	if os.Symlink(path, alias) != nil {
		t.Fatal("symlink setup")
	}
	if _, err := Read(alias, 100, true); err == nil {
		t.Fatal("symlink read accepted")
	}
	if WriteNew(alias, []byte("replacement")) == nil {
		t.Fatal("symlink output replaced")
	}
	if os.Link(path, filepath.Join(parent, "hardlink")) != nil {
		t.Fatal("hardlink setup")
	}
	if _, err := Read(path, 100, true); err == nil {
		t.Fatal("hardlinked transfer accepted")
	}
	if os.Remove(filepath.Join(parent, "hardlink")) != nil || os.Chmod(path, 0644) != nil {
		t.Fatal("mode setup")
	}
	if _, err := Read(path, 100, true); err == nil {
		t.Fatal("publicly readable private transfer accepted")
	}
	if _, err := Read(path, 100, false); err != nil {
		t.Fatal("safe public certificate mode refused")
	}
	if os.Chmod(parent, 0777) != nil {
		t.Fatal("parent setup")
	}
	if WriteNew(filepath.Join(parent, "new"), []byte("public")) == nil {
		t.Fatal("writable parent accepted")
	}
}
