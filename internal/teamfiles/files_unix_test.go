//go:build unix

package teamfiles

import (
	"os"
	"path/filepath"
	"testing"
)

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
