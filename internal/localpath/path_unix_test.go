//go:build unix

package localpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedParentChecksAncestorsAndReturnsCanonicalPath(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	leaf := filepath.Join(parent, "private")
	if os.Mkdir(parent, 0700) != nil || os.Mkdir(leaf, 0700) != nil {
		t.Fatal("directory fixture failed")
	}
	if _, e := TrustedTemporaryParent(leaf); e != nil {
		t.Fatal("private directory rejected")
	}
	if os.Chmod(parent, 0777) != nil {
		t.Fatal("unsafe ancestor fixture failed")
	}
	if _, e := TrustedTemporaryParent(leaf); e == nil {
		t.Fatal("private leaf hid an unsafe ancestor")
	}
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("restore fixture failed")
	}
	alias := filepath.Join(root, "alias")
	if os.Symlink(leaf, alias) != nil {
		t.Fatal("alias fixture failed")
	}
	got, e := TrustedTemporaryParent(alias)
	want, e2 := filepath.EvalSymlinks(leaf)
	if e != nil || e2 != nil || got != want {
		t.Fatal("caller did not receive canonical trusted path")
	}
	if os.Chmod(leaf, 0755) != nil {
		t.Fatal("public leaf fixture failed")
	}
	if _, e = TrustedTemporaryParent(alias); e == nil {
		t.Fatal("nonprivate temporary parent accepted")
	}
}
func TestStandardRootOwnedStickyTmpIsAccepted(t *testing.T) {
	info, e := os.Stat("/tmp")
	if e != nil || info.Mode()&os.ModeSticky == 0 {
		t.Skip("no standard sticky temporary directory")
	}
	if _, e = TrustedTemporaryParent("/tmp"); e != nil {
		t.Fatal("standard root-owned sticky temp rejected")
	}
}
