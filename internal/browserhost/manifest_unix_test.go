//go:build unix

package browserhost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrationRejectsUnsafePathsAndReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if e := os.WriteFile(host, []byte("binary"), 0700); e != nil {
		t.Fatal(e)
	}
	unsafe := filepath.Join(dir, "unsafe")
	if os.Mkdir(unsafe, 0700) != nil || os.Chmod(unsafe, 0777) != nil {
		t.Fatal("unsafe fixture")
	}
	if e := Register("chrome", host, filepath.Join(unsafe, HostName+".json"), false); e == nil {
		t.Fatal("world-writable manifest ancestor accepted")
	}
	otherHost := filepath.Join(unsafe, "host")
	os.WriteFile(otherHost, []byte("binary"), 0700)
	if _, e := Manifest("chrome", otherHost); e == nil {
		t.Fatal("world-writable host ancestor accepted")
	}
	link := filepath.Join(dir, "host-link")
	if os.Symlink(host, link) != nil {
		t.Fatal("symlink fixture")
	}
	if _, e := Manifest("chrome", link); e == nil {
		t.Fatal("host symlink accepted")
	}
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("untouched"), 0600)
	output := filepath.Join(dir, HostName+".json")
	os.Symlink(victim, output)
	if e := Register("chrome", host, output, true); e == nil {
		t.Fatal("followed manifest symlink")
	}
	value, _ := os.ReadFile(victim)
	if string(value) != "untouched" {
		t.Fatal("overwrote symlink target")
	}
	// The checks above only need a temp path; the remaining success and atomic
	// replacement assertions require an owner-controlled ancestry.
	requireTrustedTempDir(t, dir)
	os.Remove(output)
	if Register("chrome", host, output, false) != nil {
		t.Fatal("safe registration")
	}
	old, e := os.Open(output)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	before, _ := old.Stat()
	if Register("edge", host, output, true) != nil {
		t.Fatal("atomic replace")
	}
	after, _ := os.Stat(output)
	if os.SameFile(before, after) {
		t.Fatal("replacement truncated old inode")
	}
	if e = os.Chmod(output, 0666); e != nil {
		t.Fatal(e)
	}
	if Register("chrome", host, output, true) == nil {
		t.Fatal("writable existing manifest accepted")
	}
}
