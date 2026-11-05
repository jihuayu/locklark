//go:build unix

package management

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRejectsWritableFilesAndParents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	if e := os.WriteFile(path, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := openTrustedConfiguration(path)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if e = os.Chmod(path, 0666); e != nil {
		t.Fatal(e)
	}
	if f, e = openTrustedConfiguration(path); e == nil {
		f.Close()
		t.Fatal("world writable pins trusted")
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	if f, e = openTrustedConfiguration(path); e == nil {
		f.Close()
		t.Fatal("writable parent trusted")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "symlink.json")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if f, e = openTrustedConfiguration(link); e == nil {
		f.Close()
		t.Fatal("symlink config trusted")
	}
}
func TestConnectionRejectsWritableParentAndPublicRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connection.json")
	c := Connection{Version: 1, URL: "http://127.0.0.1:3418", Token: strings.Repeat("a", 64)}
	if e := os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	if e := WriteConnection(path, c); e == nil {
		t.Fatal("published into replaceable directory")
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := WriteConnection(path, c); e != nil {
		t.Fatal(e)
	}
	if got, e := ReadConnection(path); e != nil || got != c {
		t.Fatal("private roundtrip", e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadConnection(path); e == nil {
		t.Fatal("publicly readable credential accepted")
	}
}
