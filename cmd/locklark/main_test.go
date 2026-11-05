package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestDemoThenExplicitExport(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "demo")
	var out, diagnostics bytes.Buffer
	if err := run([]string{"demo", "--out", root, "--session", "migration", "--reason", "test"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("[1,2,3]")) {
		t.Fatal("demo output omits edited snapshot")
	}
	out.Reset()
	if err := run([]string{"fixture-export", "--bundle", filepath.Join(root, "share", "epoch-3"), "--device", filepath.Join(root, "clients", "B"), "--epoch", "3", "--out", filepath.Join(dir, "sample.1pux")}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("otpauth")) || !bytes.Contains(out.Bytes(), []byte("\"synthetic\":true")) {
		t.Fatal("unexpected export receipt")
	}
}
