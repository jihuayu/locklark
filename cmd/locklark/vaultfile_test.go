package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultfileInspectDispatch(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "vaultfileinspect", "testdata")
	file := filepath.Join(fixture, "vault.ll")
	checkpoint := filepath.Join(fixture, "checkpoint.json")
	var out bytes.Buffer
	if err := run([]string{"vaultfile", "inspect", "--file", file, "--checkpoint", checkpoint}, &out, io.Discard); err != nil {
		t.Fatal("vaultfile inspect dispatch failed")
	}
	if !strings.Contains(out.String(), `"result":"verified"`) || !strings.Contains(out.String(), `"payload":"not_decrypted"`) {
		t.Fatal("vaultfile inspect dispatch output mismatch")
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"vaultfile", "inspect", "--file", file, "--checkpoint", filepath.Join(t.TempDir(), "missing.json")}, &out, io.Discard); err == nil {
		t.Fatal("missing checkpoint was accepted")
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("missing-checkpoint dispatch changed the file")
	}
}
