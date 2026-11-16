//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The existing product-binary gate supplies one independently built CLI.
// Python's stdlib owns the PTY; only a finite verdict returns to this test.
func TestVaultFileCreatePrepareProductPTY(t *testing.T) {
	product := vaultFileProductBinary(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("CREATE_PREPARE_PTY_RUNTIME_UNAVAILABLE")
	}
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal("CREATE_PREPARE_PRIVATE_FIXTURE_FAILED")
	}
	request, err := json.Marshal(struct {
		Product string `json:"product"`
		Root    string `json:"root"`
	}{Product: product, Root: root})
	if err != nil {
		t.Fatal("CREATE_PREPARE_PTY_REQUEST_FAILED")
	}
	defer clear(request)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join("testdata", "vault_file_create_prepare_pty.py"))
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("CREATE_PREPARE_PTY_EXECUTION_FAILED")
	}
	var result struct {
		Stage string `json:"stage"`
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("CREATE_PREPARE_PTY_VERDICT_INVALID")
	}
	if result.Stage != "PASS" {
		// Do not print child output or runtime values. The finite stage is
		// enough to locate the broken product boundary.
		switch result.Stage {
		case "SETUP", "PERSONAL_INIT", "FIRST_CREATE", "PRIVATE_MANIFEST", "EXACT_RETRY",
			"BAD_FACTOR", "LEGACY_CONFIG", "UNSAFE_PARENT", "UNEXPECTED_PUBLICATION", "HARNESS_ERROR":
			t.Fatalf("CREATE_PREPARE_PRODUCT_%s", result.Stage)
		default:
			t.Fatal("CREATE_PREPARE_PTY_VERDICT_INVALID")
		}
	}
}
