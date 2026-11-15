//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/personal"
)

type vaultFileDevicePublicPTYResult struct {
	Status string            `json:"status"`
	Echoed bool              `json:"echoed"`
	Public map[string]string `json:"public"`
}

func publicDeviceProductFixture(t *testing.T) (string, []byte, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "personal.ll")
	password := []byte("owned-product-master-factor")
	secret := bytes.Repeat([]byte{0x4b}, 16)
	if err := personal.Create(path, string(password), secret); err != nil {
		t.Fatal("PUBLIC_PRODUCT_FIXTURE_CREATE_FAILED")
	}
	formatted := personal.FormatSecret(secret)
	clear(secret)
	return path, password, formatted
}

// The Python stdlib owns the controlling PTY and never prints its transcript.
// Both factors travel through its stdin pipe, then into the real product's
// hidden terminal prompts; neither factor is placed in argv or the environment.
func runVaultFileDevicePublicProduct(t *testing.T, product, path string, password []byte, secret string, missingSecret bool) vaultFileDevicePublicPTYResult {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("PUBLIC_PRODUCT_PTY_RUNTIME_UNAVAILABLE")
	}
	request, err := json.Marshal(struct {
		Product       string `json:"product"`
		Path          string `json:"path"`
		Password      string `json:"password"`
		Secret        string `json:"secret"`
		MissingSecret bool   `json:"missing_secret"`
	}{product, path, string(password), secret, missingSecret})
	if err != nil {
		t.Fatal("PUBLIC_PRODUCT_PTY_REQUEST_FAILED")
	}
	defer clear(request)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join("testdata", "vault_file_device_public_pty.py"))
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("PUBLIC_PRODUCT_PTY_EXECUTION_FAILED")
	}
	var result vaultFileDevicePublicPTYResult
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("PUBLIC_PRODUCT_PTY_VERDICT_INVALID")
	}
	return result
}

func TestVaultFileDevicePublicProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	path, password, secret := publicDeviceProductFixture(t)
	defer clear(password)
	first := runVaultFileDevicePublicProduct(t, product, path, password, secret, false)
	if first.Status != "PUBLIC" || first.Echoed || len(first.Public) != 2 {
		t.Fatal("PUBLIC_PRODUCT_MINIMUM_FAILED")
	}
	if _, err := age.ParseX25519Recipient(first.Public["age_recipient"]); err != nil {
		t.Fatal("PUBLIC_PRODUCT_RECIPIENT_INVALID")
	}
	key, err := hex.DecodeString(first.Public["content_signing_public_key"])
	if err != nil || len(key) != 32 || hex.EncodeToString(key) != first.Public["content_signing_public_key"] {
		t.Fatal("PUBLIC_PRODUCT_SIGNER_INVALID")
	}
	second := runVaultFileDevicePublicProduct(t, product, path, password, secret, false)
	if second.Status != "PUBLIC" || second.Echoed || len(second.Public) != 2 ||
		second.Public["age_recipient"] != first.Public["age_recipient"] ||
		second.Public["content_signing_public_key"] != first.Public["content_signing_public_key"] {
		t.Fatal("PUBLIC_PRODUCT_FULL_FACTOR_IDENTITY_UNSTABLE")
	}
}

func TestVaultFileDevicePublicProductFactorRefusal(t *testing.T) {
	product := vaultFileProductBinary(t)
	path, password, secret := publicDeviceProductFixture(t)
	defer clear(password)
	for _, tc := range []struct {
		name, secret string
		password     []byte
		missing      bool
	}{
		{"wrong-password", secret, []byte("wrong-product-master"), false},
		{"wrong-secret", personal.FormatSecret(bytes.Repeat([]byte{0x6a}, 16)), password, false},
		{"missing-secret", secret, password, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runVaultFileDevicePublicProduct(t, product, path, tc.password, tc.secret, tc.missing)
			if result.Status != "REFUSED" || result.Echoed || result.Public != nil {
				t.Fatal("PUBLIC_PRODUCT_FACTOR_REFUSAL_FAILED")
			}
		})
	}
}

// A prompt-following child that crashes, exits with a different status or
// reports another error must not be counted as a factor refusal. These are
// separate real child processes under the same PTY helper, not a mock verdict.
func TestVaultFileDevicePublicPTYRefusalClassifier(t *testing.T) {
	const prompts = "#!/bin/sh\nstty -echo\nprintf '主密码: '\nIFS= read -r ignored\nprintf '\nSecret Key: '\nIFS= read -r ignored\n"
	for _, tc := range []struct {
		name, ending string
	}{
		{"wrong-exit", "printf '\nlocklark: invalid personal vault, unlock factors or journal\n'\nexit 2\n"},
		{"unrelated-error", "printf '\nlocklark: unrelated error\n'\nexit 1\n"},
		{"signaled", "printf '\nlocklark: invalid personal vault, unlock factors or journal\n'\nkill -TERM $$\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := filepath.Join(t.TempDir(), "owned-child")
			if err := os.WriteFile(fake, []byte(prompts+tc.ending), 0700); err != nil {
				t.Fatal("PTY_CONTRACT_CHILD_CREATE_FAILED")
			}
			result := runVaultFileDevicePublicProduct(t, fake, filepath.Join(t.TempDir(), "unused.ll"), []byte("owned-factor"), "owned-secret", false)
			if result.Status != "HARNESS_ERROR" || result.Echoed || result.Public != nil {
				t.Fatal("PTY_CONTRACT_FALSE_FACTOR_REFUSAL")
			}
		})
	}
}
