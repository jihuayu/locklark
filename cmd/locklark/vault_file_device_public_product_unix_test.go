//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
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

// Only the fixture's signed, encrypted snapshot is read. Neither its device
// slot nor the personal identity is opened by the test's expected-value path.
func publicDeviceFixtureSnapshot(t *testing.T, path string) vault.Snapshot {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal("PUBLIC_PRODUCT_SNAPSHOT_OPEN_FAILED")
	}
	var snapshot vault.Snapshot
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("locklark.personal/v1"))
		if bucket == nil {
			return vault.ErrSnapshot
		}
		raw := bucket.Get([]byte("snapshot"))
		if len(raw) == 0 || len(raw) > vault.MaxStoredSnapshot()+vault.MaxStoredSnapshot()/2 {
			return vault.ErrSnapshot
		}
		return json.Unmarshal(raw, &snapshot)
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatal("PUBLIC_PRODUCT_SNAPSHOT_READ_FAILED")
	}
	return snapshot
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
	snapshot := publicDeviceFixtureSnapshot(t, path)
	if vault.VerifySnapshot(snapshot, ed25519.PublicKey(key), snapshot.Epoch) != nil {
		t.Fatal("PUBLIC_PRODUCT_SIGNER_NOT_SNAPSHOT_AUTHORITY")
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

// These children produce well-shaped public JSON but add a second output,
// another field or a factor disclosure. The PTY result must reject the whole
// transcript instead of silently taking its last JSON line.
func TestVaultFileDevicePublicPTYDisclosureClassifier(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("PTY_DISCLOSURE_PUBLIC_FIXTURE_FAILED")
	}
	signer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("PTY_DISCLOSURE_PUBLIC_FIXTURE_FAILED")
	}
	fields := map[string]string{
		"age_recipient":              identity.Recipient().String(),
		"content_signing_public_key": hex.EncodeToString(signer),
	}
	record, err := json.Marshal(fields)
	if err != nil {
		t.Fatal("PTY_DISCLOSURE_PUBLIC_FIXTURE_FAILED")
	}
	fields["debug"] = "extra"
	extraField, err := json.Marshal(fields)
	if err != nil {
		t.Fatal("PTY_DISCLOSURE_PUBLIC_FIXTURE_FAILED")
	}
	const prompts = "#!/bin/sh\nstty -echo\nprintf '主密码: '\nIFS= read -r ignored\nprintf '\nSecret Key: '\nIFS= read -r ignored\n"
	jsonLine := "printf '\\n%s\\n' '" + string(record) + "'\n"
	for _, tc := range []struct {
		name, ending string
		echo         bool
	}{
		{"extra-line", "printf '\\nDEBUG\\n'\n" + jsonLine, false},
		{"second-json", jsonLine + "printf '%s\\n' '" + string(record) + "'\n", false},
		{"extra-field", "printf '\\n%s\\n' '" + string(extraField) + "'\n", false},
		{"factor-leak", "printf '\\n%s\\n' \"$ignored\"\n" + "printf '%s\\n' '" + string(record) + "'\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := filepath.Join(t.TempDir(), "owned-child")
			if err := os.WriteFile(fake, []byte(prompts+tc.ending), 0700); err != nil {
				t.Fatal("PTY_DISCLOSURE_CHILD_CREATE_FAILED")
			}
			result := runVaultFileDevicePublicProduct(t, fake, filepath.Join(t.TempDir(), "unused.ll"), []byte("owned-factor"), "owned-secret", false)
			if result.Status != "HARNESS_ERROR" || result.Echoed != tc.echo || result.Public != nil {
				t.Fatal("PTY_DISCLOSURE_FALSE_PUBLIC_RESULT")
			}
		})
	}
}

// The drain regression drives a real owned PTY child with one-byte reads and
// waits for the direct child to exit before collecting its residual bytes. A
// leaked factor written before that earlier exit must still be detected, and an
// exact public or refusal transcript produced the same way must still classify.
func TestVaultFileDevicePublicPTYDrainRegression(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("PTY_DRAIN_REGRESSION_PYTHON_UNAVAILABLE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join("testdata", "vault_file_device_public_pty.py"), "selftest")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("PTY_DRAIN_REGRESSION_EXEC_FAILED")
	}
	var result struct {
		LeakRefused           bool `json:"leak_refused"`
		LeakAfterExit         bool `json:"leak_after_exit"`
		PublicExact           bool `json:"public_exact"`
		PublicAfterExit       bool `json:"public_after_exit"`
		RefusalExact          bool `json:"refusal_exact"`
		RefusalAfterExit      bool `json:"refusal_after_exit"`
		LateCompletionRefused bool `json:"late_completion_refused"`
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("PTY_DRAIN_REGRESSION_VERDICT_INVALID")
	}
	if !result.LeakRefused || !result.LeakAfterExit || !result.PublicExact ||
		!result.PublicAfterExit || !result.RefusalExact || !result.RefusalAfterExit ||
		!result.LateCompletionRefused {
		t.Fatalf("PTY_DRAIN_REGRESSION_FAILED leak=%t leak_after_exit=%t public=%t public_after_exit=%t refusal=%t refusal_after_exit=%t late_completion=%t",
			result.LeakRefused, result.LeakAfterExit, result.PublicExact,
			result.PublicAfterExit, result.RefusalExact, result.RefusalAfterExit,
			result.LateCompletionRefused)
	}
}
