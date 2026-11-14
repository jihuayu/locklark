package vaultfileinspect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

func TestInspectRealFixture(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.ll")
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	vaultRaw, err := os.ReadFile("testdata/vault.ll")
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw, err := os.ReadFile("testdata/checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, vaultRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkpointPath, checkpointRaw, 0600); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(vaultRaw)

	outPath := filepath.Join(dir, "stdout.json")
	out := createPrivateOutput(t, outPath)
	if err := run([]string{"--file", vaultPath, "--checkpoint", checkpointPath}, out); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivateOutput(t, outPath)
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"schema": true, "result": true, "policy": true, "payload": true, "format": true, "version": true, "policy_seq": true, "content_seq": true, "revision_id": true, "file_digest": true, "policy_proofs": true, "device_slots": true}
	for key := range got {
		if !allowed[key] {
			t.Fatalf("unexpected stdout key %q", key)
		}
	}
	if got["result"] != "verified" || got["policy"] != "verified" || got["payload"] != "not_decrypted" {
		t.Fatalf("wrong verification enums: %#v", got)
	}
	for _, key := range []string{"revision_id", "file_digest"} {
		value, _ := got[key].(string)
		if len(value) != 64 || strings.ToLower(value) != value || strings.Trim(value, "0123456789abcdef") != "" {
			t.Fatalf("%s is not a lowercase hash: %q", key, value)
		}
	}
	if strings.Contains(string(raw), "correct horse battery staple") {
		t.Fatal("payload secret appeared in stdout")
	}
	if after := sha256.Sum256(mustRead(t, vaultPath)); after != before {
		t.Fatal("inspection changed the vault file")
	}

	wrongRaw := append([]byte(nil), checkpointRaw...)
	var checkpoint map[string]any
	if err := json.Unmarshal(wrongRaw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint["policy_digest"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	wrongRaw, _ = json.Marshal(checkpoint)
	wrongPath := filepath.Join(dir, "wrong-checkpoint.json")
	if err := os.WriteFile(wrongPath, wrongRaw, 0600); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, vaultPath, wrongPath, "policy_checkpoint_failed")
	if after := sha256.Sum256(mustRead(t, vaultPath)); after != before {
		t.Fatal("wrong-pin refusal changed the vault file")
	}

	f, err := vaultfile.ParseFile(vaultRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.ContentSignature.Sig[0] ^= 1
	tampered, err := vaultfile.EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dir, "tampered.ll")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, tamperedPath, checkpointPath, "signature_verify_failed")
	if after := sha256.Sum256(mustRead(t, vaultPath)); after != before {
		t.Fatal("tamper inspection changed the original vault file")
	}
}

func assertRefused(t *testing.T, vaultPath, checkpointPath, code string) {
	t.Helper()
	var out strings.Builder
	if err := run([]string{"--file", vaultPath, "--checkpoint", checkpointPath}, &out); err == nil {
		t.Fatal("inspection unexpectedly succeeded")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got["result"] != "refused" || got["error"] != code {
		t.Fatalf("refusal = %#v, want %s", got, code)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
