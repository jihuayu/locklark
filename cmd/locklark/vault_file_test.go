package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func resumeConfigDocument(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"version": 1, "backend_root": filepath.Join(t.TempDir(), "backend"),
		"name": "vault.locklark", "journal": filepath.Join(t.TempDir(), "journal.db"),
		"checkpoint": map[string]any{
			"vault_id": "owned-vault", "owner_root_key_id": "owned-root",
			"owner_root_public_key": strings.Repeat("1", 64), "policy_seq": uint64(0),
			"policy_digest": strings.Repeat("2", 64),
		},
	}
}

func encodeResumeConfigTest(t *testing.T, value map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("CONFIG_FIXTURE_ENCODE_FAILED")
	}
	return raw
}

func TestVaultFileConfigSequencePresence(t *testing.T) {
	document := resumeConfigDocument(t)
	_, pin, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document))
	if err != nil || pin.PolicySeq != 0 {
		t.Fatal("EXPLICIT_ZERO_SEQUENCE_REJECTED")
	}
	checkpoint := document["checkpoint"].(map[string]any)
	delete(checkpoint, "policy_seq")
	if _, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != errVaultFileConfig {
		t.Fatal("MISSING_SEQUENCE_ACCEPTED")
	}
	checkpoint["policy_seq"] = nil
	if _, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != errVaultFileConfig {
		t.Fatal("NULL_SEQUENCE_ACCEPTED")
	}
}

func TestVaultFileConfigOptionalPersonalFile(t *testing.T) {
	document := resumeConfigDocument(t)
	if cfg, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != nil || cfg.PersonalFile != "" {
		t.Fatal("EXISTING_CONFIG_CHANGED")
	}
	document["personal_file"] = filepath.Join(t.TempDir(), "personal.ll")
	if cfg, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != nil || cfg.PersonalFile != document["personal_file"] {
		t.Fatal("ABSOLUTE_PERSONAL_FILE_REJECTED")
	}
	document["personal_file"] = "personal.ll"
	if _, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != errVaultFileConfig {
		t.Fatal("RELATIVE_PERSONAL_FILE_ACCEPTED")
	}
}

func TestVaultFileConfigStrictSchema(t *testing.T) {
	for _, name := range []string{"UNKNOWN", "MISSING_ROOT", "MISSING_NAME", "MISSING_JOURNAL", "MISSING_CHECKPOINT", "MISSING_VAULT", "MISSING_ROOT_ID", "UPPER_PUBLIC", "SHORT_DIGEST", "RELATIVE_ROOT"} {
		t.Run(name, func(t *testing.T) {
			document := resumeConfigDocument(t)
			checkpoint := document["checkpoint"].(map[string]any)
			switch name {
			case "UNKNOWN":
				document["trust_readback"] = true
			case "MISSING_ROOT":
				delete(document, "backend_root")
			case "MISSING_NAME":
				delete(document, "name")
			case "MISSING_JOURNAL":
				delete(document, "journal")
			case "MISSING_CHECKPOINT":
				delete(document, "checkpoint")
			case "MISSING_VAULT":
				delete(checkpoint, "vault_id")
			case "MISSING_ROOT_ID":
				delete(checkpoint, "owner_root_key_id")
			case "UPPER_PUBLIC":
				checkpoint["owner_root_public_key"] = strings.Repeat("A", 64)
			case "SHORT_DIGEST":
				checkpoint["policy_digest"] = "22"
			case "RELATIVE_ROOT":
				document["backend_root"] = "backend"
			}
			if _, _, err := decodeVaultFileResumeConfig(encodeResumeConfigTest(t, document)); err != errVaultFileConfig {
				t.Fatal("INVALID_CONFIG_ACCEPTED")
			}
		})
	}
	document := encodeResumeConfigTest(t, resumeConfigDocument(t))
	for _, raw := range [][]byte{
		append(bytes.Clone(document), []byte(` {}`)...),
		bytes.Replace(document, []byte(`"version":1`), []byte(`"version":1,"VERSION":1`), 1),
	} {
		if _, _, err := decodeVaultFileResumeConfig(raw); !errors.Is(err, errVaultFileConfig) {
			t.Fatal("AMBIGUOUS_JSON_ACCEPTED")
		}
	}
}
