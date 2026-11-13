package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecodeCheckpointStrict(t *testing.T) {
	valid := mustRead(t, "testdata/checkpoint.json")
	fields := func() map[string]json.RawMessage {
		var out map[string]json.RawMessage
		if err := json.Unmarshal(valid, &out); err != nil {
			t.Fatal("fixture checkpoint is not an object")
		}
		return out
	}
	encoded := func(mutate func(map[string]json.RawMessage)) []byte {
		m := fields()
		mutate(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal("fixture checkpoint encoding failed")
		}
		return raw
	}
	allFields := []string{"v", "vault_id", "owner_root_key_id", "owner_root_public_key", "policy_seq", "policy_digest"}

	tests := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"valid", valid, true},
		{"valid-trailing-whitespace", append(append([]byte(nil), valid...), []byte(" \r\n")...), true},
		{"duplicate-v", bytes.Replace(valid, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1), false},
		{"wrongcase-key", bytes.Replace(valid, []byte(`"vault_id"`), []byte(`"Vault_ID"`), 1), false},
		{"unknown-key", bytes.Replace(valid, []byte(`"v":1`), []byte(`"v":1,"extra":1`), 1), false},
		{"top-array", []byte(`[]`), false},
		{"top-null", []byte(`null`), false},
		{"top-string", []byte(`"x"`), false},
		{"trailing-object", append(append([]byte(nil), valid...), []byte(`{}`)...), false},
		{"trailing-nonwhite", append(append([]byte(nil), valid...), []byte(`x`)...), false},
		{"v-zero", encoded(func(m map[string]json.RawMessage) { m["v"] = json.RawMessage(`0`) }), false},
		{"v-string", encoded(func(m map[string]json.RawMessage) { m["v"] = json.RawMessage(`"1"`) }), false},
		{"v-null", encoded(func(m map[string]json.RawMessage) { m["v"] = json.RawMessage(`null`) }), false},
		{"seq-zero-allowed-by-parser", encoded(func(m map[string]json.RawMessage) { m["policy_seq"] = json.RawMessage(`0`) }), true},
		{"seq-negative", encoded(func(m map[string]json.RawMessage) { m["policy_seq"] = json.RawMessage(`-1`) }), false},
		{"seq-string", encoded(func(m map[string]json.RawMessage) { m["policy_seq"] = json.RawMessage(`"5"`) }), false},
		{"seq-float", encoded(func(m map[string]json.RawMessage) { m["policy_seq"] = json.RawMessage(`5.0`) }), false},
		{"seq-null", encoded(func(m map[string]json.RawMessage) { m["policy_seq"] = json.RawMessage(`null`) }), false},
		{"id-number", encoded(func(m map[string]json.RawMessage) { m["vault_id"] = json.RawMessage(`1`) }), false},
		{"id-null", encoded(func(m map[string]json.RawMessage) { m["vault_id"] = json.RawMessage(`null`) }), false},
		{"id-invalid-shape-left-to-sdk", encoded(func(m map[string]json.RawMessage) { m["vault_id"] = json.RawMessage(`"Vault ID"`) }), true},
		{"short-public-key", encoded(func(m map[string]json.RawMessage) { m["owner_root_public_key"] = json.RawMessage(`"AAAA"`) }), false},
		{"short-digest", encoded(func(m map[string]json.RawMessage) { m["policy_digest"] = json.RawMessage(`"AAAA"`) }), false},
		{"noncanonical-digest", encoded(func(m map[string]json.RawMessage) {
			m["policy_digest"] = json.RawMessage(`"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"`)
		}), false},
	}
	for _, field := range allFields {
		field := field
		tests = append(tests,
			struct {
				name string
				raw  []byte
				ok   bool
			}{"missing-" + field, encoded(func(m map[string]json.RawMessage) { delete(m, field) }), false},
			struct {
				name string
				raw  []byte
				ok   bool
			}{"null-" + field, encoded(func(m map[string]json.RawMessage) { m[field] = json.RawMessage(`null`) }), false},
		)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeCheckpoint(tc.raw)
			if (err == nil) != tc.ok {
				t.Fatalf("checkpoint acceptance mismatch for %s", tc.name)
			}
		})
	}
}
