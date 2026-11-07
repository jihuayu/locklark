package personal

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestDecodeSystemPasskeyCapsuleClearsPartialIdentity is the regression for a
// refused decode that already assigned Identity before the offending field: the
// partial identity bytes must be zeroed and the value must never be interpreted.
func TestDecodeSystemPasskeyCapsuleClearsPartialIdentity(t *testing.T) {
	capsule := systemCapsule{Version: 1, Path: "/vault.ll", Slot: [32]byte{1}, Identity: []byte("partial-identity"), Created: time.Now(), Expires: time.Now().Add(24 * time.Hour)}
	valid, e := json.Marshal(capsule)
	if e != nil {
		t.Fatal(e)
	}
	base := string(bytes.TrimSuffix(valid, []byte("}")))
	// A syntactically valid trailing object with an unknown field, and a
	// truncated object, both fail after identity has been decoded.
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown-after-identity", []byte(base + `,"extra":1}`)},
		{"truncated-after-identity", []byte(base + `,"extra`)},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeSystemPasskeyCapsule(tc.raw)
			if err == nil {
				t.Fatal("accepted unusable capsule")
			}
			defer clear(decoded.Identity)
			for _, b := range decoded.Identity {
				if b != 0 {
					t.Fatal("partial identity bytes survived a refused decode")
				}
			}
		})
	}
}
