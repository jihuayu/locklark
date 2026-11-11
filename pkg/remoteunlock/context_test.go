package remoteunlock

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The fixed vector below is synthetic. It demonstrates codec behaviour only;
// it is not a real pairing, request, policy, identity or authorization.
const vectorJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"channel-binding-context","request_id":"req-0001","request_digest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","pair_id":"pair-0001","pair_generation":0,"lock_generation":1,"member_id":"member-0001","source_device_id":"device-source","target_device_id":"device-target","vault_id":"vault-0001","key_epoch":7,"policy_seq":0,"policy_digest":"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA","deadline_unix_ms":1800000000000}`

func ascendingDigest() [DigestSize]byte {
	var d [DigestSize]byte
	for i := range d {
		d[i] = byte(i)
	}
	return d
}

func descendingDigest() [DigestSize]byte {
	var d [DigestSize]byte
	for i := range d {
		d[i] = byte(31 - i)
	}
	return d
}

func vectorContext() ChannelBindingContext {
	return ChannelBindingContext{
		RequestID:      "req-0001",
		RequestDigest:  ascendingDigest(),
		PairID:         "pair-0001",
		PairGeneration: 0, // explicit genesis
		LockGeneration: 1,
		MemberID:       "member-0001",
		SourceDeviceID: "device-source",
		TargetDeviceID: "device-target",
		VaultID:        "vault-0001",
		KeyEpoch:       7,
		PolicySeq:      0, // explicit genesis
		PolicyDigest:   descendingDigest(),
		DeadlineUnixMS: 1800000000000,
	}
}

func mustEncode(t *testing.T, c ChannelBindingContext) []byte {
	t.Helper()
	b, err := EncodeChannelBindingContext(c)
	if err != nil {
		t.Fatalf("EncodeChannelBindingContext: %v", err)
	}
	return b
}

// TestFixedSyntheticVector pins the exact canonical bytes and checks
// encode/parse/re-encode parity.
func TestFixedSyntheticVector(t *testing.T) {
	c := vectorContext()
	got := mustEncode(t, c)
	if string(got) != vectorJSON {
		t.Fatalf("canonical encoding mismatch\n got: %s\nwant: %s", got, vectorJSON)
	}
	if len(got) > MaxContextSize {
		t.Fatalf("vector uses %d bytes, over budget %d", len(got), MaxContextSize)
	}

	parsed, err := ParseChannelBindingContext([]byte(vectorJSON))
	if err != nil {
		t.Fatalf("ParseChannelBindingContext: %v", err)
	}
	if parsed != c {
		t.Fatalf("parsed context mismatch\n got: %+v\nwant: %+v", parsed, c)
	}
	reencoded := mustEncode(t, parsed)
	if !bytes.Equal(reencoded, []byte(vectorJSON)) {
		t.Fatalf("re-encode mismatch\n got: %s\nwant: %s", reencoded, vectorJSON)
	}

	// The JSON and stream APIs must not diverge.
	marshaled, err := c.MarshalJSON()
	if err != nil || !bytes.Equal(marshaled, got) {
		t.Fatalf("MarshalJSON = %s, %v; want %s, nil", marshaled, err, got)
	}
	var decoded ChannelBindingContext
	if err := decoded.UnmarshalJSON(got); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if decoded != c {
		t.Fatalf("UnmarshalJSON context mismatch\n got: %+v\nwant: %+v", decoded, c)
	}

	// Genesis zeroes and the supplied deadline survive exactly.
	if parsed.PairGeneration != 0 || parsed.PolicySeq != 0 {
		t.Fatalf("genesis zeroes were not preserved: %+v", parsed)
	}
	if parsed.DeadlineUnixMS != 1800000000000 {
		t.Fatalf("deadline was changed: %d", parsed.DeadlineUnixMS)
	}
}

func TestMinimalContext(t *testing.T) {
	c := ChannelBindingContext{
		RequestID:      "a",
		PairID:         "a",
		MemberID:       "a",
		SourceDeviceID: "a",
		TargetDeviceID: "a",
		VaultID:        "a",
		KeyEpoch:       1,
		DeadlineUnixMS: 1,
	}
	got := mustEncode(t, c)
	parsed, err := ParseChannelBindingContext(got)
	if err != nil {
		t.Fatalf("ParseChannelBindingContext: %v", err)
	}
	if parsed != c {
		t.Fatalf("round trip mismatch: got %+v want %+v", parsed, c)
	}
}

// TestMaximumLegalBudget shows that a context using every maximum legal
// identifier length, digest and integer value still fits comfortably below the
// 4096-byte budget and round-trips.
func TestMaximumLegalBudget(t *testing.T) {
	id := func(prefix string) string {
		s := prefix + strings.Repeat("a", MaxIdentifierLen-len(prefix))
		if len(s) != MaxIdentifierLen {
			t.Fatalf("bad test id length %d", len(s))
		}
		return s
	}
	c := ChannelBindingContext{
		RequestID:      id("req:"),
		RequestDigest:  ascendingDigest(),
		PairID:         id("pair:"),
		PairGeneration: ^uint64(0),
		LockGeneration: ^uint64(0),
		MemberID:       id("member:"),
		SourceDeviceID: id("source:"),
		TargetDeviceID: id("target:"),
		VaultID:        id("vault:"),
		KeyEpoch:       ^uint64(0),
		PolicySeq:      ^uint64(0),
		PolicyDigest:   descendingDigest(),
		DeadlineUnixMS: 1<<63 - 1,
	}
	got := mustEncode(t, c)
	const maxLegalSize = 1259 // 6 IDs (128 each), four uint64 maxima, int64 maximum and two digests.
	if len(got) != maxLegalSize {
		t.Fatalf("maximum legal context uses %d bytes, want %d", len(got), maxLegalSize)
	}
	if len(got) >= MaxContextSize {
		t.Fatalf("maximum legal context uses %d bytes, budget is %d", len(got), MaxContextSize)
	}
	t.Logf("maximum legal context size: %d bytes (budget %d, headroom %d)", len(got), MaxContextSize, MaxContextSize-len(got))

	parsed, err := ParseChannelBindingContext(got)
	if err != nil {
		t.Fatalf("ParseChannelBindingContext: %v", err)
	}
	if parsed != c {
		t.Fatalf("maximum context did not round-trip")
	}
	for name, v := range map[string]string{
		"request_id":       parsed.RequestID,
		"pair_id":          parsed.PairID,
		"member_id":        parsed.MemberID,
		"source_device_id": parsed.SourceDeviceID,
		"target_device_id": parsed.TargetDeviceID,
		"vault_id":         parsed.VaultID,
	} {
		if len(v) != MaxIdentifierLen {
			t.Fatalf("%s length = %d, want %d", name, len(v), MaxIdentifierLen)
		}
	}
	if parsed.PairGeneration != ^uint64(0) || parsed.LockGeneration != ^uint64(0) ||
		parsed.KeyEpoch != ^uint64(0) || parsed.PolicySeq != ^uint64(0) ||
		parsed.DeadlineUnixMS != 1<<63-1 {
		t.Fatalf("maximum integers did not round-trip: %+v", parsed)
	}
	reencoded := mustEncode(t, parsed)
	if !bytes.Equal(reencoded, got) {
		t.Fatalf("maximum context re-encode mismatch")
	}
}

func TestEncodeRejectsInvalidContext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ChannelBindingContext)
		field  string
	}{
		{"request id empty", func(c *ChannelBindingContext) { c.RequestID = "" }, "request_id"},
		{"pair id empty", func(c *ChannelBindingContext) { c.PairID = "" }, "pair_id"},
		{"member id empty", func(c *ChannelBindingContext) { c.MemberID = "" }, "member_id"},
		{"source id empty", func(c *ChannelBindingContext) { c.SourceDeviceID = "" }, "source_device_id"},
		{"target id empty", func(c *ChannelBindingContext) { c.TargetDeviceID = "" }, "target_device_id"},
		{"vault id empty", func(c *ChannelBindingContext) { c.VaultID = "" }, "vault_id"},
		{"id too long", func(c *ChannelBindingContext) { c.RequestID = strings.Repeat("a", MaxIdentifierLen+1) }, "request_id"},
		{"id uppercase", func(c *ChannelBindingContext) { c.PairID = "PAIR-0001" }, "pair_id"},
		{"id non ascii", func(c *ChannelBindingContext) { c.MemberID = "mémber-0001" }, "member_id"},
		{"id slash", func(c *ChannelBindingContext) { c.SourceDeviceID = "device/source" }, "source_device_id"},
		{"id space", func(c *ChannelBindingContext) { c.TargetDeviceID = "device target" }, "target_device_id"},
		{"id control", func(c *ChannelBindingContext) { c.VaultID = "vault\x00id" }, "vault_id"},
		{"id tilde", func(c *ChannelBindingContext) { c.RequestID = "req~0001" }, "request_id"},
		{"key epoch zero", func(c *ChannelBindingContext) { c.KeyEpoch = 0 }, "key_epoch"},
		{"deadline zero", func(c *ChannelBindingContext) { c.DeadlineUnixMS = 0 }, "deadline_unix_ms"},
		{"deadline negative", func(c *ChannelBindingContext) { c.DeadlineUnixMS = -1 }, "deadline_unix_ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := vectorContext()
			tt.mutate(&c)
			_, err := EncodeChannelBindingContext(c)
			if err == nil {
				t.Fatal("EncodeChannelBindingContext accepted an invalid context")
			}
			if !errors.Is(err, ErrInvalidContext) {
				t.Fatalf("error does not wrap ErrInvalidContext: %v", err)
			}
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != tt.field {
				t.Fatalf("FieldError = %+v, want field %q", fe, tt.field)
			}
		})
	}
}

// removeMember removes one top-level member from canonical JSON, preserving
// well-formed JSON for the remaining members.
func removeMember(t *testing.T, b []byte, name string) []byte {
	t.Helper()
	key := []byte(`"` + name + `":`)
	i := bytes.Index(b, key)
	if i < 0 {
		t.Fatalf("member %q not found in vector", name)
	}
	start := i
	if i > 0 && b[i-1] == ',' {
		start = i - 1
	}
	j := i + len(key)
	switch {
	case j < len(b) && b[j] == '"':
		j++
		for j < len(b) && b[j] != '"' {
			j++
		}
		if j >= len(b) {
			t.Fatalf("unterminated string for %q", name)
		}
		j++
	case j < len(b) && b[j] == '{':
		for j < len(b) && b[j] != '}' {
			j++
		}
		if j >= len(b) {
			t.Fatalf("unterminated object for %q", name)
		}
		j++
	default:
		for j < len(b) && b[j] != ',' && b[j] != '}' {
			j++
		}
	}
	if j < len(b) && b[j] == ',' {
		j++
	}
	out := append([]byte(nil), b[:start]...)
	out = append(out, b[j:]...)
	return out
}

func replaceOnce(t *testing.T, b []byte, old, replacement string) []byte {
	t.Helper()
	if got := bytes.Count(b, []byte(old)); got != 1 {
		t.Fatalf("replacement anchor %q occurs %d times", old, got)
	}
	return bytes.Replace(b, []byte(old), []byte(replacement), 1)
}

func TestParseRejectsNonCanonicalInput(t *testing.T) {
	canonical := []byte(vectorJSON)

	tests := []struct {
		name   string
		mutate func(t *testing.T, b []byte) []byte
	}{
		// Missing members, one case per schema field.
		{name: "missing format", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "format") }},
		{name: "missing version", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "version") }},
		{name: "missing kind", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "kind") }},
		{name: "missing request_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "request_id") }},
		{name: "missing request_digest", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "request_digest") }},
		{name: "missing pair_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "pair_id") }},
		{name: "missing pair_generation", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "pair_generation") }},
		{name: "missing lock_generation", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "lock_generation") }},
		{name: "missing member_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "member_id") }},
		{name: "missing source_device_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "source_device_id") }},
		{name: "missing target_device_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "target_device_id") }},
		{name: "missing vault_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "vault_id") }},
		{name: "missing key_epoch", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "key_epoch") }},
		{name: "missing policy_seq", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "policy_seq") }},
		{name: "missing policy_digest", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "policy_digest") }},
		{name: "missing deadline", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "deadline_unix_ms") }},

		// Unknown, duplicate and reordered members.
		{name: "unknown member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `}`, `,"extra":0}`)
		}},
		{name: "unknown renamed member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"request_id":`, `"request_identifier":`)
		}},
		{name: "duplicate member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"request_id":"req-0001",`,
				`"request_id":"req-0001","request_id":"req-0001",`)
		}},
		{name: "duplicate last member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"deadline_unix_ms":1800000000000}`,
				`"deadline_unix_ms":1800000000000,"deadline_unix_ms":1800000000000}`)
		}},
		{name: "reordered members", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"pair_generation":0,"lock_generation":1`,
				`"lock_generation":1,"pair_generation":0`)
		}},
		{name: "reordered earlier member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"request_id":"req-0001","request_digest":`,
				`"request_digest":`)
		}},

		// Trailing data and surrounding whitespace.
		{name: "trailing newline", mutate: func(t *testing.T, b []byte) []byte { return append(b, '\n') }},
		{name: "trailing space", mutate: func(t *testing.T, b []byte) []byte { return append(b, ' ') }},
		{name: "trailing crlf", mutate: func(t *testing.T, b []byte) []byte { return append(b, '\r', '\n') }},
		{name: "trailing second value", mutate: func(t *testing.T, b []byte) []byte { return append(b, canonical...) }},
		{name: "trailing object", mutate: func(t *testing.T, b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{name: "trailing byte", mutate: func(t *testing.T, b []byte) []byte { return append(b, 'x') }},
		{name: "leading space", mutate: func(t *testing.T, b []byte) []byte { return append([]byte(" "), b...) }},
		{name: "internal whitespace", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version": 1`)
		}},
		{name: "missing closing brace", mutate: func(t *testing.T, b []byte) []byte { return b[:len(b)-1] }},
		{name: "extra closing brace", mutate: func(t *testing.T, b []byte) []byte { return append(b, '}') }},
		{name: "missing comma", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"request_digest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","pair_id"`,
				`"request_digest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8""pair_id"`)
		}},
		{name: "missing colon", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_id":`, `"pair_id"`)
		}},

		// Shape and top-level type.
		{name: "empty input", mutate: func(t *testing.T, b []byte) []byte { return nil }},
		{name: "not an object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`[]`) }},
		{name: "null", mutate: func(t *testing.T, b []byte) []byte { return []byte(`null`) }},
		{name: "number input", mutate: func(t *testing.T, b []byte) []byte { return []byte(`1`) }},
		{name: "string input", mutate: func(t *testing.T, b []byte) []byte { return []byte(`"context"`) }},

		// Invalid UTF-8 and non-canonical strings.
		{name: "invalid utf8", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"req-0001"`, "\"req-\xff0001\"")
		}},
		{name: "invalid utf8 in key", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format"`, "\"form\xffat\"")
		}},
		{name: "escaped id", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"req-0001"`, `"req\u002d0001"`)
		}},
		{name: "escaped constant", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark\u002eremote-unlock"`)
		}},
		{name: "uppercase escape in key", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format"`, `"\u0066ormat"`)
		}},
		{name: "control byte in id", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair-0001"`, "\"pair-\x010001\"")
		}},

		// Constants and types.
		{name: "wrong format", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark.remote-unlock.v2"`)
		}},
		{name: "wrong kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"channel-binding-context"`, `"request-context"`)
		}},
		{name: "wrong version value", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":2`)
		}},
		{name: "version as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":"1"`)
		}},
		{name: "version leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":01`)
		}},
		{name: "id as number", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"request_id":"req-0001"`, `"request_id":123`)
		}},
		{name: "digest as number", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"request_digest":`, `"request_digest":0,"x":`)
		}},
		{name: "generation as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":"0"`)
		}},

		// Integer spelling: sign, fraction, exponent, leading zero, overflow.
		{name: "generation fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":0.5`)
		}},
		{name: "generation exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"lock_generation":1`, `"lock_generation":1e0`)
		}},
		{name: "generation negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":-1`)
		}},
		{name: "generation plus sign", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":+0`)
		}},
		{name: "generation leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"lock_generation":1`, `"lock_generation":01`)
		}},
		{name: "generation uint64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"lock_generation":1`, `"lock_generation":18446744073709551616`)
		}},
		{name: "policy seq leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"policy_seq":0`, `"policy_seq":00`)
		}},
		{name: "policy seq negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"policy_seq":0`, `"policy_seq":-1`)
		}},
		{name: "key epoch zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"key_epoch":7`, `"key_epoch":0`)
		}},
		{name: "key epoch overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"key_epoch":7`, `"key_epoch":18446744073709551616`)
		}},
		{name: "key epoch fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"key_epoch":7`, `"key_epoch":7.0`)
		}},
		{name: "deadline zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":0`)
		}},
		{name: "deadline negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":-1`)
		}},
		{name: "deadline fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":1800000000000.5`)
		}},
		{name: "deadline exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":18e11`)
		}},
		{name: "deadline leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":01800000000000`)
		}},
		{name: "deadline int64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":9223372036854775808`)
		}},

		// Identifier grammar.
		{name: "id empty", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member-0001"`, `""`)
		}},
		{name: "id 129 bytes", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"req-0001"`, `"`+strings.Repeat("a", MaxIdentifierLen+1)+`"`)
		}},
		{name: "id uppercase", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair-0001"`, `"PAIR-0001"`)
		}},
		{name: "id non ascii", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member-0001"`, `"mémber-0001"`)
		}},
		{name: "id slash", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"device-source"`, `"device/source"`)
		}},
		{name: "id tilde", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"device-target"`, `"device~target"`)
		}},
		{name: "id space", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"vault-0001"`, `"vault 0001"`)
		}},

		// Digest form.
		{name: "request digest one byte short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh"`)
		}},
		{name: "request digest one byte long", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A"`)
		}},
		{name: "request digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`)
		}},
		{name: "request digest noncanonical trailing bits", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"`)
		}},
		{name: "request digest standard base64 alphabet", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"+AECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`)
		}},
		{name: "policy digest wrong size", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA"`,
				`"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQ"`)
		}},
		{name: "policy digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA"`,
				`"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=="`)
		}},

		// Input budget.
		{name: "input over budget", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxContextSize+1)...)
		}},
		{name: "input exactly budget with trailing data", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxContextSize-len(b))...)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(t, append([]byte(nil), canonical...))
			if _, err := ParseChannelBindingContext(data); err == nil {
				t.Fatalf("ParseChannelBindingContext accepted non-canonical input: %s", data)
			} else if !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("error does not wrap ErrInvalidEncoding: %v", err)
			}
		})
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	for _, size := range []int{MaxContextSize + 1, MaxContextSize * 2} {
		input := bytes.Repeat([]byte(" "), size)
		_, err := ParseChannelBindingContext(input)
		if err == nil {
			t.Fatalf("accepted %d bytes", size)
		}
		if !errors.Is(err, ErrInvalidEncoding) {
			t.Fatalf("error does not wrap ErrInvalidEncoding: %v", err)
		}
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	secretID := "UPPERSECRETIDENTIFIER"
	c := vectorContext()
	c.RequestID = secretID
	if _, err := EncodeChannelBindingContext(c); err == nil {
		t.Fatal("expected encode error")
	} else if strings.Contains(err.Error(), secretID) {
		t.Fatalf("encode error leaked an identifier value: %v", err)
	}

	longID := strings.Repeat("z", MaxIdentifierLen+1)
	c = vectorContext()
	c.VaultID = longID
	if _, err := EncodeChannelBindingContext(c); err == nil {
		t.Fatal("expected encode error")
	} else if strings.Contains(err.Error(), longID) {
		t.Fatalf("encode error leaked an identifier value: %v", err)
	}

	d := ascendingDigest()
	digestValue := base64.RawURLEncoding.EncodeToString(d[:])
	data := replaceOnce(t, []byte(vectorJSON),
		`"request_digest":"`+digestValue+`"`,
		`"request_digest":"`+digestValue+`="`)
	if _, err := ParseChannelBindingContext(data); err == nil {
		t.Fatal("expected parse error")
	} else if strings.Contains(err.Error(), digestValue) {
		t.Fatalf("parse error leaked a digest value: %v", err)
	}

	data = replaceOnce(t, []byte(vectorJSON), `"req-0001"`, `"`+secretID+`"`)
	if _, err := ParseChannelBindingContext(data); err == nil {
		t.Fatal("expected parse error")
	} else if strings.Contains(err.Error(), secretID) {
		t.Fatalf("parse error leaked an identifier value: %v", err)
	}

	// Unknown keys are attacker-controlled input and must not be echoed.
	data = replaceOnce(t, []byte(vectorJSON), `"request_id":`, `"`+secretID+`":`)
	if _, err := ParseChannelBindingContext(data); err == nil {
		t.Fatal("expected parse error")
	} else if strings.Contains(err.Error(), secretID) {
		t.Fatalf("parse error leaked an unknown key: %v", err)
	}
}

func TestParseErrorIdentifiesField(t *testing.T) {
	tests := []struct {
		name  string
		old   string
		new   string
		field string
	}{
		{"request id uppercase", `"req-0001"`, `"REQ-0001"`, "request_id"},
		{"digest wrong size", `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"AAEC"`, "request_digest"},
		{"key epoch zero", `"key_epoch":7`, `"key_epoch":0`, "key_epoch"},
		{"deadline zero", `"deadline_unix_ms":1800000000000`, `"deadline_unix_ms":0`, "deadline_unix_ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := replaceOnce(t, []byte(vectorJSON), tt.old, tt.new)
			_, err := ParseChannelBindingContext(data)
			if err == nil {
				t.Fatal("expected parse error")
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error is not a *FieldError: %v", err)
			}
			if fe.Field != tt.field {
				t.Fatalf("FieldError.Field = %q, want %q", fe.Field, tt.field)
			}
		})
	}
}
