package vaultcreationauth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// baseContext has distinct values in every field, so a reordering is visible.
func baseContext() Context {
	var c Context
	c.Scope = Scope{TenantID: "Zt1", UserID: "Zu1", DeviceID: "Zd1"}
	c.Challenge.ID = "Zi1"
	c.Challenge.DeadlineUnixMS = 1_760_000_000_000
	for i := range c.Challenge.Nonce {
		c.Challenge.Nonce[i] = byte(i)
	}
	for i := range c.PlanDigest {
		c.PlanDigest[i] = byte(0xA0 + i)
	}
	return c
}

// maxContext is the largest context the budgets admit: four ids of MaxIDBytes
// and the largest positive deadline.
func maxContext() Context {
	return Context{
		Scope: Scope{
			TenantID: strings.Repeat("Z", MaxIDBytes),
			UserID:   strings.Repeat("Z", MaxIDBytes),
			DeviceID: strings.Repeat("Z", MaxIDBytes),
		},
		Challenge: Challenge{ID: strings.Repeat("Z", MaxIDBytes), DeadlineUnixMS: 1<<63 - 1},
	}
}

var rawURL = base64.RawURLEncoding

// testSig is a fixed, well-shaped signature value.
func testSig() []byte {
	sig := make([]byte, SignatureBytes)
	return sig
}

// contextJSON is the expected canonical context of c, written independently of
// the code under test.
func contextJSON(t *testing.T, c Context) string {
	t.Helper()
	return `{"scope":{"tenant_id":"` + c.Scope.TenantID + `","user_id":"` + c.Scope.UserID +
		`","device_id":"` + c.Scope.DeviceID + `"},"challenge":{"id":"` + c.Challenge.ID +
		`","nonce":"` + rawURL.EncodeToString(c.Challenge.Nonce[:]) +
		`","deadline_unix_ms":` + itoa(c.Challenge.DeadlineUnixMS) +
		`},"creation_plan_sha256":"` + rawURL.EncodeToString(c.PlanDigest[:]) + `"}`
}

// proofJSON is the expected canonical proof for c and sig.
func proofJSON(t *testing.T, c Context, sig []byte) string {
	t.Helper()
	return `{"format":"` + Format + `","version":1,"kind":"` + Kind + `","context":` +
		contextJSON(t, c) + `,"signature":"` + rawURL.EncodeToString(sig) + `"}`
}

// scopeJSON and challengeJSON are the independently written sub-objects of c.
func scopeJSON(c Context) string {
	return `{"tenant_id":"` + c.Scope.TenantID + `","user_id":"` + c.Scope.UserID + `","device_id":"` + c.Scope.DeviceID + `"}`
}

func challengeJSON(c Context) string {
	return `{"id":"` + c.Challenge.ID + `","nonce":"` + rawURL.EncodeToString(c.Challenge.Nonce[:]) +
		`","deadline_unix_ms":` + itoa(c.Challenge.DeadlineUnixMS) + `}`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func mustEncode(t *testing.T, p Proof) []byte {
	t.Helper()
	b, err := Encode(p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(b) > MaxProofBytes {
		t.Fatalf("Encode returned %d bytes, over the %d-byte cap", len(b), MaxProofBytes)
	}
	return b
}

func TestSigningPreimage(t *testing.T) {
	c := baseContext()
	pre, err := SigningBytes(c)
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	want := SigningDomain + "\x00" +
		`{"scope":{"tenant_id":"Zt1","user_id":"Zu1","device_id":"Zd1"},` +
		`"challenge":{"id":"Zi1",` +
		`"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",` +
		`"deadline_unix_ms":1760000000000},` +
		`"creation_plan_sha256":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"}`
	if string(pre) != want {
		t.Fatalf("SigningBytes mismatch\n got: %q\nwant: %q", pre, want)
	}
}

func TestRoundTrip(t *testing.T) {
	c := baseContext()
	p := Proof{Context: c, Signature: testSig()}
	b := mustEncode(t, p)
	if want := proofJSON(t, c, p.Signature); string(b) != want {
		t.Fatalf("Encode mismatch\n got: %s\nwant: %s", b, want)
	}
	// The signed context appears in the proof byte for byte.
	pre, _ := SigningBytes(c)
	if !bytes.Contains(b, pre[len(SigningDomain)+1:]) {
		t.Fatalf("proof does not carry the signed context verbatim: %s", b)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Context != c || !bytes.Equal(got.Signature, p.Signature) {
		t.Fatalf("round trip changed the proof: %+v", got)
	}
	if again := mustEncode(t, got); !bytes.Equal(again, b) {
		t.Fatalf("re-encode differs\n got: %s\nwant: %s", again, b)
	}
}

func TestNonCanonicalSpellings(t *testing.T) {
	c := baseContext()
	valid := string(mustEncode(t, Proof{Context: c, Signature: testSig()}))
	replace := func(old, new string) string {
		t.Helper()
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(valid, old, new, 1)
	}
	nonceA := rawURL.EncodeToString(c.Challenge.Nonce[:])
	sigA := rawURL.EncodeToString(testSig())
	for _, tc := range []struct {
		name string
		in   string
		err  error
	}{
		{"top member order", replace(`"format":`, `"kind":"`+Kind+`","format":`), ErrMalformed},
		{"context member order", replace(
			`{"scope":`+scopeJSON(c)+`,"challenge":`,
			`{"challenge":`+challengeJSON(c)+`,"scope":`+scopeJSON(c)+`,"challenge":`), ErrMalformed},
		{"scope member order", replace(
			`"tenant_id":"`+c.Scope.TenantID+`","user_id":"`+c.Scope.UserID+`"`,
			`"user_id":"`+c.Scope.UserID+`","tenant_id":"`+c.Scope.TenantID+`"`), ErrNonCanonical},
		// An id not at MaxIDBytes, so the swap stays inside the id grammar.
		{"challenge member order", replace(
			`"id":"Zi1","nonce":"`+nonceA+`"`,
			`"nonce":"`+nonceA+`","id":"Zi1"`), ErrNonCanonical},
		{"deadline before id", replace(
			`"id":"Zi1","nonce":"`+nonceA+`","deadline_unix_ms":1760000000000`,
			`"deadline_unix_ms":1760000000000,"id":"Zi1","nonce":"`+nonceA+`"`), ErrNonCanonical},
		{"leading whitespace", " " + valid, ErrNonCanonical},
		{"trailing whitespace", valid + "\n", ErrNonCanonical},
		{"trailing object", valid + "{}", ErrMalformed},
		{"duplicate member", replace(`"kind":"`+Kind+`",`, `"kind":"`+Kind+`","kind":"`+Kind+`",`), ErrMalformed},
		{"unknown member", replace(`"signature":`, `"extra":1,"signature":`), ErrNonCanonical},
		{"escaped id", replace(`"Zu1"`, `"Zu\u0031"`), ErrNonCanonical},
		{"version string", replace(`"version":1`, `"version":"1"`), ErrMalformed},
		{"version fraction", replace(`"version":1`, `"version":1.0`), ErrMalformed},
		{"version exponent", replace(`"version":1`, `"version":1e0`), ErrMalformed},
		{"version leading zero", replace(`"version":1`, `"version":01`), ErrMalformed},
		{"padded nonce", replace(nonceA, nonceA+"="), ErrInvalidNonce},
		{"short nonce", replace(nonceA, nonceA[:42]), ErrInvalidNonce},
		{"empty id", replace(`"Zt1"`, `""`), ErrInvalidID},
		{"signature too short", replace(sigA, sigA[:84]), ErrInvalidSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.in == valid {
				t.Fatalf("mutation did not change the fixture")
			}
			if _, err := Parse([]byte(tc.in)); err != tc.err {
				t.Fatalf("Parse(%q) = %v, want %v", tc.in, err, tc.err)
			}
		})
	}
	// A proof is accepted only as its own canonical encoding: Encode is the
	// sole writer, so any other spelling is refused even when it decodes.
}

func TestFieldErrors(t *testing.T) {
	c := baseContext()
	with := func(mutate func(*Context)) Context {
		c := c
		mutate(&c)
		return c
	}
	sig := testSig()
	for _, tc := range []struct {
		name string
		ctx  Context
		sig  []byte
		err  error
	}{
		{"empty tenant", with(func(c *Context) { c.Scope.TenantID = "" }), sig, ErrInvalidID},
		{"oversize user", with(func(c *Context) { c.Scope.UserID = strings.Repeat("u", MaxIDBytes+1) }), sig, ErrInvalidID},
		{"space in device", with(func(c *Context) { c.Scope.DeviceID = "a b" }), sig, ErrInvalidID},
		{"non-ascii challenge", with(func(c *Context) { c.Challenge.ID = "ch\u00e1l" }), sig, ErrInvalidID},
		{"control in challenge", with(func(c *Context) { c.Challenge.ID = "a\tb" }), sig, ErrInvalidID},
		{"zero deadline", with(func(c *Context) { c.Challenge.DeadlineUnixMS = 0 }), sig, ErrInvalidDeadline},
		{"negative deadline", with(func(c *Context) { c.Challenge.DeadlineUnixMS = -1 }), sig, ErrInvalidDeadline},
		{"nil signature", c, nil, ErrInvalidSignature},
		{"short signature", c, sig[:63], ErrInvalidSignature},
		{"long signature", c, append(append([]byte(nil), sig...), 0), ErrInvalidSignature},
	} {
		if _, err := Encode(Proof{Context: tc.ctx, Signature: tc.sig}); err != tc.err {
			t.Errorf("%s: Encode = %v, want %v", tc.name, err, tc.err)
		}
		if tc.err != ErrInvalidSignature {
			if _, err := SigningBytes(tc.ctx); err != tc.err {
				t.Errorf("%s: SigningBytes = %v, want %v", tc.name, err, tc.err)
			}
		}
	}

	valid := string(mustEncode(t, Proof{Context: c, Signature: sig}))
	for _, tc := range []struct {
		in  string
		err error
	}{
		{strings.Replace(valid, Format, "locklark.vault-creation/v2", 1), ErrMalformed},
		{strings.Replace(valid, `"version":1`, `"version":2`, 1), ErrMalformed},
		{strings.Replace(valid, `"kind":"`+Kind+`"`, `"kind":"scope-proof"`, 1), ErrMalformed},
		// Field wrong types and missing members are malformed.
		{strings.Replace(valid, `"version":1`, `"version":"1"`, 1), ErrMalformed},
		{strings.Replace(valid, `"nonce":"`, `"nonce":1,"x":"`, 1), ErrMalformed},
		{strings.Replace(valid, `"kind":"`+Kind+`",`, "", 1), ErrMalformed},
	} {
		if _, err := Parse([]byte(tc.in)); err != tc.err {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, err, tc.err)
		}
	}
}

func TestSizeCap(t *testing.T) {
	// Exactly MaxProofBytes reaches JSON validation and is rejected on
	// content; field bounds keep every valid proof shorter than the cap.
	atCap := bytes.Repeat([]byte(" "), MaxProofBytes)
	if _, err := Parse(atCap); err != ErrMalformed {
		t.Fatalf("Parse(%d bytes) = %v, want ErrMalformed", len(atCap), err)
	}
	// One byte more is refused before any parsing.
	over := bytes.Repeat([]byte(" "), MaxProofBytes+1)
	if _, err := Parse(over); err != ErrTooLarge {
		t.Fatalf("Parse(%d bytes) = %v, want ErrTooLarge", len(over), err)
	}
	// The id bound keeps every valid proof under the cap.
	c := maxContext()
	if _, err := SigningBytes(c); err != nil {
		t.Fatalf("SigningBytes(max ids): %v", err)
	}
	c.Scope.DeviceID += "x"
	if _, err := SigningBytes(c); err != ErrInvalidID {
		t.Fatalf("SigningBytes(oversize id) = %v, want ErrInvalidID", err)
	}
}
