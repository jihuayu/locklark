package vaultcreationauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// identityKey and contentKey are derived from distinct fixed 32-byte seeds:
// the identity device key signs proofs, the separate content key must not be
// accepted for them.
func identityKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
}

func contentKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
}

// signProof signs the canonical preimage of c with key.
func signProof(t *testing.T, key ed25519.PrivateKey, c Context) Proof {
	t.Helper()
	pre, err := SigningBytes(c)
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	return Proof{Context: c, Signature: ed25519.Sign(key, pre)}
}

// now returns a clock reading well before the base context's deadline.
func now(c Context) int64 { return c.Challenge.DeadlineUnixMS - 1000 }

func TestVerifyAcceptsIdentityProof(t *testing.T) {
	expected := baseContext()
	proof := signProof(t, identityKey(), expected)
	if err := Verify(proof, expected, identityKey().Public().(ed25519.PublicKey), now(expected)); err != nil {
		t.Fatalf("Verify(identity proof) = %v, want nil", err)
	}
	// The proof survives the wire round trip and still verifies.
	// (Ed25519 signing is deterministic, so Encode/Parse do not change it.)
	b, err := Encode(proof)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := Verify(parsed, expected, identityKey().Public().(ed25519.PublicKey), now(expected)); err != nil {
		t.Fatalf("Verify(round-tripped proof) = %v, want nil", err)
	}
}

func TestVerifyRejectsContentKey(t *testing.T) {
	expected := baseContext()
	proof := signProof(t, identityKey(), expected)
	// The content key's public key is a valid 32-byte key but not the
	// registered identity: the same proof fails under it.
	contentPub := contentKey().Public().(ed25519.PublicKey)
	if err := Verify(proof, expected, contentPub, now(expected)); err != ErrInvalidSignature {
		t.Fatalf("Verify(content key) = %v, want ErrInvalidSignature", err)
	}
	// A proof signed by the content key also fails under the identity key.
	if err := Verify(signProof(t, contentKey(), expected), expected, identityKey().Public().(ed25519.PublicKey), now(expected)); err != ErrInvalidSignature {
		t.Fatalf("Verify(proof by content key) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsContextMismatch(t *testing.T) {
	expected := baseContext()
	identityPub := identityKey().Public().(ed25519.PublicKey)
	mutate := func(f func(*Context)) Context {
		c := expected
		c.Challenge.Nonce = [32]byte{}
		f(&c)
		return c
	}
	cases := []struct {
		name string
		ctx  Context
	}{
		{"tenant", mutate(func(c *Context) { c.Scope.TenantID = "Zt2" })},
		{"user", mutate(func(c *Context) { c.Scope.UserID = "Zu2" })},
		{"device", mutate(func(c *Context) { c.Scope.DeviceID = "Zd2" })},
		{"challenge id", mutate(func(c *Context) { c.Challenge.ID = "Zi2" })},
		{"nonce", mutate(func(c *Context) { c.Challenge.Nonce[0] = 1 })},
		{"deadline", mutate(func(c *Context) { c.Challenge.DeadlineUnixMS++ })},
		{"plan digest", mutate(func(c *Context) { c.PlanDigest[0] ^= 1 })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Signed over the expected context but presented with another.
			proof := signProof(t, identityKey(), expected)
			proof.Context = tc.ctx
			if err := Verify(proof, expected, identityPub, now(expected)); err != ErrContextMismatch {
				t.Fatalf("Verify = %v, want ErrContextMismatch", err)
			}
			// Exactly the same tampering with a valid signature over the
			// other context: still not the expected one.
			if err := Verify(signProof(t, identityKey(), tc.ctx), expected, identityPub, now(expected)); err != ErrContextMismatch {
				t.Fatalf("Verify(signed other context) = %v, want ErrContextMismatch", err)
			}
		})
	}
	// The comparison precedes the signature: a garbage signature on another
	// context is reported as a mismatch, not a signature failure.
	bad := Proof{Context: mutate(func(c *Context) { c.Scope.DeviceID = "Zd9" }), Signature: make([]byte, SignatureBytes)}
	if err := Verify(bad, expected, identityPub, now(expected)); err != ErrContextMismatch {
		t.Fatalf("Verify(mismatch, bad sig) = %v, want ErrContextMismatch", err)
	}
}

func TestVerifyExpiry(t *testing.T) {
	expected := baseContext()
	identityPub := identityKey().Public().(ed25519.PublicKey)
	proof := signProof(t, identityKey(), expected)
	deadline := expected.Challenge.DeadlineUnixMS
	for _, tc := range []struct {
		name string
		now  int64
		err  error
	}{
		{"deadline minus one", deadline - 1, nil},
		{"at deadline", deadline, ErrChallengeExpired},
		{"past deadline", deadline + 1, ErrChallengeExpired},
	} {
		if err := Verify(proof, expected, identityPub, tc.now); err != tc.err {
			t.Errorf("%s: Verify(now=%d) = %v, want %v", tc.name, tc.now, err, tc.err)
		}
	}
}

func TestVerifyBadInputs(t *testing.T) {
	expected := baseContext()
	identityPub := identityKey().Public().(ed25519.PublicKey)
	good := signProof(t, identityKey(), expected)

	tampered := Proof{Context: expected, Signature: append([]byte(nil), good.Signature...)}
	tampered.Signature[0] ^= 0xff
	for _, tc := range []struct {
		name  string
		proof Proof
		key   ed25519.PublicKey
		err   error
	}{
		{"altered signature", tampered, identityPub, ErrInvalidSignature},
		{"zero signature", Proof{Context: expected, Signature: make([]byte, SignatureBytes)}, identityPub, ErrInvalidSignature},
		{"short signature", Proof{Context: expected, Signature: good.Signature[:63]}, identityPub, ErrInvalidSignature},
		{"nil identity key", good, nil, ErrInvalidIdentityKey},
		{"short identity key", good, identityPub[:31], ErrInvalidIdentityKey},
		{"long identity key", good, append(append(ed25519.PublicKey(nil), identityPub...), 0), ErrInvalidIdentityKey},
	} {
		if err := Verify(tc.proof, expected, tc.key, now(expected)); err != tc.err {
			t.Errorf("%s: Verify = %v, want %v", tc.name, err, tc.err)
		}
	}

	// An invalid expected context is refused before anything else, whatever
	// the proof and key look like.
	for _, tc := range []struct {
		name string
		ctx  Context
		err  error
	}{
		{"empty tenant", func() Context { c := expected; c.Scope.TenantID = ""; return c }(), ErrInvalidID},
		{"oversize challenge id", func() Context { c := expected; c.Challenge.ID = strings.Repeat("Z", MaxIDBytes+1); return c }(), ErrInvalidID},
		{"zero deadline", func() Context { c := expected; c.Challenge.DeadlineUnixMS = 0; return c }(), ErrInvalidDeadline},
	} {
		if err := Verify(good, tc.ctx, identityPub, now(expected)); err != tc.err {
			t.Errorf("%s: Verify = %v, want %v", tc.name, err, tc.err)
		}
		if err := Verify(good, tc.ctx, nil, now(expected)); err != tc.err {
			t.Errorf("%s (nil key): Verify = %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestVerifyErrorsAreSentinels(t *testing.T) {
	for _, err := range []error{ErrContextMismatch, ErrChallengeExpired, ErrInvalidIdentityKey} {
		if !errors.Is(err, err) || err.Error() == "" {
			t.Fatalf("sentinel %v is not usable", err)
		}
	}
	if ErrContextMismatch == ErrChallengeExpired || ErrInvalidIdentityKey == ErrInvalidSignature {
		t.Fatal("sentinels must be distinct")
	}
}
