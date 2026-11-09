package passkeytransfer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"filippo.io/age"
)

// recipientString returns the canonical age X25519 recipient encoding.
func recipientString(r *age.X25519Recipient) (string, bool) {
	if r == nil {
		return "", false
	}
	s := r.String()
	parsed, err := age.ParseX25519Recipient(s)
	if err != nil || parsed.String() != s || s == "" {
		return "", false
	}
	return s, true
}

// parseRecipient accepts only the canonical age X25519 recipient encoding.
func parseRecipient(s string) (*age.X25519Recipient, bool) {
	if s == "" {
		return nil, false
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil || r.String() != s {
		return nil, false
	}
	return r, true
}

// auditKey derives the existing Ed25519 audit identity from the caller's seed.
func auditKey(seed []byte) (ed25519.PrivateKey, bool) {
	if len(seed) != ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed), true
}

func auditPublic(key ed25519.PrivateKey) ed25519.PublicKey {
	return key.Public().(ed25519.PublicKey)
}

// PublicFingerprint validates a canonical age recipient and an Ed25519 audit
// public key and returns their public target fingerprint. It accepts public
// inputs only: no seed, private key or user handle is read.
func PublicFingerprint(recipient string, auditPublic []byte) (string, error) {
	if _, ok := parseRecipient(recipient); !ok || len(auditPublic) != ed25519.PublicKeySize {
		return "", ErrRefused
	}
	pin := fingerprint(recipient, auditPublic)
	if !validPin(pin) {
		return "", ErrRefused
	}
	return pin, nil
}

// fingerprint hashes the protocol domain, the canonical recipient encoding and
// the length-framed audit public key. It is a lowercase SHA-256 hex string.
func fingerprint(recipient string, auditPublic []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write([]byte(recipient))
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], uint32(len(auditPublic)))
	h.Write(frame[:])
	h.Write(auditPublic)
	return hex.EncodeToString(h.Sum(nil))
}

// validPin accepts exactly 64 lowercase hex characters and nothing else.
func validPin(pin string) bool {
	if len(pin) != 64 || strings.ToLower(pin) != pin {
		return false
	}
	b, err := hex.DecodeString(pin)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == pin
}

// isDigest accepts a lowercase SHA-256 hex digest.
func isDigest(s string) bool { return validPin(s) }
