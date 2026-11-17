package onedriveauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Entropy sizes for the two random values the authorization flow needs. Both
// are at least the RFC 7636 minimum (32 octets) and well inside the RFC 6749
// recommendation that an authorization request carry 128 bits of state entropy.
//
// Both encode to 43 unpadded base64url characters, and 43*6 = 258 bits, so the
// final character carries 2 significant bits and the last 4 bits of the last
// octet's encoding are zero (the trailing-bits rule RFC 4648 §3.5 expects of a
// decoder).
const (
	verifierBytes = 32
	stateBytes    = 32
	encodedLen    = 43
)

// S256 returns the RFC 7636 S256 code challenge for verifier:
// BASE64URL(SHA256(ASCII(verifier))) without padding. It does not validate the
// verifier; use ValidVerifier to check attacker- or config-supplied input first.
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewVerifier returns a fresh PKCE code verifier from the system CSPRNG: 32
// random octets encoded as 43 unpadded base64url characters, using only the
// RFC 7636 unreserved set (A-Z a-z 0-9 - _). It is the only constructor,
// because a verifier with less entropy cannot be detected after the fact.
func NewVerifier() (string, error) {
	raw := make([]byte, verifierBytes)
	if err := randomBytes(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// NewState returns a fresh OAuth state value from the system CSPRNG, encoded
// like the verifier (encodedLen unpadded base64url characters). The caller keeps it out
// of logs and compares it only through Start's callback verification.
func NewState() (string, error) {
	raw := make([]byte, stateBytes)
	if err := randomBytes(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ValidVerifier reports whether verifier is a well-formed RFC 7636 code
// verifier: 43 to 128 unreserved characters.
func ValidVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreserved(verifier[i]) {
			return false
		}
	}
	return true
}

// ValidState reports whether state has the shape NewState produces. It is a
// shape check, not a freshness or binding check; only Start binds state to a
// redirect.
func ValidState(state string) bool {
	return state != "" && len(state) <= 128 && strings.Trim(state, unreservedChars) == ""
}

// unreservedChars is every RFC 3986 unreserved character, for strings.Trim.
const unreservedChars = rawURLAlphabet

// rawURLAlphabet is the RFC 4648 §5 base64url alphabet, already in value order,
// which is the unreserved character set NewVerifier/NewState emit.
const rawURLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func isUnreserved(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	case c == '-', c == '_':
		return true
	}
	return false
}

// randomBytes fills b from crypto/rand. Failures carry no state, because none
// is generated yet.
func randomBytes(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return wrap(ErrRandom, nil)
	}
	return nil
}
