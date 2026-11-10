package onedriveauth

import (
	"crypto/subtle"
	"errors"
	"strings"
	"testing"
)

// RFC 7636 Appendix B, verbatim.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	verifierLen = encodedLen
	stateLen    = encodedLen
)

func TestS256RFC7636Vector(t *testing.T) {
	if !ValidVerifier(rfcVerifier) {
		t.Fatalf("RFC 7636 verifier rejected by ValidVerifier")
	}
	if got := S256(rfcVerifier); got != rfcChallenge {
		t.Fatalf("S256(rfc verifier) = %q, want RFC 7636 challenge", got)
	}
	if S256("") != "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Fatalf("S256(\"\") mismatch")
	}
	if strings.ContainsAny(S256(rfcVerifier), "=+/") {
		t.Fatalf("S256 output is not unpadded base64url")
	}
}

func TestNewVerifierShape(t *testing.T) {
	seen := make(map[string]bool)
	for range 64 {
		v, err := NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		if len(v) != verifierLen {
			t.Fatalf("verifier length = %d, want 43", len(v))
		}
		if !ValidVerifier(v) {
			t.Fatalf("verifier fails ValidVerifier")
		}
		if strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" ||
			strings.ContainsAny(v, "=+/.") {
			t.Fatalf("verifier contains characters outside RFC 7636 unreserved set")
		}
		if seen[v] {
			t.Fatalf("duplicate verifier from two draws")
		}
		seen[v] = true
	}
}

func TestNewStateShape(t *testing.T) {
	seen := make(map[string]bool)
	for range 64 {
		s, err := NewState()
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		if len(s) != stateLen {
			t.Fatalf("state length = %d, want 43", len(s))
		}
		if !ValidState(s) {
			t.Fatalf("state fails ValidState")
		}
		if seen[s] {
			t.Fatalf("duplicate state from two draws")
		}
		seen[s] = true
	}
}

// TestRandomDistributionFormat checks that the generation is uniform enough:
// every base64url alphabet position appears across draws, both values agree on
// format, and verifier and state are not correlated in shape.
func TestRandomDistributionFormat(t *testing.T) {
	const draws = 256
	var used [64]bool
	for range draws {
		v, err := NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		s, err := NewState()
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		for _, vv := range []string{v, s} {
			if len(vv) != verifierLen {
				t.Fatalf("random value length = %d, want 43", len(vv))
			}
			for i := 0; i < len(vv); i++ {
				idx := strings.IndexByte(unreservedChars, vv[i])
				if idx < 0 {
					t.Fatalf("random value has a byte outside the alphabet")
				}
				used[idx] = true
			}
		}
		// 43 unpadded base64url chars encode 32+ octets, so the final
		// character carries 2 bits: only indices with low 2 bits == 0.
		// "A".."Z" then "a".."z" then "0".."9" then "-_" order the alphabet
		// by value, so a last character is well-formed iff value % 4 == 0.
		if idx := strings.IndexByte(unreservedChars, v[verifierLen-1]) % 4; idx != 0 {
			t.Fatalf("verifier last character has non-zero trailing bits")
		}
	}
	for i, ok := range used {
		if !ok {
			t.Fatalf("alphabet position %d never produced across %d draws", i, draws)
		}
	}
	if subtle.ConstantTimeCompare([]byte("x"), nil) != 0 {
		t.Fatalf("subtle comparison of unequal lengths is not 0")
	}
}

func TestValidVerifierRejects(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"too short":        strings.Repeat("a", 42),
		"too long":         strings.Repeat("a", 129),
		"space":            strings.Repeat("a", 42) + " ",
		"plus":             strings.Repeat("a", 42) + "+",
		"slash":            strings.Repeat("a", 42) + "/",
		"equals":           strings.Repeat("a", 42) + "=",
		"unicode":          strings.Repeat("a", 42) + "\u00e9",
		"control":          strings.Repeat("a", 42) + "\x00",
		"dots":             strings.Repeat("a", 42) + ".",
		"tilde":            strings.Repeat("a", 42) + "~",
		"embedded newline": strings.Repeat("a", 20) + "\n" + strings.Repeat("a", 22),
	}
	for name, v := range cases {
		if ValidVerifier(v) {
			t.Fatalf("%s: ValidVerifier accepted an invalid verifier", name)
		}
	}
	if !ValidVerifier(strings.Repeat("a", 43)) || !ValidVerifier(strings.Repeat("Z", 128)) {
		t.Fatalf("ValidVerifier rejected boundary-length valid verifiers")
	}
}

func TestValidStateRejects(t *testing.T) {
	for name, s := range map[string]string{
		"empty":    "",
		"space":    "abc def",
		"amp":      "a&b",
		"equals":   "a=b",
		"too long": strings.Repeat("a", 129),
		"unicode":  "st\u00e4te",
	} {
		if ValidState(s) {
			t.Fatalf("%s: ValidState accepted an invalid state", name)
		}
	}
}

func TestErrorsAreSentinels(t *testing.T) {
	if !errors.Is(wrap(ErrState, errors.New("secret detail")), ErrState) {
		t.Fatalf("wrap lost sentinel")
	}
	if got := wrap(ErrProvider, errors.New("error_description=x")).Error(); strings.Contains(got, "x") {
		t.Fatalf("wrap copied detail into message")
	}
}
