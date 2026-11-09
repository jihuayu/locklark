package passkeytransfer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// decodeCanonical accepts exactly one bounded JSON value and then requires the
// decoded value to re-encode to the same bytes (modulo surrounding whitespace).
// That rejects duplicate keys, key aliases, unknown fields, invalid UTF-8,
// escaped variants and non-canonical base64 before any field is trusted.
func decodeCanonical(raw []byte, limit int, dst any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrRefused
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrRefused
	}
	if dec.Decode(new(any)) != io.EOF {
		return ErrRefused
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return ErrRefused
	}
	return nil
}

// decodeStdAny accepts only canonical padded standard base64.
func decodeStdAny(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// decodeStd accepts canonical padded standard base64 for exactly n bytes.
func decodeStd(s string, n int) ([]byte, bool) {
	b, ok := decodeStdAny(s)
	return b, ok && len(b) == n
}

// decodeURL accepts canonical unpadded base64url for exactly n bytes.
func decodeURL(s string, n int) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != n || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// decodeHex32 accepts 32 lowercase hex characters (a 16-byte identifier).
func decodeHex32(s string) bool {
	if len(s) != 32 || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == s
}

// textOK bounds optional display text and rejects control characters that
// could forge logs or line-oriented formats.
func textOK(s string) bool {
	return len(s) <= maxTitle && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
