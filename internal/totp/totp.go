// Package totp implements a bounded OTP configuration profile and RFC 6238
// calculation. It performs no I/O, authentication, authorization or audit.
// A trusted caller must commit its use/disclosure intent before requesting or
// exposing a code. This package is not an Agent or CLI entry point.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxInput = 4096

var ErrInvalid = errors.New("invalid TOTP configuration")
var ErrUnsupported = errors.New("unsupported TOTP configuration")
var ErrLimit = errors.New("TOTP configuration capacity exceeded")
var ErrTime = errors.New("TOTP time outside supported range")

type Parameters struct {
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int64  `json:"period"`
}

// Config has no seed accessor. Default formatting and JSON are redacted.
// This limits accidental logging, not access by code in the same process.
type Config struct {
	key    [64]byte
	size   int
	params Parameters
}

// Window is a half-open interval of UTC Unix seconds: [From, Until).
type Window struct{ From, Until int64 }

// Code requires an explicit Value call to expose its sensitive digits.
// Formatting and JSON never expose the digits; this type grants no authority.
type Code struct {
	value  string
	window Window
}

func (c Code) Value() string  { return c.value }
func (c Code) Window() Window { return c.window }
func (c *Config) Parameters() Parameters {
	if c == nil {
		return Parameters{}
	}
	return c.params
}
func (Config) Format(s fmt.State, _ rune) { io.WriteString(s, "[redacted OTP configuration]") }
func (Code) Format(s fmt.State, _ rune)   { io.WriteString(s, "[redacted OTP code]") }
func (Config) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted OTP configuration]"`), nil
}
func (Code) MarshalJSON() ([]byte, error)  { return []byte(`"[redacted OTP code]"`), nil }
func (*Config) UnmarshalJSON([]byte) error { return ErrUnsupported }
func (*Code) UnmarshalJSON([]byte) error   { return ErrUnsupported }

// Parse accepts canonical base32 (ASCII case-insensitive, with or without
// padding), or a strict otpauth://totp URI. It never returns an input-bearing
// decoder error. The returned configuration is immutable and safe to share.
func Parse(raw string) (*Config, error) {
	if len(raw) > MaxInput {
		return nil, ErrLimit
	}
	params := Parameters{"SHA1", 6, 30}
	seed := raw
	if strings.Contains(raw, ":") {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "otpauth" || u.Opaque != "" || u.User != nil || strings.Contains(raw, "#") {
			return nil, ErrInvalid
		}
		if strings.EqualFold(u.Host, "hotp") {
			return nil, ErrUnsupported
		}
		if !strings.EqualFold(u.Host, "totp") || !strings.HasPrefix(u.Path, "/") {
			return nil, ErrInvalid
		}
		label := strings.TrimPrefix(u.Path, "/")
		if !labelText(label) || strings.Count(label, ":") > 1 || u.RawQuery == "" || strings.Contains(u.RawQuery, ";") {
			return nil, ErrInvalid
		}
		values := map[string]string{}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return nil, ErrInvalid
			}
			key, err = url.QueryUnescape(key)
			if err != nil {
				return nil, ErrInvalid
			}
			value, err = url.QueryUnescape(value)
			if err != nil || value == "" {
				return nil, ErrInvalid
			}
			if _, exists := values[key]; exists {
				return nil, ErrInvalid
			}
			switch key {
			case "secret", "algorithm", "digits", "period", "issuer":
				values[key] = value
			default:
				return nil, ErrUnsupported
			}
		}
		seed = values["secret"]
		if issuer, ok := values["issuer"]; ok && (!labelText(issuer) || strings.Contains(issuer, ":")) {
			return nil, ErrInvalid
		}
		if issuer, account, hasIssuer := strings.Cut(label, ":"); hasIssuer {
			if !labelText(issuer) || !labelText(account) || values["issuer"] != "" && values["issuer"] != issuer {
				return nil, ErrInvalid
			}
		}
		if algorithm, ok := values["algorithm"]; ok {
			for _, c := range []byte(algorithm) {
				if c > 127 {
					return nil, ErrUnsupported
				}
			}
			params.Algorithm = strings.ToUpper(algorithm)
			switch params.Algorithm {
			case "SHA1", "SHA256", "SHA512":
			default:
				return nil, ErrUnsupported
			}
		}
		if digits, ok := values["digits"]; ok {
			n, err := positiveDecimal(digits)
			if err != nil {
				return nil, err
			}
			if n != 6 && n != 8 {
				return nil, ErrUnsupported
			}
			params.Digits = int(n)
		}
		if period, ok := values["period"]; ok {
			n, err := positiveDecimal(period)
			if err != nil {
				return nil, err
			}
			if n > 3600 {
				return nil, ErrUnsupported
			}
			params.Period = n
		}
	}
	if len(seed) > 104 {
		return nil, ErrLimit
	}
	for _, c := range []byte(seed) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '2' && c <= '7' || c == '=') {
			return nil, ErrInvalid
		}
	}
	seed = strings.ToUpper(seed)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	if strings.Contains(seed, "=") {
		encoding = base32.StdEncoding
	}
	key, err := encoding.DecodeString(seed)
	defer clear(key)
	if err != nil || encoding.EncodeToString(key) != seed || len(key) < 16 {
		return nil, ErrInvalid
	}
	if len(key) > 64 {
		return nil, ErrLimit
	}
	config := &Config{size: len(key), params: params}
	copy(config.key[:], key)
	return config, nil
}

func labelText(s string) bool {
	if len(s) > 256 || strings.TrimSpace(s) == "" || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func positiveDecimal(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return 0, ErrInvalid
	}
	return n, nil
}

// At uses an explicit UTC Unix second, never a hidden system clock. Negative
// times and unrepresentable validity windows fail with a zero Code.
func (c *Config) At(unixSeconds int64) (Code, error) {
	if c == nil || c.size < 16 || c.size > len(c.key) || c.params.Digits != 6 && c.params.Digits != 8 || c.params.Period < 1 || c.params.Period > 3600 {
		return Code{}, ErrInvalid
	}
	var newHash func() hash.Hash
	switch c.params.Algorithm {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return Code{}, ErrInvalid
	}
	if unixSeconds < 0 {
		return Code{}, ErrTime
	}
	from := unixSeconds - unixSeconds%c.params.Period
	if from > math.MaxInt64-c.params.Period {
		return Code{}, ErrTime
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(unixSeconds/c.params.Period))
	mac := hmac.New(newHash, c.key[:c.size])
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 15
	n := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if c.params.Digits == 8 {
		modulus = 100000000
	}
	return Code{fmt.Sprintf("%0*d", c.params.Digits, n%modulus), Window{from, from + c.params.Period}}, nil
}
