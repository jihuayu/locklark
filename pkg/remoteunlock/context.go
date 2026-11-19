package remoteunlock

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Wire constants of the v1 canonical binding context.
const (
	// Format is the fixed value of the "format" member.
	Format = "locklark.remote-unlock"
	// Version is the canonical JSON integer of the "version" member.
	Version = 1
	// Kind is the fixed value of the "kind" member.
	Kind = "channel-binding-context"
	// MaxContextSize is the maximum encoded or accepted size in bytes.
	MaxContextSize = 4096
	// MaxIdentifierLen is the maximum identifier length in bytes.
	MaxIdentifierLen = 128
	// DigestSize is the exact length of every digest in bytes.
	DigestSize = 32
)

// ErrInvalidContext reports a context that cannot be encoded.
var ErrInvalidContext = errors.New("remoteunlock: invalid binding context")

// ErrInvalidEncoding reports bytes that are not the canonical encoding of a
// valid binding context.
var ErrInvalidEncoding = errors.New("remoteunlock: invalid binding context encoding")

// Reasons reported by *FieldError. They wrap ErrInvalidContext when encoding
// and ErrInvalidEncoding when parsing. Messages are static so they never embed
// a field value or secret bytes.
var (
	errEmpty           = fmt.Errorf("%w: identifier must not be empty", ErrInvalidContext)
	errTooLong         = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidContext, MaxIdentifierLen)
	errInvalidChar     = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidContext)
	errEpoch           = fmt.Errorf("%w: key_epoch must be greater than zero", ErrInvalidContext)
	errDeadline        = fmt.Errorf("%w: deadline_unix_ms must be greater than zero", ErrInvalidContext)
	errOverBudget      = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidContext, MaxContextSize)
	errNotObject       = fmt.Errorf("%w: not a single JSON object", ErrInvalidEncoding)
	errMissing         = fmt.Errorf("%w: missing member", ErrInvalidEncoding)
	errInvalidUTF8     = fmt.Errorf("%w: not valid UTF-8", ErrInvalidEncoding)
	errNonCanonicalStr = fmt.Errorf("%w: string is not canonical", ErrInvalidEncoding)
	errWrongValue      = fmt.Errorf("%w: wrong constant or type", ErrInvalidEncoding)
	errDuplicate       = fmt.Errorf("%w: duplicate member", ErrInvalidEncoding)
	errOutOfOrder      = fmt.Errorf("%w: member out of order", ErrInvalidEncoding)
	errUnknown         = fmt.Errorf("%w: unknown member", ErrInvalidEncoding)
	errTrailing        = fmt.Errorf("%w: trailing data", ErrInvalidEncoding)
	errTooLarge        = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidEncoding, MaxContextSize)
	errEmptyInput      = fmt.Errorf("%w: empty input", ErrInvalidEncoding)
	errKeyEpoch        = fmt.Errorf("%w: key_epoch must be canonical decimal greater than zero", ErrInvalidEncoding)
	errDeadlineField   = fmt.Errorf("%w: deadline_unix_ms must be canonical decimal greater than zero", ErrInvalidEncoding)
	errDigest          = fmt.Errorf("%w: digest must be exactly %d bytes", ErrInvalidEncoding, DigestSize)
	errDigestForm      = fmt.Errorf("%w: digest is not strict unpadded base64url", ErrInvalidEncoding)
	errUintSyntax      = fmt.Errorf("%w: integer is not canonical unsigned decimal", ErrInvalidEncoding)
	errLeadingZero     = fmt.Errorf("%w: integer has a leading zero", ErrInvalidEncoding)
	errFraction        = fmt.Errorf("%w: integer has a fraction", ErrInvalidEncoding)
	errExponent        = fmt.Errorf("%w: integer has an exponent", ErrInvalidEncoding)
	errOverflow        = fmt.Errorf("%w: integer overflows its type", ErrInvalidEncoding)
	errReencode        = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidEncoding)

	errIdentifierEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidEncoding)
	errIdentifierTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidEncoding, MaxIdentifierLen)
	errIdentifierChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidEncoding)
)

// FieldError identifies the schema member that failed validation. The error
// message never includes the member's value.
type FieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *FieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: binding context: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: binding context field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *FieldError) Unwrap() error { return e.Err }

func fieldErr(field string, err error) error {
	if field == "" {
		return &FieldError{Err: err}
	}
	return &FieldError{Field: field, Err: err}
}

// members lists the schema members in their exact required order.
var members = [...]string{
	"format",
	"version",
	"kind",
	"request_id",
	"request_digest",
	"pair_id",
	"pair_generation",
	"lock_generation",
	"member_id",
	"source_device_id",
	"target_device_id",
	"vault_id",
	"key_epoch",
	"policy_seq",
	"policy_digest",
	"deadline_unix_ms",
}

// ChannelBindingContext is the v1 binding context that identifies one remote
// unlock request on a pinned TLS 1.3 channel. Every member is required.
//
// The struct only carries claims. Encoding or parsing it proves none of them:
// see the package documentation for the scope boundary.
type ChannelBindingContext struct {
	// RequestID is the opaque request identifier.
	RequestID string
	// RequestDigest is an opaque 32-byte summary of the unlock request. Its
	// preimage is defined by a separate request codec and is not interpreted
	// here; a verifier must recompute and compare it.
	RequestDigest [DigestSize]byte
	// PairID is the opaque pairing identifier.
	PairID string
	// PairGeneration is the pairing generation; zero is an explicit genesis
	// value.
	PairGeneration uint64
	// LockGeneration is the lock generation; zero is an explicit genesis
	// value.
	LockGeneration uint64
	// MemberID is the opaque member identifier.
	MemberID string
	// SourceDeviceID is the opaque identifier of the requesting device.
	SourceDeviceID string
	// TargetDeviceID is the opaque identifier of the unlocking device.
	TargetDeviceID string
	// VaultID is the opaque vault identifier.
	VaultID string
	// KeyEpoch is the vault key epoch; it must be greater than zero.
	KeyEpoch uint64
	// PolicySeq is the policy sequence number; zero is an explicit genesis
	// value.
	PolicySeq uint64
	// PolicyDigest is an opaque 32-byte digest of the governing policy. Its
	// preimage is defined by a separate policy encoding and is not interpreted
	// here.
	PolicyDigest [DigestSize]byte
	// DeadlineUnixMS is the absolute deadline in Unix milliseconds. It must be
	// strictly positive and is used exactly as supplied: the codec never reads
	// the clock or adjusts it.
	DeadlineUnixMS int64
}

// EncodeChannelBindingContext validates c and returns its canonical v1 JSON
// encoding, which is never longer than MaxContextSize bytes.
func EncodeChannelBindingContext(c ChannelBindingContext) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 512)
	buf = append(buf, '{')
	buf = appendStringMember(buf, members[0], Format)
	buf = appendUintMember(buf, members[1], Version)
	buf = appendStringMember(buf, members[2], Kind)
	buf = appendStringMember(buf, members[3], c.RequestID)
	buf = appendDigestMember(buf, members[4], c.RequestDigest)
	buf = appendStringMember(buf, members[5], c.PairID)
	buf = appendUintMember(buf, members[6], c.PairGeneration)
	buf = appendUintMember(buf, members[7], c.LockGeneration)
	buf = appendStringMember(buf, members[8], c.MemberID)
	buf = appendStringMember(buf, members[9], c.SourceDeviceID)
	buf = appendStringMember(buf, members[10], c.TargetDeviceID)
	buf = appendStringMember(buf, members[11], c.VaultID)
	buf = appendUintMember(buf, members[12], c.KeyEpoch)
	buf = appendUintMember(buf, members[13], c.PolicySeq)
	buf = appendDigestMember(buf, members[14], c.PolicyDigest)
	buf = appendIntMember(buf, members[15], c.DeadlineUnixMS)
	buf[len(buf)-1] = '}'

	// validate guarantees ids of at most MaxIdentifierLen bytes over an ASCII
	// alphabet that needs no escaping, so the size bound holds trivially; the
	// check is kept as a defensive invariant.
	if len(buf) > MaxContextSize {
		return nil, fieldErr("", errOverBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (c ChannelBindingContext) validate() error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{members[3], c.RequestID},
		{members[5], c.PairID},
		{members[8], c.MemberID},
		{members[9], c.SourceDeviceID},
		{members[10], c.TargetDeviceID},
		{members[11], c.VaultID},
	} {
		if err := validateIdentifier(f.value); err != nil {
			return fieldErr(f.name, err)
		}
	}
	if c.KeyEpoch == 0 {
		return fieldErr(members[12], errEpoch)
	}
	if c.DeadlineUnixMS <= 0 {
		return fieldErr(members[15], errDeadline)
	}
	return nil
}

// validateIdentifier enforces the opaque identifier grammar: 1 to
// MaxIdentifierLen bytes, each ASCII a-z, 0-9, '.', '_', ':' or '-'.
func validateIdentifier(s string) error {
	if s == "" {
		return errEmpty
	}
	if len(s) > MaxIdentifierLen {
		return errTooLong
	}
	for i := 0; i < len(s); i++ {
		if !isIdentifierByte(s[i]) {
			return errInvalidChar
		}
	}
	return nil
}

func isIdentifierByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	return b == '.' || b == '_' || b == ':' || b == '-'
}

// appendStringMember appends `"name":"value",`: a string member plus the
// comma that separates it from the next member.
func appendStringMember(buf []byte, name, value string) []byte {
	buf = append(buf, '"')
	buf = append(buf, name...)
	buf = append(buf, '"', ':')
	buf = appendJSONString(buf, value)
	return append(buf, ',')
}

// appendJSONString writes value as a canonical JSON string. Every byte allowed
// by the identifier grammar is written verbatim.
func appendJSONString(buf []byte, value string) []byte {
	buf = append(buf, '"')
	for i := 0; i < len(value); i++ {
		switch b := value[i]; b {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		default:
			if b < 0x20 {
				buf = append(buf, '\\', 'u', '0', '0', hexDigit(b>>4), hexDigit(b))
				continue
			}
			buf = append(buf, b)
		}
	}
	return append(buf, '"')
}

func hexDigit(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}

// appendMemberName appends `"name":`, the key of a member. Every appender
// writes one member and its trailing comma so the encoder can drop the final
// comma for the closing brace.
func appendMemberName(buf []byte, name string) []byte {
	buf = append(buf, '"')
	buf = append(buf, name...)
	return append(buf, '"', ':')
}

func appendUintMember(buf []byte, name string, v uint64) []byte {
	buf = appendMemberName(buf, name)
	buf = strconv.AppendUint(buf, v, 10)
	return append(buf, ',')
}

func appendIntMember(buf []byte, name string, v int64) []byte {
	buf = appendMemberName(buf, name)
	buf = strconv.AppendInt(buf, v, 10)
	return append(buf, ',')
}

func appendDigestMember(buf []byte, name string, d [DigestSize]byte) []byte {
	buf = appendMemberName(buf, name)
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, d[:])
	return append(buf, '"', ',')
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// context. It never falls back to the struct field order.
func (c ChannelBindingContext) MarshalJSON() ([]byte, error) {
	return EncodeChannelBindingContext(c)
}

// UnmarshalJSON replaces c only when data is exactly the canonical encoding of
// a valid context.
func (c *ChannelBindingContext) UnmarshalJSON(data []byte) error {
	if c == nil {
		return fieldErr("", errEmptyInput)
	}
	parsed, err := ParseChannelBindingContext(data)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// ParseChannelBindingContext parses b, which must be exactly the canonical v1
// encoding of a valid context. Every other spelling (unknown, missing,
// duplicate or reordered members, non-canonical strings or numbers, padded or
// oversized digests, trailing data) is rejected with an error wrapping
// ErrInvalidEncoding. Errors never contain field values.
func ParseChannelBindingContext(b []byte) (ChannelBindingContext, error) {
	var c ChannelBindingContext
	if len(b) > MaxContextSize {
		return c, fieldErr("", errTooLarge)
	}
	if len(b) == 0 {
		return c, fieldErr("", errEmptyInput)
	}
	if !utf8.Valid(b) {
		return c, fieldErr("", errInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.expect('{', errNotObject); err != nil {
		return c, err
	}
	for i, want := range members {
		if i > 0 {
			if err := p.expect(',', errMissing); err != nil {
				return c, err
			}
		}
		key, err := p.string()
		if err != nil {
			return c, fieldErr(want, err)
		}
		if err := p.expect(':', errMissing); err != nil {
			return c, fieldErr(want, err)
		}
		// A key that repeats an earlier member is reported as a duplicate,
		// not as an unknown key or a reordering.
		for j := 0; j < i; j++ {
			if key == members[j] {
				return c, fieldErr(key, errDuplicate)
			}
		}
		if key != want {
			if j := memberIndex(key); j >= 0 {
				if j > i {
					// The expected member and any before key were omitted.
					return c, fieldErr(want, errMissing)
				}
				return c, fieldErr(key, errOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return c, fieldErr("", errUnknown)
		}
		if err := p.member(i, &c); err != nil {
			return c, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		key, err := p.peekString()
		if err == nil && isKnownMember(key) {
			return c, fieldErr(key, errDuplicate)
		}
		if err == nil {
			// Unknown keys are attacker-controlled; do not echo them.
			return c, fieldErr("", errUnknown)
		}
		return c, fieldErr("", errTrailing)
	}
	if err := p.expect('}', errMissing); err != nil {
		return c, err
	}
	if p.pos != len(p.buf) {
		return c, fieldErr("", errTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodeChannelBindingContext(c)
	if err != nil || !bytes.Equal(reencoded, b) {
		return ChannelBindingContext{}, fieldErr("", errReencode)
	}
	return c, nil
}

type parser struct {
	buf []byte
	pos int
}

func isKnownMember(key string) bool { return memberIndex(key) >= 0 }

// memberIndex returns the schema position of key, or -1 if key is not a
// schema member.
func memberIndex(key string) int {
	for i, m := range members {
		if m == key {
			return i
		}
	}
	return -1
}

// peekString parses a string at the cursor without consuming it.
func (p *parser) peekString() (string, error) {
	saved := p.pos
	v, err := p.string()
	p.pos = saved
	return v, err
}

// expect consumes the literal byte want, reporting end-of-input and
// mismatches with the static reason given by the caller.
func (p *parser) expect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return fieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		return fieldErr("", errWrongValue)
	}
	p.pos++
	return nil
}

// string parses a JSON string and returns its decoded value. Raw control
// bytes, non-canonical escapes and invalid escapes are rejected.
func (p *parser) string() (string, error) {
	if p.pos >= len(p.buf) || p.buf[p.pos] != '"' {
		return "", errWrongValue
	}
	p.pos++
	start := p.pos
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		switch {
		case c == '"':
			v := string(p.buf[start:p.pos])
			p.pos++
			return v, nil
		case c == '\\':
			return "", errNonCanonicalStr
		case c < 0x20:
			return "", errNonCanonicalStr
		}
		p.pos++
	}
	return "", errNonCanonicalStr
}

// number scans one JSON number token and returns it.
func (p *parser) number() (string, error) {
	start := p.pos
	for p.pos < len(p.buf) {
		switch p.buf[p.pos] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '+', '.', 'e', 'E':
			p.pos++
			continue
		}
		break
	}
	if p.pos == start {
		return "", errUintSyntax
	}
	return string(p.buf[start:p.pos]), nil
}

// member parses the value of members[i] into c.
func (p *parser) member(i int, c *ChannelBindingContext) error {
	name := members[i]
	switch i {
	case 0:
		v, err := p.string()
		if err != nil {
			return fieldErr(name, err)
		}
		if v != Format {
			return fieldErr(name, errWrongValue)
		}
		return nil
	case 1:
		v, err := p.number()
		if err != nil {
			return fieldErr(name, err)
		}
		if v != "1" {
			return fieldErr(name, errWrongValue)
		}
		return nil
	case 2:
		v, err := p.string()
		if err != nil {
			return fieldErr(name, err)
		}
		if v != Kind {
			return fieldErr(name, errWrongValue)
		}
		return nil
	case 3:
		return p.identifier(name, &c.RequestID)
	case 4:
		return p.digest(name, &c.RequestDigest)
	case 5:
		return p.identifier(name, &c.PairID)
	case 6:
		return p.uint(name, &c.PairGeneration)
	case 7:
		return p.uint(name, &c.LockGeneration)
	case 8:
		return p.identifier(name, &c.MemberID)
	case 9:
		return p.identifier(name, &c.SourceDeviceID)
	case 10:
		return p.identifier(name, &c.TargetDeviceID)
	case 11:
		return p.identifier(name, &c.VaultID)
	case 12:
		if err := p.uint(name, &c.KeyEpoch); err != nil {
			return err
		}
		if c.KeyEpoch == 0 {
			return fieldErr(name, errKeyEpoch)
		}
		return nil
	case 13:
		return p.uint(name, &c.PolicySeq)
	case 14:
		return p.digest(name, &c.PolicyDigest)
	case 15:
		return p.deadline(name, &c.DeadlineUnixMS)
	}
	return fieldErr(name, errUnknown)
}

func (p *parser) identifier(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return fieldErr(name, err)
	}
	if err := validateIdentifier(v); err != nil {
		return fieldErr(name, identifierError(err))
	}
	*dst = v
	return nil
}

// identifierError maps a shared identifier-grammar failure to its static
// parsing reason.
func identifierError(err error) error {
	switch {
	case errors.Is(err, errEmpty):
		return errIdentifierEmpty
	case errors.Is(err, errTooLong):
		return errIdentifierTooLong
	default:
		return errIdentifierChar
	}
}

func (p *parser) digest(name string, dst *[DigestSize]byte) error {
	v, err := p.string()
	if err != nil {
		return fieldErr(name, err)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(DigestSize) {
		return fieldErr(name, errDigest)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst[:], []byte(v))
	if err != nil || n != DigestSize || base64.RawURLEncoding.EncodeToString(dst[:]) != v {
		return fieldErr(name, errDigestForm)
	}
	return nil
}

// uint parses a canonical unsigned decimal integer: digits only, no sign, no
// leading zero except the value "0", no fraction or exponent, in uint64 range.
func (p *parser) uint(name string, dst *uint64) error {
	raw, err := p.number()
	if err != nil {
		return fieldErr(name, err)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return fieldErr(name, errUintSyntax)
		case c == '.':
			return fieldErr(name, errFraction)
		case c == 'e' || c == 'E':
			return fieldErr(name, errExponent)
		case c < '0' || c > '9':
			return fieldErr(name, errUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return fieldErr(name, errLeadingZero)
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fieldErr(name, errOverflow)
	}
	*dst = v
	return nil
}

// deadline parses a canonical positive decimal int64 in Unix milliseconds.
func (p *parser) deadline(name string, dst *int64) error {
	raw, err := p.number()
	if err != nil {
		return fieldErr(name, err)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return fieldErr(name, errUintSyntax)
		case c == '.':
			return fieldErr(name, errFraction)
		case c == 'e' || c == 'E':
			return fieldErr(name, errExponent)
		case c < '0' || c > '9':
			return fieldErr(name, errUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return fieldErr(name, errLeadingZero)
	}
	if raw[0] == '0' {
		return fieldErr(name, errDeadlineField)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return fieldErr(name, errDeadlineField)
	}
	*dst = v
	return nil
}
