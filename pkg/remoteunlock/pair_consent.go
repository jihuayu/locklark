package remoteunlock

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Wire constants of the v1 canonical pair consent.
const (
	// PairConsentFormat is the fixed value of the consent's "format" member.
	// It equals Format.
	PairConsentFormat = Format
	// PairConsentVersion is the canonical JSON integer of the consent's
	// "version" member. It equals Version.
	PairConsentVersion = Version
	// KindPairConsent is the fixed value of the consent's "kind" member.
	KindPairConsent = "pair-consent"
	// PairConsentSignatureDomain separates the pair-consent signature
	// preimage from every other signed structure. The preimage is this domain
	// followed by the canonical JSON of members 1..13 (format through
	// deadline_unix_ms). Both endpoints sign exactly these bytes.
	PairConsentSignatureDomain = "locklark.remote-unlock/v1/pair-consent\x00"
	// MaxPairConsentSize is the maximum encoded or accepted consent size in
	// bytes.
	MaxPairConsentSize = 2048
	// PairConsentDigestSize is the exact length of device_a_binding_sha256
	// and device_b_binding_sha256 in bytes.
	PairConsentDigestSize = 32
	// PairConsentSignatureSize is the exact length of device_a_signature and
	// device_b_signature in bytes.
	PairConsentSignatureSize = ed25519.SignatureSize
)

// ErrInvalidPairConsent reports a pair consent that cannot be encoded or
// verified.
var ErrInvalidPairConsent = errors.New("remoteunlock: invalid pair consent")

// ErrInvalidPairConsentEncoding reports bytes that are not the canonical
// encoding of a valid pair consent.
var ErrInvalidPairConsentEncoding = errors.New("remoteunlock: invalid pair consent encoding")

// Pair-consent rejection reasons. They wrap ErrInvalidPairConsent for values,
// keys, signatures and verification and ErrInvalidPairConsentEncoding for
// spellings. Messages are static and never embed a member value, an
// identifier, a key, a digest, a signature or a verification time.
var (
	errPairConsentEndpointOrder = fmt.Errorf("%w: device_a_id must be strictly less than device_b_id in bytewise order", ErrInvalidPairConsent)
	errPairConsentEndpointEqual = fmt.Errorf("%w: device_a_id and device_b_id must differ", ErrInvalidPairConsent)
	errPairConsentDeadline      = fmt.Errorf("%w: deadline_unix_ms must be greater than zero", ErrInvalidPairConsent)
	errPairConsentBudget        = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidPairConsent, MaxPairConsentSize)
	errPairConsentParseOrder    = fmt.Errorf("%w: device_a_id must be strictly less than device_b_id in bytewise order", ErrInvalidPairConsentEncoding)
	errPairConsentParseEqual    = fmt.Errorf("%w: device_a_id and device_b_id must differ", ErrInvalidPairConsentEncoding)
	errPairConsentParseDeadline = fmt.Errorf("%w: deadline_unix_ms must be canonical decimal greater than zero", ErrInvalidPairConsentEncoding)

	errPairConsentNow              = fmt.Errorf("%w: nowUnixMS must be greater than zero", ErrInvalidPairConsent)
	errPairConsentExpired          = fmt.Errorf("%w: pair consent is not valid at nowUnixMS: the original challenge deadline has passed", ErrInvalidPairConsent)
	errPairConsentExpectedID       = fmt.Errorf("%w: expected identifiers are empty or outside the identifier grammar", ErrInvalidPairConsent)
	errPairConsentTenant           = fmt.Errorf("%w: tenant_id differs from the expected caller-pinned tenant", ErrInvalidPairConsent)
	errPairConsentUser             = fmt.Errorf("%w: user_id differs from the expected caller-pinned user", ErrInvalidPairConsent)
	errPairConsentPair             = fmt.Errorf("%w: pair_id differs from the expected caller-pinned pair", ErrInvalidPairConsent)
	errPairConsentGeneration       = fmt.Errorf("%w: pair_generation differs from the expected caller-pinned generation", ErrInvalidPairConsent)
	errPairConsentChallenge        = fmt.Errorf("%w: challenge_id differs from the expected caller-pinned challenge", ErrInvalidPairConsent)
	errPairConsentDeadlineMismatch = fmt.Errorf("%w: deadline_unix_ms differs from the exact original server-issued challenge deadline", ErrInvalidPairConsent)
	errPairConsentDeviceIDs        = fmt.Errorf("%w: device_a_id or device_b_id differs from the expected endpoint identifiers", ErrInvalidPairConsent)
	errPairConsentIdentityKeySize  = fmt.Errorf("%w: a registered device identity public key is not exactly %d bytes", ErrInvalidPairConsent, ed25519.PublicKeySize)
	errPairConsentIdentityKeyReuse = fmt.Errorf("%w: device_a and device_b resolve to the same registered identity key", ErrInvalidPairConsent)
	errPairConsentSignatureDeviceA = fmt.Errorf("%w: device_a Ed25519 signature does not verify under device_a's registered identity key", ErrInvalidPairConsent)
	errPairConsentSignatureDeviceB = fmt.Errorf("%w: device_b Ed25519 signature does not verify under device_b's registered identity key", ErrInvalidPairConsent)

	// Encoding and parsing reasons. None of them embeds a value.
	errPairConsentNotObject   = fmt.Errorf("%w: not a single JSON object", ErrInvalidPairConsentEncoding)
	errPairConsentMissing     = fmt.Errorf("%w: missing member", ErrInvalidPairConsentEncoding)
	errPairConsentInvalidUTF8 = fmt.Errorf("%w: not valid UTF-8", ErrInvalidPairConsentEncoding)
	errPairConsentString      = fmt.Errorf("%w: string is not canonical", ErrInvalidPairConsentEncoding)
	errPairConsentWrongValue  = fmt.Errorf("%w: wrong constant, type or shape", ErrInvalidPairConsentEncoding)
	errPairConsentDuplicate   = fmt.Errorf("%w: duplicate member", ErrInvalidPairConsentEncoding)
	errPairConsentOutOfOrder  = fmt.Errorf("%w: member out of order", ErrInvalidPairConsentEncoding)
	errPairConsentUnknown     = fmt.Errorf("%w: unknown member", ErrInvalidPairConsentEncoding)
	errPairConsentTrailing    = fmt.Errorf("%w: trailing data", ErrInvalidPairConsentEncoding)
	errPairConsentTooLarge    = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidPairConsentEncoding, MaxPairConsentSize)
	errPairConsentEmptyInput  = fmt.Errorf("%w: empty input", ErrInvalidPairConsentEncoding)
	errPairConsentUintSyntax  = fmt.Errorf("%w: pair_generation is not canonical unsigned decimal", ErrInvalidPairConsentEncoding)
	errPairConsentLeadingZero = fmt.Errorf("%w: integer has a leading zero", ErrInvalidPairConsentEncoding)
	errPairConsentFraction    = fmt.Errorf("%w: integer has a fraction", ErrInvalidPairConsentEncoding)
	errPairConsentExponent    = fmt.Errorf("%w: integer has an exponent", ErrInvalidPairConsentEncoding)
	errPairConsentOverflow    = fmt.Errorf("%w: integer overflows its range", ErrInvalidPairConsentEncoding)
	errPairConsentDigestSize  = fmt.Errorf("%w: digest must be exactly %d bytes", ErrInvalidPairConsentEncoding, PairConsentDigestSize)
	errPairConsentDigestForm  = fmt.Errorf("%w: digest is not strict unpadded base64url", ErrInvalidPairConsentEncoding)
	errPairConsentSigSize     = fmt.Errorf("%w: signature must be exactly %d bytes", ErrInvalidPairConsentEncoding, PairConsentSignatureSize)
	errPairConsentSigForm     = fmt.Errorf("%w: signature is not strict unpadded base64url", ErrInvalidPairConsentEncoding)
	errPairConsentReencode    = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidPairConsentEncoding)

	errPairConsentIDEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidPairConsentEncoding)
	errPairConsentIDTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidPairConsentEncoding, MaxIdentifierLen)
	errPairConsentIDChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidPairConsentEncoding)
)

// PairConsentFieldError identifies the consent member that failed validation.
// The message never includes the member's value, an identifier, a digest, a
// key or a signature.
type PairConsentFieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *PairConsentFieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: pair consent: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: pair consent field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *PairConsentFieldError) Unwrap() error { return e.Err }

func pairConsentFieldErr(field string, err error) error {
	return &PairConsentFieldError{Field: field, Err: err}
}

// pairConsentMembers lists the consent members in their exact required order:
// members 1..13 (indices 0..12) are the signed tuple that both endpoints sign,
// and members 14 and 15 (device_a_signature, device_b_signature) are excluded
// from the preimage and close the object.
var pairConsentMembers = [...]string{
	"format",
	"version",
	"kind",
	"tenant_id",
	"user_id",
	"pair_id",
	"pair_generation",
	"device_a_id",
	"device_a_binding_sha256",
	"device_b_id",
	"device_b_binding_sha256",
	"challenge_id",
	"deadline_unix_ms",
	"device_a_signature",
	"device_b_signature",
}

// PairConsent is the v1 canonical consent that both endpoints of one remote
// unlock pair sign over the same metadata tuple for one server-issued pair
// challenge.
//
// The two signatures are produced by the current registered device identity
// keys: DeviceIDSignerKeys.DeviceAKey is the registered identity key of exactly
// DeviceAID and DeviceIDSignerKeys.DeviceBKey is the registered identity key of
// exactly DeviceBID. They are not vault-policy content signing keys
// (vaultfile.Device.ContentSigningKey), which authenticate a
// DeviceTransportBinding and never verify this object.
//
// DeviceAID must be strictly less in bytewise order than DeviceBID, so the two
// endpoints sign exactly the same ordered tuple and neither side controls the
// signing side.
//
// The object binds only the tenant, the user, the pair and its generation, the
// two device identifiers, the 32-byte digests of each endpoint's complete
// DeviceTransportBinding, the server challenge identifier and the exact
// original challenge deadline. It carries no vault_id, SPKI, age recipient,
// full binding bytes, vault unlock key (VUK), grant, authorization or private
// key.
//
// The struct only carries claims. Encoding or parsing it proves none of them.
// VerifyPairConsent checks both signatures under caller-pinned keys; see its
// documentation and the package documentation for the exact boundary.
type PairConsent struct {
	// TenantID is the opaque tenant identifier.
	TenantID string
	// UserID is the opaque user identifier.
	UserID string
	// PairID is the opaque pairing identifier.
	PairID string
	// PairGeneration is the pairing generation; zero is an explicit genesis
	// value and is always present on the wire.
	PairGeneration uint64
	// DeviceAID is the opaque identifier of the bytewise-lower endpoint; it
	// must be strictly less than DeviceBID.
	DeviceAID string
	// DeviceABindingSHA256 is DeviceTransportBindingDigest of exactly
	// DeviceAID's complete signed DeviceTransportBinding.
	DeviceABindingSHA256 [PairConsentDigestSize]byte
	// DeviceBID is the opaque identifier of the bytewise-higher endpoint.
	DeviceBID string
	// DeviceBBindingSHA256 is DeviceTransportBindingDigest of exactly
	// DeviceBID's complete signed DeviceTransportBinding.
	DeviceBBindingSHA256 [PairConsentDigestSize]byte
	// ChallengeID is the opaque identifier of the server-issued pair
	// challenge.
	ChallengeID string
	// DeadlineUnixMS is the exact original server-issued challenge deadline
	// in Unix milliseconds. It must be strictly positive; a consent never
	// extends it.
	DeadlineUnixMS int64
	// DeviceASignature is DeviceAID's registered identity key's Ed25519
	// signature over PairConsentSigningBytes.
	DeviceASignature [PairConsentSignatureSize]byte
	// DeviceBSignature is DeviceBID's registered identity key's Ed25519
	// signature over the same PairConsentSigningBytes.
	DeviceBSignature [PairConsentSignatureSize]byte
}

// DeviceIDSignerKeys carries the caller-pinned CURRENT REGISTERED DEVICE
// IDENTITY keys of the two consent endpoints.
//
// DeviceAKey must be the Ed25519 identity public key registered for exactly
// DeviceAID under the expected tenant and user, and DeviceBKey the key
// registered for exactly DeviceBID. The caller must fetch each key from the
// tenant's and user's current verified device registration and pin it; this
// package does not read, cache, refresh or establish that registration, and it
// accepts no key that is not supplied here. These are registered device
// identity keys, not vault-policy ContentSigningKey values, owner-root keys or
// policy signing keys.
type DeviceIDSignerKeys struct {
	// DeviceAKey is the registered identity public key of exactly the
	// endpoint named expectedDeviceAID; it is never the key of any other
	// device.
	DeviceAKey ed25519.PublicKey
	// DeviceBKey is the registered identity public key of exactly the
	// endpoint named expectedDeviceBID; it is never the key of any other
	// device.
	DeviceBKey ed25519.PublicKey
}

// PairConsentSigningBytes returns the exact bytes both endpoints sign:
// PairConsentSignatureDomain followed by the canonical JSON of members 1..13
// (format through deadline_unix_ms), in schema order. The two signature
// members, 14 and 15, are the only members excluded. It accepts the same
// values as EncodePairConsent and ignores both signatures.
//
// The returned bytes are public and contain no key material. Each platform
// signs them with its own protected registered device identity key; this
// package neither stores private keys nor signs.
func PairConsentSigningBytes(c PairConsent) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(PairConsentSignatureDomain)+1024)
	preimage = append(preimage, PairConsentSignatureDomain...)
	return appendPairConsentSignedMembers(preimage, c), nil
}

// appendPairConsentSignedMembers appends the canonical JSON object of the
// signed members (every member except both signatures) to buf and returns buf.
func appendPairConsentSignedMembers(buf []byte, c PairConsent) []byte {
	m := &pairConsentMembers
	buf = append(buf, '{')
	buf = appendStringMember(buf, m[0], PairConsentFormat)
	buf = appendUintMember(buf, m[1], PairConsentVersion)
	buf = appendStringMember(buf, m[2], KindPairConsent)
	buf = appendStringMember(buf, m[3], c.TenantID)
	buf = appendStringMember(buf, m[4], c.UserID)
	buf = appendStringMember(buf, m[5], c.PairID)
	buf = appendUintMember(buf, m[6], c.PairGeneration)
	buf = appendStringMember(buf, m[7], c.DeviceAID)
	buf = appendPairConsentBytesMember(buf, m[8], c.DeviceABindingSHA256[:])
	buf = appendStringMember(buf, m[9], c.DeviceBID)
	buf = appendPairConsentBytesMember(buf, m[10], c.DeviceBBindingSHA256[:])
	buf = appendStringMember(buf, m[11], c.ChallengeID)
	buf = appendIntMember(buf, m[12], c.DeadlineUnixMS)
	buf[len(buf)-1] = '}'
	return buf
}

// appendPairConsentBytesMember appends a strict unpadded base64url member
// carrying b and its trailing comma.
func appendPairConsentBytesMember(buf []byte, name string, v []byte) []byte {
	buf = appendMemberName(buf, name)
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, v)
	return append(buf, '"', ',')
}

// EncodePairConsent validates c and returns its canonical v1 JSON encoding,
// which is never longer than MaxPairConsentSize bytes.
func EncodePairConsent(c PairConsent) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1200)
	buf = appendPairConsentSignedMembers(buf, c)
	buf[len(buf)-1] = ','
	buf = appendPairConsentBytesMember(buf, pairConsentMembers[13], c.DeviceASignature[:])
	buf = appendPairConsentBytesMember(buf, pairConsentMembers[14], c.DeviceBSignature[:])
	buf[len(buf)-1] = '}'
	if len(buf) > MaxPairConsentSize {
		return nil, pairConsentFieldErr("", errPairConsentBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (c PairConsent) validate() error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{pairConsentMembers[3], c.TenantID},
		{pairConsentMembers[4], c.UserID},
		{pairConsentMembers[5], c.PairID},
		{pairConsentMembers[7], c.DeviceAID},
		{pairConsentMembers[9], c.DeviceBID},
		{pairConsentMembers[11], c.ChallengeID},
	} {
		if err := validateIdentifier(f.value); err != nil {
			return pairConsentFieldErr(f.name, pairConsentIdentifierError(err))
		}
	}
	if c.DeviceAID == c.DeviceBID {
		return pairConsentFieldErr(pairConsentMembers[9], errPairConsentEndpointEqual)
	}
	if c.DeviceAID >= c.DeviceBID {
		return pairConsentFieldErr(pairConsentMembers[9], errPairConsentEndpointOrder)
	}
	if c.DeadlineUnixMS <= 0 {
		return pairConsentFieldErr(pairConsentMembers[12], errPairConsentDeadline)
	}
	return nil
}

// pairConsentIdentifierError maps a shared identifier-grammar failure to its
// consent-specific static reason wrapping ErrInvalidPairConsent.
func pairConsentIdentifierError(err error) error {
	switch {
	case errors.Is(err, errEmpty):
		return fmt.Errorf("%w: identifier must not be empty", ErrInvalidPairConsent)
	case errors.Is(err, errTooLong):
		return fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidPairConsent, MaxIdentifierLen)
	default:
		return fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidPairConsent)
	}
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// consent. It never falls back to the struct field order.
func (c PairConsent) MarshalJSON() ([]byte, error) {
	return EncodePairConsent(c)
}

// UnmarshalJSON replaces c only when data is exactly the canonical encoding of
// a valid consent.
func (c *PairConsent) UnmarshalJSON(data []byte) error {
	if c == nil {
		return pairConsentFieldErr("", errPairConsentEmptyInput)
	}
	parsed, err := ParsePairConsent(data)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// ParsePairConsent parses b, which must be exactly the canonical v1 encoding of
// a valid consent. Every other spelling (unknown, missing, duplicate or
// reordered members, invalid UTF-8, non-canonical strings, integers,
// timestamps or base64url, wrong digest or signature lengths, equal or
// reversed device identifiers, trailing data) is rejected with an error
// wrapping ErrInvalidPairConsentEncoding, as is input larger than
// MaxPairConsentSize. Errors never contain member values, identifiers,
// digests, keys or signatures.
func ParsePairConsent(b []byte) (PairConsent, error) {
	var out PairConsent
	if len(b) > MaxPairConsentSize {
		return out, pairConsentFieldErr("", errPairConsentTooLarge)
	}
	if len(b) == 0 {
		return out, pairConsentFieldErr("", errPairConsentEmptyInput)
	}
	if !utf8.Valid(b) {
		return out, pairConsentFieldErr("", errPairConsentInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.pairConsentExpect('{', errPairConsentNotObject); err != nil {
		return out, err
	}
	for i, want := range pairConsentMembers {
		if i > 0 {
			if err := p.pairConsentSeparator(',', want); err != nil {
				return out, err
			}
		}
		key, err := p.string()
		if err != nil {
			// The key's position is reported as the expected member: this is
			// a static schema name, never an attacker-controlled byte.
			return out, pairConsentFieldErr(want, errPairConsentString)
		}
		if err := p.pairConsentSeparator(':', want); err != nil {
			return out, err
		}
		for j := 0; j < i; j++ {
			if key == pairConsentMembers[j] {
				return out, pairConsentFieldErr(key, errPairConsentDuplicate)
			}
		}
		if key != want {
			if j := pairConsentMemberIndex(key); j >= 0 {
				if j > i {
					return out, pairConsentFieldErr(want, errPairConsentMissing)
				}
				return out, pairConsentFieldErr(key, errPairConsentOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return out, pairConsentFieldErr("", errPairConsentUnknown)
		}
		if err := p.pairConsentMember(i, &out); err != nil {
			return out, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		// The object must close here; a member name that repeats an earlier
		// schema name or is unknown is reported as such, otherwise the data is
		// trailing.
		key, err := p.peekString()
		if err == nil && pairConsentMemberIndex(key) >= 0 {
			return out, pairConsentFieldErr(key, errPairConsentDuplicate)
		}
		if err == nil {
			// Unknown keys are attacker-controlled; do not echo them.
			return out, pairConsentFieldErr("", errPairConsentUnknown)
		}
		return out, pairConsentFieldErr("", errPairConsentTrailing)
	}
	if err := p.pairConsentExpect('}', errPairConsentMissing); err != nil {
		return out, err
	}
	if p.pos != len(p.buf) {
		return out, pairConsentFieldErr("", errPairConsentTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodePairConsent(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return PairConsent{}, pairConsentFieldErr("", errPairConsentReencode)
	}
	return out, nil
}

// pairConsentExpect consumes the literal byte want with consent errors, so a
// structural failure never reports another structure's field error.
func (p *parser) pairConsentExpect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return pairConsentFieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		if want == ',' || want == ':' {
			return pairConsentFieldErr("", errPairConsentMissing)
		}
		return pairConsentFieldErr("", errPairConsentWrongValue)
	}
	p.pos++
	return nil
}

// pairConsentSeparator consumes the separator want (a comma or colon) before
// member expected, naming the omitted or misplaced schema member. The reported
// names are schema constants only, never attacker-controlled bytes.
func (p *parser) pairConsentSeparator(want byte, expected string) error {
	if p.pos >= len(p.buf) {
		return pairConsentFieldErr(expected, errPairConsentMissing)
	}
	if p.buf[p.pos] == want {
		p.pos++
		return nil
	}
	// A schema member name where a separator was expected: after another
	// member's value a duplicate or reordered name is reported by key, while
	// a missing separator keeps the schema order and names the expected
	// member.
	if key, err := p.peekString(); err == nil && pairConsentMemberIndex(key) >= 0 {
		if want == ':' || key != expected {
			return pairConsentFieldErr(key, errPairConsentMissing)
		}
	}
	return pairConsentFieldErr(expected, errPairConsentMissing)
}

func pairConsentMemberIndex(key string) int {
	for i, m := range pairConsentMembers {
		if m == key {
			return i
		}
	}
	return -1
}

// pairConsentMember parses the value of pairConsentMembers[i] into c.
func (p *parser) pairConsentMember(i int, c *PairConsent) error {
	name := pairConsentMembers[i]
	switch i {
	case 0:
		return p.pairConsentConstant(name, PairConsentFormat)
	case 1:
		v, err := p.number()
		if err != nil || v != "1" {
			return pairConsentFieldErr(name, errPairConsentWrongValue)
		}
		return nil
	case 2:
		return p.pairConsentConstant(name, KindPairConsent)
	case 3:
		return p.pairConsentIdentifier(name, &c.TenantID)
	case 4:
		return p.pairConsentIdentifier(name, &c.UserID)
	case 5:
		return p.pairConsentIdentifier(name, &c.PairID)
	case 6:
		return p.pairConsentUint(name, &c.PairGeneration)
	case 7:
		return p.pairConsentIdentifier(name, &c.DeviceAID)
	case 8:
		return decodePairConsentBytes(p, name, c.DeviceABindingSHA256[:], errPairConsentDigestSize, errPairConsentDigestForm)
	case 9:
		if err := p.pairConsentIdentifier(name, &c.DeviceBID); err != nil {
			return err
		}
		switch {
		case c.DeviceAID == c.DeviceBID:
			return pairConsentFieldErr(name, errPairConsentParseEqual)
		case c.DeviceAID > c.DeviceBID:
			return pairConsentFieldErr(name, errPairConsentParseOrder)
		}
		return nil
	case 10:
		return decodePairConsentBytes(p, name, c.DeviceBBindingSHA256[:], errPairConsentDigestSize, errPairConsentDigestForm)
	case 11:
		return p.pairConsentIdentifier(name, &c.ChallengeID)
	case 12:
		return p.pairConsentDeadline(name, &c.DeadlineUnixMS)
	case 13:
		return decodePairConsentBytes(p, name, c.DeviceASignature[:], errPairConsentSigSize, errPairConsentSigForm)
	case 14:
		return decodePairConsentBytes(p, name, c.DeviceBSignature[:], errPairConsentSigSize, errPairConsentSigForm)
	}
	return pairConsentFieldErr(name, errPairConsentUnknown)
}

func (p *parser) pairConsentConstant(name, want string) error {
	v, err := p.string()
	if err != nil {
		return pairConsentFieldErr(name, errPairConsentString)
	}
	if v != want {
		return pairConsentFieldErr(name, errPairConsentWrongValue)
	}
	return nil
}

func (p *parser) pairConsentIdentifier(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return pairConsentFieldErr(name, errPairConsentString)
	}
	if err := validateIdentifier(v); err != nil {
		switch {
		case errors.Is(err, errEmpty):
			return pairConsentFieldErr(name, errPairConsentIDEmpty)
		case errors.Is(err, errTooLong):
			return pairConsentFieldErr(name, errPairConsentIDTooLong)
		default:
			return pairConsentFieldErr(name, errPairConsentIDChar)
		}
	}
	*dst = v
	return nil
}

// pairConsentUint parses a canonical unsigned decimal uint64. An explicit zero
// is accepted: pair_generation has no sentinel spelling.
func (p *parser) pairConsentUint(name string, dst *uint64) error {
	raw, err := p.pairConsentDigits(name)
	if err != nil {
		return err
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return pairConsentFieldErr(name, errPairConsentOverflow)
	}
	*dst = v
	return nil
}

// pairConsentDeadline parses a canonical positive decimal int64 in Unix
// milliseconds.
func (p *parser) pairConsentDeadline(name string, dst *int64) error {
	raw, err := p.pairConsentDigits(name)
	if err != nil {
		return err
	}
	if raw == "0" {
		return pairConsentFieldErr(name, errPairConsentParseDeadline)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return pairConsentFieldErr(name, errPairConsentParseDeadline)
	}
	*dst = v
	return nil
}

// pairConsentDigits scans one canonical unsigned decimal integer token: digits
// only, no leading zero except "0", no fraction or exponent.
func (p *parser) pairConsentDigits(name string) (string, error) {
	raw, err := p.number()
	if err != nil || len(raw) == 0 {
		return "", pairConsentFieldErr(name, errPairConsentUintSyntax)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return "", pairConsentFieldErr(name, errPairConsentUintSyntax)
		case c == '.':
			return "", pairConsentFieldErr(name, errPairConsentFraction)
		case c == 'e' || c == 'E':
			return "", pairConsentFieldErr(name, errPairConsentExponent)
		case c < '0' || c > '9':
			return "", pairConsentFieldErr(name, errPairConsentUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return "", pairConsentFieldErr(name, errPairConsentLeadingZero)
	}
	return raw, nil
}

// decodePairConsentBytes parses a strict unpadded base64url string decoding to
// exactly len(dst) bytes, using the given reasons for a wrong size or spelling.
func decodePairConsentBytes(p *parser, name string, dst []byte, sizeErr, formErr error) error {
	v, err := p.string()
	if err != nil {
		return pairConsentFieldErr(name, errPairConsentString)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return pairConsentFieldErr(name, sizeErr)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst, []byte(v))
	if err != nil || n != len(dst) || base64.RawURLEncoding.EncodeToString(dst) != v {
		return pairConsentFieldErr(name, formErr)
	}
	return nil
}

// pairConsentScope is the caller-pinned authority a consent is verified
// against: the exact tenant, user, pair and generation, the exact server
// challenge identifier and its exact original deadline, and the exact two
// endpoint identifiers.
type pairConsentScope struct {
	tenantID     string
	userID       string
	pairID       string
	generation   uint64
	challengeID  string
	deadlineUnix int64
	deviceAID    string
	deviceBID    string
}

// VerifyPairConsent verifies that both endpoints of exactly the expected
// pair challenge signed the same canonical PairConsent tuple under their
// current registered device identity keys.
//
// expectedDeviceAID must be strictly less than expectedDeviceBID in bytewise
// order; expectedDeadlineUnixMS must equal the exact original server-issued
// challenge deadline and must be positive; nowUnixMS must be positive and
// strictly earlier than that deadline. The deadline is never extended: a
// consent whose deadline differs from expectedDeadlineUnixMS by even one
// millisecond is rejected. No system clock is read.
//
// It runs, in exactly this order, and returns on the first failure:
//
//  1. nowUnixMS must be positive.
//  2. The expected scope must be canonical: every expected identifier must
//     satisfy the identifier grammar, the expected endpoints must differ and
//     be in strict bytewise order, and the expected deadline must be positive.
//  3. c must be canonical-valid, including a deadline above zero and its own
//     strict device order.
//  4. nowUnixMS must be strictly earlier than c.DeadlineUnixMS.
//  5. c.TenantID, UserID, PairID, PairGeneration, ChallengeID and
//     DeadlineUnixMS must equal the expected values exactly.
//  6. c.DeviceAID and c.DeviceBID must equal the expected endpoint
//     identifiers exactly.
//  7. keys.DeviceAKey must be exactly the 32-byte Ed25519 key registered for
//     DeviceAID and keys.DeviceBKey exactly the 32-byte Ed25519 key registered
//     for DeviceBID, and the two keys must differ.
//  8. c.DeviceASignature must verify under keys.DeviceAKey and then
//     c.DeviceBSignature under keys.DeviceBKey, over PairConsentSigningBytes.
//
// A nil return proves only that the two caller-pinned current registered
// device identity keys, one per endpoint, signed the same IDs, generation, two
// binding digests, challenge identifier and unextended deadline before the
// deadline. It does NOT establish that either key is still currently
// registered (the caller must have fetched and pinned it), that a human
// scanned or compared a fingerprint or otherwise consented, that a device
// holds its private key, vault authorization or role, that either digest
// matches a valid DeviceTransportBinding, the TLS identity of a live peer, or
// any unlock, VUK delivery or one-shot property.
func VerifyPairConsent(c PairConsent, expectedTenantID, expectedUserID, expectedPairID string, expectedGeneration uint64, expectedChallengeID string, expectedDeadlineUnixMS int64, expectedDeviceAID, expectedDeviceBID string, keys DeviceIDSignerKeys, nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return pairConsentFieldErr("", errPairConsentNow)
	}
	expected := pairConsentScope{
		tenantID:     expectedTenantID,
		userID:       expectedUserID,
		pairID:       expectedPairID,
		generation:   expectedGeneration,
		challengeID:  expectedChallengeID,
		deadlineUnix: expectedDeadlineUnixMS,
		deviceAID:    expectedDeviceAID,
		deviceBID:    expectedDeviceBID,
	}
	if err := expected.validate(); err != nil {
		return err
	}

	// 3. Values.
	if err := c.validate(); err != nil {
		return err
	}

	// 4. The deadline is exclusive and never extended.
	if nowUnixMS >= c.DeadlineUnixMS {
		return pairConsentFieldErr(pairConsentMembers[12], errPairConsentExpired)
	}

	// 5. Caller-pinned scope.
	switch {
	case c.TenantID != expected.tenantID:
		return pairConsentFieldErr(pairConsentMembers[3], errPairConsentTenant)
	case c.UserID != expected.userID:
		return pairConsentFieldErr(pairConsentMembers[4], errPairConsentUser)
	case c.PairID != expected.pairID:
		return pairConsentFieldErr(pairConsentMembers[5], errPairConsentPair)
	case c.PairGeneration != expected.generation:
		return pairConsentFieldErr(pairConsentMembers[6], errPairConsentGeneration)
	case c.ChallengeID != expected.challengeID:
		return pairConsentFieldErr(pairConsentMembers[11], errPairConsentChallenge)
	case c.DeadlineUnixMS != expected.deadlineUnix:
		return pairConsentFieldErr(pairConsentMembers[12], errPairConsentDeadlineMismatch)
	}

	// 6. The exact endpoints, in their fixed order.
	switch {
	case c.DeviceAID != expected.deviceAID:
		return pairConsentFieldErr(pairConsentMembers[7], errPairConsentDeviceIDs)
	case c.DeviceBID != expected.deviceBID:
		return pairConsentFieldErr(pairConsentMembers[9], errPairConsentDeviceIDs)
	}

	// 7. Both registered identity keys, each pinned to exactly its endpoint.
	if len(keys.DeviceAKey) != ed25519.PublicKeySize || len(keys.DeviceBKey) != ed25519.PublicKeySize {
		return pairConsentFieldErr("identity_key", errPairConsentIdentityKeySize)
	}
	if bytes.Equal(keys.DeviceAKey, keys.DeviceBKey) {
		return pairConsentFieldErr("identity_key", errPairConsentIdentityKeyReuse)
	}

	// 8. Both signatures over the one shared preimage, a then b.
	msg, err := PairConsentSigningBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(keys.DeviceAKey), msg, c.DeviceASignature[:]) {
		return pairConsentFieldErr(pairConsentMembers[13], errPairConsentSignatureDeviceA)
	}
	if !ed25519.Verify(ed25519.PublicKey(keys.DeviceBKey), msg, c.DeviceBSignature[:]) {
		return pairConsentFieldErr(pairConsentMembers[14], errPairConsentSignatureDeviceB)
	}
	return nil
}

// validate checks the caller-pinned expectation itself, so a malformed or
// reversed expectation can never be matched by any consent.
func (s pairConsentScope) validate() error {
	for _, id := range []string{s.tenantID, s.userID, s.pairID, s.challengeID, s.deviceAID, s.deviceBID} {
		if validateIdentifier(id) != nil {
			return pairConsentFieldErr("expected", errPairConsentExpectedID)
		}
	}
	if s.deviceAID == s.deviceBID {
		return pairConsentFieldErr("expected", errPairConsentEndpointEqual)
	}
	if s.deviceAID >= s.deviceBID {
		return pairConsentFieldErr("expected", errPairConsentEndpointOrder)
	}
	if s.deadlineUnix <= 0 {
		return pairConsentFieldErr("expected", errPairConsentDeadline)
	}
	return nil
}
