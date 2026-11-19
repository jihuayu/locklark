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

	"filippo.io/age"
)

// Wire constants of the v1 canonical device transport binding.
const (
	// DeviceTransportBindingFormat is the fixed value of the binding's
	// "format" member. It equals Format.
	DeviceTransportBindingFormat = Format
	// DeviceTransportBindingVersion is the canonical JSON integer of the
	// binding's "version" member. It equals Version.
	DeviceTransportBindingVersion = Version
	// KindDeviceTransportBinding is the fixed value of the binding's "kind"
	// member.
	KindDeviceTransportBinding = "device-transport-binding"
	// BindingSignatureDomain separates the binding signature preimage from
	// every other signed structure. The preimage is this domain followed by
	// the canonical JSON of the binding fields without "signature".
	BindingSignatureDomain = "locklark.remote-unlock/v1/device-transport-binding\x00"
	// MaxBindingSize is the maximum encoded or accepted size in bytes.
	MaxBindingSize = 2048
	// BindingSPKIDigestSize is the exact length of spki_sha256 in bytes.
	BindingSPKIDigestSize = 32
	// BindingSignatureSize is the exact length of signature in bytes.
	BindingSignatureSize = ed25519.SignatureSize
)

// ErrInvalidBinding reports a binding that cannot be encoded or verified.
var ErrInvalidBinding = errors.New("remoteunlock: invalid device transport binding")

// ErrInvalidBindingEncoding reports bytes that are not the canonical encoding
// of a valid device transport binding.
var ErrInvalidBindingEncoding = errors.New("remoteunlock: invalid device transport binding encoding")

// BindingFieldError identifies the binding member that failed validation. The
// message never includes the member's value, a key, a signature, a certificate
// digest or a recipient string.
type BindingFieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *BindingFieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: device transport binding: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: device transport binding field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *BindingFieldError) Unwrap() error { return e.Err }

func bindingFieldErr(field string, err error) error {
	return &BindingFieldError{Field: field, Err: err}
}

// Binding rejection reasons. They wrap ErrInvalidBinding when encoding and
// ErrInvalidBindingEncoding when parsing. Messages are static and never embed a
// field value, key, signature, certificate digest or recipient string.
var (
	errBindingRecipient = fmt.Errorf("%w: recipient_public_key is not a canonical age X25519 recipient", ErrInvalidBinding)
	errBindingBudget    = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidBinding, MaxBindingSize)

	errBindingNotObject    = fmt.Errorf("%w: not a single JSON object", ErrInvalidBindingEncoding)
	errBindingMissing      = fmt.Errorf("%w: missing member", ErrInvalidBindingEncoding)
	errBindingInvalidUTF8  = fmt.Errorf("%w: not valid UTF-8", ErrInvalidBindingEncoding)
	errBindingString       = fmt.Errorf("%w: string is not canonical", ErrInvalidBindingEncoding)
	errBindingWrongValue   = fmt.Errorf("%w: wrong constant, type or shape", ErrInvalidBindingEncoding)
	errBindingDuplicate    = fmt.Errorf("%w: duplicate member", ErrInvalidBindingEncoding)
	errBindingOutOfOrder   = fmt.Errorf("%w: member out of order", ErrInvalidBindingEncoding)
	errBindingUnknown      = fmt.Errorf("%w: unknown member", ErrInvalidBindingEncoding)
	errBindingTrailing     = fmt.Errorf("%w: trailing data", ErrInvalidBindingEncoding)
	errBindingTooLarge     = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidBindingEncoding, MaxBindingSize)
	errBindingEmptyInput   = fmt.Errorf("%w: empty input", ErrInvalidBindingEncoding)
	errBindingUintSyntax   = fmt.Errorf("%w: pair_generation is not canonical unsigned decimal", ErrInvalidBindingEncoding)
	errBindingLeadingZero  = fmt.Errorf("%w: pair_generation has a leading zero", ErrInvalidBindingEncoding)
	errBindingFraction     = fmt.Errorf("%w: pair_generation has a fraction", ErrInvalidBindingEncoding)
	errBindingExponent     = fmt.Errorf("%w: pair_generation has an exponent", ErrInvalidBindingEncoding)
	errBindingOverflow     = fmt.Errorf("%w: pair_generation overflows uint64", ErrInvalidBindingEncoding)
	errBindingSPKISize     = fmt.Errorf("%w: spki_sha256 must be exactly %d bytes", ErrInvalidBindingEncoding, BindingSPKIDigestSize)
	errBindingSPKIForm     = fmt.Errorf("%w: spki_sha256 is not strict unpadded base64url", ErrInvalidBindingEncoding)
	errBindingRecipientBad = fmt.Errorf("%w: recipient_public_key is not a canonical age X25519 recipient", ErrInvalidBindingEncoding)
	errBindingSigSize      = fmt.Errorf("%w: signature must be exactly %d bytes", ErrInvalidBindingEncoding, BindingSignatureSize)
	errBindingSigForm      = fmt.Errorf("%w: signature is not strict unpadded base64url", ErrInvalidBindingEncoding)
	errBindingReencode     = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidBindingEncoding)

	// Encoding-side identifier reasons wrap ErrInvalidBinding.
	errBindingIdentifierEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidBinding)
	errBindingIdentifierTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidBinding, MaxIdentifierLen)
	errBindingIdentifierChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidBinding)
	// Parsing-side identifier reasons wrap ErrInvalidBindingEncoding.
	errBindingParseIdentifierEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidBindingEncoding)
	errBindingParseIdentifierTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidBindingEncoding, MaxIdentifierLen)
	errBindingParseIdentifierChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidBindingEncoding)

	errDeviceMismatch     = fmt.Errorf("%w: device_id does not equal the expected device identifier", ErrInvalidBinding)
	errSigningKeySize     = fmt.Errorf("%w: pinned signing key is not exactly %d bytes", ErrInvalidBinding, ed25519.PublicKeySize)
	errSignature          = fmt.Errorf("%w: Ed25519 signature does not verify", ErrInvalidBinding)
	errInvalidContext     = fmt.Errorf("%w: context is not canonical-valid", ErrInvalidBinding)
	errMemberMismatch     = fmt.Errorf("%w: member_id differs from the context", ErrInvalidBinding)
	errVaultMismatch      = fmt.Errorf("%w: vault_id differs from the context", ErrInvalidBinding)
	errGenerationMismatch = fmt.Errorf("%w: pair_generation differs from the context", ErrInvalidBinding)
	errEndpointReuse      = fmt.Errorf("%w: context source and target device identifiers are equal", ErrInvalidBinding)
	errEndpointMismatch   = fmt.Errorf("%w: device_id is neither the context source nor target device", ErrInvalidBinding)
)

// bindingMembers lists the binding members in their exact required order.
var bindingMembers = [...]string{
	"format",
	"version",
	"kind",
	"member_id",
	"device_id",
	"install_id",
	"vault_id",
	"pair_generation",
	"spki_sha256",
	"recipient_public_key",
	"signature",
}

// DeviceTransportBinding is the stable per-device v1 binding of a member's
// device to its vault: an existing enrolled vault-device signing key signs it
// once, and later protocol layers may reference it by digest.
//
// The binding is stable across requests. It deliberately does not contain a
// request ID or digest, lock generation, deadline, key epoch, or policy
// sequence or digest; those belong to the request ChannelBindingContext and to
// later signed authorization, and they never appear here.
//
// The struct only carries claims. Encoding or parsing it proves none of them,
// and VerifyDeviceTransportBinding checks only the Ed25519 signature over
// these bytes with a caller-supplied key. The type does not establish
// enrollment, owner or admin remote_unlock authorization, pairing approval,
// request freshness, TLS identity, vault unlock key (VUK) access, or an
// end-to-end unlock flow.
type DeviceTransportBinding struct {
	// MemberID is the opaque member identifier.
	MemberID string
	// DeviceID is the opaque identifier of the device that holds the private
	// signing key.
	DeviceID string
	// InstallID is the opaque identifier of the app installation on that
	// device.
	InstallID string
	// VaultID is the opaque vault identifier.
	VaultID string
	// PairGeneration is the pairing generation; zero is an explicit genesis
	// value.
	PairGeneration uint64
	// SPKISHA256 is the SHA-256 digest of the DER SubjectPublicKeyInfo of
	// the device certificate bound to the device's live channel. The codec
	// neither computes nor compares it; a caller must compare it to the
	// actual pinned peer certificate.
	SPKISHA256 [BindingSPKIDigestSize]byte
	// RecipientPublicKey is the canonical age X25519 recipient string
	// ("age1...", lowercase bech32) the device claims as its delivery
	// recipient. It is not proof that the device holds the matching identity.
	RecipientPublicKey string
	// Signature is the Ed25519 signature over SigningBytes.
	Signature [BindingSignatureSize]byte
}

// SigningBytes returns the exact bytes an enrolled vault-device signing key
// signs: BindingSignatureDomain followed by the canonical JSON of every binding
// member except "signature", in schema order. It accepts the same values as
// EncodeDeviceTransportBinding and ignores Signature.
//
// The returned bytes are public; they contain no key material. Platform code
// signs them with its protected existing device key; this package neither
// stores private keys nor signs.
func SigningBytes(b DeviceTransportBinding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(BindingSignatureDomain)+512)
	preimage = append(preimage, BindingSignatureDomain...)
	return appendSignedMembers(preimage, b), nil
}

// appendSignedMembers appends the canonical JSON object of the signed members
// (every member except "signature") to buf and returns buf.
func appendSignedMembers(buf []byte, b DeviceTransportBinding) []byte {
	buf = append(buf, '{')
	buf = appendStringMember(buf, bindingMembers[0], DeviceTransportBindingFormat)
	buf = appendUintMember(buf, bindingMembers[1], DeviceTransportBindingVersion)
	buf = appendStringMember(buf, bindingMembers[2], KindDeviceTransportBinding)
	buf = appendStringMember(buf, bindingMembers[3], b.MemberID)
	buf = appendStringMember(buf, bindingMembers[4], b.DeviceID)
	buf = appendStringMember(buf, bindingMembers[5], b.InstallID)
	buf = appendStringMember(buf, bindingMembers[6], b.VaultID)
	buf = appendUintMember(buf, bindingMembers[7], b.PairGeneration)
	buf = appendDigestMember(buf, bindingMembers[8], b.SPKISHA256)
	buf = appendStringMember(buf, bindingMembers[9], b.RecipientPublicKey)
	buf[len(buf)-1] = '}'
	return buf
}

// EncodeDeviceTransportBinding validates b and returns its canonical v1 JSON
// encoding, which is never longer than MaxBindingSize bytes.
func EncodeDeviceTransportBinding(b DeviceTransportBinding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 512)
	buf = append(buf, '{')
	buf = appendStringMember(buf, bindingMembers[0], DeviceTransportBindingFormat)
	buf = appendUintMember(buf, bindingMembers[1], DeviceTransportBindingVersion)
	buf = appendStringMember(buf, bindingMembers[2], KindDeviceTransportBinding)
	buf = appendStringMember(buf, bindingMembers[3], b.MemberID)
	buf = appendStringMember(buf, bindingMembers[4], b.DeviceID)
	buf = appendStringMember(buf, bindingMembers[5], b.InstallID)
	buf = appendStringMember(buf, bindingMembers[6], b.VaultID)
	buf = appendUintMember(buf, bindingMembers[7], b.PairGeneration)
	buf = appendDigestMember(buf, bindingMembers[8], b.SPKISHA256)
	buf = appendStringMember(buf, bindingMembers[9], b.RecipientPublicKey)
	buf = appendMemberName(buf, bindingMembers[10])
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, b.Signature[:])
	buf = append(buf, '"', '}')
	if len(buf) > MaxBindingSize {
		return nil, bindingFieldErr("", errBindingBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (b DeviceTransportBinding) validate() error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{bindingMembers[3], b.MemberID},
		{bindingMembers[4], b.DeviceID},
		{bindingMembers[5], b.InstallID},
		{bindingMembers[6], b.VaultID},
	} {
		if err := validateIdentifier(f.value); err != nil {
			return bindingFieldErr(f.name, bindingIdentifierError(err))
		}
	}
	if err := validateRecipient(b.RecipientPublicKey); err != nil {
		return bindingFieldErr(bindingMembers[9], err)
	}
	return nil
}

// bindingIdentifierError maps a shared identifier-grammar failure to its
// binding-specific static reason so encoding and signing errors wrap
// ErrInvalidBinding.
func bindingIdentifierError(err error) error {
	switch {
	case errors.Is(err, errEmpty):
		return errBindingIdentifierEmpty
	case errors.Is(err, errTooLong):
		return errBindingIdentifierTooLong
	default:
		return errBindingIdentifierChar
	}
}

// validateRecipient requires an age X25519 recipient whose canonical
// spelling is byte-identical to s. The round trip rejects differently-cased,
// padded, and any other non-canonical encoding.
func validateRecipient(s string) error {
	r, err := age.ParseX25519Recipient(s)
	if err != nil || r.String() != s {
		return errBindingRecipient
	}
	return nil
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// binding. It never falls back to the struct field order.
func (b DeviceTransportBinding) MarshalJSON() ([]byte, error) {
	return EncodeDeviceTransportBinding(b)
}

// UnmarshalJSON replaces b only when data is exactly the canonical encoding of
// a valid binding.
func (b *DeviceTransportBinding) UnmarshalJSON(data []byte) error {
	if b == nil {
		return bindingFieldErr("", errBindingEmptyInput)
	}
	parsed, err := ParseDeviceTransportBinding(data)
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

// ParseDeviceTransportBinding parses b, which must be exactly the canonical v1
// encoding of a valid binding. Every other spelling (unknown, missing,
// duplicate or reordered members, non-canonical strings, numbers, base64url or
// age recipients, trailing data) is rejected with an error wrapping
// ErrInvalidBindingEncoding. Errors never contain field values.
func ParseDeviceTransportBinding(b []byte) (DeviceTransportBinding, error) {
	var out DeviceTransportBinding
	if len(b) > MaxBindingSize {
		return out, bindingFieldErr("", errBindingTooLarge)
	}
	if len(b) == 0 {
		return out, bindingFieldErr("", errBindingEmptyInput)
	}
	if !utf8.Valid(b) {
		return out, bindingFieldErr("", errBindingInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.bindingExpect('{', errBindingNotObject); err != nil {
		return out, err
	}
	for i, want := range bindingMembers {
		if i > 0 {
			if err := p.bindingExpect(',', errBindingMissing); err != nil {
				return out, err
			}
		}
		key, err := p.string()
		if err != nil {
			return out, bindingFieldErr(want, err)
		}
		if err := p.bindingExpect(':', errBindingMissing); err != nil {
			return out, bindingFieldErr(want, err)
		}
		for j := 0; j < i; j++ {
			if key == bindingMembers[j] {
				return out, bindingFieldErr(key, errBindingDuplicate)
			}
		}
		if key != want {
			if j := bindingMemberIndex(key); j >= 0 {
				if j > i {
					return out, bindingFieldErr(want, errBindingMissing)
				}
				return out, bindingFieldErr(key, errBindingOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return out, bindingFieldErr("", errBindingUnknown)
		}
		if err := p.bindingMember(i, &out); err != nil {
			return out, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		key, err := p.peekString()
		if err == nil && bindingMemberIndex(key) >= 0 {
			return out, bindingFieldErr(key, errBindingDuplicate)
		}
		if err == nil {
			return out, bindingFieldErr("", errBindingUnknown)
		}
		return out, bindingFieldErr("", errBindingTrailing)
	}
	if err := p.bindingExpect('}', errBindingMissing); err != nil {
		return out, err
	}
	if p.pos != len(p.buf) {
		return out, bindingFieldErr("", errBindingTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodeDeviceTransportBinding(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return DeviceTransportBinding{}, bindingFieldErr("", errBindingReencode)
	}
	return out, nil
}

// bindingExpect consumes the literal byte want with binding-specific errors,
// so a structural failure never reports a binding-context field error.
func (p *parser) bindingExpect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return bindingFieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		return bindingFieldErr("", errBindingWrongValue)
	}
	p.pos++
	return nil
}

func bindingMemberIndex(key string) int {
	for i, m := range bindingMembers {
		if m == key {
			return i
		}
	}
	return -1
}

// bindingMember parses the value of bindingMembers[i] into b.
func (p *parser) bindingMember(i int, b *DeviceTransportBinding) error {
	name := bindingMembers[i]
	switch i {
	case 0:
		return p.bindingConstant(name, DeviceTransportBindingFormat)
	case 1:
		return p.bindingVersion(name)
	case 2:
		return p.bindingConstant(name, KindDeviceTransportBinding)
	case 3:
		return p.bindingIdentifier(name, &b.MemberID)
	case 4:
		return p.bindingIdentifier(name, &b.DeviceID)
	case 5:
		return p.bindingIdentifier(name, &b.InstallID)
	case 6:
		return p.bindingIdentifier(name, &b.VaultID)
	case 7:
		return p.bindingUint(name, &b.PairGeneration)
	case 8:
		return p.bindingDigest(name, &b.SPKISHA256)
	case 9:
		return p.bindingRecipient(name, &b.RecipientPublicKey)
	case 10:
		return p.bindingSignature(name, &b.Signature)
	}
	return bindingFieldErr(name, errBindingUnknown)
}

func (p *parser) bindingConstant(name, want string) error {
	v, err := p.string()
	if err != nil {
		return bindingFieldErr(name, errBindingString)
	}
	if v != want {
		return bindingFieldErr(name, errBindingWrongValue)
	}
	return nil
}

func (p *parser) bindingVersion(name string) error {
	v, err := p.number()
	if err != nil {
		return bindingFieldErr(name, errBindingWrongValue)
	}
	if v != "1" {
		return bindingFieldErr(name, errBindingWrongValue)
	}
	return nil
}

func (p *parser) bindingIdentifier(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return bindingFieldErr(name, errBindingString)
	}
	if err := validateIdentifier(v); err != nil {
		switch {
		case errors.Is(err, errEmpty):
			return bindingFieldErr(name, errBindingParseIdentifierEmpty)
		case errors.Is(err, errTooLong):
			return bindingFieldErr(name, errBindingParseIdentifierTooLong)
		default:
			return bindingFieldErr(name, errBindingParseIdentifierChar)
		}
	}
	*dst = v
	return nil
}

// bindingUint parses a canonical unsigned decimal uint64. A fraction,
// exponent, sign, leading zero or overflow is rejected.
func (p *parser) bindingUint(name string, dst *uint64) error {
	raw, err := p.number()
	if err != nil {
		return bindingFieldErr(name, errBindingUintSyntax)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return bindingFieldErr(name, errBindingUintSyntax)
		case c == '.':
			return bindingFieldErr(name, errBindingFraction)
		case c == 'e' || c == 'E':
			return bindingFieldErr(name, errBindingExponent)
		case c < '0' || c > '9':
			return bindingFieldErr(name, errBindingUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return bindingFieldErr(name, errBindingLeadingZero)
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return bindingFieldErr(name, errBindingOverflow)
	}
	*dst = v
	return nil
}

// bindingDigest parses spki_sha256.
func (p *parser) bindingDigest(name string, dst *[BindingSPKIDigestSize]byte) error {
	return decodeBindingBytes(p, name, dst[:], errBindingSPKISize, errBindingSPKIForm)
}

// bindingSignature parses signature.
func (p *parser) bindingSignature(name string, dst *[BindingSignatureSize]byte) error {
	return decodeBindingBytes(p, name, dst[:], errBindingSigSize, errBindingSigForm)
}

// decodeBindingBytes parses a strict unpadded base64url string decoding to
// exactly len(dst) bytes, using the given reasons for a wrong size or spelling.
func decodeBindingBytes(p *parser, name string, dst []byte, sizeErr, formErr error) error {
	v, err := p.string()
	if err != nil {
		return bindingFieldErr(name, errBindingString)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return bindingFieldErr(name, sizeErr)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst, []byte(v))
	if err != nil || n != len(dst) || base64.RawURLEncoding.EncodeToString(dst) != v {
		return bindingFieldErr(name, formErr)
	}
	return nil
}

func (p *parser) bindingRecipient(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return bindingFieldErr(name, errBindingString)
	}
	if err := validateRecipient(v); err != nil {
		return bindingFieldErr(name, errBindingRecipientBad)
	}
	*dst = v
	return nil
}

// VerifyDeviceTransportBinding verifies b's Ed25519 signature with the
// caller-pinned signing key. The signature is a fixed 64-byte array; the
// function checks that the key is exactly one Ed25519 public key before calling
// ed25519.Verify. It does not pin the key itself: the caller must resolve it
// from authenticated vault policy for b's member and device.
func VerifyDeviceTransportBinding(b DeviceTransportBinding, expectedDeviceID string, pinnedSigningKey ed25519.PublicKey) error {
	if err := b.validate(); err != nil {
		return err
	}
	if expectedDeviceID == "" || b.DeviceID != expectedDeviceID {
		return bindingFieldErr(bindingMembers[4], errDeviceMismatch)
	}
	if len(pinnedSigningKey) != ed25519.PublicKeySize {
		return bindingFieldErr("", errSigningKeySize)
	}
	msg, err := SigningBytes(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pinnedSigningKey), msg, b.Signature[:]) {
		return bindingFieldErr(bindingMembers[10], errSignature)
	}
	return nil
}

// VerifyDeviceTransportBindingForContext verifies b against pinnedSigningKey
// exactly as VerifyDeviceTransportBinding does, and additionally requires:
//
//   - c is canonical-valid;
//   - expectedDeviceID equals b.DeviceID;
//   - b.MemberID, b.VaultID and b.PairGeneration equal c's;
//   - c.SourceDeviceID and c.TargetDeviceID differ;
//   - b.DeviceID equals exactly one of c.SourceDeviceID or c.TargetDeviceID.
//
// The caller should pass the key pinned for the matched endpoint. A successful
// return proves only that this signature by that pinned key covers a stable
// binding consistent with these context claims. It does not authenticate the
// context, prove enrollment, owner or admin remote_unlock authorization,
// pairing approval, request freshness, TLS identity or spki_sha256, or grant
// VUK access or authorize the unlock; see the package documentation.
func VerifyDeviceTransportBindingForContext(b DeviceTransportBinding, c ChannelBindingContext, expectedDeviceID string, pinnedSigningKey ed25519.PublicKey) error {
	if _, err := EncodeChannelBindingContext(c); err != nil {
		return bindingFieldErr("", errInvalidContext)
	}
	if err := VerifyDeviceTransportBinding(b, expectedDeviceID, pinnedSigningKey); err != nil {
		return err
	}
	if b.MemberID != c.MemberID {
		return bindingFieldErr(bindingMembers[3], errMemberMismatch)
	}
	if b.VaultID != c.VaultID {
		return bindingFieldErr(bindingMembers[6], errVaultMismatch)
	}
	if b.PairGeneration != c.PairGeneration {
		return bindingFieldErr(bindingMembers[7], errGenerationMismatch)
	}
	if c.SourceDeviceID == c.TargetDeviceID {
		return bindingFieldErr("", errEndpointReuse)
	}
	if !bindingDeviceIsEndpoint(b.DeviceID, c) {
		return bindingFieldErr(bindingMembers[4], errEndpointMismatch)
	}
	return nil
}

// bindingDeviceIsEndpoint reports whether deviceID is exactly one of c's two
// distinct endpoints. Callers must reject equal endpoints first.
func bindingDeviceIsEndpoint(deviceID string, c ChannelBindingContext) bool {
	if deviceID == c.SourceDeviceID {
		return c.SourceDeviceID != c.TargetDeviceID
	}
	return deviceID == c.TargetDeviceID
}
