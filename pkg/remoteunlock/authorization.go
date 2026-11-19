package remoteunlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Wire constants of the v1 canonical owner-root remote-unlock authorization.
const (
	// OwnerRootAuthorizationFormat is the fixed value of the authorization's
	// "format" member. It equals Format.
	OwnerRootAuthorizationFormat = Format
	// OwnerRootAuthorizationVersion is the canonical JSON integer of the
	// authorization's "version" member. It equals Version.
	OwnerRootAuthorizationVersion = Version
	// KindOwnerRootAuthorization is the fixed value of the authorization's
	// "kind" member.
	KindOwnerRootAuthorization = "owner-authorization"
	// AuthorizationContextDomain separates the context digest preimage from
	// every other structure. The preimage is this domain followed by exactly
	// EncodeChannelBindingContext(context) bytes.
	AuthorizationContextDomain = "locklark.remote-unlock/v1/authorization-context\x00"
	// BindingDigestDomain separates the binding digest preimage. The preimage
	// is this domain followed by exactly the complete canonical
	// EncodeDeviceTransportBinding bytes of the binding, signature included.
	BindingDigestDomain = "locklark.remote-unlock/v1/device-transport-binding-digest\x00"
	// OwnerRootAuthorizationSignatureDomain separates the authorization
	// signature preimage. The preimage is this domain followed by the
	// canonical JSON of every authorization member except "signature".
	OwnerRootAuthorizationSignatureDomain = "locklark.remote-unlock/v1/owner-authorization\x00"
	// MaxAuthorizationSize is the maximum encoded or accepted authorization
	// size in bytes.
	MaxAuthorizationSize = 1024
	// AuthorizationSignatureSize is the exact length of signature in bytes.
	AuthorizationSignatureSize = ed25519.SignatureSize
)

// ErrInvalidAuthorization reports an owner-root authorization that cannot be
// encoded, digested or signed, or that fails verification.
var ErrInvalidAuthorization = errors.New("remoteunlock: invalid owner-root authorization")

// ErrInvalidAuthorizationEncoding reports bytes that are not the canonical
// encoding of a valid owner-root authorization.
var ErrInvalidAuthorizationEncoding = errors.New("remoteunlock: invalid owner-root authorization encoding")

// Authorization rejection reasons. They wrap ErrInvalidAuthorization for
// values, digests and verification and ErrInvalidAuthorizationEncoding for
// spellings. Messages are static and never embed a member value, a key, a
// digest, a signature or a verification time.
var (
	errAuthorizationOwnerRootKeyID = fmt.Errorf("%w: owner_root_key_id must be a non-empty identifier of at most %d bytes", ErrInvalidAuthorization, MaxIdentifierLen)
	errAuthorizationExpires        = fmt.Errorf("%w: expires_unix_ms must be greater than zero", ErrInvalidAuthorization)
	errAuthorizationBudget         = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidAuthorization, MaxAuthorizationSize)
	errAuthorizationNotCanonical   = fmt.Errorf("%w: input is not canonical-valid", ErrInvalidAuthorization)
	errAuthorizationNow            = fmt.Errorf("%w: nowUnixMS must be greater than zero", ErrInvalidAuthorization)
	errAuthorizationExpired        = fmt.Errorf("%w: authorization has expired at nowUnixMS", ErrInvalidAuthorization)
	errAuthorizationPastDeadline   = fmt.Errorf("%w: authorization expires after the context deadline", ErrInvalidAuthorization)
	errAuthorizationContext        = fmt.Errorf("%w: context is not canonical-valid", ErrInvalidAuthorization)
	errAuthorizationVault          = fmt.Errorf("%w: header vault_id differs from the context", ErrInvalidAuthorization)
	errAuthorizationKeyEpoch       = fmt.Errorf("%w: header key_epoch differs from the context", ErrInvalidAuthorization)
	errAuthorizationContextDigest  = fmt.Errorf("%w: context_sha256 does not match the context", ErrInvalidAuthorization)
	errAuthorizationPolicySeq      = fmt.Errorf("%w: header policy_seq differs from the context", ErrInvalidAuthorization)
	errAuthorizationPolicyDigest   = fmt.Errorf("%w: header policy_digest differs from the context", ErrInvalidAuthorization)
	errAuthorizationEndpoints      = fmt.Errorf("%w: context source and target device identifiers are equal", ErrInvalidAuthorization)
	errAuthorizationMemberPolicy   = fmt.Errorf("%w: context member is not a reader, writer, admin or owner of the authenticated policy", ErrInvalidAuthorization)
	errAuthorizationSourceDevice   = fmt.Errorf("%w: source device does not resolve in the authenticated policy", ErrInvalidAuthorization)
	errAuthorizationTargetDevice   = fmt.Errorf("%w: target device does not resolve in the authenticated policy", ErrInvalidAuthorization)
	errAuthorizationDeviceOwner    = fmt.Errorf("%w: device principal differs from the context member", ErrInvalidAuthorization)
	errAuthorizationRecipient      = fmt.Errorf("%w: binding recipient_public_key differs from the policy age encryption key", ErrInvalidAuthorization)
	errAuthorizationSourceBinding  = fmt.Errorf("%w: source binding does not verify for the source device", ErrInvalidAuthorization)
	errAuthorizationTargetBinding  = fmt.Errorf("%w: target binding does not verify for the target device", ErrInvalidAuthorization)
	errAuthorizationSourceDigest   = fmt.Errorf("%w: source_binding_sha256 does not match the source binding", ErrInvalidAuthorization)
	errAuthorizationTargetDigest   = fmt.Errorf("%w: target_binding_sha256 does not match the target binding", ErrInvalidAuthorization)
	errAuthorizationOwnerRootPin   = fmt.Errorf("%w: owner_root_key_id or owner root pin differs from the authenticated owner root", ErrInvalidAuthorization)
	errAuthorizationSignature      = fmt.Errorf("%w: owner-root Ed25519 signature does not verify", ErrInvalidAuthorization)

	// Encoding and parsing reasons. None of them embeds a value.
	errAuthorizationNotObject   = fmt.Errorf("%w: not a single JSON object", ErrInvalidAuthorizationEncoding)
	errAuthorizationMissing     = fmt.Errorf("%w: missing member", ErrInvalidAuthorizationEncoding)
	errAuthorizationInvalidUTF8 = fmt.Errorf("%w: not valid UTF-8", ErrInvalidAuthorizationEncoding)
	errAuthorizationString      = fmt.Errorf("%w: string is not canonical", ErrInvalidAuthorizationEncoding)
	errAuthorizationWrongValue  = fmt.Errorf("%w: wrong constant, type or shape", ErrInvalidAuthorizationEncoding)
	errAuthorizationDuplicate   = fmt.Errorf("%w: duplicate member", ErrInvalidAuthorizationEncoding)
	errAuthorizationOutOfOrder  = fmt.Errorf("%w: member out of order", ErrInvalidAuthorizationEncoding)
	errAuthorizationUnknown     = fmt.Errorf("%w: unknown member", ErrInvalidAuthorizationEncoding)
	errAuthorizationTrailing    = fmt.Errorf("%w: trailing data", ErrInvalidAuthorizationEncoding)
	errAuthorizationTooLarge    = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidAuthorizationEncoding, MaxAuthorizationSize)
	errAuthorizationEmptyInput  = fmt.Errorf("%w: empty input", ErrInvalidAuthorizationEncoding)
	errAuthorizationUintSyntax  = fmt.Errorf("%w: integer is not canonical decimal", ErrInvalidAuthorizationEncoding)
	errAuthorizationLeadingZero = fmt.Errorf("%w: integer has a leading zero", ErrInvalidAuthorizationEncoding)
	errAuthorizationFraction    = fmt.Errorf("%w: integer has a fraction", ErrInvalidAuthorizationEncoding)
	errAuthorizationExponent    = fmt.Errorf("%w: integer has an exponent", ErrInvalidAuthorizationEncoding)
	errAuthorizationOverflow    = fmt.Errorf("%w: integer overflows int64", ErrInvalidAuthorizationEncoding)
	errAuthorizationZero        = fmt.Errorf("%w: expires_unix_ms must be greater than zero", ErrInvalidAuthorizationEncoding)
	errAuthorizationDigestSize  = fmt.Errorf("%w: digest must be exactly %d bytes", ErrInvalidAuthorizationEncoding, DigestSize)
	errAuthorizationDigestForm  = fmt.Errorf("%w: digest is not strict unpadded base64url", ErrInvalidAuthorizationEncoding)
	errAuthorizationSigSize     = fmt.Errorf("%w: signature must be exactly %d bytes", ErrInvalidAuthorizationEncoding, AuthorizationSignatureSize)
	errAuthorizationSigForm     = fmt.Errorf("%w: signature is not strict unpadded base64url", ErrInvalidAuthorizationEncoding)
	errAuthorizationReencode    = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidAuthorizationEncoding)

	errAuthorizationParseIDEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidAuthorizationEncoding)
	errAuthorizationParseIDTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidAuthorizationEncoding, MaxIdentifierLen)
	errAuthorizationParseIDChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidAuthorizationEncoding)
)

// AuthorizationFieldError identifies the authorization member that failed
// validation. The message never includes the member's value, a digest, a key,
// a signature or a verification time.
type AuthorizationFieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *AuthorizationFieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: owner-root authorization: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: owner-root authorization field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *AuthorizationFieldError) Unwrap() error { return e.Err }

func authorizationFieldErr(field string, err error) error {
	return &AuthorizationFieldError{Field: field, Err: err}
}

// authorizationMembers lists the authorization members in their exact required
// order. The first eight are the signed members.
var authorizationMembers = [...]string{
	"format",
	"version",
	"kind",
	"owner_root_key_id",
	"context_sha256",
	"source_binding_sha256",
	"target_binding_sha256",
	"expires_unix_ms",
	"signature",
}

// OwnerRootAuthorization is the v1 owner-root authorization of one remote
// unlock request. The independent vault owner root signs once that the request
// bound by the context, from this source device to this target device, is
// authorized until expires_unix_ms.
//
// It supplements, and does not replace, ChannelBindingContext,
// DeviceTransportBinding and the TLS channel APIs. It carries no request
// identifier, pair, lock generation, member, device or vault identifier: those
// are bound through context_sha256, and both endpoint bindings are bound whole
// through their digests, including their own device signatures.
//
// The struct only carries claims. Encoding or parsing it proves none of them.
// VerifyOwnerRootAuthorization checks it against a caller-pinned owner root and
// an authenticated current vault-file policy; see the package documentation
// for the exact boundary. The owner root is the only issuer accepted: there is
// no admin, reader, device or delegation path.
type OwnerRootAuthorization struct {
	// OwnerRootKeyID is the opaque owner-root key identifier that must equal
	// the key identifier of the caller-pinned root.
	OwnerRootKeyID string
	// ContextSHA256 is RemoteUnlockContextDigest of the context.
	ContextSHA256 [DigestSize]byte
	// SourceBindingSHA256 is DeviceTransportBindingDigest of the source
	// device's complete signed binding.
	SourceBindingSHA256 [DigestSize]byte
	// TargetBindingSHA256 is DeviceTransportBindingDigest of the target
	// device's complete signed binding.
	TargetBindingSHA256 [DigestSize]byte
	// ExpiresUnixMS is the absolute expiry in Unix milliseconds. It must be
	// strictly positive and is used exactly as supplied: the codec never
	// reads the clock or adjusts it.
	ExpiresUnixMS int64
	// Signature is the owner root's Ed25519 signature over SigningBytes.
	Signature [AuthorizationSignatureSize]byte
}

// RemoteUnlockContextDigest returns the SHA-256 of AuthorizationContextDomain
// followed by the canonical EncodeChannelBindingContext bytes of c. An invalid
// context returns an error wrapping ErrInvalidAuthorization; the returned
// digest is a hash, not a signature, and proves nothing about the claims.
func RemoteUnlockContextDigest(c ChannelBindingContext) ([DigestSize]byte, error) {
	var out [DigestSize]byte
	canonical, err := EncodeChannelBindingContext(c)
	if err != nil {
		return out, authorizationFieldErr("context", errAuthorizationContext)
	}
	out = sha256.Sum256(append([]byte(AuthorizationContextDomain), canonical...))
	return out, nil
}

// DeviceTransportBindingDigest returns the SHA-256 of BindingDigestDomain
// followed by the complete canonical EncodeDeviceTransportBinding bytes of b,
// signature member included. A changed device signature therefore changes the
// digest. An invalid binding returns an error wrapping ErrInvalidBinding; the
// returned digest is a hash, not a signature check.
func DeviceTransportBindingDigest(b DeviceTransportBinding) ([DigestSize]byte, error) {
	var out [DigestSize]byte
	canonical, err := EncodeDeviceTransportBinding(b)
	if err != nil {
		return out, err
	}
	out = sha256.Sum256(append([]byte(BindingDigestDomain), canonical...))
	return out, nil
}

// AuthorizationSigningBytes returns the exact bytes the owner root signs:
// OwnerRootAuthorizationSignatureDomain followed by the canonical JSON of
// every authorization member except "signature", in schema order. It accepts
// the same values as EncodeOwnerRootAuthorization and ignores Signature.
//
// The returned bytes are public and contain no key material. The owner root
// signs them with its protected Ed25519 key; this package neither stores
// private keys nor signs.
func AuthorizationSigningBytes(a OwnerRootAuthorization) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(OwnerRootAuthorizationSignatureDomain)+512)
	preimage = append(preimage, OwnerRootAuthorizationSignatureDomain...)
	return appendAuthorizationSignedMembers(preimage, a), nil
}

// appendAuthorizationSignedMembers appends the canonical JSON object of the
// signed members (every member except "signature") to buf and returns buf.
func appendAuthorizationSignedMembers(buf []byte, a OwnerRootAuthorization) []byte {
	buf = append(buf, '{')
	buf = appendStringMember(buf, authorizationMembers[0], OwnerRootAuthorizationFormat)
	buf = appendUintMember(buf, authorizationMembers[1], OwnerRootAuthorizationVersion)
	buf = appendStringMember(buf, authorizationMembers[2], KindOwnerRootAuthorization)
	buf = appendStringMember(buf, authorizationMembers[3], a.OwnerRootKeyID)
	buf = appendDigestMember(buf, authorizationMembers[4], a.ContextSHA256)
	buf = appendDigestMember(buf, authorizationMembers[5], a.SourceBindingSHA256)
	buf = appendDigestMember(buf, authorizationMembers[6], a.TargetBindingSHA256)
	buf = appendIntMember(buf, authorizationMembers[7], a.ExpiresUnixMS)
	buf[len(buf)-1] = '}'
	return buf
}

// EncodeOwnerRootAuthorization validates a and returns its canonical v1 JSON
// encoding, which is never longer than MaxAuthorizationSize bytes.
func EncodeOwnerRootAuthorization(a OwnerRootAuthorization) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 512)
	buf = appendAuthorizationSignedMembers(buf, a)
	buf[len(buf)-1] = ','
	buf = appendMemberName(buf, authorizationMembers[8])
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, a.Signature[:])
	buf = append(buf, '"', '}')
	if len(buf) > MaxAuthorizationSize {
		return nil, authorizationFieldErr("", errAuthorizationBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (a OwnerRootAuthorization) validate() error {
	if err := validateIdentifier(a.OwnerRootKeyID); err != nil {
		return authorizationFieldErr(authorizationMembers[3], errAuthorizationOwnerRootKeyID)
	}
	if a.ExpiresUnixMS <= 0 {
		return authorizationFieldErr(authorizationMembers[7], errAuthorizationExpires)
	}
	return nil
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// authorization. It never falls back to the struct field order.
func (a OwnerRootAuthorization) MarshalJSON() ([]byte, error) {
	return EncodeOwnerRootAuthorization(a)
}

// UnmarshalJSON replaces a only when data is exactly the canonical encoding of
// a valid authorization.
func (a *OwnerRootAuthorization) UnmarshalJSON(data []byte) error {
	if a == nil {
		return authorizationFieldErr("", errAuthorizationEmptyInput)
	}
	parsed, err := ParseOwnerRootAuthorization(data)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// ParseOwnerRootAuthorization parses b, which must be exactly the canonical v1
// encoding of a valid authorization. Every other spelling (unknown, missing,
// duplicate or reordered members, non-canonical strings, integers or
// base64url, trailing data) is rejected with an error wrapping
// ErrInvalidAuthorizationEncoding, as is input larger than
// MaxAuthorizationSize. Errors never contain member values, keys or
// signatures.
func ParseOwnerRootAuthorization(b []byte) (OwnerRootAuthorization, error) {
	var out OwnerRootAuthorization
	if len(b) > MaxAuthorizationSize {
		return out, authorizationFieldErr("", errAuthorizationTooLarge)
	}
	if len(b) == 0 {
		return out, authorizationFieldErr("", errAuthorizationEmptyInput)
	}
	if !utf8.Valid(b) {
		return out, authorizationFieldErr("", errAuthorizationInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.authorizationExpect('{', errAuthorizationNotObject); err != nil {
		return out, err
	}
	for i, want := range authorizationMembers {
		if i > 0 {
			if err := p.authorizationSeparator(',', want); err != nil {
				return out, err
			}
		}
		key, err := p.string()
		if err != nil {
			// The key's position is reported as the expected member: this is
			// a static schema name, never an attacker-controlled byte.
			return out, authorizationFieldErr(want, errAuthorizationString)
		}
		if err := p.authorizationSeparator(':', want); err != nil {
			return out, err
		}
		for j := 0; j < i; j++ {
			if key == authorizationMembers[j] {
				return out, authorizationFieldErr(key, errAuthorizationDuplicate)
			}
		}
		if key != want {
			if j := authorizationMemberIndex(key); j >= 0 {
				if j > i {
					return out, authorizationFieldErr(want, errAuthorizationMissing)
				}
				return out, authorizationFieldErr(key, errAuthorizationOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return out, authorizationFieldErr("", errAuthorizationUnknown)
		}
		if err := p.authorizationMember(i, &out); err != nil {
			return out, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		// The object must close here: a member name, or a missing comma
		// before it, means the signature member was omitted.
		if _, err := p.peekString(); err == nil {
			return out, authorizationFieldErr(authorizationMembers[len(authorizationMembers)-1], errAuthorizationMissing)
		}
		return out, authorizationFieldErr("", errAuthorizationTrailing)
	}
	if err := p.authorizationExpect('}', errAuthorizationMissing); err != nil {
		return out, err
	}
	if p.pos != len(p.buf) {
		return out, authorizationFieldErr("", errAuthorizationTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodeOwnerRootAuthorization(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return OwnerRootAuthorization{}, authorizationFieldErr("", errAuthorizationReencode)
	}
	return out, nil
}

// authorizationExpect consumes the literal byte want with
// authorization-specific errors, so a structural failure never reports a
// context or binding field error.
func (p *parser) authorizationExpect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return authorizationFieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		// A member starting where the separator was expected means the
		// preceding member was omitted.
		if want == ',' || want == ':' {
			return authorizationFieldErr("", errAuthorizationMissing)
		}
		return authorizationFieldErr("", errAuthorizationWrongValue)
	}
	p.pos++
	return nil
}

// authorizationSeparator consumes the separator want (a comma or colon)
// before member expected. A member name at the cursor means that member was
// carried where expected should be, so the error names it; a closing brace or
// end of input means expected is omitted, so the error names expected. The
// reported names are schema constants only, never attacker-controlled bytes.
func (p *parser) authorizationSeparator(want byte, expected string) error {
	if p.pos >= len(p.buf) {
		return authorizationFieldErr(expected, errAuthorizationMissing)
	}
	if p.buf[p.pos] != want {
		if want == ',' {
			// The next member name identifies the omitted member; a closing
			// brace identifies the expected (final) member.
			if key, err := p.peekString(); err == nil && authorizationMemberIndex(key) >= 0 {
				return authorizationFieldErr(key, errAuthorizationMissing)
			}
		}
		return authorizationFieldErr(expected, errAuthorizationMissing)
	}
	p.pos++
	return nil
}

func authorizationMemberIndex(key string) int {
	for i, m := range authorizationMembers {
		if m == key {
			return i
		}
	}
	return -1
}

// authorizationMember parses the value of authorizationMembers[i] into a.
func (p *parser) authorizationMember(i int, a *OwnerRootAuthorization) error {
	name := authorizationMembers[i]
	switch i {
	case 0:
		return p.authorizationConstant(name, OwnerRootAuthorizationFormat)
	case 1:
		v, err := p.number()
		if err != nil || v != "1" {
			return authorizationFieldErr(name, errAuthorizationWrongValue)
		}
		return nil
	case 2:
		return p.authorizationConstant(name, KindOwnerRootAuthorization)
	case 3:
		return p.authorizationIdentifier(name, &a.OwnerRootKeyID)
	case 4:
		return p.authorizationDigest(name, &a.ContextSHA256)
	case 5:
		return p.authorizationDigest(name, &a.SourceBindingSHA256)
	case 6:
		return p.authorizationDigest(name, &a.TargetBindingSHA256)
	case 7:
		return p.authorizationExpires(name, &a.ExpiresUnixMS)
	case 8:
		return p.authorizationSignature(name, &a.Signature)
	}
	return authorizationFieldErr(name, errAuthorizationUnknown)
}

func (p *parser) authorizationConstant(name, want string) error {
	v, err := p.string()
	if err != nil {
		return authorizationFieldErr(name, errAuthorizationString)
	}
	if v != want {
		return authorizationFieldErr(name, errAuthorizationWrongValue)
	}
	return nil
}

func (p *parser) authorizationIdentifier(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return authorizationFieldErr(name, errAuthorizationString)
	}
	if err := validateIdentifier(v); err != nil {
		switch {
		case errors.Is(err, errEmpty):
			return authorizationFieldErr(name, errAuthorizationParseIDEmpty)
		case errors.Is(err, errTooLong):
			return authorizationFieldErr(name, errAuthorizationParseIDTooLong)
		default:
			return authorizationFieldErr(name, errAuthorizationParseIDChar)
		}
	}
	*dst = v
	return nil
}

func (p *parser) authorizationDigest(name string, dst *[DigestSize]byte) error {
	return decodeAuthorizationBytes(p, name, dst[:], errAuthorizationDigestSize, errAuthorizationDigestForm)
}

func (p *parser) authorizationSignature(name string, dst *[AuthorizationSignatureSize]byte) error {
	return decodeAuthorizationBytes(p, name, dst[:], errAuthorizationSigSize, errAuthorizationSigForm)
}

// decodeAuthorizationBytes parses a strict unpadded base64url string decoding
// to exactly len(dst) bytes, using the given reasons for a wrong size or
// spelling.
func decodeAuthorizationBytes(p *parser, name string, dst []byte, sizeErr, formErr error) error {
	v, err := p.string()
	if err != nil {
		return authorizationFieldErr(name, errAuthorizationString)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return authorizationFieldErr(name, sizeErr)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst, []byte(v))
	if err != nil || n != len(dst) || base64.RawURLEncoding.EncodeToString(dst) != v {
		return authorizationFieldErr(name, formErr)
	}
	return nil
}

// authorizationExpires parses a canonical positive decimal int64 in Unix
// milliseconds.
func (p *parser) authorizationExpires(name string, dst *int64) error {
	raw, err := p.number()
	if err != nil {
		return authorizationFieldErr(name, errAuthorizationUintSyntax)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return authorizationFieldErr(name, errAuthorizationUintSyntax)
		case c == '.':
			return authorizationFieldErr(name, errAuthorizationFraction)
		case c == 'e' || c == 'E':
			return authorizationFieldErr(name, errAuthorizationExponent)
		case c < '0' || c > '9':
			return authorizationFieldErr(name, errAuthorizationUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return authorizationFieldErr(name, errAuthorizationLeadingZero)
	}
	if raw[0] == '0' {
		return authorizationFieldErr(name, errAuthorizationZero)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return authorizationFieldErr(name, errAuthorizationOverflow)
	}
	*dst = v
	return nil
}

// VerifyOwnerRootAuthorization verifies a against the context c, the two
// device transport bindings and the caller's pinned policy checkpoint cp,
// which must authenticate the current policy of f.
//
// It runs, in exactly this order, and returns on the first failure:
//
//  1. nowUnixMS must be positive, a, c and both bindings must be
//     canonical-valid, a.ExpiresUnixMS must be strictly after nowUnixMS and
//     must not be after c.DeadlineUnixMS (an authorization may expire before
//     the request does, never after). The time is the caller's only clock.
//  2. a.ContextSHA256 must equal RemoteUnlockContextDigest(c).
//  3. vaultfile.VerifyPolicyCheckpoint(f, cp) must succeed before any policy
//     claim is trusted. Its error is returned wrapped with
//     ErrInvalidAuthorization. Only then are f.Header and the last carried
//     policy proof used, and they are the current, authenticated policy.
//  4. f.Header.VaultID, KeyEpoch, PolicySeq and PolicyDigest must equal the
//     context, and vaultfile.PolicyDigest of the authenticated current policy
//     must equal Header.PolicyDigest and again the context digest. An
//     owner-authorization-chain element between the context and the
//     checkpoint policy sequence is rejected.
//  5. The context source and target must differ, both must resolve in the
//     authenticated policy, both must belong to c.MemberID, and that principal
//     must hold an existing read role (a reader, writer, admin or owner,
//     matched exactly as the vault file's role semantics allow). The policy
//     device age encryption key must equal each binding's recipient.
//  6. Each binding must verify with
//     VerifyDeviceTransportBindingForContext under its device's authenticated
//     content signing key, and the digest of each must equal the matching
//     authorization member: source then target.
//  7. a.OwnerRootKeyID must equal cp.OwnerRootKeyID and the signature must
//     verify under exactly cp.OwnerRootPublicKey.
//
// A nil return proves only that the owner root that owns cp issued this
// authorization for this request context, these two signed stable bindings of
// the authenticated current policy, before the expiry and the request
// deadline. It does not prove the request digest preimage, the actual channel
// exporter value or a handshake, the SPKI of the live peer (the internal TLS
// adapter's separate check), that either device holds its private keys, that
// the authorization is used at most once across restarts, or any VUK
// decryption or delivery. VerifyPolicyCheckpoint remains the authority for the
// content author role and mutation, which this function never performs.
func VerifyOwnerRootAuthorization(f *vaultfile.File, cp *vaultfile.PolicyCheckpoint, a OwnerRootAuthorization, c ChannelBindingContext, source, target DeviceTransportBinding, nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return authorizationFieldErr("", errAuthorizationNow)
	}
	if err := a.validate(); err != nil {
		return err
	}
	if err := c.validate(); err != nil {
		return authorizationFieldErr("", errAuthorizationContext)
	}
	if _, err := EncodeChannelBindingContext(c); err != nil {
		return authorizationFieldErr("", errAuthorizationContext)
	}
	if err := source.validate(); err != nil {
		return authorizationFieldErr("source_binding", errAuthorizationSourceBinding)
	}
	if err := target.validate(); err != nil {
		return authorizationFieldErr("target_binding", errAuthorizationTargetBinding)
	}

	// 1. Expiry. Both bounds are strict on the now side: an authorization is
	// expired at exactly its expiry instant.
	if nowUnixMS >= a.ExpiresUnixMS {
		return authorizationFieldErr(authorizationMembers[7], errAuthorizationExpired)
	}
	if a.ExpiresUnixMS > c.DeadlineUnixMS {
		return authorizationFieldErr(authorizationMembers[7], errAuthorizationPastDeadline)
	}

	// 2. Context digest.
	contextDigest, err := RemoteUnlockContextDigest(c)
	if err != nil {
		return err
	}
	if contextDigest != a.ContextSHA256 {
		return authorizationFieldErr(authorizationMembers[4], errAuthorizationContextDigest)
	}

	// 3. The carried policy is untrusted until the caller's checkpoint
	// authenticates its continuation and content signature.
	if err := vaultfile.VerifyPolicyCheckpoint(f, cp); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthorization, err)
	}
	policy := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy

	// 4. Header and policy claims against the context. Nothing is normalized.
	switch {
	case f.Header.VaultID != c.VaultID:
		return authorizationFieldErr("header.vault_id", errAuthorizationVault)
	case f.Header.KeyEpoch != c.KeyEpoch:
		return authorizationFieldErr("header.key_epoch", errAuthorizationKeyEpoch)
	case f.Header.PolicySeq != c.PolicySeq:
		return authorizationFieldErr("header.policy_seq", errAuthorizationPolicySeq)
	}
	policyDigest := vaultfile.PolicyDigest(policy)
	if !bytes.Equal(f.Header.PolicyDigest, policyDigest) {
		return authorizationFieldErr("header.policy_digest", errAuthorizationPolicyDigest)
	}
	if !bytes.Equal(policyDigest, c.PolicyDigest[:]) {
		return authorizationFieldErr(authorizationMembers[4], errAuthorizationPolicyDigest)
	}
	if policy.VaultID != c.VaultID || policy.PolicySeq != c.PolicySeq {
		return authorizationFieldErr("policy", errAuthorizationPolicySeq)
	}
	for _, sp := range f.SignedPolicyProofs {
		if sp.Policy.PolicySeq > c.PolicySeq {
			return authorizationFieldErr("policy.policy_seq", errAuthorizationPolicySeq)
		}
	}

	// 5. Devices and the member's existing read qualification.
	if c.SourceDeviceID == c.TargetDeviceID {
		return authorizationFieldErr("context", errAuthorizationEndpoints)
	}
	if !policyReadQualified(c.MemberID, policy) {
		return authorizationFieldErr("context.member_id", errAuthorizationMemberPolicy)
	}
	srcDev := policyDevice(policy, c.SourceDeviceID)
	if srcDev == nil || srcDev.PrincipalID != c.MemberID {
		return authorizationFieldErr("context.source_device_id", errAuthorizationSourceDevice)
	}
	if srcDev.AgeEncryptionKey != source.RecipientPublicKey {
		return authorizationFieldErr("source_binding.recipient_public_key", errAuthorizationRecipient)
	}
	tgtDev := policyDevice(policy, c.TargetDeviceID)
	if tgtDev == nil || tgtDev.PrincipalID != c.MemberID {
		return authorizationFieldErr("context.target_device_id", errAuthorizationTargetDevice)
	}
	if tgtDev.AgeEncryptionKey != target.RecipientPublicKey {
		return authorizationFieldErr("target_binding.recipient_public_key", errAuthorizationRecipient)
	}

	// 6. Binding signatures under the authenticated device keys, then the
	// complete-binding digests in source-then-target order.
	if err := VerifyDeviceTransportBindingForContext(source, c, c.SourceDeviceID, ed25519.PublicKey(srcDev.ContentSigningKey.PublicKey)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthorization, err)
	}
	if err := VerifyDeviceTransportBindingForContext(target, c, c.TargetDeviceID, ed25519.PublicKey(tgtDev.ContentSigningKey.PublicKey)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthorization, err)
	}
	srcDigest, err := DeviceTransportBindingDigest(source)
	if err != nil {
		return err
	}
	if srcDigest != a.SourceBindingSHA256 {
		return authorizationFieldErr(authorizationMembers[5], errAuthorizationSourceDigest)
	}
	tgtDigest, err := DeviceTransportBindingDigest(target)
	if err != nil {
		return err
	}
	if tgtDigest != a.TargetBindingSHA256 {
		return authorizationFieldErr(authorizationMembers[6], errAuthorizationTargetDigest)
	}

	// 7. The owner root: identifier and caller-pinned key only.
	if a.OwnerRootKeyID != cp.OwnerRootKeyID || cp.OwnerRootKeyID != policy.OwnerRoot.KeyID ||
		!bytes.Equal(cp.OwnerRootPublicKey, policy.OwnerRoot.PublicKey) ||
		len(cp.OwnerRootPublicKey) != ed25519.PublicKeySize {
		return authorizationFieldErr(authorizationMembers[3], errAuthorizationOwnerRootPin)
	}
	msg, err := AuthorizationSigningBytes(a)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(cp.OwnerRootPublicKey), msg, a.Signature[:]) {
		return authorizationFieldErr(authorizationMembers[8], errAuthorizationSignature)
	}
	return nil
}

// policyReadQualified reports whether principalID is listed with any existing
// read-capable vault role. By the vault file's role order a writer, admin or
// owner reads too, so each of the four role arrays is checked on its own with
// no normalization, inheritance synthesis or mutation. This is read
// qualification only: it grants no content or policy signing role.
func policyReadQualified(principalID string, p *vaultfile.Policy) bool {
	for _, role := range [4][]vaultfile.Member{p.Readers, p.Writers, p.Admins, p.Owners} {
		for i := range role {
			if role[i].PrincipalID == principalID {
				return true
			}
		}
	}
	return false
}

// policyDevice returns the authenticated policy device with id, or nil.
func policyDevice(p *vaultfile.Policy, id string) *vaultfile.Device {
	for i := range p.Devices {
		if p.Devices[i].DeviceID == id {
			return &p.Devices[i]
		}
	}
	return nil
}
