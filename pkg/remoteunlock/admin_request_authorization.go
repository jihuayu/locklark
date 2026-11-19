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

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Wire constants of the v1 canonical admin remote-unlock authorization.
const (
	// AdminAuthorizationFormat is the fixed value of the authorization's
	// "format" member. It equals Format.
	AdminAuthorizationFormat = Format
	// AdminAuthorizationVersion is the canonical JSON integer of the
	// authorization's "version" member. It equals Version.
	AdminAuthorizationVersion = Version
	// KindAdminAuthorization is the fixed value of the authorization's "kind"
	// member.
	KindAdminAuthorization = "admin-authorization"
	// AdminAuthorizationSignatureDomain separates the delegated-device
	// signature preimage. The preimage is this domain followed by the
	// canonical JSON of every authorization member except "signature". It is
	// distinct from the owner-root authorization, owner-root delegation and
	// device binding domains: a signature made for one never verifies for
	// another.
	AdminAuthorizationSignatureDomain = "locklark.remote-unlock/v1/admin-authorization\x00"
	// MaxAdminAuthorizationSize is the maximum encoded or accepted
	// authorization size in bytes.
	MaxAdminAuthorizationSize = 1024
	// AdminAuthorizationSignatureSize is the exact length of signature in
	// bytes.
	AdminAuthorizationSignatureSize = ed25519.SignatureSize
)

// ErrInvalidAdminAuthorization reports an admin remote-unlock authorization
// that cannot be encoded or signed, or that fails verification.
var ErrInvalidAdminAuthorization = errors.New("remoteunlock: invalid admin remote-unlock authorization")

// ErrInvalidAdminAuthorizationEncoding reports bytes that are not the canonical
// encoding of a valid admin remote-unlock authorization.
var ErrInvalidAdminAuthorizationEncoding = errors.New("remoteunlock: invalid admin remote-unlock authorization encoding")

// Admin-authorization rejection reasons. They wrap ErrInvalidAdminAuthorization
// for values and verification and ErrInvalidAdminAuthorizationEncoding for
// spellings. Messages are static and never embed a member value, an
// identifier, a key, a digest, a signature or a verification time.
var (
	errAdminAuthorizationExpires = fmt.Errorf("%w: expires_unix_ms must be greater than zero", ErrInvalidAdminAuthorization)
	errAdminAuthorizationBudget  = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidAdminAuthorization, MaxAdminAuthorizationSize)

	// Verification reasons, in the order the verifier checks them.
	errAdminAuthorizationNow           = fmt.Errorf("%w: nowUnixMS must be greater than zero", ErrInvalidAdminAuthorization)
	errAdminAuthorizationNotCanonical  = fmt.Errorf("%w: input is not canonical-valid", ErrInvalidAdminAuthorization)
	errAdminAuthorizationExpired       = fmt.Errorf("%w: authorization has expired at nowUnixMS", ErrInvalidAdminAuthorization)
	errAdminAuthorizationPastDeadline  = fmt.Errorf("%w: authorization expires after the context deadline", ErrInvalidAdminAuthorization)
	errAdminAuthorizationContextBad    = fmt.Errorf("%w: context is not canonical-valid", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceBindBad = fmt.Errorf("%w: source binding is not canonical-valid", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetBindBad = fmt.Errorf("%w: target binding is not canonical-valid", ErrInvalidAdminAuthorization)
	errAdminAuthorizationContextDigest = fmt.Errorf("%w: context_sha256 does not match the context", ErrInvalidAdminAuthorization)
	errAdminAuthorizationDelegationDig = fmt.Errorf("%w: delegation_digest does not match the reusable grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationGrantNotTrust = fmt.Errorf("%w: reusable grant does not verify against the authenticated current policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationGrantExpired  = fmt.Errorf("%w: authorization expires after the reusable grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationVault         = fmt.Errorf("%w: context vault_id differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationRequester     = fmt.Errorf("%w: context member_id is not the grant requester", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceDev     = fmt.Errorf("%w: context source_device_id differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetDev     = fmt.Errorf("%w: context target_device_id differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationPairGen       = fmt.Errorf("%w: context pair_generation differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationKeyEpoch      = fmt.Errorf("%w: context key_epoch differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationPolicySeq     = fmt.Errorf("%w: context policy_seq differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationPolicyDigest  = fmt.Errorf("%w: context policy_digest differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationDelegate      = fmt.Errorf("%w: delegate device is missing from the authenticated current policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationDelegateRole  = fmt.Errorf("%w: delegate principal is not currently an admin or owner", ErrInvalidAdminAuthorization)
	errAdminAuthorizationDelegateKey   = fmt.Errorf("%w: delegate policy signing key is missing, not Ed25519 or differs from the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourcePolicy  = fmt.Errorf("%w: source device does not resolve to the requester in the authenticated policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetPolicy  = fmt.Errorf("%w: target device does not resolve to the requester in the authenticated policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceKey     = fmt.Errorf("%w: source device content signing key is missing or not Ed25519 in the authenticated policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetKey     = fmt.Errorf("%w: target device content signing key is missing or not Ed25519 in the authenticated policy", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceRecip   = fmt.Errorf("%w: source binding recipient_public_key differs from the policy age encryption key", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetRecip   = fmt.Errorf("%w: target binding recipient_public_key differs from the policy age encryption key", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceBind    = fmt.Errorf("%w: source binding does not verify for the source device", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetBind    = fmt.Errorf("%w: target binding does not verify for the target device", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSourceDigest  = fmt.Errorf("%w: source_binding_sha256 does not match the source binding or the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationTargetDigest  = fmt.Errorf("%w: target_binding_sha256 does not match the target binding or the grant", ErrInvalidAdminAuthorization)
	errAdminAuthorizationSignature     = fmt.Errorf("%w: delegate-device Ed25519 signature does not verify", ErrInvalidAdminAuthorization)

	// Encoding and parsing reasons. None of them embeds a value.
	errAdminAuthorizationNotObject   = fmt.Errorf("%w: not a single JSON object", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationMissing     = fmt.Errorf("%w: missing member", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationInvalidUTF8 = fmt.Errorf("%w: not valid UTF-8", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationString      = fmt.Errorf("%w: string is not canonical", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationWrongValue  = fmt.Errorf("%w: wrong constant, type or shape", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationDuplicate   = fmt.Errorf("%w: duplicate member", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationOutOfOrder  = fmt.Errorf("%w: member out of order", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationUnknown     = fmt.Errorf("%w: unknown member", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationTrailing    = fmt.Errorf("%w: trailing data", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationTooLarge    = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidAdminAuthorizationEncoding, MaxAdminAuthorizationSize)
	errAdminAuthorizationEmptyInput  = fmt.Errorf("%w: empty input", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationUintSyntax  = fmt.Errorf("%w: integer is not canonical unsigned decimal", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationLeadingZero = fmt.Errorf("%w: integer has a leading zero", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationFraction    = fmt.Errorf("%w: integer has a fraction", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationExponent    = fmt.Errorf("%w: integer has an exponent", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationUintRange   = fmt.Errorf("%w: integer overflows its signed range", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationZeroTime    = fmt.Errorf("%w: expires_unix_ms must be greater than zero", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationDigestSize  = fmt.Errorf("%w: digest must be exactly %d bytes", ErrInvalidAdminAuthorizationEncoding, DigestSize)
	errAdminAuthorizationDigestForm  = fmt.Errorf("%w: digest is not strict unpadded base64url", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationSigSize     = fmt.Errorf("%w: signature must be exactly %d bytes", ErrInvalidAdminAuthorizationEncoding, AdminAuthorizationSignatureSize)
	errAdminAuthorizationSigForm     = fmt.Errorf("%w: signature is not strict unpadded base64url", ErrInvalidAdminAuthorizationEncoding)
	errAdminAuthorizationReencode    = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidAdminAuthorizationEncoding)
)

// AdminAuthorizationFieldError identifies the authorization member that
// failed validation. The message never includes the member's value, a key, a
// digest, a signature or a verification time.
type AdminAuthorizationFieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *AdminAuthorizationFieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: admin remote-unlock authorization: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: admin remote-unlock authorization field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *AdminAuthorizationFieldError) Unwrap() error { return e.Err }

func adminAuthorizationFieldErr(field string, err error) error {
	return &AdminAuthorizationFieldError{Field: field, Err: err}
}

// adminAuthorizationMembers lists the authorization members in their exact
// required order. The first eight are the delegated-device signed members.
var adminAuthorizationMembers = [...]string{
	"format",
	"version",
	"kind",
	"delegation_digest",
	"context_sha256",
	"source_binding_sha256",
	"target_binding_sha256",
	"expires_unix_ms",
	"signature",
}

// AdminRemoteUnlockAuthorization is the v1 per-request authorization of one
// remote unlock request under a reusable OwnerRootAdminRemoteUnlockDelegation.
//
// The delegated administrator device, not the owner root, signs it fresh for
// every request: the owner root signs the reusable grant exactly once, and
// never a per-request object or a new root contact. The authorization binds
// AdminDelegationDigest of the reusable grant, RemoteUnlockContextDigest of
// the full fresh ChannelBindingContext (request identifier, request digest,
// pair, lock generation, member, both endpoints, vault, key epoch, policy
// anchor and request deadline), DeviceTransportBindingDigest of the complete
// signed source and target bindings, and one absolute expiry.
//
// The type carries no requester, device, vault, pair, epoch or policy member:
// those are bound through context_sha256 and checked by
// VerifyAdminRemoteUnlockAuthorization against the grant scope. Like the
// reusable grant it carries no request identifier itself, and an
// authorization is not proof of one-shot use.
//
// The struct only carries claims. Encoding or parsing it proves none of them.
// VerifyAdminRemoteUnlockAuthorization checks it against a caller-pinned
// vault-file PolicyCheckpoint, the reusable grant, the request context, both
// bindings and the caller's clock; see the package documentation for the exact
// boundary. No role is asserted here, and the owner root key is never used to
// sign or verify this object.
type AdminRemoteUnlockAuthorization struct {
	// DelegationDigest is AdminDelegationDigest of the exact reusable grant
	// the authorization is issued under.
	DelegationDigest [DigestSize]byte
	// ContextSHA256 is RemoteUnlockContextDigest of the full request context.
	ContextSHA256 [DigestSize]byte
	// SourceBindingSHA256 is DeviceTransportBindingDigest of the source
	// device's complete signed binding.
	SourceBindingSHA256 [DigestSize]byte
	// TargetBindingSHA256 is DeviceTransportBindingDigest of the target
	// device's complete signed binding.
	TargetBindingSHA256 [DigestSize]byte
	// ExpiresUnixMS is the absolute exclusive end of the validity interval
	// in Unix milliseconds. It must be strictly positive and is used exactly
	// as supplied: the codec never reads the clock or adjusts it.
	ExpiresUnixMS int64
	// Signature is the delegated device's Ed25519 signature over
	// AdminAuthorizationSigningBytes, made with the grant's
	// DelegatePolicySigningKey.
	Signature [AdminAuthorizationSignatureSize]byte
}

// AdminAuthorizationSigningBytes returns the exact bytes the delegated admin
// device signs: AdminAuthorizationSignatureDomain followed by the canonical
// JSON of every authorization member except "signature", in schema order. It
// accepts the same values as EncodeAdminRemoteUnlockAuthorization and ignores
// Signature.
//
// The returned bytes are public and contain no key material. The delegated
// device signs them with the private half of the grant's
// DelegatePolicySigningKey; this package neither stores private keys nor
// signs.
func AdminAuthorizationSigningBytes(a AdminRemoteUnlockAuthorization) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(AdminAuthorizationSignatureDomain)+512)
	preimage = append(preimage, AdminAuthorizationSignatureDomain...)
	return appendAdminAuthorizationSignedMembers(preimage, a), nil
}

// appendAdminAuthorizationSignedMembers appends the canonical JSON object of
// the signed members (every member except "signature") to buf and returns buf.
func appendAdminAuthorizationSignedMembers(buf []byte, a AdminRemoteUnlockAuthorization) []byte {
	m := &adminAuthorizationMembers
	buf = append(buf, '{')
	buf = appendStringMember(buf, m[0], AdminAuthorizationFormat)
	buf = appendUintMember(buf, m[1], AdminAuthorizationVersion)
	buf = appendStringMember(buf, m[2], KindAdminAuthorization)
	buf = appendDigestMember(buf, m[3], a.DelegationDigest)
	buf = appendDigestMember(buf, m[4], a.ContextSHA256)
	buf = appendDigestMember(buf, m[5], a.SourceBindingSHA256)
	buf = appendDigestMember(buf, m[6], a.TargetBindingSHA256)
	buf = appendIntMember(buf, m[7], a.ExpiresUnixMS)
	buf[len(buf)-1] = '}'
	return buf
}

// EncodeAdminRemoteUnlockAuthorization validates a and returns its canonical
// v1 JSON encoding, which is never longer than MaxAdminAuthorizationSize
// bytes.
func EncodeAdminRemoteUnlockAuthorization(a AdminRemoteUnlockAuthorization) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 512)
	buf = appendAdminAuthorizationSignedMembers(buf, a)
	buf[len(buf)-1] = ','
	buf = appendMemberName(buf, adminAuthorizationMembers[8])
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, a.Signature[:])
	buf = append(buf, '"', '}')
	if len(buf) > MaxAdminAuthorizationSize {
		return nil, adminAuthorizationFieldErr("", errAdminAuthorizationBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (a AdminRemoteUnlockAuthorization) validate() error {
	if a.ExpiresUnixMS <= 0 {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[7], errAdminAuthorizationExpires)
	}
	return nil
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// authorization. It never falls back to the struct field order.
func (a AdminRemoteUnlockAuthorization) MarshalJSON() ([]byte, error) {
	return EncodeAdminRemoteUnlockAuthorization(a)
}

// UnmarshalJSON replaces a only when data is exactly the canonical encoding of
// a valid authorization.
func (a *AdminRemoteUnlockAuthorization) UnmarshalJSON(data []byte) error {
	if a == nil {
		return adminAuthorizationFieldErr("", errAdminAuthorizationEmptyInput)
	}
	parsed, err := ParseAdminRemoteUnlockAuthorization(data)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// ParseAdminRemoteUnlockAuthorization parses b, which must be exactly the
// canonical v1 encoding of a valid authorization. Every other spelling
// (unknown, missing, duplicate or reordered members, non-canonical strings,
// integers or base64url, trailing data) is rejected with an error wrapping
// ErrInvalidAdminAuthorizationEncoding, as is input larger than
// MaxAdminAuthorizationSize. Errors never contain member values, keys, digests
// or signatures.
func ParseAdminRemoteUnlockAuthorization(b []byte) (AdminRemoteUnlockAuthorization, error) {
	var out AdminRemoteUnlockAuthorization
	if len(b) > MaxAdminAuthorizationSize {
		return out, adminAuthorizationFieldErr("", errAdminAuthorizationTooLarge)
	}
	if len(b) == 0 {
		return out, adminAuthorizationFieldErr("", errAdminAuthorizationEmptyInput)
	}
	if !utf8.Valid(b) {
		return out, adminAuthorizationFieldErr("", errAdminAuthorizationInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.adminAuthorizationExpect('{', errAdminAuthorizationNotObject); err != nil {
		return out, err
	}
	for i, want := range adminAuthorizationMembers {
		if i > 0 {
			if err := p.adminAuthorizationSeparator(',', want); err != nil {
				return out, err
			}
		}
		key, err := p.string()
		if err != nil {
			// The key's position is reported as the expected member: this is
			// a static schema name, never an attacker-controlled byte.
			return out, adminAuthorizationFieldErr(want, errAdminAuthorizationString)
		}
		if err := p.adminAuthorizationSeparator(':', want); err != nil {
			return out, err
		}
		for j := 0; j < i; j++ {
			if key == adminAuthorizationMembers[j] {
				return out, adminAuthorizationFieldErr(key, errAdminAuthorizationDuplicate)
			}
		}
		if key != want {
			if j := adminAuthorizationMemberIndex(key); j >= 0 {
				if j > i {
					return out, adminAuthorizationFieldErr(want, errAdminAuthorizationMissing)
				}
				return out, adminAuthorizationFieldErr(key, errAdminAuthorizationOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return out, adminAuthorizationFieldErr("", errAdminAuthorizationUnknown)
		}
		if err := p.adminAuthorizationMember(i, &out); err != nil {
			return out, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		// The object must close here: a member name, or a missing comma
		// before it, means the signature member was omitted.
		if _, err := p.peekString(); err == nil {
			return out, adminAuthorizationFieldErr(adminAuthorizationMembers[len(adminAuthorizationMembers)-1], errAdminAuthorizationMissing)
		}
		return out, adminAuthorizationFieldErr("", errAdminAuthorizationTrailing)
	}
	if err := p.adminAuthorizationExpect('}', errAdminAuthorizationMissing); err != nil {
		return out, err
	}
	if p.pos != len(p.buf) {
		return out, adminAuthorizationFieldErr("", errAdminAuthorizationTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodeAdminRemoteUnlockAuthorization(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return AdminRemoteUnlockAuthorization{}, adminAuthorizationFieldErr("", errAdminAuthorizationReencode)
	}
	return out, nil
}

// adminAuthorizationExpect consumes the literal byte want with
// authorization-specific errors, so a structural failure never reports
// another structure's field error.
func (p *parser) adminAuthorizationExpect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return adminAuthorizationFieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		if want == ',' || want == ':' {
			return adminAuthorizationFieldErr("", errAdminAuthorizationMissing)
		}
		return adminAuthorizationFieldErr("", errAdminAuthorizationWrongValue)
	}
	p.pos++
	return nil
}

// adminAuthorizationSeparator consumes the separator want (a comma or colon)
// before member expected. A known member name at the cursor means that member
// was carried where expected should be, so the error names it; a closing brace
// or end of input means expected is omitted, so the error names expected. The
// reported names are schema constants only, never attacker-controlled bytes.
func (p *parser) adminAuthorizationSeparator(want byte, expected string) error {
	if p.pos >= len(p.buf) {
		return adminAuthorizationFieldErr(expected, errAdminAuthorizationMissing)
	}
	if p.buf[p.pos] != want {
		if want == ',' {
			if key, err := p.peekString(); err == nil && adminAuthorizationMemberIndex(key) >= 0 {
				return adminAuthorizationFieldErr(key, errAdminAuthorizationMissing)
			}
		}
		return adminAuthorizationFieldErr(expected, errAdminAuthorizationMissing)
	}
	p.pos++
	return nil
}

func adminAuthorizationMemberIndex(key string) int {
	for i, m := range adminAuthorizationMembers {
		if m == key {
			return i
		}
	}
	return -1
}

// adminAuthorizationMember parses the value of adminAuthorizationMembers[i]
// into a.
func (p *parser) adminAuthorizationMember(i int, a *AdminRemoteUnlockAuthorization) error {
	name := adminAuthorizationMembers[i]
	switch i {
	case 0:
		return p.adminAuthorizationConstant(name, AdminAuthorizationFormat)
	case 1:
		v, err := p.number()
		if err != nil || v != "1" {
			return adminAuthorizationFieldErr(name, errAdminAuthorizationWrongValue)
		}
		return nil
	case 2:
		return p.adminAuthorizationConstant(name, KindAdminAuthorization)
	case 3:
		return decodeAdminAuthorizationBytes(p, name, a.DelegationDigest[:], errAdminAuthorizationDigestSize, errAdminAuthorizationDigestForm)
	case 4:
		return decodeAdminAuthorizationBytes(p, name, a.ContextSHA256[:], errAdminAuthorizationDigestSize, errAdminAuthorizationDigestForm)
	case 5:
		return decodeAdminAuthorizationBytes(p, name, a.SourceBindingSHA256[:], errAdminAuthorizationDigestSize, errAdminAuthorizationDigestForm)
	case 6:
		return decodeAdminAuthorizationBytes(p, name, a.TargetBindingSHA256[:], errAdminAuthorizationDigestSize, errAdminAuthorizationDigestForm)
	case 7:
		return p.adminAuthorizationExpires(name, &a.ExpiresUnixMS)
	case 8:
		return decodeAdminAuthorizationBytes(p, name, a.Signature[:], errAdminAuthorizationSigSize, errAdminAuthorizationSigForm)
	}
	return adminAuthorizationFieldErr(name, errAdminAuthorizationUnknown)
}

func (p *parser) adminAuthorizationConstant(name, want string) error {
	v, err := p.string()
	if err != nil {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationString)
	}
	if v != want {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationWrongValue)
	}
	return nil
}

// decodeAdminAuthorizationBytes parses a strict unpadded base64url string
// decoding to exactly len(dst) bytes, using the given reasons for a wrong size
// or spelling.
func decodeAdminAuthorizationBytes(p *parser, name string, dst []byte, sizeErr, formErr error) error {
	v, err := p.string()
	if err != nil {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationString)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return adminAuthorizationFieldErr(name, sizeErr)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst, []byte(v))
	if err != nil || n != len(dst) || base64.RawURLEncoding.EncodeToString(dst) != v {
		return adminAuthorizationFieldErr(name, formErr)
	}
	return nil
}

// adminAuthorizationExpires parses a canonical positive decimal int64 in Unix
// milliseconds.
func (p *parser) adminAuthorizationExpires(name string, dst *int64) error {
	raw, err := p.number()
	if err != nil {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationUintSyntax)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return adminAuthorizationFieldErr(name, errAdminAuthorizationUintSyntax)
		case c == '.':
			return adminAuthorizationFieldErr(name, errAdminAuthorizationFraction)
		case c == 'e' || c == 'E':
			return adminAuthorizationFieldErr(name, errAdminAuthorizationExponent)
		case c < '0' || c > '9':
			return adminAuthorizationFieldErr(name, errAdminAuthorizationUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationLeadingZero)
	}
	if raw[0] == '0' {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationZeroTime)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return adminAuthorizationFieldErr(name, errAdminAuthorizationUintRange)
	}
	*dst = v
	return nil
}

// VerifyAdminRemoteUnlockAuthorization verifies a fresh per-request
// authorization a, signed by the delegated administrator device of the
// reusable grant d, for the request context c and the two device transport
// bindings.
//
// It runs, in exactly this order, and returns on the first failure:
//
//  1. nowUnixMS must be positive, a and c must be canonical-valid and both
//     bindings must validate. The failure reasons wrap
//     ErrInvalidAdminAuthorization; a binding's own error is additionally
//     wrapped unchanged.
//  2. a.ExpiresUnixMS must be strictly after nowUnixMS (the authorization is
//     expired at exactly its expiry instant) and must not be after
//     c.DeadlineUnixMS (an authorization may expire before the request does,
//     never after). The time is the caller's only clock.
//  3. a.ContextSHA256 must equal RemoteUnlockContextDigest(c) and
//     a.DelegationDigest must equal AdminDelegationDigest(d).
//  4. VerifyOwnerRootAdminRemoteUnlockDelegation(f, cp, d, nowUnixMS) must
//     succeed: the owner root that owns cp must have issued d, the
//     checkpoint must authenticate the current policy, that current policy
//     must be exactly d's anchor, and nowUnixMS must lie in
//     [d.NotBeforeUnixMS, d.ExpiresUnixMS). Its error is returned wrapped with
//     ErrInvalidAdminAuthorization.
//  5. a.ExpiresUnixMS must not be after d.ExpiresUnixMS.
//  6. The context must match the grant scope exactly: c.VaultID,
//     c.MemberID, c.SourceDeviceID, c.TargetDeviceID, c.PairGeneration,
//     c.KeyEpoch, c.PolicySeq and c.PolicyDigest must equal d's vault,
//     requester, source and target device, pair generation, key epoch, policy
//     sequence and policy digest.
//  7. In the authenticated current policy, the delegate device d must still
//     exist with d's principal, that principal must hold the admin (or, as
//     the vault file's role order also permits, owner) role, and the device's
//     non-nil Ed25519 policy signing key must equal exactly d's
//     DelegatePolicySigningKey. That exact key, and no content or owner root
//     key, is the only key this verifier accepts for a.Signature. Both
//     endpoint devices must resolve to the requester and carry an Ed25519
//     content signing key.
//  8. Each binding's recipient_public_key must equal its device's
//     authenticated policy age encryption key, and each binding must verify
//     with VerifyDeviceTransportBindingForContext under that device's
//     authenticated content signing key: source first, then target.
//  9. The complete-binding digest of the source, then of the target, must
//     equal both the matching authorization member and the matching digest
//     recorded in the grant.
//  10. a.Signature must verify under exactly d.DelegatePolicySigningKey over
//     AdminAuthorizationSigningBytes(a).
//
// The owner root is never contacted and never verifies a per-request object:
// only step 4 checks its one reusable signature over d.
//
// A nil return proves only that the reusable grant is currently valid and that
// its delegated admin or owner device signed this exact request context and
// these two signed bindings, within the authorization expiry, the request
// deadline and the grant interval. It does NOT prove the request digest
// preimage, TLS identity, the actual exporter value or handshake, or the live
// peer's SPKI; it is not part of a TLS, relay, VUK delivery or production
// identity flow; it is not proof that either device holds its private keys;
// and it provides no durable one-shot or replay defense: the same valid bytes
// verify again until they expire, before and after a restart. The caller's
// request lifecycle must prevent replay and one-shot use. vaultfile is only
// read: no role, policy, key or file byte is changed.
func VerifyAdminRemoteUnlockAuthorization(f *vaultfile.File, cp *vaultfile.PolicyCheckpoint, d OwnerRootAdminRemoteUnlockDelegation, a AdminRemoteUnlockAuthorization, c ChannelBindingContext, source, target DeviceTransportBinding, nowUnixMS int64) error {
	// 1. Caller clock and canonical inputs.
	if nowUnixMS <= 0 {
		return adminAuthorizationFieldErr("", errAdminAuthorizationNow)
	}
	if err := a.validate(); err != nil {
		return err
	}
	if _, err := EncodeAdminRemoteUnlockAuthorization(a); err != nil {
		return adminAuthorizationFieldErr("", errAdminAuthorizationNotCanonical)
	}
	if _, err := EncodeChannelBindingContext(c); err != nil {
		return adminAuthorizationFieldErr("", errAdminAuthorizationContextBad)
	}
	if _, err := EncodeDeviceTransportBinding(source); err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr("source_binding", errAdminAuthorizationSourceBindBad), err)
	}
	if _, err := EncodeDeviceTransportBinding(target); err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr("target_binding", errAdminAuthorizationTargetBindBad), err)
	}

	// 2. Expiry. Both bounds are strict on the now side.
	if nowUnixMS >= a.ExpiresUnixMS {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[7], errAdminAuthorizationExpired)
	}
	if a.ExpiresUnixMS > c.DeadlineUnixMS {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[7], errAdminAuthorizationPastDeadline)
	}

	// 3. Context and grant digests.
	contextDigest, err := RemoteUnlockContextDigest(c)
	if err != nil {
		return err
	}
	if contextDigest != a.ContextSHA256 {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[4], errAdminAuthorizationContextDigest)
	}
	delegationDigest, err := AdminDelegationDigest(d)
	if err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr(adminAuthorizationMembers[3], errAdminAuthorizationDelegationDig), err)
	}
	if delegationDigest != a.DelegationDigest {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[3], errAdminAuthorizationDelegationDig)
	}

	// 4. The reusable grant: owner root, credential, current-policy anchor and
	// [not_before, expires) interval.
	if err := VerifyOwnerRootAdminRemoteUnlockDelegation(f, cp, d, nowUnixMS); err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr("", errAdminAuthorizationGrantNotTrust), err)
	}

	// 5. The request authorization may never outlive the grant.
	if a.ExpiresUnixMS > d.ExpiresUnixMS {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[7], errAdminAuthorizationGrantExpired)
	}

	// 6. The context must be exactly in the grant's scope.
	switch {
	case c.VaultID != d.VaultID:
		return adminAuthorizationFieldErr("context.vault_id", errAdminAuthorizationVault)
	case c.MemberID != d.RequesterMemberID:
		return adminAuthorizationFieldErr("context.member_id", errAdminAuthorizationRequester)
	case c.SourceDeviceID != d.SourceDeviceID:
		return adminAuthorizationFieldErr("context.source_device_id", errAdminAuthorizationSourceDev)
	case c.TargetDeviceID != d.TargetDeviceID:
		return adminAuthorizationFieldErr("context.target_device_id", errAdminAuthorizationTargetDev)
	case c.PairGeneration != d.PairGeneration:
		return adminAuthorizationFieldErr("context.pair_generation", errAdminAuthorizationPairGen)
	case c.KeyEpoch != d.KeyEpoch:
		return adminAuthorizationFieldErr("context.key_epoch", errAdminAuthorizationKeyEpoch)
	case c.PolicySeq != d.PolicySeq:
		return adminAuthorizationFieldErr("context.policy_seq", errAdminAuthorizationPolicySeq)
	case c.PolicyDigest != d.PolicyDigest:
		return adminAuthorizationFieldErr("context.policy_digest", errAdminAuthorizationPolicyDigest)
	}

	// The checkpoint above authenticated this policy; only it is consulted.
	policy := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy

	// 7. The delegate's current device, principal, role and exact policy
	// signing key.
	delegate := policyDevice(policy, d.DelegateDeviceID)
	if delegate == nil || delegate.PrincipalID != d.DelegateMemberID {
		return adminAuthorizationFieldErr("policy.delegate_device_id", errAdminAuthorizationDelegate)
	}
	if !policyAdminQualified(d.DelegateMemberID, policy) {
		return adminAuthorizationFieldErr("policy.delegate_member_id", errAdminAuthorizationDelegateRole)
	}
	if delegate.PolicySigningKey == nil || delegate.PolicySigningKey.Alg != vaultfile.PolicySigAlgEd25519 ||
		len(delegate.PolicySigningKey.PublicKey) != AdminDelegationPublicKeySize ||
		!bytes.Equal(delegate.PolicySigningKey.PublicKey, d.DelegatePolicySigningKey[:]) {
		return adminAuthorizationFieldErr("policy.delegate_policy_signing_key", errAdminAuthorizationDelegateKey)
	}
	// Only this exact current-policy policy signing key is accepted for the
	// per-request signature; never a content signing key or the owner root.
	delegateKey := ed25519.PublicKey(delegate.PolicySigningKey.PublicKey)

	// 8. The requester's scoped endpoint devices and their current content
	// signing keys.
	srcDev := policyDevice(policy, d.SourceDeviceID)
	if srcDev == nil || srcDev.PrincipalID != d.RequesterMemberID {
		return adminAuthorizationFieldErr("policy.source_device_id", errAdminAuthorizationSourcePolicy)
	}
	if srcDev.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 || len(srcDev.ContentSigningKey.PublicKey) != ed25519.PublicKeySize {
		return adminAuthorizationFieldErr("policy.source_device_id", errAdminAuthorizationSourceKey)
	}
	tgtDev := policyDevice(policy, d.TargetDeviceID)
	if tgtDev == nil || tgtDev.PrincipalID != d.RequesterMemberID {
		return adminAuthorizationFieldErr("policy.target_device_id", errAdminAuthorizationTargetPolicy)
	}
	if tgtDev.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 || len(tgtDev.ContentSigningKey.PublicKey) != ed25519.PublicKeySize {
		return adminAuthorizationFieldErr("policy.target_device_id", errAdminAuthorizationTargetKey)
	}

	// 9. Recipients, then binding signatures, source then target.
	if srcDev.AgeEncryptionKey != source.RecipientPublicKey {
		return adminAuthorizationFieldErr("source_binding.recipient_public_key", errAdminAuthorizationSourceRecip)
	}
	if tgtDev.AgeEncryptionKey != target.RecipientPublicKey {
		return adminAuthorizationFieldErr("target_binding.recipient_public_key", errAdminAuthorizationTargetRecip)
	}
	if err := VerifyDeviceTransportBindingForContext(source, c, c.SourceDeviceID, ed25519.PublicKey(srcDev.ContentSigningKey.PublicKey)); err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr("source_binding", errAdminAuthorizationSourceBind), err)
	}
	if err := VerifyDeviceTransportBindingForContext(target, c, c.TargetDeviceID, ed25519.PublicKey(tgtDev.ContentSigningKey.PublicKey)); err != nil {
		return fmt.Errorf("%w: %w", adminAuthorizationFieldErr("target_binding", errAdminAuthorizationTargetBind), err)
	}

	// 10. The complete-binding digests, against the authorization and the
	// grant scope.
	srcDigest, err := DeviceTransportBindingDigest(source)
	if err != nil {
		return err
	}
	if srcDigest != a.SourceBindingSHA256 || srcDigest != d.SourceBindingSHA256 {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[5], errAdminAuthorizationSourceDigest)
	}
	tgtDigest, err := DeviceTransportBindingDigest(target)
	if err != nil {
		return err
	}
	if tgtDigest != a.TargetBindingSHA256 || tgtDigest != d.TargetBindingSHA256 {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[6], errAdminAuthorizationTargetDigest)
	}

	// 11. The delegated device's own signature, under exactly the grant's
	// policy signing key that step 7 re-proved in the current policy.
	msg, err := AdminAuthorizationSigningBytes(a)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegateKey, msg, a.Signature[:]) {
		return adminAuthorizationFieldErr(adminAuthorizationMembers[8], errAdminAuthorizationSignature)
	}
	return nil
}
