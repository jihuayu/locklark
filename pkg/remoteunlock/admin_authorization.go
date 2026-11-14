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

// Wire constants of the v1 canonical owner-root admin remote-unlock
// delegation.
const (
	// AdminDelegationFormat is the fixed value of the delegation's "format"
	// member. It equals Format.
	AdminDelegationFormat = Format
	// AdminDelegationVersion is the canonical JSON integer of the
	// delegation's "version" member. It equals Version.
	AdminDelegationVersion = Version
	// KindAdminDelegation is the fixed value of the delegation's "kind"
	// member.
	KindAdminDelegation = "owner-admin-delegation"
	// AdminDelegationSignatureDomain separates the delegation signature
	// preimage. The preimage is this domain followed by the canonical JSON of
	// members 1..19.
	AdminDelegationSignatureDomain = "locklark.remote-unlock/v1/admin-delegation\x00"
	// AdminDelegationDigestDomain separates the complete delegation digest
	// preimage. The preimage is this domain followed by the complete
	// canonical EncodeOwnerRootAdminRemoteUnlockDelegation bytes, signature
	// included.
	AdminDelegationDigestDomain = "locklark.remote-unlock/v1/admin-delegation-digest\x00"
	// MaxAdminDelegationSize is the maximum encoded or accepted delegation
	// size in bytes.
	MaxAdminDelegationSize = 2048
	// AdminDelegationPublicKeySize is the exact length of
	// delegate_policy_signing_key in bytes.
	AdminDelegationPublicKeySize = ed25519.PublicKeySize
	// AdminDelegationSignatureSize is the exact length of signature in bytes.
	AdminDelegationSignatureSize = ed25519.SignatureSize
)

// ErrInvalidAdminDelegation reports an admin remote-unlock delegation that
// cannot be encoded, parsed, digested or signed, or that fails verification.
var ErrInvalidAdminDelegation = errors.New("remoteunlock: invalid admin remote-unlock delegation")

// ErrInvalidAdminDelegationEncoding reports bytes that are not the canonical
// encoding of a valid admin remote-unlock delegation.
var ErrInvalidAdminDelegationEncoding = errors.New("remoteunlock: invalid admin remote-unlock delegation encoding")

// Admin-delegation rejection reasons. They wrap ErrInvalidAdminDelegation for
// values, digests and verification and ErrInvalidAdminDelegationEncoding for
// spellings. Messages are static and never embed a member value, an
// identifier, a key, a digest, a signature or a verification time.
var (
	errAdminDelegationEndpointEqual = fmt.Errorf("%w: source_device_id and target_device_id must differ", ErrInvalidAdminDelegation)
	errAdminDelegationKeyEpoch      = fmt.Errorf("%w: key_epoch must be greater than zero", ErrInvalidAdminDelegation)
	errAdminDelegationNotBefore     = fmt.Errorf("%w: not_before_unix_ms must be greater than zero", ErrInvalidAdminDelegation)
	errAdminDelegationExpires       = fmt.Errorf("%w: expires_unix_ms must be greater than not_before_unix_ms", ErrInvalidAdminDelegation)
	errAdminDelegationBudget        = fmt.Errorf("%w: encoding exceeds %d bytes", ErrInvalidAdminDelegation, MaxAdminDelegationSize)

	errAdminDelegationNow         = fmt.Errorf("%w: nowUnixMS must be greater than zero", ErrInvalidAdminDelegation)
	errAdminDelegationNotYetValid = fmt.Errorf("%w: delegation is not valid yet at nowUnixMS", ErrInvalidAdminDelegation)
	errAdminDelegationExpired     = fmt.Errorf("%w: delegation has expired at nowUnixMS", ErrInvalidAdminDelegation)
	errAdminDelegationVault       = fmt.Errorf("%w: header vault_id differs from the delegation", ErrInvalidAdminDelegation)
	errAdminDelegationKeyEpochNow = fmt.Errorf("%w: header key_epoch differs from the delegation", ErrInvalidAdminDelegation)
	errAdminDelegationPolicySeq   = fmt.Errorf("%w: header policy_seq differs from the delegation anchor", ErrInvalidAdminDelegation)
	errAdminDelegationPolicyDig   = fmt.Errorf("%w: header or current policy digest differs from the delegation anchor", ErrInvalidAdminDelegation)
	errAdminDelegationDelegate    = fmt.Errorf("%w: delegate_device_id does not resolve in the authenticated current policy", ErrInvalidAdminDelegation)
	errAdminDelegationPrincipal   = fmt.Errorf("%w: delegate device principal differs from delegate_member_id", ErrInvalidAdminDelegation)
	errAdminDelegationRole        = fmt.Errorf("%w: delegate principal currently holds neither the admin nor the owner role", ErrInvalidAdminDelegation)
	errAdminDelegationPolicyKey   = fmt.Errorf("%w: delegate device policy signing key is missing, not Ed25519 or differs from the delegation", ErrInvalidAdminDelegation)
	errAdminDelegationRequester   = fmt.Errorf("%w: requester_member_id is not a reader, writer, admin or owner of the authenticated policy", ErrInvalidAdminDelegation)
	errAdminDelegationSourceDev   = fmt.Errorf("%w: source_device_id does not resolve to the requester in the authenticated policy", ErrInvalidAdminDelegation)
	errAdminDelegationTargetDev   = fmt.Errorf("%w: target_device_id does not resolve to the requester in the authenticated policy", ErrInvalidAdminDelegation)
	errAdminDelegationRootPin     = fmt.Errorf("%w: owner_root_key_id or owner root pin differs from the authenticated owner root", ErrInvalidAdminDelegation)
	errAdminDelegationSignature   = fmt.Errorf("%w: owner-root Ed25519 signature does not verify", ErrInvalidAdminDelegation)

	// Encoding and parsing reasons. None of them embeds a value.
	errAdminDelegationNotObject   = fmt.Errorf("%w: not a single JSON object", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationMissing     = fmt.Errorf("%w: missing member", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationInvalidUTF8 = fmt.Errorf("%w: not valid UTF-8", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationString      = fmt.Errorf("%w: string is not canonical", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationWrongValue  = fmt.Errorf("%w: wrong constant, type or shape", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationDuplicate   = fmt.Errorf("%w: duplicate member", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationOutOfOrder  = fmt.Errorf("%w: member out of order", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationUnknown     = fmt.Errorf("%w: unknown member", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationTrailing    = fmt.Errorf("%w: trailing data", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationTooLarge    = fmt.Errorf("%w: input exceeds %d bytes", ErrInvalidAdminDelegationEncoding, MaxAdminDelegationSize)
	errAdminDelegationEmptyInput  = fmt.Errorf("%w: empty input", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationUintSyntax  = fmt.Errorf("%w: integer is not canonical unsigned decimal", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationLeadingZero = fmt.Errorf("%w: integer has a leading zero", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationFraction    = fmt.Errorf("%w: integer has a fraction", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationExponent    = fmt.Errorf("%w: integer has an exponent", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationUintRange   = fmt.Errorf("%w: integer overflows its unsigned/signed range", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationZeroEpoch   = fmt.Errorf("%w: key_epoch must be greater than zero", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationZeroTime    = fmt.Errorf("%w: timestamp must be greater than zero", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationInterval    = fmt.Errorf("%w: expires_unix_ms is not after not_before_unix_ms", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationDigestSize  = fmt.Errorf("%w: digest must be exactly %d bytes", ErrInvalidAdminDelegationEncoding, DigestSize)
	errAdminDelegationDigestForm  = fmt.Errorf("%w: digest is not strict unpadded base64url", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationKeySize     = fmt.Errorf("%w: delegate_policy_signing_key must be exactly %d bytes", ErrInvalidAdminDelegationEncoding, AdminDelegationPublicKeySize)
	errAdminDelegationKeyForm     = fmt.Errorf("%w: delegate_policy_signing_key is not strict unpadded base64url", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationSigSize     = fmt.Errorf("%w: signature must be exactly %d bytes", ErrInvalidAdminDelegationEncoding, AdminDelegationSignatureSize)
	errAdminDelegationSigForm     = fmt.Errorf("%w: signature is not strict unpadded base64url", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationReencode    = fmt.Errorf("%w: spelling is not byte-identical when re-encoded", ErrInvalidAdminDelegationEncoding)

	errAdminDelegationIDEmpty   = fmt.Errorf("%w: identifier must not be empty", ErrInvalidAdminDelegationEncoding)
	errAdminDelegationIDTooLong = fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidAdminDelegationEncoding, MaxIdentifierLen)
	errAdminDelegationIDChar    = fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidAdminDelegationEncoding)
)

// AdminDelegationFieldError identifies the delegation member that failed
// validation. The message never includes the member's value, an identifier, a
// key, a digest or a signature.
type AdminDelegationFieldError struct {
	Field string
	Err   error
}

// Error returns a static description naming only the member.
func (e *AdminDelegationFieldError) Error() string {
	if e.Field == "" {
		return "remoteunlock: admin remote-unlock delegation: " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
	}
	return "remoteunlock: admin remote-unlock delegation field " + e.Field + ": " + strings.TrimPrefix(e.Err.Error(), "remoteunlock: ")
}

// Unwrap returns the underlying reason.
func (e *AdminDelegationFieldError) Unwrap() error { return e.Err }

func adminDelegationFieldErr(field string, err error) error {
	return &AdminDelegationFieldError{Field: field, Err: err}
}

// adminDelegationMembers lists the delegation members in their exact required
// order. The first nineteen are the signed members.
var adminDelegationMembers = [...]string{
	"format",
	"version",
	"kind",
	"owner_root_key_id",
	"delegate_member_id",
	"delegate_device_id",
	"delegate_policy_signing_key",
	"vault_id",
	"requester_member_id",
	"source_device_id",
	"target_device_id",
	"source_binding_sha256",
	"target_binding_sha256",
	"pair_generation",
	"key_epoch",
	"policy_seq",
	"policy_digest",
	"not_before_unix_ms",
	"expires_unix_ms",
	"signature",
}

// OwnerRootAdminRemoteUnlockDelegation is the v1 reusable remote-unlock
// delegation from the vault owner root to one named current admin or owner
// device, for one named requester's two stable endpoints.
//
// It is not a per-request authorization. It carries no request identifier,
// request digest, lock generation or request deadline: the same grant may
// cover any number of unlock requests on the scoped source and target
// bindings until expires_unix_ms, provided the vault's current policy is
// still exactly the policy anchored by policy_seq and policy_digest. Any
// policy update, including removing, demoting or re-adding a device or
// principal, changes the policy digest and invalidates the grant; only a new
// owner-root-signed delegation for the new policy can replace it. There is no
// key epoch transition or scope re-derivation.
//
// The struct only carries claims. Encoding or parsing it proves none of them.
// VerifyOwnerRootAdminRemoteUnlockDelegation checks the scope against a
// caller-pinned owner root and a checkpoint-authenticated current policy and
// key interval; the bindings of any concrete request, and that request's own
// authorization, are separate and later checks. See the package
// documentation for the exact boundary. This type never mutates a role or a
// policy.
type OwnerRootAdminRemoteUnlockDelegation struct {
	// OwnerRootKeyID is the opaque owner-root key identifier that must equal
	// the key identifier of the caller-pinned root.
	OwnerRootKeyID string
	// DelegateMemberID is the opaque identifier of the delegated principal.
	DelegateMemberID string
	// DelegateDeviceID is the opaque identifier of the delegated current
	// device.
	DelegateDeviceID string
	// DelegatePolicySigningKey is the exact Ed25519 public key of the
	// delegated device's distinct policy signing key. It must equal the
	// PolicySigningKey recorded for that device in the authenticated current
	// policy.
	DelegatePolicySigningKey [AdminDelegationPublicKeySize]byte
	// VaultID is the opaque vault identifier.
	VaultID string
	// RequesterMemberID is the opaque identifier of the member whose unlock
	// requests the delegation covers. That principal must hold an existing
	// read role in the authenticated current policy.
	RequesterMemberID string
	// SourceDeviceID is the opaque identifier of the requesting device.
	SourceDeviceID string
	// TargetDeviceID is the opaque identifier of the unlocking device; it
	// must differ from SourceDeviceID.
	TargetDeviceID string
	// SourceBindingSHA256 is DeviceTransportBindingDigest of the exact
	// source device binding the delegation covers.
	SourceBindingSHA256 [DigestSize]byte
	// TargetBindingSHA256 is DeviceTransportBindingDigest of the exact
	// target device binding the delegation covers.
	TargetBindingSHA256 [DigestSize]byte
	// PairGeneration is the pairing generation; zero is an explicit genesis
	// value.
	PairGeneration uint64
	// KeyEpoch is the vault key epoch; it must be greater than zero.
	KeyEpoch uint64
	// PolicySeq is the policy sequence of the authenticated current policy
	// the delegation was issued against.
	PolicySeq uint64
	// PolicyDigest is the 32-byte vaultfile.PolicyDigest of that exact
	// current policy.
	PolicyDigest [DigestSize]byte
	// NotBeforeUnixMS is the absolute start of the validity interval in Unix
	// milliseconds. It must be strictly positive and is used exactly as
	// supplied: the codec never reads the clock or adjusts it.
	NotBeforeUnixMS int64
	// ExpiresUnixMS is the absolute exclusive end of the validity interval
	// in Unix milliseconds. It must be strictly after NotBeforeUnixMS.
	ExpiresUnixMS int64
	// Signature is the owner root's Ed25519 signature over
	// AdminDelegationSigningBytes.
	Signature [AdminDelegationSignatureSize]byte
}

// AdminDelegationSigningBytes returns the exact bytes the owner root signs:
// AdminDelegationSignatureDomain followed by the canonical JSON of members
// 1..19, in schema order. It accepts the same values as
// EncodeOwnerRootAdminRemoteUnlockDelegation and ignores Signature.
//
// The returned bytes are public and contain no key material. The owner root
// signs them with its protected Ed25519 key; this package neither stores
// private keys nor signs.
func AdminDelegationSigningBytes(d OwnerRootAdminRemoteUnlockDelegation) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(AdminDelegationSignatureDomain)+1024)
	preimage = append(preimage, AdminDelegationSignatureDomain...)
	return appendAdminDelegationMembers(preimage, d), nil
}

// AdminDelegationDigest returns the SHA-256 of AdminDelegationDigestDomain
// followed by the complete canonical encoding of d, signature member included,
// so any change to a claim or to the signature changes the digest.
//
// The digest is a reference for a later signed request, not a signature and
// not an authorization. An invalid delegation returns an error wrapping
// ErrInvalidAdminDelegation.
func AdminDelegationDigest(d OwnerRootAdminRemoteUnlockDelegation) ([DigestSize]byte, error) {
	var out [DigestSize]byte
	canonical, err := EncodeOwnerRootAdminRemoteUnlockDelegation(d)
	if err != nil {
		return out, err
	}
	out = sha256.Sum256(append([]byte(AdminDelegationDigestDomain), canonical...))
	return out, nil
}

// appendAdminDelegationMembers appends the canonical JSON object of the
// signed members (every member except "signature") to buf and returns buf.
func appendAdminDelegationMembers(buf []byte, d OwnerRootAdminRemoteUnlockDelegation) []byte {
	m := &adminDelegationMembers
	buf = append(buf, '{')
	buf = appendStringMember(buf, m[0], AdminDelegationFormat)
	buf = appendUintMember(buf, m[1], AdminDelegationVersion)
	buf = appendStringMember(buf, m[2], KindAdminDelegation)
	buf = appendStringMember(buf, m[3], d.OwnerRootKeyID)
	buf = appendStringMember(buf, m[4], d.DelegateMemberID)
	buf = appendStringMember(buf, m[5], d.DelegateDeviceID)
	buf = appendPublicKeyMember(buf, m[6], d.DelegatePolicySigningKey)
	buf = appendStringMember(buf, m[7], d.VaultID)
	buf = appendStringMember(buf, m[8], d.RequesterMemberID)
	buf = appendStringMember(buf, m[9], d.SourceDeviceID)
	buf = appendStringMember(buf, m[10], d.TargetDeviceID)
	buf = appendDigestMember(buf, m[11], d.SourceBindingSHA256)
	buf = appendDigestMember(buf, m[12], d.TargetBindingSHA256)
	buf = appendUintMember(buf, m[13], d.PairGeneration)
	buf = appendUintMember(buf, m[14], d.KeyEpoch)
	buf = appendUintMember(buf, m[15], d.PolicySeq)
	buf = appendDigestMember(buf, m[16], d.PolicyDigest)
	buf = appendIntMember(buf, m[17], d.NotBeforeUnixMS)
	buf = appendIntMember(buf, m[18], d.ExpiresUnixMS)
	buf[len(buf)-1] = '}'
	return buf
}

func appendPublicKeyMember(buf []byte, name string, k [AdminDelegationPublicKeySize]byte) []byte {
	buf = appendMemberName(buf, name)
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, k[:])
	return append(buf, '"', ',')
}

// EncodeOwnerRootAdminRemoteUnlockDelegation validates d and returns its
// canonical v1 JSON encoding, which is never longer than
// MaxAdminDelegationSize bytes.
func EncodeOwnerRootAdminRemoteUnlockDelegation(d OwnerRootAdminRemoteUnlockDelegation) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1200)
	buf = appendAdminDelegationMembers(buf, d)
	buf[len(buf)-1] = ','
	buf = appendMemberName(buf, adminDelegationMembers[19])
	buf = append(buf, '"')
	buf = base64.RawURLEncoding.AppendEncode(buf, d.Signature[:])
	buf = append(buf, '"', '}')
	if len(buf) > MaxAdminDelegationSize {
		return nil, adminDelegationFieldErr("", errAdminDelegationBudget)
	}
	return buf, nil
}

// validate checks every field independently of its JSON spelling.
func (d OwnerRootAdminRemoteUnlockDelegation) validate() error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{adminDelegationMembers[3], d.OwnerRootKeyID},
		{adminDelegationMembers[4], d.DelegateMemberID},
		{adminDelegationMembers[5], d.DelegateDeviceID},
		{adminDelegationMembers[7], d.VaultID},
		{adminDelegationMembers[8], d.RequesterMemberID},
		{adminDelegationMembers[9], d.SourceDeviceID},
		{adminDelegationMembers[10], d.TargetDeviceID},
	} {
		if err := validateIdentifier(f.value); err != nil {
			return adminDelegationFieldErr(f.name, errAdminDelegationIdentifier(err))
		}
	}
	if d.SourceDeviceID == d.TargetDeviceID {
		return adminDelegationFieldErr(adminDelegationMembers[10], errAdminDelegationEndpointEqual)
	}
	if d.KeyEpoch == 0 {
		return adminDelegationFieldErr(adminDelegationMembers[14], errAdminDelegationKeyEpoch)
	}
	if d.NotBeforeUnixMS <= 0 {
		return adminDelegationFieldErr(adminDelegationMembers[17], errAdminDelegationNotBefore)
	}
	if d.ExpiresUnixMS <= d.NotBeforeUnixMS {
		return adminDelegationFieldErr(adminDelegationMembers[18], errAdminDelegationExpires)
	}
	return nil
}

// errAdminDelegationIdentifier maps a shared identifier-grammar failure to a
// static delegation reason wrapping ErrInvalidAdminDelegation.
func errAdminDelegationIdentifier(err error) error {
	switch {
	case errors.Is(err, errEmpty):
		return fmt.Errorf("%w: identifier must not be empty", ErrInvalidAdminDelegation)
	case errors.Is(err, errTooLong):
		return fmt.Errorf("%w: identifier exceeds %d bytes", ErrInvalidAdminDelegation, MaxIdentifierLen)
	default:
		return fmt.Errorf("%w: identifier contains a byte outside the identifier grammar", ErrInvalidAdminDelegation)
	}
}

// MarshalJSON returns the canonical encoding, or an error for an invalid
// delegation. It never falls back to the struct field order.
func (d OwnerRootAdminRemoteUnlockDelegation) MarshalJSON() ([]byte, error) {
	return EncodeOwnerRootAdminRemoteUnlockDelegation(d)
}

// UnmarshalJSON replaces d only when data is exactly the canonical encoding of
// a valid delegation.
func (d *OwnerRootAdminRemoteUnlockDelegation) UnmarshalJSON(data []byte) error {
	if d == nil {
		return adminDelegationFieldErr("", errAdminDelegationEmptyInput)
	}
	parsed, err := ParseOwnerRootAdminRemoteUnlockDelegation(data)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// ParseOwnerRootAdminRemoteUnlockDelegation parses b, which must be exactly
// the canonical v1 encoding of a valid delegation. Every other spelling
// (unknown, missing, duplicate or reordered members, non-canonical strings,
// integers or base64url, trailing data) is rejected with an error wrapping
// ErrInvalidAdminDelegationEncoding, as is input larger than
// MaxAdminDelegationSize. Errors never contain member values, identifiers,
// keys or signatures.
func ParseOwnerRootAdminRemoteUnlockDelegation(b []byte) (OwnerRootAdminRemoteUnlockDelegation, error) {
	var out OwnerRootAdminRemoteUnlockDelegation
	if len(b) > MaxAdminDelegationSize {
		return out, adminDelegationFieldErr("", errAdminDelegationTooLarge)
	}
	if len(b) == 0 {
		return out, adminDelegationFieldErr("", errAdminDelegationEmptyInput)
	}
	if !utf8.Valid(b) {
		return out, adminDelegationFieldErr("", errAdminDelegationInvalidUTF8)
	}
	p := parser{buf: b}
	if err := p.adminDelegationExpect('{', errAdminDelegationNotObject); err != nil {
		return out, err
	}
	for i, want := range adminDelegationMembers {
		if i > 0 {
			if err := p.adminDelegationSeparator(',', want); err != nil {
				return out, err
			}
		}
		key, err := p.string()
		if err != nil {
			// The key's position is reported as the expected member: this is
			// a static schema name, never an attacker-controlled byte.
			return out, adminDelegationFieldErr(want, errAdminDelegationString)
		}
		if err := p.adminDelegationSeparator(':', want); err != nil {
			return out, err
		}
		for j := 0; j < i; j++ {
			if key == adminDelegationMembers[j] {
				return out, adminDelegationFieldErr(key, errAdminDelegationDuplicate)
			}
		}
		if key != want {
			if j := adminDelegationMemberIndex(key); j >= 0 {
				if j > i {
					return out, adminDelegationFieldErr(want, errAdminDelegationMissing)
				}
				return out, adminDelegationFieldErr(key, errAdminDelegationOutOfOrder)
			}
			// Unknown keys are attacker-controlled; do not echo them.
			return out, adminDelegationFieldErr("", errAdminDelegationUnknown)
		}
		if err := p.adminDelegationMember(i, &out); err != nil {
			return out, err
		}
	}
	if p.pos < len(p.buf) && p.buf[p.pos] != '}' {
		// The object must close here: a member name means the final member
		// was omitted.
		if _, err := p.peekString(); err == nil {
			return out, adminDelegationFieldErr(adminDelegationMembers[len(adminDelegationMembers)-1], errAdminDelegationMissing)
		}
		return out, adminDelegationFieldErr("", errAdminDelegationTrailing)
	}
	if err := p.adminDelegationExpect('}', errAdminDelegationMissing); err != nil {
		return out, err
	}
	if p.pos != len(p.buf) {
		return out, adminDelegationFieldErr("", errAdminDelegationTrailing)
	}
	// Every spelling that parses must re-encode to the identical bytes.
	reencoded, err := EncodeOwnerRootAdminRemoteUnlockDelegation(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return OwnerRootAdminRemoteUnlockDelegation{}, adminDelegationFieldErr("", errAdminDelegationReencode)
	}
	return out, nil
}

// adminDelegationExpect consumes the literal byte want with delegation errors,
// so a structural failure never reports another structure's field error.
func (p *parser) adminDelegationExpect(want byte, eof error) error {
	if p.pos >= len(p.buf) {
		return adminDelegationFieldErr("", eof)
	}
	if p.buf[p.pos] != want {
		if want == ',' || want == ':' {
			return adminDelegationFieldErr("", errAdminDelegationMissing)
		}
		return adminDelegationFieldErr("", errAdminDelegationWrongValue)
	}
	p.pos++
	return nil
}

// adminDelegationSeparator consumes the separator want (a comma or colon)
// before member expected, naming the omitted or misplaced schema member. The
// reported names are schema constants only, never attacker-controlled bytes.
func (p *parser) adminDelegationSeparator(want byte, expected string) error {
	if p.pos >= len(p.buf) {
		return adminDelegationFieldErr(expected, errAdminDelegationMissing)
	}
	if p.buf[p.pos] != want {
		if want == ',' {
			if key, err := p.peekString(); err == nil && adminDelegationMemberIndex(key) >= 0 {
				return adminDelegationFieldErr(key, errAdminDelegationMissing)
			}
		}
		return adminDelegationFieldErr(expected, errAdminDelegationMissing)
	}
	p.pos++
	return nil
}

func adminDelegationMemberIndex(key string) int {
	for i, m := range adminDelegationMembers {
		if m == key {
			return i
		}
	}
	return -1
}

// adminDelegationMember parses the value of adminDelegationMembers[i] into d.
func (p *parser) adminDelegationMember(i int, d *OwnerRootAdminRemoteUnlockDelegation) error {
	name := adminDelegationMembers[i]
	switch i {
	case 0:
		return p.adminDelegationConstant(name, AdminDelegationFormat)
	case 1:
		v, err := p.number()
		if err != nil || v != "1" {
			return adminDelegationFieldErr(name, errAdminDelegationWrongValue)
		}
		return nil
	case 2:
		return p.adminDelegationConstant(name, KindAdminDelegation)
	case 3:
		return p.adminDelegationIdentifier(name, &d.OwnerRootKeyID)
	case 4:
		return p.adminDelegationIdentifier(name, &d.DelegateMemberID)
	case 5:
		return p.adminDelegationIdentifier(name, &d.DelegateDeviceID)
	case 6:
		return p.adminDelegationPublicKey(name, &d.DelegatePolicySigningKey)
	case 7:
		return p.adminDelegationIdentifier(name, &d.VaultID)
	case 8:
		return p.adminDelegationIdentifier(name, &d.RequesterMemberID)
	case 9:
		return p.adminDelegationIdentifier(name, &d.SourceDeviceID)
	case 10:
		return p.adminDelegationIdentifier(name, &d.TargetDeviceID)
	case 11:
		return decodeAdminDelegationBytes(p, name, d.SourceBindingSHA256[:], errAdminDelegationDigestSize, errAdminDelegationDigestForm)
	case 12:
		return decodeAdminDelegationBytes(p, name, d.TargetBindingSHA256[:], errAdminDelegationDigestSize, errAdminDelegationDigestForm)
	case 13:
		return p.adminDelegationUint(name, &d.PairGeneration)
	case 14:
		if err := p.adminDelegationUint(name, &d.KeyEpoch); err != nil {
			return err
		}
		if d.KeyEpoch == 0 {
			return adminDelegationFieldErr(name, errAdminDelegationZeroEpoch)
		}
		return nil
	case 15:
		return p.adminDelegationUint(name, &d.PolicySeq)
	case 16:
		return decodeAdminDelegationBytes(p, name, d.PolicyDigest[:], errAdminDelegationDigestSize, errAdminDelegationDigestForm)
	case 17:
		return p.adminDelegationTime(name, &d.NotBeforeUnixMS)
	case 18:
		if err := p.adminDelegationTime(name, &d.ExpiresUnixMS); err != nil {
			return err
		}
		if d.ExpiresUnixMS <= d.NotBeforeUnixMS {
			return adminDelegationFieldErr(name, errAdminDelegationInterval)
		}
		return nil
	case 19:
		return decodeAdminDelegationBytes(p, name, d.Signature[:], errAdminDelegationSigSize, errAdminDelegationSigForm)
	}
	return adminDelegationFieldErr(name, errAdminDelegationUnknown)
}

func (p *parser) adminDelegationConstant(name, want string) error {
	v, err := p.string()
	if err != nil {
		return adminDelegationFieldErr(name, errAdminDelegationString)
	}
	if v != want {
		return adminDelegationFieldErr(name, errAdminDelegationWrongValue)
	}
	return nil
}

func (p *parser) adminDelegationIdentifier(name string, dst *string) error {
	v, err := p.string()
	if err != nil {
		return adminDelegationFieldErr(name, errAdminDelegationString)
	}
	if err := validateIdentifier(v); err != nil {
		switch {
		case errors.Is(err, errEmpty):
			return adminDelegationFieldErr(name, errAdminDelegationIDEmpty)
		case errors.Is(err, errTooLong):
			return adminDelegationFieldErr(name, errAdminDelegationIDTooLong)
		default:
			return adminDelegationFieldErr(name, errAdminDelegationIDChar)
		}
	}
	*dst = v
	return nil
}

func (p *parser) adminDelegationPublicKey(name string, dst *[AdminDelegationPublicKeySize]byte) error {
	return decodeAdminDelegationBytes(p, name, dst[:], errAdminDelegationKeySize, errAdminDelegationKeyForm)
}

// decodeAdminDelegationBytes parses a strict unpadded base64url string decoding
// to exactly len(dst) bytes, using the given reasons for a wrong size or
// spelling.
func decodeAdminDelegationBytes(p *parser, name string, dst []byte, sizeErr, formErr error) error {
	v, err := p.string()
	if err != nil {
		return adminDelegationFieldErr(name, errAdminDelegationString)
	}
	if len(v) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return adminDelegationFieldErr(name, sizeErr)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(dst, []byte(v))
	if err != nil || n != len(dst) || base64.RawURLEncoding.EncodeToString(dst) != v {
		return adminDelegationFieldErr(name, formErr)
	}
	return nil
}

// adminDelegationUint parses a canonical unsigned decimal uint64.
func (p *parser) adminDelegationUint(name string, dst *uint64) error {
	raw, err := p.adminDelegationDigits(name)
	if err != nil {
		return err
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return adminDelegationFieldErr(name, errAdminDelegationUintRange)
	}
	*dst = v
	return nil
}

// adminDelegationTime parses a canonical positive decimal int64 in Unix
// milliseconds.
func (p *parser) adminDelegationTime(name string, dst *int64) error {
	raw, err := p.adminDelegationDigits(name)
	if err != nil {
		return err
	}
	if raw == "0" {
		return adminDelegationFieldErr(name, errAdminDelegationZeroTime)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return adminDelegationFieldErr(name, errAdminDelegationUintRange)
	}
	*dst = v
	return nil
}

// adminDelegationDigits scans one canonical unsigned decimal integer token:
// digits only, no leading zero except "0", no fraction or exponent.
func (p *parser) adminDelegationDigits(name string) (string, error) {
	raw, err := p.number()
	if err != nil {
		return "", adminDelegationFieldErr(name, errAdminDelegationUintSyntax)
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '-' || c == '+':
			return "", adminDelegationFieldErr(name, errAdminDelegationUintSyntax)
		case c == '.':
			return "", adminDelegationFieldErr(name, errAdminDelegationFraction)
		case c == 'e' || c == 'E':
			return "", adminDelegationFieldErr(name, errAdminDelegationExponent)
		case c < '0' || c > '9':
			return "", adminDelegationFieldErr(name, errAdminDelegationUintSyntax)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return "", adminDelegationFieldErr(name, errAdminDelegationLeadingZero)
	}
	return raw, nil
}

// VerifyOwnerRootAdminRemoteUnlockDelegation verifies that the owner root that
// owns cp signed this reusable delegation to the named current admin or owner
// device for the named requester's two stable endpoints, and that it is still
// valid at nowUnixMS under the checkpoint-authenticated current policy.
//
// It runs, in exactly this order, and returns on the first failure:
//
//  1. nowUnixMS must be positive and d must be canonical-valid, including a
//     key epoch above zero, a distinct source and target and
//     NotBeforeUnixMS < ExpiresUnixMS. The time is the caller's only clock and
//     refers to a value d already carries.
//  2. nowUnixMS must be at or after d.NotBeforeUnixMS and strictly before
//     d.ExpiresUnixMS. The interval is inclusive at its start and exclusive at
//     its end.
//  3. vaultfile.VerifyPolicyCheckpoint(f, cp) must succeed before any policy
//     claim is trusted. Its error is returned wrapped with
//     ErrInvalidAdminDelegation.
//  4. The authenticated current policy is exactly the delegation's anchor:
//     f.Header.VaultID, KeyEpoch, PolicySeq and PolicyDigest equal d, and
//     vaultfile.PolicyDigest of the last carried proof equals both. Any other
//     policy, including one at a later sequence, invalidates the delegation.
//  5. d.OwnerRootKeyID equals cp.OwnerRootKeyID and the authenticated policy
//     root key ID and algorithm; d.VaultID equals the header and policy vault.
//  6. The delegate device resolves in the authenticated current policy, its
//     principal equals d.DelegateMemberID, that principal holds the admin or
//     the owner role there, and the device carries a non-nil Ed25519 policy
//     signing key whose bytes exactly equal d.DelegatePolicySigningKey.
//  7. d.RequesterMemberID holds an existing read role (a reader, writer, admin
//     or owner, by the vault file's role order), and both SourceDeviceID and
//     TargetDeviceID resolve in the authenticated policy and belong to that
//     requester.
//  8. The delegation signature verifies under exactly cp.OwnerRootPublicKey
//     over AdminDelegationSigningBytes.
//
// Only the authenticated current policy is ever consulted, and since the
// policy anchor must match exactly, a later policy can never revive a
// removed, demoted or re-added delegate or endpoint. No role is asserted by
// the caller, read from an old proof or changed here.
//
// A nil return proves only that the pinned owner root issued this reusable
// scope for this current policy and this time interval, and that the current
// policy still lists the delegate and requester as required. It does NOT
// authorize any request: the source and target bindings are verified, against
// their recipient keys and the policy content signing keys, only by a later
// per-request authorization, which must also match both binding digests and
// the pair generation. It does not prove the request digest, the actual TLS
// channel or exporter value, the SPKI of a live peer, that any device holds
// its private keys, durable one-shot or restart safety, or any VUK decryption
// or delivery.
func VerifyOwnerRootAdminRemoteUnlockDelegation(f *vaultfile.File, cp *vaultfile.PolicyCheckpoint, d OwnerRootAdminRemoteUnlockDelegation, nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return adminDelegationFieldErr("", errAdminDelegationNow)
	}
	if err := d.validate(); err != nil {
		return err
	}

	// 2. Validity interval: start inclusive, end exclusive.
	if nowUnixMS < d.NotBeforeUnixMS {
		return adminDelegationFieldErr(adminDelegationMembers[17], errAdminDelegationNotYetValid)
	}
	if nowUnixMS >= d.ExpiresUnixMS {
		return adminDelegationFieldErr(adminDelegationMembers[18], errAdminDelegationExpired)
	}

	// 3. The carried policy is untrusted until the caller's checkpoint
	// authenticates its continuation and content signature.
	if err := vaultfile.VerifyPolicyCheckpoint(f, cp); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAdminDelegation, err)
	}
	policy := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy

	// 4. The current policy must be exactly the delegation's anchor.
	switch {
	case f.Header.VaultID != d.VaultID || policy.VaultID != d.VaultID:
		return adminDelegationFieldErr(adminDelegationMembers[7], errAdminDelegationVault)
	case f.Header.KeyEpoch != d.KeyEpoch:
		return adminDelegationFieldErr(adminDelegationMembers[14], errAdminDelegationKeyEpochNow)
	case f.Header.PolicySeq != d.PolicySeq || policy.PolicySeq != d.PolicySeq:
		return adminDelegationFieldErr(adminDelegationMembers[15], errAdminDelegationPolicySeq)
	}
	policyDigest := vaultfile.PolicyDigest(policy)
	if !bytes.Equal(policyDigest, d.PolicyDigest[:]) || !bytes.Equal(f.Header.PolicyDigest, d.PolicyDigest[:]) {
		return adminDelegationFieldErr(adminDelegationMembers[16], errAdminDelegationPolicyDig)
	}

	// 5. The owner root pin against the authenticated policy.
	if d.OwnerRootKeyID != cp.OwnerRootKeyID || cp.OwnerRootKeyID != policy.OwnerRoot.KeyID ||
		policy.OwnerRoot.Alg != vaultfile.PolicySigAlgEd25519 ||
		!bytes.Equal(cp.OwnerRootPublicKey, policy.OwnerRoot.PublicKey) ||
		len(cp.OwnerRootPublicKey) != ed25519.PublicKeySize {
		return adminDelegationFieldErr(adminDelegationMembers[3], errAdminDelegationRootPin)
	}

	// 6. The delegated current admin or owner device and its exact policy
	// signing key.
	delegate := policyDevice(policy, d.DelegateDeviceID)
	if delegate == nil {
		return adminDelegationFieldErr(adminDelegationMembers[5], errAdminDelegationDelegate)
	}
	if delegate.PrincipalID != d.DelegateMemberID {
		return adminDelegationFieldErr(adminDelegationMembers[4], errAdminDelegationPrincipal)
	}
	if !policyAdminQualified(delegate.PrincipalID, policy) {
		return adminDelegationFieldErr(adminDelegationMembers[4], errAdminDelegationRole)
	}
	if delegate.PolicySigningKey == nil || delegate.PolicySigningKey.Alg != vaultfile.PolicySigAlgEd25519 ||
		len(delegate.PolicySigningKey.PublicKey) != AdminDelegationPublicKeySize ||
		!bytes.Equal(delegate.PolicySigningKey.PublicKey, d.DelegatePolicySigningKey[:]) {
		return adminDelegationFieldErr(adminDelegationMembers[6], errAdminDelegationPolicyKey)
	}

	// 7. The requester's read qualification and its two scoped devices.
	if !policyReadQualified(d.RequesterMemberID, policy) {
		return adminDelegationFieldErr(adminDelegationMembers[8], errAdminDelegationRequester)
	}
	if src := policyDevice(policy, d.SourceDeviceID); src == nil || src.PrincipalID != d.RequesterMemberID {
		return adminDelegationFieldErr(adminDelegationMembers[9], errAdminDelegationSourceDev)
	}
	if tgt := policyDevice(policy, d.TargetDeviceID); tgt == nil || tgt.PrincipalID != d.RequesterMemberID {
		return adminDelegationFieldErr(adminDelegationMembers[10], errAdminDelegationTargetDev)
	}

	// 8. The owner root signature over members 1..19.
	msg, err := AdminDelegationSigningBytes(d)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(cp.OwnerRootPublicKey), msg, d.Signature[:]) {
		return adminDelegationFieldErr(adminDelegationMembers[19], errAdminDelegationSignature)
	}
	return nil
}

// policyAdminQualified reports whether principalID is listed with the admin or
// the owner role of p, by the vault file's role order where an owner also
// administers. Each of the two role arrays is checked on its own with no
// normalization, inheritance synthesis or mutation. A reader- or writer-only
// principal is rejected; nothing is promoted.
func policyAdminQualified(principalID string, p *vaultfile.Policy) bool {
	for _, role := range [2][]vaultfile.Member{p.Admins, p.Owners} {
		for i := range role {
			if role[i].PrincipalID == principalID {
				return true
			}
		}
	}
	return false
}
