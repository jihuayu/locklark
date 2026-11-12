// Package vaultcreationauth defines the locklark.vault-creation/v1 identity
// proof: the canonical codec and signing preimage for the proof a creator
// device presents when asking a backend to create a new vault. It also defines
// CreationPlanDigest, the canonical digest of the creation plan a proof may
// carry as its creation_plan_sha256.
//
// Encode, SigningBytes and Parse are a codec: they validate shapes and
// canonical spelling and build the exact bytes a signer signs. Verify checks
// one proof against a caller-supplied expected context, a registered Ed25519
// identity key and the caller's clock.
//
// Verify verifies only the identity proof. It treats the expected plan digest
// as opaque: it compares the proof's creation_plan_sha256 with the expected
// one byte for byte and authenticates those bytes with the identity signature,
// but it never recomputes the digest and never establishes what the digest
// describes. CreationPlanDigest, defined in this package, is the only
// derivation offered here, and Verify does not call it. Verify does not check
// root authorization or content signatures, persist or consume a challenge or
// enforce single use, and it does no HTTP. A caller with a valid Verify result
// still has to run those steps itself before approving a vault creation.
//
// # Proof
//
// One proof is a context and a signature over that context:
//
//	{
//	  "format":"locklark.vault-creation/v1",
//	  "version":1,
//	  "kind":"identity-proof",
//	  "context":{
//	    "scope":{"tenant_id":…,"user_id":…,"device_id":…},
//	    "challenge":{"id":…,"nonce":…,"deadline_unix_ms":…},
//	    "creation_plan_sha256":…
//	  },
//	  "signature":…
//	}
//
// Encode is the only canonical writer. Members appear in exactly that order,
// without whitespace, with binary values as unpadded base64url. Parse accepts
// only bytes that Encode reproduces byte for byte, so there is no second
// spelling: whitespace, another member order, escapes, duplicate or unknown
// members and non-canonical base64url are all refused.
//
// TenantID, UserID, DeviceID and Challenge.ID are opaque identifiers of at
// most MaxIDBytes printable ASCII bytes. They are compared bytewise and
// case-sensitively, never normalized, and never interpreted by this package.
//
// # Signing preimage
//
// A signer signs exactly SigningBytes(c). A verifier must check the signature
// against exactly the SigningBytes of the context it built itself, and must
// not sign or trust preimage bytes supplied by a peer. The preimage is
//
//	SigningDomain = "locklark.vault-creation/v1/identity-proof"
//	SigningBytes(c) = SigningDomain || 0x00 || canonicalContextJSON(c)
//
// where canonicalContextJSON is exactly the proof's "context" member: scope,
// challenge and creation_plan_sha256 in that order, and inside scope tenant_id,
// user_id, device_id and inside challenge id, nonce, deadline_unix_ms. The
// context appears identically in the proof and in the preimage.
//
// # Plan digest
//
// Context.PlanDigest (creation_plan_sha256) is a 32-byte value. Verify treats
// it as opaque: it compares it with the expected digest byte for byte and, as
// part of the signed context, the identity signature authenticates those
// bytes. That says the identity signed a context naming those bytes; it says
// nothing about what the bytes describe. Verify never recomputes them from a
// plan.
//
// CreationPlanDigest computes the canonical digest of a CreationPlan instead:
//
//	SHA-256( CreationPlanDomain || 0x00 ||
//	  u32be(len(GenesisBytes)) || GenesisBytes ||
//	  u32be(len(VaultID)) || VaultID ||
//	  u32be(len(OwnerRootKeyID)) || OwnerRootKeyID ||
//	  OwnerRootPublicKey[32] ||
//	  PolicySeq[8] ||              (uint64, big-endian)
//	  PolicyDigest[32] ||
//	  u32be(len(BackendLocator)) || BackendLocator ||
//	  u32be(len(Slug)) || Slug ||
//	  u32be(len(Name)) || Name )
//
// where CreationPlanDomain is "locklark.vault-creation-plan/v1". GenesisBytes
// is hashed as the exact bytes supplied, never parsed or re-encoded. Nothing
// is concatenated into a full preimage: the hash is fed field by field. Only
// fresh vaults are digested: PolicySeq must be zero.
//
// A caller approves a vault creation only after deriving its own expected
// plan digest, passing it to Verify as expected.PlanDigest (which requires it
// to equal the proof's) and deriving the rest of expected from its own
// database, session and immutable challenge state. The future server must
// derive the raw genesis bytes, the complete root pin, the backend locator
// and the slug and name from its own durable database, session, backend
// configuration and immutable creation plan, never from the proof. The proof
// only carries the digest, and it carries nothing the digest covers, so a
// proof value is never a source for any plan field.
//
// The digest binds the exact bytes of one CreationPlan; it does not prove
// that BackendLocator resolves to actual storage, that the genesis bytes are a
// well-formed vault file, or that the caller approved creating the vault.
package vaultcreationauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Wire constants fixed by this schema. They are part of the protocol.
const (
	// Format is the proof's "format" member.
	Format = "locklark.vault-creation/v1"
	// Version is the proof's "version" member.
	Version = 1
	// Kind is the proof's "kind" member.
	Kind = "identity-proof"

	// SigningDomain prefixes every signing preimage. It is domain separation
	// only: it is never a SHA-256 domain label and is never hashed by this
	// package. The 0x00 that follows it is not a part of this string.
	SigningDomain = "locklark.vault-creation/v1/identity-proof"

	// SignatureAlgorithm names the algorithm of the 64-byte signature this
	// schema carries (Ed25519). It is not a wire member; it documents the
	// one signature shape the codec accepts.
	SignatureAlgorithm = "Ed25519"
)

// Size and shape budgets fixed by this schema. Each is checked before the
// value it bounds is accepted.
const (
	// MaxProofBytes is the maximum encoded size of one proof.
	MaxProofBytes = 2048
	// MaxIDBytes is the maximum length in bytes of every identifier.
	MaxIDBytes = 128
	// NonceBytes is the exact decoded length of Challenge.Nonce.
	NonceBytes = 32
	// PlanDigestBytes is the exact decoded length of Context.PlanDigest.
	PlanDigestBytes = 32
	// SignatureBytes is the exact decoded length of Proof.Signature.
	SignatureBytes = 64
	// DomainSeparator is the byte between SigningDomain and the context.
	DomainSeparator byte = 0x00
)

// Scope is the identity a proof is issued for. TenantID, UserID and DeviceID
// are mandatory opaque identifiers (1 to MaxIDBytes printable ASCII bytes
// each, compared bytewise) and are never interpreted by this package.
type Scope struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
}

// Challenge is the single request a proof answers. ID is an opaque
// identifier; Nonce is exactly NonceBytes; DeadlineUnixMS is a positive Unix
// time in milliseconds. Encode and Parse only check the deadline's shape (a
// positive int64); they never read a clock. Verify does compare the caller's
// nowUnixMS with the expected challenge's DeadlineUnixMS and refuses at or
// after it, but no function here consumes a challenge or enforces single use.
type Challenge struct {
	ID             string   `json:"id"`
	Nonce          [32]byte `json:"nonce"`
	DeadlineUnixMS int64    `json:"deadline_unix_ms"`
}

// Context is the signed part of a proof. Verify treats PlanDigest as opaque:
// it compares and signature-authenticates its bytes but does not establish
// what they describe. CreationPlanDigest is the canonical derivation of a
// plan into such a digest; Verify does not call it (see the package comment).
type Context struct {
	Scope      Scope     `json:"scope"`
	Challenge  Challenge `json:"challenge"`
	PlanDigest [32]byte  `json:"creation_plan_sha256"`
}

// Proof is one complete locklark.vault-creation/v1 identity proof. Signature
// is exactly SignatureBytes. Encode and Parse only check its wire shape (the
// exact unpadded base64url of SignatureBytes); Parse never verifies it. Verify
// does verify it with ed25519.Verify against SigningBytes of the caller's
// independently built expected context and the registered identity key.
type Proof struct {
	Context   Context `json:"context"`
	Signature []byte  `json:"signature"`
}

// Sentinel errors. Every error returned by this package is one of these
// values, unwrapped and free of the offending input, so callers compare them
// with errors.Is or ==.
var (
	// ErrInvalidID reports an identifier that is empty, longer than
	// MaxIDBytes, or not printable ASCII.
	ErrInvalidID = errors.New("vaultcreationauth: invalid identifier")
	// ErrInvalidNonce reports a nonce that is not exactly NonceBytes of
	// canonical unpadded base64url.
	ErrInvalidNonce = errors.New("vaultcreationauth: invalid nonce")
	// ErrInvalidPlanDigest reports a plan digest that is not exactly
	// PlanDigestBytes of canonical unpadded base64url.
	ErrInvalidPlanDigest = errors.New("vaultcreationauth: invalid plan digest")
	// ErrInvalidSignature reports a signature of the wrong wire shape: not
	// exactly SignatureBytes of canonical unpadded base64url outside a string
	// token. Verify also returns it for a SignatureBytes-long signature that
	// fails Ed25519 verification against the registered identity key.
	ErrInvalidSignature = errors.New("vaultcreationauth: invalid signature")
	// ErrInvalidDeadline reports a deadline that is not a positive int64.
	ErrInvalidDeadline = errors.New("vaultcreationauth: invalid deadline")
	// ErrMalformed reports input that is not one UTF-8 JSON object of this
	// schema: broken or trailing JSON, a missing member, a wrong type or
	// value, or a format, version or kind that is not the fixed one.
	ErrMalformed = errors.New("vaultcreationauth: malformed proof")
	// ErrTooLarge reports input longer than MaxProofBytes.
	ErrTooLarge = errors.New("vaultcreationauth: proof too large")
	// ErrNonCanonical reports input that decodes to a valid proof but is not
	// the exact canonical encoding of it: whitespace, another member order,
	// escapes, unknown members, or any other difference from Encode's output.
	// A duplicate member is ErrMalformed, refused before decoding. Parse
	// reports ErrNonCanonical only after the shape of every field has been
	// checked.
	ErrNonCanonical = errors.New("vaultcreationauth: non-canonical proof")

	// ErrContextMismatch reports a proof whose context differs from the
	// caller's expected context in any field: scope, challenge ID, nonce,
	// deadline or creation plan digest. It is checked before the signature.
	ErrContextMismatch = errors.New("vaultcreationauth: proof context mismatch")
	// ErrChallengeExpired reports nowUnixMS at or past the expected
	// challenge deadline.
	ErrChallengeExpired = errors.New("vaultcreationauth: challenge expired")
	// ErrInvalidIdentityKey reports a registered identity key that is not a
	// 32-byte Ed25519 public key.
	ErrInvalidIdentityKey = errors.New("vaultcreationauth: invalid identity key")

	// ErrInvalidCreationPlan reports a creation plan that CreationPlanDigest
	// refuses: a genesis outside 1..vaultfile.MaxFileBytes; a root pin
	// whose VaultID or OwnerRootKeyID is not a vaultfile ID of 1..64 bytes,
	// whose OwnerRootPublicKey is not exactly 32 bytes, whose PolicySeq is
	// not zero or whose PolicyDigest is not exactly 32 bytes; a
	// BackendLocator outside 1..MaxBackendLocatorBytes bytes, not UTF-8 or
	// holding a Unicode control character; a Slug outside its ASCII
	// grammar; or a Name outside the service directory-name rule.
	ErrInvalidCreationPlan = errors.New("vaultcreationauth: invalid creation plan")
)

// SigningBytes returns the exact signing preimage of c:
//
//	SigningDomain || 0x00 || canonicalContextJSON(c)
//
// c is validated exactly as Encode validates it. The result is a fresh slice
// that never aliases c. SigningBytes does not sign anything.
func SigningBytes(c Context) ([]byte, error) {
	ctx, err := marshalContext(c)
	if err != nil {
		return nil, err
	}
	pre := make([]byte, 0, len(SigningDomain)+1+len(ctx))
	pre = append(pre, SigningDomain...)
	pre = append(pre, DomainSeparator)
	return append(pre, ctx...), nil
}

// Encode validates p and returns its canonical encoding. It never sorts,
// repairs or re-spells a value: an invalid value is an error, never bytes.
func Encode(p Proof) ([]byte, error) {
	ctx, err := marshalContext(p.Context)
	if err != nil {
		return nil, err
	}
	if len(p.Signature) != SignatureBytes {
		return nil, ErrInvalidSignature
	}
	var b bytes.Buffer
	b.Grow(len(ctx) + 160)
	fmt.Fprintf(&b, `{"format":%q,"version":%d,"kind":%q,"context":`, Format, Version, Kind)
	b.Write(ctx)
	b.WriteString(`,"signature":"`)
	b.WriteString(base64.RawURLEncoding.EncodeToString(p.Signature))
	b.WriteString(`"}`)
	if b.Len() > MaxProofBytes {
		return nil, ErrTooLarge
	}
	return b.Bytes(), nil
}

// Parse parses one proof and accepts it only in the canonical encoding Encode
// writes.
//
// The input must be at most MaxProofBytes of UTF-8 holding exactly one JSON
// object. Duplicate members are refused outright; the object is then decoded
// into a wire-only shape whose binary members are strings, so encoding/json
// never applies its own base64 or []byte rules. Each field is checked:
// fixed format, version and kind; identifiers; positive deadline; and nonce,
// plan digest and signature as strict unpadded base64url of their exact
// lengths whose re-encoding is identical. Finally the parsed proof is
// re-encoded and must equal data byte for byte, which is what refuses any
// alternate spelling. Parse never verifies the signature and never reads a
// clock.
func Parse(data []byte) (Proof, error) {
	if len(data) > MaxProofBytes {
		return Proof{}, ErrTooLarge
	}
	if !utf8.Valid(data) {
		return Proof{}, ErrMalformed
	}
	if err := checkNoDuplicateMembers(data); err != nil {
		return Proof{}, err
	}
	// A version that is not a canonical decimal integer (fraction, exponent,
	// leading zero) is malformed input, not a different schema version.
	carried, err := carriedVersion(data)
	if err != nil {
		return Proof{}, err
	}
	if carried != strconv.Itoa(Version) {
		return Proof{}, ErrMalformed
	}
	var w wireProof
	if err := json.Unmarshal(data, &w); err != nil {
		return Proof{}, ErrMalformed
	}
	p, err := w.proof()
	if err != nil {
		return Proof{}, err
	}
	// Only reached for a structurally valid value, so re-encoding is paid
	// once per accepted proof, never per rejection.
	canon, err := Encode(p)
	if err != nil {
		return Proof{}, err
	}
	if !bytes.Equal(canon, data) {
		return Proof{}, ErrNonCanonical
	}
	return p, nil
}

// Verify checks one identity proof against the expected context, a registered
// identity key and the caller's clock, and returns nil only when it is a
// valid, unexpired proof for exactly that context.
//
// expected must be built by the caller from its own database, session and
// immutable challenge state, never from proof: it carries the exact scope,
// challenge ID, nonce and deadline and the creation plan digest the caller
// derived itself. Verify does not recompute the plan digest; CreationPlanDigest
// is this package's derivation from a CreationPlan, and the plan fields behind
// the expected digest must come from the caller's own durable sources, not
// from proof. A proof with a different context in any field is refused, but
// checking a proof against a context copied from that same proof proves
// nothing.
//
// registeredIdentity is the Ed25519 public key registered for
// expected.Scope.DeviceID; it must be exactly 32 bytes. proof.Signature must
// be exactly SignatureBytes, and is checked with ed25519.Verify over
// SigningBytes(expected). The context comparison runs first, so a proof for
// another context is refused as ErrContextMismatch whatever its signature.
//
// nowUnixMS is the caller's current Unix time in milliseconds; a challenge is
// expired when now >= expected.Challenge.DeadlineUnixMS (ErrChallengeExpired).
//
// Verify verifies only the identity proof. It does not recompute the
// creation-plan digest, check root authorization or content signatures,
// persist or consume the challenge or enforce single use, and does no HTTP.
func Verify(proof Proof, expected Context, registeredIdentity ed25519.PublicKey, nowUnixMS int64) error {
	if _, err := marshalContext(expected); err != nil {
		return err
	}
	if proof.Context != expected {
		return ErrContextMismatch
	}
	if nowUnixMS >= expected.Challenge.DeadlineUnixMS {
		return ErrChallengeExpired
	}
	if len(registeredIdentity) != ed25519.PublicKeySize {
		return ErrInvalidIdentityKey
	}
	if len(proof.Signature) != SignatureBytes {
		return ErrInvalidSignature
	}
	pre, err := SigningBytes(expected)
	if err != nil {
		return err
	}
	if !ed25519.Verify(registeredIdentity, pre, proof.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Creation plan digest constants and budgets. They are part of the schema.
const (
	// CreationPlanDomain is the domain bytes CreationPlanDigest hashes before
	// the plan fields. The 0x00 that follows it in the preimage is not a part
	// of this string.
	CreationPlanDomain = "locklark.vault-creation-plan/v1"

	// MaxCreationPlanIDBytes is the maximum length in bytes of
	// RootPin.VaultID and RootPin.OwnerRootKeyID. It is the public
	// vaultfile identifier bound.
	MaxCreationPlanIDBytes = 64
	// MaxBackendLocatorBytes is the maximum length in bytes of
	// CreationPlan.BackendLocator.
	MaxBackendLocatorBytes = 4096
	// MaxCreationPlanSlugBytes is the maximum length in bytes of
	// CreationPlan.Slug.
	MaxCreationPlanSlugBytes = 63
	// MaxCreationPlanNameBytes is the maximum length in bytes of
	// CreationPlan.Name.
	MaxCreationPlanNameBytes = 256
)

// CreationPlan is the plan of one fresh vault creation, as CreationPlanDigest
// binds it.
//
// GenesisBytes are the exact raw genesis bytes the vault would be created
// with, at most vaultfile.MaxFileBytes; they are hashed as supplied and never
// parsed or re-encoded here. RootPin is the complete vaultfile.PolicyCheckpoint
// of a fresh vault: its PolicySeq must be zero and every one of its other
// fields is bound. BackendLocator is an opaque, non-secret canonical
// identifier of the backend the vault would be created on; the future caller
// must derive it independently from its server backend configuration, and
// this package neither resolves it nor validates that it maps to actual
// storage. Slug and Name are the vault's directory values, bound exactly, not
// trimmed, folded or normalized.
type CreationPlan struct {
	GenesisBytes   []byte
	RootPin        vaultfile.PolicyCheckpoint
	BackendLocator string
	Slug           string
	Name           string
}

// CreationPlanDigest returns the canonical SHA-256 digest of plan (see the
// package comment for the exact preimage). It validates every field before
// writing anything to the hash, then feeds the domain and each field, with its
// fixed-length encoding, to the hash in small pieces: no full preimage is ever
// built, so the genesis's vaultfile.MaxFileBytes budget costs no extra memory.
//
// The digest binds the exact bytes of plan. It does not prove that
// BackendLocator resolves to any storage, that the genesis bytes are a valid
// vault file, or that the plan came from the caller's own sources.
//
// A plan with any invalid field returns the zero digest and exactly
// ErrInvalidCreationPlan.
func CreationPlanDigest(plan CreationPlan) ([32]byte, error) {
	if err := validCreationPlan(plan); err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte(CreationPlanDomain))
	h.Write([]byte{DomainSeparator})
	creationPlanHash(h, plan.GenesisBytes)
	creationPlanHash(h, []byte(plan.RootPin.VaultID))
	creationPlanHash(h, []byte(plan.RootPin.OwnerRootKeyID))
	h.Write(plan.RootPin.OwnerRootPublicKey)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], plan.RootPin.PolicySeq)
	h.Write(seq[:])
	h.Write(plan.RootPin.PolicyDigest)
	creationPlanHash(h, []byte(plan.BackendLocator))
	creationPlanHash(h, []byte(plan.Slug))
	creationPlanHash(h, []byte(plan.Name))
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

// creationPlanHash feeds b to h behind its uint32 big-endian byte length. b is
// already bounded by validCreationPlan, so the length fits uint32.
func creationPlanHash(h io.Writer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// validCreationPlan checks every field of plan without touching a hash.
func validCreationPlan(plan CreationPlan) error {
	if len(plan.GenesisBytes) == 0 || len(plan.GenesisBytes) > vaultfile.MaxFileBytes {
		return ErrInvalidCreationPlan
	}
	pin := plan.RootPin
	if !validCreationPlanID(pin.VaultID) || !validCreationPlanID(pin.OwnerRootKeyID) {
		return ErrInvalidCreationPlan
	}
	if len(pin.OwnerRootPublicKey) != ed25519.PublicKeySize ||
		pin.PolicySeq != 0 ||
		len(pin.PolicyDigest) != sha256.Size {
		return ErrInvalidCreationPlan
	}
	if !validBackendLocator(plan.BackendLocator) || !validCreationPlanSlug(plan.Slug) ||
		!validCreationPlanName(plan.Name) {
		return ErrInvalidCreationPlan
	}
	return nil
}

// validCreationPlanID applies the public vaultfile identifier rule: 1 to
// MaxCreationPlanIDBytes bytes of lowercase ASCII a-z, 0-9, '-', '_', '.'
// and ':'.
func validCreationPlanID(s string) bool {
	if len(s) == 0 || len(s) > MaxCreationPlanIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':' {
			continue
		}
		return false
	}
	return true
}

// validBackendLocator reports whether s is a non-empty locator of at most
// MaxBackendLocatorBytes bytes of UTF-8 without Unicode control characters
// (which include NUL, C1 controls and the bidi and other format controls).
// Nothing is trimmed, case-folded or normalized.
func validBackendLocator(s string) bool {
	if len(s) == 0 || len(s) > MaxBackendLocatorBytes || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// validCreationPlanSlug reports whether s is exactly [a-z0-9][a-z0-9-]{0,62}
// ASCII: it has no normalization, so uppercase, '_', '.', ':' or any other
// byte is refused.
func validCreationPlanSlug(s string) bool {
	if len(s) == 0 || len(s) > MaxCreationPlanSlugBytes {
		return false
	}
	if c := s[0]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validCreationPlanName mirrors, without importing any internal server
// package, the tenantauth.validDirectoryName rule shared by directory and
// vault names (fixed at locklark-server commit
// 1a5167bbc4ec53334817b289f35eb54f84fb1d96): non-empty, at most
// MaxCreationPlanNameBytes bytes of UTF-8, no control character, no Unicode Zl
// or Zp, and no Cf except U+200C ZWNJ and U+200D ZWJ, with at least one rune
// that unicode.IsSpace reports false. Ordinary spaces, inner or outer, are
// allowed when some visible rune exists. Callers must keep this rule aligned
// with the service validator: if the service changes it, this copy is stale.
func validCreationPlanName(s string) bool {
	if len(s) == 0 || len(s) > MaxCreationPlanNameBytes || !utf8.ValidString(s) {
		return false
	}
	hasVisible := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
			(unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d') {
			return false
		}
		if !unicode.IsSpace(r) {
			hasVisible = true
		}
	}
	return hasVisible
}

// wireProof mirrors the schema with every binary member carried as its
// base64url text. It exists only to decode; Encode is the only writer.
type wireProof struct {
	Format    string      `json:"format"`
	Version   int         `json:"version"`
	Kind      string      `json:"kind"`
	Context   wireContext `json:"context"`
	Signature string      `json:"signature"`
}

type wireContext struct {
	Scope      wireScope `json:"scope"`
	Challenge  wireChall `json:"challenge"`
	PlanDigest string    `json:"creation_plan_sha256"`
}

type wireScope struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
}

type wireChall struct {
	ID             string `json:"id"`
	Nonce          string `json:"nonce"`
	DeadlineUnixMS int64  `json:"deadline_unix_ms"`
}

// carriedVersion returns the exact lexeme of the top-level "version" member.
// encoding/json would map 1.0, 1e0 and 01 all to the int 1, hiding a
// non-canonical or malformed spelling until a later error; this reads the
// member's raw digits instead. A missing version is malformed.
func carriedVersion(data []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return "", ErrMalformed
	}
	raw, ok := top["version"]
	if !ok {
		return "", ErrMalformed
	}
	return string(raw), nil
}

// proof validates the decoded wire value and converts it to a Proof.
func (w *wireProof) proof() (Proof, error) {
	var p Proof
	if w.Format != Format || w.Version != Version || w.Kind != Kind {
		return p, ErrMalformed
	}
	ids := []string{w.Context.Scope.TenantID, w.Context.Scope.UserID, w.Context.Scope.DeviceID, w.Context.Challenge.ID}
	for _, id := range ids {
		if !validID(id) {
			return p, ErrInvalidID
		}
	}
	if w.Context.Challenge.DeadlineUnixMS <= 0 {
		return p, ErrInvalidDeadline
	}
	p.Context.Scope = Scope{TenantID: ids[0], UserID: ids[1], DeviceID: ids[2]}
	p.Context.Challenge.ID = ids[3]
	p.Context.Challenge.DeadlineUnixMS = w.Context.Challenge.DeadlineUnixMS
	members := []struct {
		name string
		raw  string
		dst  []byte
		err  error
	}{
		{"nonce", w.Context.Challenge.Nonce, p.Context.Challenge.Nonce[:], ErrInvalidNonce},
		{"creation_plan_sha256", w.Context.PlanDigest, p.Context.PlanDigest[:], ErrInvalidPlanDigest},
		{"signature", w.Signature, make([]byte, SignatureBytes), ErrInvalidSignature},
	}
	for _, m := range members {
		if !decodeCanonicalB64(m.dst, m.raw) {
			return Proof{}, m.err
		}
	}
	p.Signature = members[2].dst
	return p, nil
}

// marshalContext validates c and returns its canonical context object.
func marshalContext(c Context) ([]byte, error) {
	for _, id := range []string{c.Scope.TenantID, c.Scope.UserID, c.Scope.DeviceID, c.Challenge.ID} {
		if !validID(id) {
			return nil, ErrInvalidID
		}
	}
	if c.Challenge.DeadlineUnixMS <= 0 {
		return nil, ErrInvalidDeadline
	}
	// validID admits printable ASCII, and %q escapes exactly the JSON-special
	// bytes (quote, backslash, controls) that the strict wire decoder decodes
	// back to the same ID; an escaped ID is non-canonical and Parse rejects it.
	return fmt.Appendf(nil,
		`{"scope":{"tenant_id":%q,"user_id":%q,"device_id":%q},`+
			`"challenge":{"id":%q,"nonce":"%s","deadline_unix_ms":%d},`+
			`"creation_plan_sha256":"%s"}`,
		c.Scope.TenantID, c.Scope.UserID, c.Scope.DeviceID,
		c.Challenge.ID, base64.RawURLEncoding.EncodeToString(c.Challenge.Nonce[:]),
		c.Challenge.DeadlineUnixMS,
		base64.RawURLEncoding.EncodeToString(c.PlanDigest[:])), nil
}

// validID reports whether s is a non-empty identifier of printable ASCII, no
// more than MaxIDBytes long. Identifiers compare bytewise; nothing is folded
// or normalized.
func validID(s string) bool {
	if len(s) == 0 || len(s) > MaxIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7E {
			return false
		}
	}
	return true
}

// decodeCanonicalB64 decodes raw as unpadded base64url of exactly len(dst)
// bytes that is its own canonical encoding, and copies it into dst. raw is
// never []byte at the JSON layer, so encoding/json's standard-base64 rule
// never applies.
func decodeCanonicalB64(dst []byte, raw string) bool {
	if len(raw) != base64.RawURLEncoding.EncodedLen(len(dst)) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != len(dst) || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return false
	}
	copy(dst, decoded)
	return true
}

// reInt matches a JSON integer lexeme: an optional minus sign and canonical
// digits. It rejects fractions, exponents and leading zeros.
var reInt = regexp.MustCompile(`\A-?(?:0|[1-9][0-9]*)\z`)

// checkNoDuplicateMembers walks every object in data in order and refuses one
// that names a member twice, as well as a number token that is not a canonical
// integer. encoding/json resolves duplicate members as last-wins and would
// otherwise let one proof carry two meanings. It runs only on inputs that
// already passed the size and UTF-8 checks; every structural error is
// reported as ErrMalformed, so the re-encode comparison in Parse is the one
// that reports a merely non-canonical spelling.
func checkNoDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	err := walkValue(dec, 0)
	if err != nil {
		return ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

// maxWireDepth bounds nesting of a proof; the schema nests two levels below
// the top-level object.
const maxWireDepth = 4

func walkValue(dec *json.Decoder, depth int) error {
	if depth > maxWireDepth {
		return errUnsupported
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return errUnsupported
				}
				if _, dup := seen[key]; dup {
					return errDuplicate
				}
				seen[key] = struct{}{}
				if err := walkValue(dec, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			for dec.More() {
				if err := walkValue(dec, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
	case json.Number:
		if !reInt.MatchString(string(t)) {
			return errUnsupported
		}
	}
	return nil
}

var (
	errUnsupported = errors.New("vaultcreationauth: unsupported json value")
	errDuplicate   = errors.New("vaultcreationauth: duplicate member")
)
