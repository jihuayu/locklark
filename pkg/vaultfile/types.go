package vaultfile

import (
	"errors"
	"fmt"
)

// File is one complete locklark.vault-file/v1 object. It is self-contained:
// content bytes are embedded, never referenced by digest only.
//
// R in the sync protocol means exactly these bytes as read back from the
// backend; it is never a legacy document.
//
// A file has exactly two states (see ValidateFile):
//
//   - unsigned draft: content_signature is the null sig {"signer_id":"",
//     "alg":"","sig":null} and header.revision_id is "". A writer holds this
//     state between building the file and signing ContentSigningBytes.
//   - sealed: content_signature is a 64-byte signature by the header's author
//     device and header.revision_id is the derived RevisionID of the file.
//
// There is no header signature. The header is covered by the content
// signature through RevisionID, so a writer never manages a header key.
type File struct {
	Format             string         `json:"format"`
	Version            int            `json:"version"`
	Header             Header         `json:"header"`
	SignedPolicyProofs []SignedPolicy `json:"signed_policy_proofs"`
	ContentEncoding    string         `json:"content_encoding"`
	KDBXCiphertext     []byte         `json:"kdbx_ciphertext"`
	VUKDeviceSlots     []DeviceSlot   `json:"vuk_device_slots"`
	CEKSlot            CEKSlot        `json:"cek_slot"`
	ContentSignature   Signature      `json:"content_signature"`
}

// Header is the minimal plaintext metadata and version tuple of a vault file.
// Every field except prev_digest (nil only for the genesis content revision)
// is mandatory. PolicyDigest is the SHA-256 policy digest (PolicyDigest) of
// the policy document at PolicySeq, computed outside the header. All
// identifiers that are not names are opaque byte strings carried as
// base64url without padding.
//
// RevisionID is the derived revision identity of the file (RevisionID), 32
// bytes as lowercase hex, or "" in an unsigned draft. It is never an input of
// a preimage: see ContentSigningBytes.
type Header struct {
	VaultID        string `json:"vault_id"`
	KeyEpoch       uint64 `json:"key_epoch"`
	ContentSeq     uint64 `json:"content_seq"`
	RevisionID     string `json:"revision_id"`
	PrevDigest     []byte `json:"prev_digest"`
	OpID           string `json:"op_id"`
	PolicySeq      uint64 `json:"policy_seq"`
	PolicyDigest   []byte `json:"policy_digest"`
	AuthorDeviceID string `json:"author_device_id"`
}

// SignedPolicy is a signed policy document together with the encoded bytes it
// signs. The bytes are carried verbatim so the signature can be checked over
// exactly what the signer committed to; VerifyPolicyDocument re-parses them to
// prove they equal Policy and pass the same strict limits.
type SignedPolicy struct {
	Policy   Policy `json:"policy"`
	Document []byte `json:"document"`
	SignerID string `json:"signer_id"`
	Alg      string `json:"alg"`
	Sig      []byte `json:"sig"`
}

// Policy is the vault authorization document.
//
// The owner root is independent of any device: it is the security root of the
// vault. Devices hold role-bound policy signing keys and content signing keys;
// readers do not hold content signing keys.
//
// A policy carries no digest of itself. Its one and only digest is computed
// outside this document (PolicyDigest), over the canonical encoding of the
// policy; Header.PolicyDigest and the next policy's PrevPolicyDigest both
// reference that same value. PrevPolicyDigest is nil exactly for the genesis
// policy (policy_seq 0).
type Policy struct {
	Format           string            `json:"format"`
	Version          int               `json:"version"`
	VaultID          string            `json:"vault_id"`
	PolicySeq        uint64            `json:"policy_seq"`
	PrevPolicyDigest []byte            `json:"prev_policy_digest"`
	OwnerRoot        OwnerRoot         `json:"owner_root"`
	Readers          []Member          `json:"readers"`
	Writers          []Member          `json:"writers"`
	Admins           []Member          `json:"admins"`
	Owners           []Member          `json:"owners"`
	AdminDelegations []AdminDelegation `json:"admin_delegations"`
	Devices          []Device          `json:"devices"`
}

// OwnerRoot is the independent vault owner root. It is not a device and not
// a member; owner devices are members holding the owner role.
type OwnerRoot struct {
	KeyID     string      `json:"key_id"`
	Alg       string      `json:"alg"`
	PublicKey []byte      `json:"public_key"`
	Owners    []Principal `json:"owners"`
}

// Principal is a person or service identity that holds the owner role.
type Principal struct {
	PrincipalID string `json:"principal_id"`
	Label       string `json:"label"`
}

// Member is a principal granted one vault role.
type Member struct {
	PrincipalID string `json:"principal_id"`
	Label       string `json:"label"`
}

// AdminDelegation is an explicit, restricted admin delegation from the owner
// root to a named device. Scope is the machine-readable restriction; it can
// never grant owner promotion or root replacement.
type AdminDelegation struct {
	DelegationID     string          `json:"delegation_id"`
	DelegateDevice   string          `json:"delegate_device_id"`
	GrantedBy        string          `json:"granted_by"`
	Scope            DelegationScope `json:"scope"`
	ScopeNote        string          `json:"scope_note"`
	ExpiresPolicySeq uint64          `json:"expires_policy_seq"`
}

// DelegationScope is the restricted authority of an admin delegation.
type DelegationScope struct {
	InviteReaders bool `json:"invite_readers"`
	InviteWriters bool `json:"invite_writers"`
	RemoveMembers bool `json:"remove_members"`
	RemoveDevices bool `json:"remove_devices"`
	PromoteAdmin  bool `json:"promote_admin"`
	PromoteOwner  bool `json:"promote_owner"`
	ReplaceRoot   bool `json:"replace_root"`
}

// Device is one approved device. Every device belongs to exactly one
// principal, named by its mandatory PrincipalID; the device acts with that
// principal's vault roles. The three key roles are distinct: a device holds
// at most one content signing key, one policy signing key and one age X25519
// encryption key, and no key of one role may equal a key of another.
type Device struct {
	DeviceID          string     `json:"device_id"`
	PrincipalID       string     `json:"principal_id"`
	Label             string     `json:"label"`
	ContentSigningKey PublicKey  `json:"content_signing_key"`
	PolicySigningKey  *PublicKey `json:"policy_signing_key"`
	AgeEncryptionKey  string     `json:"age_encryption_key"`
}

// PublicKey is an encoded public key bound to one purpose.
type PublicKey struct {
	Alg       string `json:"alg"`
	PublicKey []byte `json:"public_key"`
}

// Signature binds signer, algorithm and value.
type Signature struct {
	SignerID string `json:"signer_id"`
	Alg      string `json:"alg"`
	Sig      []byte `json:"sig"`
}

// DeviceSlot is one VUK wrapping for one device (age X25519 recipient).
type DeviceSlot struct {
	DeviceID   string `json:"device_id"`
	Recipient  string `json:"recipient"`
	WrappedVUK []byte `json:"wrapped_vuk"`
}

// CEKSlot is the content key (CEK) wrapped by the epoch VUK. The CEK itself
// is generated fresh for every content snapshot.
type CEKSlot struct {
	KeyEpoch   uint64 `json:"key_epoch"`
	WrappedCEK []byte `json:"wrapped_cek"`
}

// ContentRevision identifies a content snapshot by its ordinal, revision
// identity and file digest. RevisionID is RevisionID of the sealed file and
// Digest is FileDigest of it; neither value is carried inside the preimage it
// is derived from.
type ContentRevision struct {
	ContentSeq uint64 `json:"content_seq"`
	RevisionID string `json:"revision_id"`
	Digest     []byte `json:"digest"`
}

// BackendRevision is the opaque backend token bound to one exact byte
// sequence (for example an ETag). It is returned verbatim to the backend's
// conditional write and is never a cryptographic digest or a trust signal.
type BackendRevision string

// Error is a structural or limit violation. The message never embeds the
// offending value, only its location and a const programmatic code.
type Error struct {
	Code string
	Path string
}

// Err builds a structural error. Codes are constants so callers can branch on
// them; offending values are never embedded.
func Err(path string, code string) error { return &Error{Code: code, Path: path} }

func (e *Error) Error() string {
	if e.Path == "" {
		return "vaultfile: " + e.Code
	}
	return fmt.Sprintf("vaultfile: %s at %s", e.Code, e.Path)
}

// Codes reported by Error.Code.
const (
	CodeTooLarge         = "too_large"
	CodeTooDeep          = "too_deep"
	CodeTooManyItems     = "too_many_items"
	CodeStringTooLong    = "string_too_long"
	CodeBytesTooLong     = "bytes_too_long"
	CodeInvalidJSON      = "invalid_json"
	CodeDuplicateField   = "duplicate_field"
	CodeUnknownField     = "unknown_field"
	CodeTrailingData     = "trailing_data"
	CodeMissingField     = "missing_field"
	CodeWrongType        = "wrong_type"
	CodeInvalidValue     = "invalid_value"
	CodeLimitExceeded    = "limit_exceeded"
	CodePolicyMismatch   = "policy_mismatch"
	CodeSignatureInvalid = "signature_shape_invalid"
	CodeHeaderMismatch   = "header_mismatch"
)

// AsError reports whether err is a *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
