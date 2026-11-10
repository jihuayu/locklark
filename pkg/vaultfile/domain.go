package vaultfile

import (
	"crypto/sha256"
	"encoding/base64"
)

// Every cryptographic use has its own domain-separation label. A value
// produced for one purpose must never be accepted for another. Labels are
// fixed by this schema and are part of its public protocol.
//
// Labels are defined here only; this package does not sign, verify, wrap or
// derive anything.
const (
	// Content signatures over ContentSigningBytes.
	DomainContentSignature = "locklark.vault-file/v1/content-signature"

	// Revision identities over the canonical file with header.revision_id and
	// content_signature removed (RevisionID).
	DomainRevision = "locklark.vault-file/v1/revision"

	// File digests over the complete canonical signed file (FileDigest).
	DomainFileDigest = "locklark.vault-file/v1/file-digest"

	// Policy document signatures over SignedPolicy.Document.
	DomainPolicyDocumentSignature = "locklark.vault-file/v1/policy-document-signature"

	// Restricted admin delegations issued by the owner root.
	DomainAdminDelegation = "locklark.vault-file/v1/admin-delegation"

	// age wrapping of the VUK to a device encryption key (vuk_device_slots).
	DomainVUKDeviceWrapping = "locklark.vault-file/v1/vuk-device-wrapping"

	// Wrapping of the per-snapshot CEK by the epoch VUK (cek_slot).
	DomainCEKWrapping = "locklark.vault-file/v1/cek-wrapping"

	// Key fingerprints, one per key role.
	UsageVaultID                 = "locklark.vault-file/v1/vault-id"
	UsageContentRevisionID       = "locklark.vault-file/v1/content-revision-id"
	UsageOpID                    = "locklark.vault-file/v1/op-id"
	UsageDeviceID                = "locklark.vault-file/v1/device-id"
	UsageDeviceContentSigningKey = "locklark.vault-file/v1/key/device-content-signing"
	UsageDevicePolicySigningKey  = "locklark.vault-file/v1/key/device-policy-signing"
	UsageAgeEncryptionKey        = "locklark.vault-file/v1/key/age-x25519"

	// UsagePolicyDocument is the policy digest domain: the SHA-256 digest of
	// a canonical policy document (PolicyDigest). It is computed outside the
	// policy and referenced by Header.PolicyDigest and the next policy's
	// PrevPolicyDigest.
	UsagePolicyDocument = "locklark.vault-file/v1/policy-document"

	// Digest algorithms named on the wire.
	DigestSHA256 = DigestAlgSHA256
)

// Key fingerprints are identification only (the Usage* labels): they never
// appear in a signing, revision or file-digest preimage.
//
// Domains lists all purpose domains in a stable order. Implementations of
// signing (outside this package) must prefix inputs with exactly one of them.
func Domains() []string {
	return []string{
		DomainContentSignature,
		DomainRevision,
		DomainFileDigest,
		DomainPolicyDocumentSignature,
		DomainAdminDelegation,
		DomainVUKDeviceWrapping,
		DomainCEKWrapping,
		UsageVaultID,
		UsageContentRevisionID,
		UsageOpID,
		UsageDeviceID,
		UsageDeviceContentSigningKey,
		UsageDevicePolicySigningKey,
		UsageAgeEncryptionKey,
		UsagePolicyDocument,
	}
}

// DomainSeparated computes SHA-256 over domain || 0x00 || data. This is a
// fingerprint for identification only; it is not a signature and grants no
// trust. Callers must use it with a label from this package.
func DomainSeparated(domain string, data []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

// KeyFingerprint identifies a public key of one role.
func KeyFingerprint(domain string, key []byte) string {
	return base64.RawURLEncoding.EncodeToString(DomainSeparated(domain, key))
}

// AgeRecipientFingerprint identifies an age recipient string.
func AgeRecipientFingerprint(recipient string) string {
	return KeyFingerprint(UsageAgeEncryptionKey, []byte(recipient))
}
