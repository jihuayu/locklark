// Package vaultfile defines the locklark.vault-file/v3 wire schema, its
// strict canonical-JSON codec and fixed synthetic encoding vectors.
//
// A vault file is a single complete object that carries everything a peer
// needs to check and open one snapshot of a vault: the embedded header, the
// signed policy proofs, the full encrypted KDBX content bytes, the per-device
// VUK wrapping slots, the CEK slot protected by the VUK and the content
// signature. It is not a reference to content stored elsewhere.
//
// This package deliberately contains no signature verification, no
// migration/import and no product wiring. It validates only wire structure,
// canonical encoding and size/length budgets. See docs/vaultfile-wire-v3.md.
package vaultfile

// Size and length budgets fixed by this schema. Every one of them is checked
// before any value is copied, decoded or used.
const (
	// MaxFileBytes is the maximum size in bytes of one encoded vault file.
	MaxFileBytes = 32 << 20
	// MaxPlaintextBytes is the plaintext budget of the encrypted content. The
	// encrypted KDBX bytes must not exceed the budget plus the size of one
	// encryption-scheme overhead (see MaxKDBXCiphertextBytes).
	MaxPlaintextBytes = 16 << 20
	// MaxKDBXCiphertextOverhead is the largest permitted encryption overhead
	// on top of MaxPlaintextBytes. It covers a v3 age/stream header, the AEAD
	// tags and chunk framing of a single encryption pass.
	MaxKDBXCiphertextOverhead = 64 << 10
	// MaxKDBXCiphertextBytes is the largest permitted encrypted content.
	MaxKDBXCiphertextBytes = MaxPlaintextBytes + MaxKDBXCiphertextOverhead

	// MaxStringTokenBytes bounds any single JSON string token before it is
	// decoded (largest legal member: the encrypted content in base64url).
	MaxStringTokenBytes = (MaxKDBXCiphertextBytes*4)/3 + 4
	// MaxTextStringBytes bounds small string members (labels and ids).
	MaxTextStringBytes = MaxLabelLength * 6
	// MaxBinaryStringBytes bounds binary-carrier string tokens other than
	// the encrypted content (policy documents, wrapped keys).
	MaxBinaryStringBytes = (MaxSignedPolicyProofBytes*4)/3 + 4

	// MaxJSONDepth bounds nesting of the canonical header document.
	MaxJSONDepth = 8

	// MaxArrayItems is the length limit for every array in the header and in
	// a policy document.
	MaxArrayItems = 128
	// MaxPolicyArrayItems is the length limit for the member arrays of a
	// policy (readers/writers/admins/owners).
	MaxPolicyArrayItems = 64
	// MaxDelegations is the length limit for the restricted admin
	// delegations carried by a policy.
	MaxDelegations = 64
	// MaxDeviceSlots is the length limit for the per-device VUK slots.
	MaxDeviceSlots = 128

	// MaxIDLength is the limit for opaque identifiers (vault, revision, op,
	// delegation ids).
	MaxIDLength = 64
	// MaxDeviceIDLength is the limit for device identifiers.
	MaxDeviceIDLength = 128
	// MaxKeyIDLength is the limit for key identifiers and key fingerprints.
	MaxKeyIDLength = 64
	// MaxLabelLength is the limit for human-readable labels such as device
	// names. Labels are metadata visible to the storage provider.
	MaxLabelLength = 128
	// MaxRoleScopeLength is the limit for the free-form scope note of a
	// restricted admin delegation. It is descriptive only; the machine
	// readable scope is DelegationScope.
	MaxRoleScopeLength = 256
	// MaxSignatureLength is the limit for a single signature value.
	MaxSignatureLength = 4 << 10
	// MaxWrappedKeyLength is the limit for one wrapped key (VUK slot or CEK
	// slot).
	MaxWrappedKeyLength = 512
	// MaxSignedPolicyProofBytes is the limit for one encoded signed policy
	// proof document.
	MaxSignedPolicyProofBytes = 256 << 10
	// MaxPublicKeyLength is the limit for an encoded public key.
	MaxPublicKeyLength = 1024
)

// Wire identifiers that must appear literally in an encoded file.
const (
	Format    = "locklark.vault-file"
	Version   = 3
	MIME      = "application/vnd.locklark.vault-file+json"
	SchemaURI = "https://locklark.dev/schema/locklark.vault-file/v3"

	EncryptionKDBXv3 = "kdbxv3"
	ContentEncoding  = "kdbx"

	SigAlgEd25519 = "ed25519"

	// Age X25519 recipients start with this prefix. The secret-key prefix is
	// listed only so a codec can reject identity material in wire fields.
	AgeX25519RecipientPrefix = "age1"
	AgeX25519IdentityPrefix  = "AGE-SECRET-KEY-1"

	DigestAlgSHA256 = "sha256"

	PolicySigAlgEd25519 = "ed25519"
)
