// Package vaultfile defines the locklark.vault-file/v1 wire schema, its
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
// canonical encoding and size/length budgets. See docs/vaultfile-wire-v1.md.
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
	// on top of MaxPlaintextBytes. It covers an age/stream header, the AEAD
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

	// MaxObjectMembers bounds the members of every JSON object, at every
	// depth, before the decoder asks for the next key. The largest object in
	// v1 is the policy document itself, with 12 members (see Policy); every
	// nested object (header, owner_root, member, delegation, scope, device,
	// signing key, device slot, cek_slot) has fewer. 16 leaves room for
	// four members of growth without admitting unbounded maps on an unknown
	// or duplicate-key path.
	MaxObjectMembers = 16

	// MaxJSONNodes bounds the number of JSON value and container nodes
	// (object, array, string, number, bool, null), object keys excluded, in
	// one ParseFile or ParsePolicyDocument input. It is counted before each
	// value token is requested, so the decoded tree can never hold more.
	//
	// The bound admits every value the other budgets allow. The checked-in
	// v1 file vector decodes to 105 nodes and its policy to 68. The largest
	// file the per-array budgets admit is dominated by 128 proofs in
	// `signed_policy_proofs`, each carrying a 5-member proof object whose
	// `policy` is a maximal policy: its object (1) and twelve members, six
	// literals (including a null `prev_policy_digest`), the owner_root
	// object with 4 literals (5), five member arrays (readers, writers,
	// admins, owners and owner_root.owners: 1 + 64*3 = 193 each),
	// admin_delegations (1 + 64*14 = 897) and devices
	// (1 + 128*11 = 1,409): 1 + 6 + 5 + 5*193 + 897 + 1,409 = 3,281
	// nodes. A proof adds its object and two literals (3,286); the file
	// adds its object and the proofs array: 2 + 128*3,286 = 420,610
	// nodes, pinned by TestNodeCapAdmitsV1ArrayBounds. That leaves a
	// margin above 100,000 nodes, more than 1/8 of the cap. Remaining
	// slack covers a further policy-list-sized growth without changing
	// the bound.
	MaxJSONNodes = 524288

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
	Version   = 1
	MIME      = "application/vnd.locklark.vault-file+json"
	SchemaURI = "https://locklark.dev/schema/locklark.vault-file/v1"

	ContentEncoding = "kdbx"

	SigAlgEd25519 = "ed25519"

	// Age X25519 recipients start with this prefix. The secret-key prefix is
	// listed only so a codec can reject identity material in wire fields.
	AgeX25519RecipientPrefix = "age1"
	AgeX25519IdentityPrefix  = "AGE-SECRET-KEY-1"

	DigestAlgSHA256 = "sha256"

	PolicySigAlgEd25519 = "ed25519"
)
