package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

// ValidateFile checks that f is a valid wire file: one sealed file with a
// non-null, correctly shaped author content signature and header.revision_id
// exactly its derived RevisionID, plus every other structural rule of the
// schema, length and size budget included.
//
// An unsigned builder draft is not a wire file and always fails here. It
// exists only in memory for preimage construction and is checked by the
// private validateDraft; ParseFile, EncodeFile and FileDigest only ever
// accept a sealed file. Validation performs no cryptographic
// verification: signatures and wrapped keys are only checked for shape and
// consistency.
func ValidateFile(f *File) error {
	current, err := validateStructure(f)
	if err != nil {
		return err
	}
	return validateSealed(f, current)
}

// validateStructure checks every rule of ValidateFile except that f is sealed.
// It returns the current policy: the one proof whose policy_seq is the header
// policy_seq, which every role and slot check binds to. Proofs are held in
// strictly increasing policy_seq order (checkPolicyProofOrder) and the list
// is old-to-current: the current policy is the final proof, and no proof may
// carry a policy newer than the one the header selects.
func validateStructure(f *File) (*Policy, error) {
	if f == nil {
		return nil, Err("", CodeInvalidValue)
	}
	if f.Format != Format {
		return nil, Err("", CodeInvalidValue)
	}
	if f.Version != Version {
		return nil, Err("", CodeInvalidValue)
	}
	h := &f.Header
	if err := ValidateHeader(h); err != nil {
		return nil, err
	}
	if f.ContentEncoding != ContentEncoding {
		return nil, Err("", CodeInvalidValue)
	}
	if f.KDBXCiphertext == nil || len(f.KDBXCiphertext) > MaxKDBXCiphertextBytes {
		return nil, Err("", CodeLimitExceeded)
	}
	if len(f.SignedPolicyProofs) == 0 || len(f.SignedPolicyProofs) > MaxArrayItems {
		return nil, Err("", CodeInvalidValue)
	}
	if err := checkPolicyProofOrder(f.SignedPolicyProofs); err != nil {
		return nil, err
	}
	for i := range f.SignedPolicyProofs {
		sp := &f.SignedPolicyProofs[i]
		if err := validateSignedPolicy(sp); err != nil {
			return nil, err
		}
		if sp.Policy.VaultID != h.VaultID {
			return nil, Err("", CodeHeaderMismatch)
		}
	}
	// Exactly one proof must carry the current policy (header policy_seq).
	// Its digest is PolicyDigest over the carried document bytes; the policy
	// carries no digest of itself.
	//
	// The current policy is the final proof: proofs are strictly increasing,
	// so the last one holds the highest sequence. A final proof below the
	// header seq means the selected policy is missing, and a highest proof
	// above it means a later policy is carried; an earlier proof is never
	// selected as current instead.
	last := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1]
	if last.Policy.PolicySeq != h.PolicySeq {
		return nil, Err("", CodeHeaderMismatch)
	}
	var current *Policy
	for i := range f.SignedPolicyProofs {
		sp := &f.SignedPolicyProofs[i]
		if sp.Policy.PolicySeq != h.PolicySeq {
			continue
		}
		if current != nil {
			return nil, Err("", CodeInvalidValue)
		}
		if !bytes.Equal(policyDigest(sp), h.PolicyDigest) {
			return nil, Err("", CodeHeaderMismatch)
		}
		current = &sp.Policy
	}
	if current == nil {
		return nil, Err("", CodeHeaderMismatch)
	}
	// A file may only be authored by a device whose principal is a writer,
	// admin or owner. Readers hold no content signing authority.
	if !current.canAuthor(h.AuthorDeviceID) {
		return nil, Err("", CodeInvalidValue)
	}
	if err := validateCEKAndSlots(f, current); err != nil {
		return nil, err
	}
	return current, nil
}

// validateCEKAndSlots checks the CEK slot epoch and the VUK device slots
// against the current policy (see validateStructure).
func validateCEKAndSlots(f *File, current *Policy) error {
	h := &f.Header
	if f.CEKSlot.KeyEpoch != h.KeyEpoch || f.CEKSlot.WrappedCEK == nil || len(f.CEKSlot.WrappedCEK) == 0 {
		return Err("", CodeInvalidValue)
	}
	if len(f.VUKDeviceSlots) == 0 || len(f.VUKDeviceSlots) > MaxDeviceSlots {
		return Err("", CodeInvalidValue)
	}
	// The VUK slots are exactly the approved devices whose principal has
	// read access (reader, writer, admin or owner). A slot for a device
	// without a read role hands the vault key to it and is rejected; a device
	// with a read role missing from the slots could not open the snapshot.
	// Membership is a set check, but the wire carries exactly one
	// representation of that set: slots in strictly increasing device_id
	// order (checkAscendingIDs, called first).
	if err := checkAscendingIDs("vuk_device_slots", len(f.VUKDeviceSlots), func(i int) string {
		return f.VUKDeviceSlots[i].DeviceID
	}); err != nil {
		return err
	}
	seen := make(map[string]bool, len(f.VUKDeviceSlots))
	for i := range f.VUKDeviceSlots {
		s := &f.VUKDeviceSlots[i]
		dev := findDevice(current, s.DeviceID)
		if dev == nil || !current.hasRole(dev.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) ||
			seen[s.DeviceID] || s.Recipient != dev.AgeEncryptionKey ||
			s.WrappedVUK == nil || len(s.WrappedVUK) == 0 {
			return Err("", CodeInvalidValue)
		}
		seen[s.DeviceID] = true
	}
	for i := range current.Devices {
		d := &current.Devices[i]
		if current.hasRole(d.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) && !seen[d.DeviceID] {
			return Err("", CodeInvalidValue)
		}
	}
	return nil
}

// validateDraft is the private validation path for the in-memory builder
// draft. It is what RevisionID and ContentSigningBytes accept so a writer can
// derive the preimages before it has a signature.
//
// f may be either shape:
//
//   - builder draft: header.revision_id is "" and content_signature is the
//     null sig {"signer_id":"","alg":"","sig":null} or the shaped signature
//     f is about to be sealed with: signer_id equal to the header's author
//     device, alg that device's content signing algorithm and a 64-byte sig.
//     Any non-empty signer or algorithm beside a null sig is rejected. A
//     draft is only ever built without a revision id, so a revision id in
//     this state is not covered here; a parsed document always carries the
//     member, and content_signature is rejected first when it is not a
//     signature.
//   - sealed: exactly what ValidateFile accepts.
//
// A non-null sig is always checked as a content signature: it must name the
// header's author device, and a non-empty revision id is accepted only when
// f is sealed and carries the exact derived id. No other combination is
// accepted: the carried revision and signature are omitted from the revision
// preimage, but they are still inspected here to decide whether f is a
// draft at all. ParseFile, EncodeFile, FileDigest and ValidateFile never
// take the draft branch of this path: a draft is never a wire record.
func validateDraft(f *File) error {
	current, err := validateStructure(f)
	if err != nil {
		return err
	}
	if err := checkCarriedSignature(f, current); err != nil {
		return err
	}
	if f.Header.RevisionID == "" {
		// A builder draft, with or without its about-to-be-sealed signature:
		// shape-checked above, never sealed.
		return nil
	}
	return validateSealed(f, current)
}

// validateSealed checks that f is the one valid wire state: sealed.
//
//   - content_signature.sig must be non-null, a 64-byte signature by the
//     header's author device with the shape of that device's content signing
//     key, resolved in the current policy. A null sig is an invalid_value at
//     content_signature: a draft is not a wire file.
//   - header.revision_id must be exactly RevisionID of f. A missing one is a
//     missing_field and a different one an invalid_value.
//
// current is the policy validateStructure selected by header policy_seq, not
// whichever proof comes first. Signature bytes are only shape-checked: no
// signature is verified anywhere in this package.
func validateSealed(f *File, current *Policy) error {
	h := &f.Header
	if f.ContentSignature.Sig == nil {
		return Err("content_signature", CodeInvalidValue)
	}
	if h.RevisionID == "" {
		return Err("revision_id", CodeMissingField)
	}
	rev, err := revisionHash(f)
	if err != nil {
		return err
	}
	if h.RevisionID != hex.EncodeToString(rev) {
		return Err("revision_id", CodeInvalidValue)
	}
	if f.ContentSignature.SignerID != h.AuthorDeviceID {
		return Err("", CodeSignatureInvalid)
	}
	return checkContentSigner(h.AuthorDeviceID, current, &f.ContentSignature)
}

// policyDigest is the one and only policy digest (see PolicyDigest) of the
// policy carried in the proof.
func policyDigest(sp *SignedPolicy) []byte {
	return PolicyDigest(&sp.Policy)
}

// PolicyDigest is the SHA-256 digest of a policy, computed outside the policy
// document and never stored inside it: SHA-256(UsagePolicyDocument || 0x00 ||
// canonical policy document bytes). Header.PolicyDigest and the next policy's
// PrevPolicyDigest both reference this one value.
func PolicyDigest(p *Policy) []byte {
	doc, err := EncodePolicyDocument(p)
	if err != nil {
		return nil
	}
	return DomainSeparated(UsagePolicyDocument, doc)
}

// ValidatePolicy checks a policy document on its own.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return Err("", CodeInvalidValue)
	}
	if p.Format != Format || p.Version != Version || !validID(p.VaultID, MaxIDLength) {
		return Err("", CodeInvalidValue)
	}
	// The genesis policy has no predecessor; every later policy references
	// exactly one predecessor digest.
	if p.PolicySeq == 0 && p.PrevPolicyDigest != nil {
		return Err("", CodeInvalidValue)
	}
	if p.PolicySeq > 0 && !validDigest(p.PrevPolicyDigest) {
		return Err("", CodeInvalidValue)
	}
	r := &p.OwnerRoot
	if !validID(r.KeyID, MaxKeyIDLength) || r.Alg != PolicySigAlgEd25519 ||
		!validEd25519Key(r.PublicKey) || len(r.Owners) == 0 || len(r.Owners) > MaxPolicyArrayItems {
		return Err("", CodeInvalidValue)
	}
	if err := checkAscendingIDs("owner_root.owners", len(r.Owners), func(i int) string {
		return r.Owners[i].PrincipalID
	}); err != nil {
		return err
	}
	if err := checkPrincipals(r.Owners); err != nil {
		return err
	}
	// Role arrays may repeat a principal across roles (writer implies reader
	// through the role ordering) but not within one role. Each array is
	// frozen to strictly increasing principal_id order.
	for _, role := range []struct {
		name string
		ps   []Member
	}{{"readers", p.Readers}, {"writers", p.Writers}, {"admins", p.Admins}, {"owners", p.Owners}} {
		if len(role.ps) > MaxPolicyArrayItems {
			return Err("", CodeLimitExceeded)
		}
		if err := checkAscendingIDs(role.name, len(role.ps), func(i int) string {
			return role.ps[i].PrincipalID
		}); err != nil {
			return err
		}
		seen := map[string]bool{}
		for i := range role.ps {
			m := &role.ps[i]
			if !validID(m.PrincipalID, MaxIDLength) || !validLabel(m.Label) || seen[m.PrincipalID] {
				return Err("", CodeInvalidValue)
			}
			seen[m.PrincipalID] = true
		}
	}
	// At least one owner must remain.
	if len(p.Owners) == 0 || len(p.OwnerRoot.Owners) == 0 {
		return Err("", CodeInvalidValue)
	}
	if len(p.Devices) == 0 || len(p.Devices) > MaxArrayItems {
		return Err("", CodeInvalidValue)
	}
	if err := checkAscendingIDs("devices", len(p.Devices), func(i int) string {
		return p.Devices[i].DeviceID
	}); err != nil {
		return err
	}
	devices := map[string]bool{}
	// Purpose separation: every key role in the policy - the owner-root
	// signing key and, on each device, the content signing, optional policy
	// signing and age encryption keys - is distinct global key material. The
	// same 32 raw public-key bytes may not occupy two entries, on one device,
	// two devices, or across root and devices, whatever encoding each role
	// carries them in. The age recipient's X25519 bytes are recovered only
	// after age has validated the string (ageX25519RecipientBytes).
	keys := map[[32]byte]bool{}
	claimKey := func(k [32]byte) error {
		if keys[k] {
			return Err("", CodeInvalidValue)
		}
		keys[k] = true
		return nil
	}
	if err := claimKey(([32]byte)(r.PublicKey)); err != nil {
		return err
	}
	for i := range p.Devices {
		d := &p.Devices[i]
		if !validID(d.DeviceID, MaxDeviceIDLength) || !validID(d.PrincipalID, MaxIDLength) ||
			!validLabel(d.Label) || devices[d.DeviceID] {
			return Err("", CodeInvalidValue)
		}
		devices[d.DeviceID] = true
		// A device acts only with the vault roles of its principal: the
		// principal must be a reader, writer, admin or owner of this policy.
		if !p.hasRole(d.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
			return Err("", CodeInvalidValue)
		}
		if d.ContentSigningKey.Alg != SigAlgEd25519 || !validEd25519Key(d.ContentSigningKey.PublicKey) {
			return Err("", CodeInvalidValue)
		}
		if d.PolicySigningKey != nil {
			if d.PolicySigningKey.Alg != PolicySigAlgEd25519 || !validEd25519Key(d.PolicySigningKey.PublicKey) {
				return Err("", CodeInvalidValue)
			}
		}
		if !validAgeX25519Recipient(d.AgeEncryptionKey) {
			return Err("", CodeInvalidValue)
		}
		if err := claimKey(([32]byte)(d.ContentSigningKey.PublicKey)); err != nil {
			return err
		}
		if d.PolicySigningKey != nil {
			if err := claimKey(([32]byte)(d.PolicySigningKey.PublicKey)); err != nil {
				return err
			}
		}
		ageKey, err := ageX25519RecipientBytes(d.AgeEncryptionKey)
		if err != nil {
			return Err("", CodeInvalidValue)
		}
		if err := claimKey(ageKey); err != nil {
			return err
		}
		// Private keys must never appear in any wire field.
		for _, b := range [][]byte{d.ContentSigningKey.PublicKey, policyKeyBytes(d)} {
			if len(b) == ed25519.PrivateKeySize {
				return Err("", CodeInvalidValue)
			}
		}
	}
	if len(p.AdminDelegations) > MaxDelegations {
		return Err("", CodeLimitExceeded)
	}
	if err := checkAscendingIDs("admin_delegations", len(p.AdminDelegations), func(i int) string {
		return p.AdminDelegations[i].DelegationID
	}); err != nil {
		return err
	}
	delSeen := map[string]bool{}
	for i := range p.AdminDelegations {
		d := &p.AdminDelegations[i]
		if !validID(d.DelegationID, MaxIDLength) || !validID(d.DelegateDevice, MaxDeviceIDLength) ||
			!validID(d.GrantedBy, MaxKeyIDLength) || delSeen[d.DelegationID] ||
			!validLabel(d.ScopeNote) || len(d.ScopeNote) > MaxRoleScopeLength {
			return Err("", CodeInvalidValue)
		}
		delSeen[d.DelegationID] = true
		if !devices[d.DelegateDevice] {
			return Err("", CodeInvalidValue)
		}
		if d.GrantedBy != r.KeyID {
			return Err("", CodeInvalidValue)
		}
		if d.ExpiresPolicySeq != 0 && d.ExpiresPolicySeq <= p.PolicySeq {
			return Err("", CodeInvalidValue)
		}
		// Restricted admin: owner promotion and root replacement are never
		// delegable.
		if d.Scope.PromoteOwner || d.Scope.ReplaceRoot {
			return Err("", CodeInvalidValue)
		}
	}
	return nil
}

func validateSignedPolicy(sp *SignedPolicy) error {
	if len(sp.Document) == 0 || len(sp.Document) > MaxSignedPolicyProofBytes {
		return Err("", CodeLimitExceeded)
	}
	if err := ValidatePolicy(&sp.Policy); err != nil {
		return err
	}
	doc, err := ParsePolicyDocument(sp.Document)
	if err != nil {
		return err
	}
	if !boolEqualPolicy(doc, &sp.Policy) {
		return Err("", CodePolicyMismatch)
	}
	canonical, err := EncodePolicyDocument(&sp.Policy)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, sp.Document) {
		return Err("", CodePolicyMismatch)
	}
	if sp.Alg != PolicySigAlgEd25519 {
		return Err("", CodeSignatureInvalid)
	}
	return checkSignatureShape(&Signature{SignerID: sp.SignerID, Alg: sp.Alg, Sig: sp.Sig}, sp.Alg)
}

func checkSignatureShape(s *Signature, alg string) error {
	if s == nil || !validID(s.SignerID, MaxDeviceIDLength) || s.Alg != alg {
		return Err("", CodeSignatureInvalid)
	}
	if len(s.Sig) != ed25519.SignatureSize {
		return Err("", CodeSignatureInvalid)
	}
	return nil
}

// checkPolicyProofOrder freezes File.SignedPolicyProofs to strictly increasing
// policy_seq order. Equal sequence numbers are rejected by the same rule as a
// decrease: two proofs of one sequence would give one policy value two signed
// encodings. Old-then-current is the only accepted order, so a proof sequence
// that starts at the current policy can only be carried as one proof.
func checkPolicyProofOrder(ps []SignedPolicy) error {
	for i := 1; i < len(ps); i++ {
		if ps[i].Policy.PolicySeq <= ps[i-1].Policy.PolicySeq {
			return Err(pathIndex(fieldSignedPolicyProofs, i, "policy.policy_seq"), CodeUnsortedCollection)
		}
	}
	return nil
}

// checkAscendingIDs freezes one semantically-set array to strictly increasing
// raw-ASCII identifier order: ids are compared bytewise and case-sensitively,
// and a repeated id is rejected by the same rule. It reports
// CodeUnsortedCollection at the path of the first element that breaks the
// order, named by its ID field. The encoder never sorts: input that is
// signed or digested must already carry the one accepted order.
func checkAscendingIDs(collection string, n int, id func(i int) string) error {
	for i := 1; i < n; i++ {
		if id(i) <= id(i-1) {
			return Err(pathIndex(collection, i), CodeUnsortedCollection)
		}
	}
	return nil
}

// pathIndex names element i of an array at path with a zero-based index.
func pathIndex(path string, i int, suffix ...string) string {
	p := path + "[" + strconv.Itoa(i) + "]"
	for _, s := range suffix {
		p += "." + s
	}
	return p
}

func checkPrincipals(ps []Principal) error {
	local := map[string]bool{}
	for i := range ps {
		p := &ps[i]
		if !validID(p.PrincipalID, MaxIDLength) || !validLabel(p.Label) || local[p.PrincipalID] {
			return Err("", CodeInvalidValue)
		}
		local[p.PrincipalID] = true
	}
	return nil
}

// Role names one vault role of a principal. The role order is significant:
// a writer, admin or owner also reads, an admin or owner also writes, and an
// owner also administers. Every role implies the roles before it.
type Role int

const (
	RoleReader Role = iota
	RoleWriter
	RoleAdmin
	RoleOwner
)

// hasRole reports whether principalID holds any of roles in p. A role also
// counts through the implication order: a writer is a reader.
func (p *Policy) hasRole(principalID string, roles ...Role) bool {
	for _, r := range roles {
		if p.hasRoleAtLeast(principalID, r) {
			return true
		}
	}
	return false
}

// hasRoleAtLeast reports whether principalID is listed under role or under any
// stronger role.
func (p *Policy) hasRoleAtLeast(principalID string, role Role) bool {
	lists := [4][]Member{p.Readers, p.Writers, p.Admins, p.Owners}
	for r := role; r <= RoleOwner; r++ {
		for i := range lists[r] {
			if lists[r][i].PrincipalID == principalID {
				return true
			}
		}
	}
	return false
}

func findDevice(p *Policy, id string) *Device {
	for i := range p.Devices {
		if p.Devices[i].DeviceID == id {
			return &p.Devices[i]
		}
	}
	return nil
}

func policyKeyBytes(d *Device) []byte {
	if d.PolicySigningKey == nil {
		return nil
	}
	return d.PolicySigningKey.PublicKey
}

func validID(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
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

func validLabel(s string) bool {
	return utf8.ValidString(s) && len(s) <= MaxLabelLength
}

func validDigest(b []byte) bool {
	return len(b) == sha256.Size
}

// validDigestID reports whether s is a SHA-256 value written as lowercase hex.
func validDigestID(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validEd25519Key(b []byte) bool {
	return len(b) == ed25519.PublicKeySize
}

// validAgeX25519Recipient reports whether s is a well-formed age X25519
// recipient. Delegated to filippo.io/age, which in v1.3.2 checks the Bech32
// encoding and checksum, the "age" HRP/type and that the payload is exactly
// 32 bytes. It does not check the curve point or reject low-order points at
// parse time; no cryptographic operation happens here.
func validAgeX25519Recipient(s string) bool {
	_, err := ageX25519RecipientBytes(s)
	return err == nil
}

// ageX25519RecipientBytes returns the raw 32 public-key bytes of a valid age
// X25519 recipient string. It is the binary form purpose separation compares,
// so the same key written as an age recipient and as an Ed25519 public key is
// one key, not two display strings.
//
// The gate is age.ParseX25519Recipient at the pinned v1.3.2: it validates the
// Bech32 encoding and checksum, the "age" HRP/type, and (in
// newX25519RecipientFromPoint) exactly 32 payload bytes. It does not check the
// curve point or reject low-order points at parse time. age keeps the payload
// in an unexported field with no raw accessor, and this package does not reach
// into it with reflection or unsafe. After that successful parse, the smallest
// Bech32 extraction needed recovers the payload from age's canonical
// recipient.String() output (lowercase "age1" text), never from the caller's
// string directly. That extraction validates only shape, payload length and a
// canonical round trip; it does not re-check the checksum, the type or the
// curve point.
func ageX25519RecipientBytes(s string) (k [32]byte, err error) {
	if len(s) > MaxPublicKeyLength || !strings.HasPrefix(s, AgeX25519RecipientPrefix) {
		return k, Err("", CodeInvalidValue)
	}
	// Identity (private key) material must never be accepted, whatever
	// case convention it is written in.
	if strings.HasPrefix(strings.ToUpper(s), AgeX25519IdentityPrefix) {
		return k, Err("", CodeInvalidValue)
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return k, Err("", CodeInvalidValue)
	}
	if err := decodeAgeRecipientPayload(r.String(), &k); err != nil {
		return k, Err("", CodeInvalidValue)
	}
	return k, nil
}

// ageBech32Charset is the BIP-173 data alphabet age encodes recipients in.
const ageBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// decodeAgeRecipientPayload recovers the 32-byte X25519 payload from canonical,
// already-validated age X25519 recipient text. It checks only encoding shape:
// lowercase, the "age" prefix, exactly 52 data characters (a 32-byte payload
// in 5-bit groups with zero padding plus a 6-character checksum) and that the
// recovered bytes encode back to exactly s. The checksum itself is not
// recomputed: age.ParseX25519Recipient has already verified it.
func decodeAgeRecipientPayload(s string, k *[32]byte) error {
	if len(s) != len(AgeX25519RecipientPrefix)+58 || !strings.HasPrefix(s, AgeX25519RecipientPrefix) {
		return Err("", CodeInvalidValue)
	}
	const dataLen, groupBits = 52, 5
	data := s[len(AgeX25519RecipientPrefix):]
	var acc uint32
	var bits uint
	var out []byte
	for i := 0; i < dataLen; i++ {
		v := strings.IndexByte(ageBech32Charset, data[i])
		if v < 0 {
			return Err("", CodeInvalidValue)
		}
		acc = acc<<groupBits | uint32(v)
		bits += groupBits
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	// 52 groups carry 260 bits: 256 payload bits and one zero-bit pad that
	// carries no value.
	if len(out) != len(k) || acc&(1<<bits-1) != 0 {
		return Err("", CodeInvalidValue)
	}
	for i := range out {
		k[i] = out[i]
	}
	// Canonical round-trip: k re-encoded must reproduce s exactly, so no
	// non-canonical spelling is admitted.
	if canonicalAgeRecipient(k) != s {
		return Err("", CodeInvalidValue)
	}
	return nil
}

// canonicalAgeRecipient encodes the 32-byte X25519 payload k as the age Bech32
// recipient string "age1" || 52 data characters || 6 checksum characters
// (BIP-173, checksum constant 1). It is the independent inverse used only to
// confirm that decodeAgeRecipientPayload recovered the canonical spelling.
func canonicalAgeRecipient(k *[32]byte) string {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	const hrp, dataLen, checksumLen = "age", 52, 6
	// 32 bytes are 256 bits: 51 full 5-bit groups and one zero-padded group.
	var acc uint32
	var bits uint
	var data [dataLen]byte
	n := 0
	for _, b := range k {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data[n] = byte(acc>>bits) & 31
			n++
		}
	}
	if bits > 0 {
		data[n] = byte(acc<<(5-bits)) & 31
		n++
	}
	if n != dataLen {
		panic("vaultfile: unexpected bech32 group count")
	}
	// BIP-173 polymod over the expanded HRP, the data and six zero
	// placeholder characters, XOR 1.
	chk := uint32(1)
	polymod := func(v uint32) {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := range gen {
			if top>>i&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	for _, c := range []byte(hrp) {
		polymod(uint32(c >> 5))
	}
	polymod(0)
	for _, c := range []byte(hrp) {
		polymod(uint32(c & 31))
	}
	for _, v := range data {
		polymod(uint32(v))
	}
	for i := 0; i < checksumLen; i++ {
		polymod(0)
	}
	mod := chk ^ 1
	var groups [dataLen + checksumLen]byte
	copy(groups[:], data[:])
	for i := 0; i < checksumLen; i++ {
		groups[dataLen+i] = byte(mod >> uint(5*(checksumLen-1-i)) & 31)
	}
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, g := range groups {
		sb.WriteByte(ageBech32Charset[g])
	}
	return sb.String()
}

// ---- role and key binding ----

// checkCarriedSignature checks the content signature shape and signer of f
// independently of its revision id, so a builder draft that carries the
// signature it is about to be sealed with gets the same shape rules as a
// sealed file. A null sig must be the exact null signature.
func checkCarriedSignature(f *File, current *Policy) error {
	s := &f.ContentSignature
	if s.Sig == nil {
		if s.SignerID != "" || s.Alg != "" {
			return Err("", CodeSignatureInvalid)
		}
		return nil
	}
	if s.SignerID != f.Header.AuthorDeviceID {
		return Err("", CodeSignatureInvalid)
	}
	return checkContentSigner(f.Header.AuthorDeviceID, current, s)
}

// canAuthor reports whether deviceID is a device of p whose principal may
// author content: a writer, admin or owner. A reader, or a principal that
// holds no role or no longer carries the device, may not.
func (p *Policy) canAuthor(deviceID string) bool {
	d := findDevice(p, deviceID)
	return d != nil && p.hasRole(d.PrincipalID, RoleWriter, RoleAdmin, RoleOwner)
}

// checkContentSigner requires deviceID to be a policy device and s to have
// the shape of a signature by that device's content signing key.
func checkContentSigner(deviceID string, p *Policy, s *Signature) error {
	d := findDevice(p, deviceID)
	if d == nil {
		return Err("", CodeSignatureInvalid)
	}
	return checkSignatureShape(s, d.ContentSigningKey.Alg)
}

func boolEqualPolicy(a, b *Policy) bool {
	ea, err := policyEqualBytes(a)
	if err != nil {
		return false
	}
	eb, err := policyEqualBytes(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ea, eb)
}

func policyEqualBytes(p *Policy) ([]byte, error) {
	var b bytes.Buffer
	writePolicy(&b, p)
	return b.Bytes(), nil
}

// ---- canonical signed forms ----

// FileBytes is the exact byte sequence stored for a sealed file, provided f is
// the parsed form of it. Like EncodeFile it rejects a draft.
func FileBytes(f *File) ([]byte, error) { return EncodeFile(f) }

// CanonicalPolicyBytes folds a policy: insist the document bytes carried in
// the proof are the canonical encoding so encoders and verifiers agree.
func CanonicalPolicyBytes(sp *SignedPolicy) ([]byte, error) {
	return EncodePolicyDocument(&sp.Policy)
}

// ValidateHeader validates a header on its own: types, value rules and sizes.
// Whether PrevDigest matches a known parent is a sync decision, not a wire one.
//
// RevisionID is 32 bytes as lowercase hex, the size of a SHA-256 value, in a
// sealed file and "" only in an in-memory builder draft, which is not a wire
// record. Over the wire ValidateFile always rejects an empty one, so an empty
// revision id is never a wire value. The header alone cannot check the
// binding: that a sealed file carries exactly its derived revision id is
// checked by ValidateFile.
func ValidateHeader(h *Header) error {
	if h == nil {
		return Err("", CodeInvalidValue)
	}
	if !validID(h.VaultID, MaxIDLength) ||
		!validID(h.OpID, MaxIDLength) ||
		!validID(h.AuthorDeviceID, MaxDeviceIDLength) {
		return Err("", CodeInvalidValue)
	}
	// A builder draft has no revision id; a sealed file carries it as
	// lowercase hex. Here it is only checked for shape; the header alone
	// cannot recompute the derivation or enforce that it is present.
	if h.RevisionID != "" && !validDigestID(h.RevisionID) {
		return Err("", CodeInvalidValue)
	}
	if h.ContentSeq == 0 && h.PrevDigest != nil {
		return Err("", CodeInvalidValue)
	}
	if h.ContentSeq > 0 && !validDigest(h.PrevDigest) {
		return Err("", CodeInvalidValue)
	}
	if !validDigest(h.PolicyDigest) {
		return Err("", CodeInvalidValue)
	}
	return nil
}
