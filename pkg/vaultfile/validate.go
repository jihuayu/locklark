package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

// ValidateFile checks every structural rule of the schema, length and size
// budget included. It performs no cryptographic verification: signatures and
// wrapped keys are only checked for shape and consistency.
func ValidateFile(f *File) error {
	if f == nil {
		return Err("", CodeInvalidValue)
	}
	if f.Format != Format {
		return Err("", CodeInvalidValue)
	}
	if f.Version != Version {
		return Err("", CodeInvalidValue)
	}
	h := &f.Header
	if err := ValidateHeader(h); err != nil {
		return err
	}
	if f.ContentEncoding != ContentEncoding {
		return Err("", CodeInvalidValue)
	}
	if f.KDBXCiphertext == nil || len(f.KDBXCiphertext) > MaxKDBXCiphertextBytes {
		return Err("", CodeLimitExceeded)
	}
	if len(f.SignedPolicyProofs) == 0 || len(f.SignedPolicyProofs) > MaxArrayItems {
		return Err("", CodeInvalidValue)
	}
	for i := range f.SignedPolicyProofs {
		sp := &f.SignedPolicyProofs[i]
		if err := validateSignedPolicy(sp); err != nil {
			return err
		}
		if sp.Policy.VaultID != h.VaultID {
			return Err("", CodeHeaderMismatch)
		}
	}
	// Exactly one proof must carry the current policy (header policy_seq).
	// Its digest is computed here from the carried document bytes;
	// Policy.PolicyDigest is an opaque member and is not used as trust.
	var current *Policy
	for i := range f.SignedPolicyProofs {
		sp := &f.SignedPolicyProofs[i]
		if sp.Policy.PolicySeq != h.PolicySeq {
			continue
		}
		if current != nil {
			return Err("", CodeInvalidValue)
		}
		if !bytes.Equal(policyDigest(sp), h.PolicyDigest) {
			return Err("", CodeHeaderMismatch)
		}
		current = &sp.Policy
	}
	if current == nil {
		return Err("", CodeHeaderMismatch)
	}
	if err := checkSigner(h.AuthorDeviceID, current, ContentSigner, &f.ContentSignature); err != nil {
		return err
	}
	// The content signature must name the authoring device itself; a valid
	// device id alone is not enough.
	if f.ContentSignature.SignerID != h.AuthorDeviceID {
		return Err("", CodeSignatureInvalid)
	}
	// A file may only be authored by a device whose principal is a writer,
	// admin or owner. Readers hold no content signing authority.
	author := findDevice(current, h.AuthorDeviceID)
	if !current.hasRole(author.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) {
		return Err("", CodeInvalidValue)
	}
	var headerSigner *Device
	for i := range current.Devices {
		d := &current.Devices[i]
		if d.DeviceID == f.HeaderSig.SignerID {
			headerSigner = d
			break
		}
	}
	if headerSigner == nil || headerSigner.PolicySigningKey == nil {
		return Err("", CodeSignatureInvalid)
	}
	if err := checkSignatureShape(&f.HeaderSig, headerSigner.PolicySigningKey.Alg); err != nil {
		return err
	}
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

// policyDigest is SHA-256 over the purpose domain and the canonical policy
// document bytes carried in the proof.
func policyDigest(sp *SignedPolicy) []byte {
	return DomainSeparated(UsagePolicyDocument, sp.Document)
}

// ValidatePolicy checks a policy document on its own.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return Err("", CodeInvalidValue)
	}
	if p.Format != Format || p.Version != Version || !validID(p.VaultID, MaxIDLength) {
		return Err("", CodeInvalidValue)
	}
	if !validDigest(p.PolicyDigest) {
		return Err("", CodeInvalidValue)
	}
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
	if err := checkPrincipals(r.Owners); err != nil {
		return err
	}
	// Role arrays may repeat a principal across roles (writer implies reader
	// through the role ordering) but not within one role.
	for _, role := range []struct {
		name string
		ps   []Member
	}{{"readers", p.Readers}, {"writers", p.Writers}, {"admins", p.Admins}, {"owners", p.Owners}} {
		if len(role.ps) > MaxPolicyArrayItems {
			return Err("", CodeLimitExceeded)
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
	devices := map[string]bool{}
	keys := map[string]string{}
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
		// Purpose separation: no key may serve two roles, on this device or
		// any other; the same raw bytes in different encodings are caught
		// too because all three canonical encodings are carried here.
		sep := [][2]string{
			{"content_signing", string(d.ContentSigningKey.PublicKey)},
			{"policy_signing", string(policyKeyBytes(d))},
			{"age_encryption", d.AgeEncryptionKey},
		}
		for _, kv := range sep {
			if kv[1] == "" {
				continue
			}
			if _, ok := keys[kv[1]]; ok {
				return Err("", CodeInvalidValue)
			}
			keys[kv[1]] = kv[0]
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

func validEd25519Key(b []byte) bool {
	return len(b) == ed25519.PublicKeySize
}

// validAgeX25519Recipient reports whether s is a well-formed age X25519
// recipient. Delegated to filippo.io/age so Bech32, the checksum and the
// 32-byte X25519 point are checked by the reference implementation; no
// cryptographic operation beyond parsing the public key happens here.
func validAgeX25519Recipient(s string) bool {
	if len(s) > MaxPublicKeyLength || !strings.HasPrefix(s, AgeX25519RecipientPrefix) {
		return false
	}
	// Identity (private key) material must never be accepted, whatever
	// case convention it is written in.
	if strings.HasPrefix(strings.ToUpper(s), AgeX25519IdentityPrefix) {
		return false
	}
	_, err := age.ParseX25519Recipient(s)
	return err == nil
}

// ---- role and key binding ----

// SignerRole says which policy key a signature must be checked with.
type SignerRole int

const (
	ContentSigner SignerRole = iota
	PolicySigner
)

func checkSigner(deviceID string, p *Policy, role SignerRole, s *Signature) error {
	d := findDevice(p, deviceID)
	if d == nil {
		return Err("", CodeSignatureInvalid)
	}
	switch role {
	case ContentSigner:
		return checkSignatureShape(s, d.ContentSigningKey.Alg)
	case PolicySigner:
		if d.PolicySigningKey == nil {
			return Err("", CodeSignatureInvalid)
		}
		return checkSignatureShape(s, d.PolicySigningKey.Alg)
	}
	return Err("", CodeSignatureInvalid)
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

// HeaderBytes returns the canonical encoding of the header that HeaderSig
// covers.
func HeaderBytes(h *Header) []byte {
	var b bytes.Buffer
	writeHeader(&b, h)
	return b.Bytes()
}

// FileBytes is the exact byte sequence stored for a file, provided f is the
// parsed form of it.
func FileBytes(f *File) ([]byte, error) { return EncodeFile(f) }

// CanonicalPolicyBytes folds a policy: insist the document bytes carried in
// the proof are the canonical encoding so encoders and verifiers agree.
func CanonicalPolicyBytes(sp *SignedPolicy) ([]byte, error) {
	return EncodePolicyDocument(&sp.Policy)
}

// ValidateHeader validates a header on its own: types, value rules and sizes.
// Whether PrevDigest matches a known parent is a sync decision, not a wire one.
func ValidateHeader(h *Header) error {
	if h == nil {
		return Err("", CodeInvalidValue)
	}
	if !validID(h.VaultID, MaxIDLength) ||
		!validID(h.RevisionID, MaxIDLength) ||
		!validID(h.OpID, MaxIDLength) ||
		!validID(h.AuthorDeviceID, MaxDeviceIDLength) {
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
