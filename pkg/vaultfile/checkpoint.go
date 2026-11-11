package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"slices"
)

// CodePolicyCheckpointFailed is reported by VerifyPolicyCheckpoint when the
// carried policy chain does not continue the caller-pinned checkpoint: a
// different vault, an anchor at the checkpoint sequence with a different
// digest or a foreign owner root, a stale or rolled-back tip, a chain gap, a
// prev_policy_digest that does not name the previous trusted digest, a
// continuation naming a different owner root, a non-root signer that the
// authenticated predecessor policy does not authorize for an InviteReaders
// transition, or, when and only when the anchor is omitted, a carried chain
// that does not begin exactly at the checkpoint sequence + 1 with a
// prev_policy_digest equal to the checkpoint digest, or whose first proof is
// not root-signed, because no predecessor body is then authenticated to
// authorize a delegated signer. Omitting the anchor is not a failure on its
// own: such a file is accepted when its first proof is exactly the
// checkpoint sequence + 1 linked to the checkpoint digest. The carried anchor
// is the proof at the checkpoint sequence; every accepted proof after it
// carries exactly the previous sequence + 1, and proofs before the anchor may
// be carried and are ignored. A continuation whose crypto/ed25519 signature
// does not verify is not this code; it is CodeSignatureVerifyFailed. Each
// case is a caller trust decision, not a structural defect of the file.
const CodePolicyCheckpointFailed = "policy_checkpoint_failed"

// PolicyCheckpoint is the caller's already-trusted policy state: the policy
// sequence and its digest (PolicyDigest) together with the owner root that
// owns it. A checkpoint is derived out of band, from a trusted sharing or
// pairing exchange or from recovery; this package neither creates nor infers
// one. A PolicyCheckpoint is caller-owned: VerifyPolicyCheckpoint reads its
// fields and the bytes of OwnerRootPublicKey and PolicyDigest during the
// call and does not retain a pointer or slices to it after the call returns;
// the verifier clones PolicyDigest internally, so that clone is the only
// byte copy. The caller must keep its fields and input bytes stable while
// the call runs. Mutating them concurrently, or after the call without
// treating that as a new checkpoint, is a caller error this package cannot
// detect.
type PolicyCheckpoint struct {
	VaultID            string
	OwnerRootKeyID     string
	OwnerRootPublicKey ed25519.PublicKey
	PolicySeq          uint64
	PolicyDigest       []byte
}

// VerifyPolicyCheckpoint authenticates f against the caller-pinned
// checkpoint c and then verifies f's content signature with the content
// signing key of the authenticated current policy.
//
// f must pass ValidateFile; any structural or sealed-state error is returned
// unchanged. Then, in order:
//
//   - f.Header.VaultID and every carried proof's policy vault must equal
//     c.VaultID, and c.VaultID, c.OwnerRootKeyID, a 32-byte
//     c.OwnerRootPublicKey and a 32-byte c.PolicyDigest must be valid;
//   - the anchor proof is located in the carried proofs and its digest must
//     equal c.PolicyDigest, and its owner root (key_id, alg and public key)
//     must equal c; proofs before it are ignored. A file whose proofs
//     begin after c.PolicySeq must begin exactly at c.PolicySeq+1 with that
//     proof's prev_policy_digest equal to c.PolicyDigest. Proofs are strictly
//     increasing and end at the current policy (header policy_seq), so a
//     file whose current policy is behind c.PolicySeq is stale;
//   - the anchor proof is trusted by the caller-supplied digest alone: its
//     signer_id, alg and sig are not examined again. Every later proof must
//     carry exactly the previous sequence + 1, prev_policy_digest equal to
//     the previous trusted digest and the owner root equal to c (key_id and
//     public key), and a crypto/ed25519 signature over exactly
//     DomainPolicyDocumentSignature || 0x00 || SignedPolicy.Document, the
//     frozen v1 policy-document preimage. A proof whose SignerID is
//     c.OwnerRootKeyID is root-signed and is unrestricted by the policy diff.
//     Any other SignerID must name a device in the authenticated predecessor
//     policy whose principal is an Admin or Owner there, that carries an
//     Ed25519 PolicySigningKey, and that an active AdminDelegation in that
//     same predecessor (a zero expiry, unbounded, or an expiry after the
//     predecessor sequence) names with Scope.InviteReaders true; the proof
//     must verify under exactly that
//     device's PolicySigningKey, and inviteReadersPolicyDiff(predecessor, next)
//     must accept the old-to-new delta. Authority is never read from the
//     successor's own delegation;
//   - having authenticated the chain, the content signature is verified
//     with the content signing key recorded for header.author_device_id in
//     the authenticated current policy, over DomainContentSignature || 0x00
//     || ContentSigningBytes(f). No key is taken from an unauthenticated
//     proof, and ValidateFile has already required the author's principal to
//     be a writer, admin or owner of the current policy.
//
// The only admin-signed transition supported is the InviteReaders one
// described above: adding readers, with optionally their devices, and nothing
// else that inviteReadersPolicyDiff forbids. Every DelegationScope other than
// InviteReaders, reader removal or edits, role changes, device edits and
// delegation changes are not delegated by this API and must be root-signed.
// When the anchor is omitted, the first proof has no authenticated
// predecessor body and must be root-signed; the policy it establishes may
// then authorize a later delegated InviteReaders transition. There is no
// reinterpretation of a delegated transition as a root-signed one.
//
// A nil return means only that the current content signature is authorized
// under this caller-pinned checkpoint and the root- or InviteReaders-signed
// continuation that leads from it. It does not prove server freshness, content-history
// continuity through prev_digest, encryption or wrapping correctness, or
// overall vault trust. VerifyContentSignature is unchanged and remains the
// narrower pinned-key check.
//
// Errors:
//   - structural, vault-consistency and role-membership failures are
//     returned from ValidateFile unchanged; a header author whose device is
//     missing from the carried current policy, or whose principal no longer
//     holds a writer, admin or owner role (removed or demoted), is an
//     invalid_value with an empty path, reported before the sealed revision
//     binding, because current.canAuthor and validateStructure run before
//     any signature lookup;
//   - structural and shape failures are returned unchanged from ValidateFile,
//     including invalid policy content-key shapes; after validation the
//     cryptographic failures of the policy and content signatures are
//     CodeSignatureVerifyFailed as listed below. A device listed without an
//     Ed25519 content signing key cannot be rejected as signature_shape_invalid
//     here, because validation rejects the invalid policy first;
//   - a nil c, or a checkpoint whose vault ID or root key ID is not a valid
//     identifier, whose root public key is not 32 bytes or whose digest is
//     not 32 bytes, is an invalid_value: the supplied anchor itself is
//     malformed;
//   - vault, anchor, tip, gap, link, root or delegated-transition
//     authorization failures (a missing predecessor for a non-root proof, or
//     an unauthorized, missing-role, missing-delegation, missing-scope,
//     missing-key or forbidden-diff transition) are *Error with Code
//     CodePolicyCheckpointFailed and an empty path;
//   - a policy proof signature that does not verify is *Error with Code
//     CodeSignatureVerifyFailed and path signed_policy_proofs[i];
//   - a content signature that does not verify is *Error with Code
//     CodeSignatureVerifyFailed and an empty path.
func VerifyPolicyCheckpoint(f *File, c *PolicyCheckpoint) error {
	if f == nil || c == nil {
		return Err("", CodeInvalidValue)
	}
	current, err := validateStructure(f)
	if err != nil {
		return err
	}
	if !current.canAuthor(f.Header.AuthorDeviceID) {
		// Reported before the sealed revision binding so a file whose author
		// is no longer authorized fails as such, not as a stale revision id.
		return Err("", CodeInvalidValue)
	}
	if err := validateSealed(f, current); err != nil {
		return err
	}
	if !validID(c.VaultID, MaxIDLength) || !validID(c.OwnerRootKeyID, MaxKeyIDLength) ||
		!validEd25519Key(c.OwnerRootPublicKey) || !validDigest(c.PolicyDigest) {
		return Err("", CodeInvalidValue)
	}
	if f.Header.VaultID != c.VaultID {
		return Err("", CodePolicyCheckpointFailed)
	}
	for i := range f.SignedPolicyProofs {
		if f.SignedPolicyProofs[i].Policy.VaultID != c.VaultID {
			return Err("", CodePolicyCheckpointFailed)
		}
	}

	// Locate the caller's trusted checkpoint. The anchor is the carried
	// proof at c.PolicySeq whose digest is c.PolicyDigest; proofs before it
	// are already established and are ignored. When no proof at c.PolicySeq
	// is carried, the slice must begin exactly at c.PolicySeq+1 and its first
	// proof must name c.PolicyDigest as its predecessor. A file whose
	// policies all precede c.PolicySeq is behind the checkpoint (stale).
	proofs := f.SignedPolicyProofs
	anchor := -1
	for i := range proofs {
		if proofs[i].Policy.PolicySeq != c.PolicySeq {
			continue
		}
		if !bytes.Equal(policyDigest(&proofs[i]), c.PolicyDigest) {
			continue
		}
		// The anchor policy's owner root must be the caller-pinned root:
		// the digest alone does not bind it, and a later proof that names
		// the pinned root would otherwise accept a foreign root transition.
		if proofs[i].Policy.OwnerRoot.KeyID != c.OwnerRootKeyID ||
			proofs[i].Policy.OwnerRoot.Alg != PolicySigAlgEd25519 ||
			!bytes.Equal(proofs[i].Policy.OwnerRoot.PublicKey, c.OwnerRootPublicKey) {
			return Err("", CodePolicyCheckpointFailed)
		}
		anchor = i
		break
	}
	if anchor < 0 {
		switch {
		case proofs[0].Policy.PolicySeq > c.PolicySeq:
			if c.PolicySeq == math.MaxUint64 || proofs[0].Policy.PolicySeq != c.PolicySeq+1 ||
				!bytes.Equal(proofs[0].Policy.PrevPolicyDigest, c.PolicyDigest) {
				return Err("", CodePolicyCheckpointFailed)
			}
		case proofs[len(proofs)-1].Policy.PolicySeq >= c.PolicySeq:
			// The checkpoint sequence is carried but its digest differs.
			return Err("", CodePolicyCheckpointFailed)
		default:
			// The current policy is behind the checkpoint: a stale file.
			return Err("", CodePolicyCheckpointFailed)
		}
	}

	// The digest of the newest policy established as trusted, and the
	// authenticated body of that policy. The anchor is trusted by the caller
	// digest; without it there is no predecessor body, so the first proof
	// must be root-signed.
	trusted := bytes.Clone(c.PolicyDigest)
	trustedPolicy := (*Policy)(nil)
	prevSeq := c.PolicySeq
	first := 0
	if anchor >= 0 {
		// The anchor is trusted by c.PolicyDigest; its sig is unused.
		first = anchor + 1
		trustedPolicy = &proofs[anchor].Policy
	}
	for i := first; i < len(proofs); i++ {
		sp := &proofs[i]
		seq := sp.Policy.PolicySeq
		if prevSeq == math.MaxUint64 || seq != prevSeq+1 ||
			!bytes.Equal(sp.Policy.PrevPolicyDigest, trusted) ||
			sp.Policy.OwnerRoot.KeyID != c.OwnerRootKeyID ||
			!bytes.Equal(sp.Policy.OwnerRoot.PublicKey, c.OwnerRootPublicKey) ||
			sp.Policy.OwnerRoot.Alg != PolicySigAlgEd25519 {
			return Err("", CodePolicyCheckpointFailed)
		}
		key := ed25519.PublicKey(c.OwnerRootPublicKey)
		if sp.SignerID != c.OwnerRootKeyID {
			// A non-root signer is authorized only by the authenticated
			// predecessor policy, never by the successor's own delegation.
			if trustedPolicy == nil || !delegatedInviteReadersAuthorized(trustedPolicy, sp.SignerID, &sp.Policy) {
				return Err("", CodePolicyCheckpointFailed)
			}
			key = ed25519.PublicKey(findDevice(trustedPolicy, sp.SignerID).PolicySigningKey.PublicKey)
		}
		msg := make([]byte, 0, len(DomainPolicyDocumentSignature)+1+len(sp.Document))
		msg = append(msg, DomainPolicyDocumentSignature...)
		msg = append(msg, 0)
		msg = append(msg, sp.Document...)
		if !ed25519.Verify(key, msg, sp.Sig) {
			return Err(pathIndex(fieldSignedPolicyProofs, i), CodeSignatureVerifyFailed)
		}
		trusted = policyDigest(sp)
		// The caller may share policy bytes between proofs, so the
		// authenticated body is copied, never pointed into the proofs, and
		// the copy is what authorizes the next proof.
		trustedPolicy = clonePolicy(&sp.Policy)
		prevSeq = seq
	}

	// The chain is authenticated; only now does the current policy decide
	// which key may have signed the content.
	signer := f.Header.AuthorDeviceID
	dev := findDevice(current, signer)
	if dev == nil || dev.ContentSigningKey.Alg != SigAlgEd25519 {
		return Err("", CodeSignatureInvalid)
	}
	input, err := contentSigningBytes(f, false)
	if err != nil {
		return err
	}
	cmsg := make([]byte, 0, len(DomainContentSignature)+1+len(input))
	cmsg = append(cmsg, DomainContentSignature...)
	cmsg = append(cmsg, 0)
	cmsg = append(cmsg, input...)
	if !ed25519.Verify(ed25519.PublicKey(dev.ContentSigningKey.PublicKey), cmsg, f.ContentSignature.Sig) {
		return Err("", CodeSignatureVerifyFailed)
	}
	return nil
}

// delegatedInviteReadersAuthorized reports whether prev, an already
// authenticated predecessor policy, authorizes the non-root device signer to
// sign next as an InviteReaders transition: signer must name a device in prev
// whose principal is an Admin or Owner in prev, that device must carry an
// Ed25519 PolicySigningKey, an active AdminDelegation in prev (a zero expiry,
// which ValidatePolicy treats as unbounded, or an expiry after
// prev.PolicySeq) must name that device with InviteReaders in its scope, and
// inviteReadersPolicyDiff(prev, next) must accept. The successor is inspected
// only through the diff, never for delegation.
func delegatedInviteReadersAuthorized(prev *Policy, signer string, next *Policy) bool {
	dev := findDevice(prev, signer)
	if dev == nil || prev.PolicySeq == math.MaxUint64 ||
		!prev.hasRole(dev.PrincipalID, RoleAdmin, RoleOwner) ||
		dev.PolicySigningKey == nil ||
		dev.PolicySigningKey.Alg != PolicySigAlgEd25519 ||
		!validEd25519Key(dev.PolicySigningKey.PublicKey) {
		return false
	}
	// ValidatePolicy rejects only a non-zero expiry at or before the policy
	// sequence, so a zero expiry is unbounded and stays active here.
	delegated := false
	for _, d := range prev.AdminDelegations {
		if d.DelegateDevice == dev.DeviceID &&
			(d.ExpiresPolicySeq == 0 || d.ExpiresPolicySeq > prev.PolicySeq) &&
			d.Scope.InviteReaders {
			delegated = true
			break
		}
	}
	return delegated && inviteReadersPolicyDiff(prev, next)
}

// inviteReadersPolicyDiff reports whether next is exactly the approved
// InviteReaders transition from the authenticated predecessor old. Both
// policies must already pass ValidatePolicy; this predicate is a pure,
// side-effect-free check of the old-to-new delta alone and does not inspect
// any proof, signer, signature or delegation scope. Arrays are compared by
// identifier, never by position: the frozen wire order is a property of each
// policy, so a newly added id may sort before an existing one.
//
// old and next must carry the same format, version, VaultID and complete
// owner root (key ID, algorithm, public key bytes and OwnerRoot.Owners), with
// next.PolicySeq == old.PolicySeq+1 and next.PrevPolicyDigest equal to
// PolicyDigest(old).
//
// The only permitted member change is an addition of between one and
// MaxPolicyArrayItems readers, and at least one reader must be new. Every old
// reader must appear unchanged by principal ID (same label) somewhere in next
// Readers, and every next reader that is not an old reader is a new reader
// which must be absent from old Readers, Writers, Admins, Owners and
// OwnerRoot.Owners. New readers must be absent from the next policy's other
// roles and root owners as well, which forbids promotions and role changes.
// Writers, Admins and Owners are unchanged exactly.
//
// Devices may be added, 0..MaxArrayItems of them, but every old device must
// appear unchanged by DeviceID in next Devices, and no old device may be
// removed or edited. A new device may sit anywhere in the sorted next array
// and must belong to a newly added reader; the root may add zero devices for
// a new reader.
//
// AdminDelegations may not be added or modified. Every old delegation is
// carried unchanged, except that a delegation which expires at
// next.PolicySeq is omitted: ValidatePolicy rejects a grant carried at its
// own expiry sequence, so this one boundary is the only permitted removal.
// No unexpired grant may be removed and no scope or expiry may change.
//
// Exhaustion of the policy sequence, or an unrepresentable count of new
// readers, fails. Any other delta fails. Structural validity, array order and
// key uniqueness remain ValidatePolicy's job; inputs are only read.
func inviteReadersPolicyDiff(old, next *Policy) bool {
	if old == nil || next == nil ||
		old.Format != next.Format || old.Version != next.Version ||
		old.VaultID != next.VaultID || old.PolicySeq == math.MaxUint64 ||
		next.PolicySeq != old.PolicySeq+1 {
		return false
	}
	if !bytes.Equal(next.PrevPolicyDigest, PolicyDigest(old)) {
		return false
	}
	if old.OwnerRoot.KeyID != next.OwnerRoot.KeyID ||
		old.OwnerRoot.Alg != next.OwnerRoot.Alg ||
		!bytes.Equal(old.OwnerRoot.PublicKey, next.OwnerRoot.PublicKey) ||
		!slices.Equal(old.OwnerRoot.Owners, next.OwnerRoot.Owners) {
		return false
	}
	// Every role other than readers is exactly unchanged: no additions, no
	// removals and no label edits.
	if !slices.Equal(old.Writers, next.Writers) ||
		!slices.Equal(old.Admins, next.Admins) ||
		!slices.Equal(old.Owners, next.Owners) {
		return false
	}

	// Readers may only grow, and only by new principals. Membership is
	// matched by principal ID, so a new reader may sort before an old one.
	if len(next.Readers) <= len(old.Readers) || len(next.Readers) > MaxPolicyArrayItems {
		return false
	}
	oldReader := memberSet(old.Readers)
	for id, label := range oldReader {
		m, ok := memberByID(next.Readers, id)
		if !ok || m != label {
			return false
		}
	}
	inRole := map[string]bool{}
	for _, ms := range [][]Member{old.Readers, old.Writers, old.Admins, old.Owners, next.Writers, next.Admins, next.Owners} {
		for _, m := range ms {
			inRole[m.PrincipalID] = true
		}
	}
	for _, pr := range old.OwnerRoot.Owners {
		inRole[pr.PrincipalID] = true
	}
	for _, pr := range next.OwnerRoot.Owners {
		inRole[pr.PrincipalID] = true
	}
	added := map[string]bool{}
	for _, m := range next.Readers {
		if _, ok := oldReader[m.PrincipalID]; ok {
			continue
		}
		if inRole[m.PrincipalID] {
			return false
		}
		added[m.PrincipalID] = true
	}

	// Every old device is carried unchanged, wherever it sorts; every new
	// device belongs to a newly added reader. Devices are never removed.
	if len(next.Devices) < len(old.Devices) || len(next.Devices) > MaxArrayItems {
		return false
	}
	for i := range old.Devices {
		dev, ok := lookupDevice(next.Devices, old.Devices[i].DeviceID)
		if !ok || !equalDevice(&old.Devices[i], dev) {
			return false
		}
	}
	for i := range next.Devices {
		d := &next.Devices[i]
		if _, ok := lookupDevice(old.Devices, d.DeviceID); ok {
			continue
		}
		if !added[d.PrincipalID] {
			return false
		}
	}

	// No delegation is added or modified. Each old delegation is either
	// carried unchanged or, when it expires exactly at next.PolicySeq, is not
	// carried at all.
	want := make(map[string]AdminDelegation, len(old.AdminDelegations))
	for _, d := range old.AdminDelegations {
		want[d.DelegationID] = d
	}
	for _, d := range next.AdminDelegations {
		prev, ok := want[d.DelegationID]
		if !ok || prev != d {
			return false
		}
		delete(want, d.DelegationID)
	}
	for _, d := range want {
		if d.ExpiresPolicySeq != next.PolicySeq {
			return false
		}
	}
	return true
}

// memberSet indexes members by principal ID and label.
func memberSet(ms []Member) map[string]Member {
	set := make(map[string]Member, len(ms))
	for _, m := range ms {
		set[m.PrincipalID] = m
	}
	return set
}

// memberByID returns the member with principal ID id, wherever it sorts.
func memberByID(ms []Member, id string) (Member, bool) {
	for _, m := range ms {
		if m.PrincipalID == id {
			return m, true
		}
	}
	return Member{}, false
}

// lookupDevice returns the device with device ID id, wherever it sorts.
func lookupDevice(ds []Device, id string) (*Device, bool) {
	for i := range ds {
		if ds[i].DeviceID == id {
			return &ds[i], true
		}
	}
	return nil, false
}

// equalDevice reports whether a and b are the same device in every field,
// including the optional policy signing key and the bytes of every key.
func equalDevice(a, b *Device) bool {
	if a.DeviceID != b.DeviceID || a.PrincipalID != b.PrincipalID || a.Label != b.Label ||
		!equalPublicKey(&a.ContentSigningKey, &b.ContentSigningKey) ||
		!equalPublicKey(a.PolicySigningKey, b.PolicySigningKey) ||
		a.AgeEncryptionKey != b.AgeEncryptionKey {
		return false
	}
	return true
}

// equalPublicKey reports whether both nil or both non-nil keys with equal
// algorithm and public key bytes.
func equalPublicKey(a, b *PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Alg == b.Alg && bytes.Equal(a.PublicKey, b.PublicKey)
}
