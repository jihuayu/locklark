package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"math"
)

// CodePolicyCheckpointFailed is reported by VerifyPolicyCheckpoint when the
// carried policy chain does not continue the caller-pinned checkpoint: a
// different vault or owner root, the anchor policy missing, a stale or
// rolled-back tip, a chain gap, a foreign or wrongly linked proof, a
// non-root policy transition, or a policy proof signature that does not
// verify. Each case is a caller trust decision, not a structural defect of
// the file.
const CodePolicyCheckpointFailed = "policy_checkpoint_failed"

// PolicyCheckpoint is the caller's already-trusted policy state: the policy
// sequence and its digest (PolicyDigest) together with the owner root that
// owns it. A checkpoint is derived out of band, from a trusted sharing or
// pairing exchange or from recovery; this package neither creates nor infers
// one. OwnerRootPublicKey is copied so later edits by the caller cannot
// change a checkpoint between calls.
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
//     equal c.PolicyDigest; proofs before it are ignored. A file whose proofs
//     begin after c.PolicySeq must begin exactly at c.PolicySeq+1 with that
//     proof's prev_policy_digest equal to c.PolicyDigest. Proofs are strictly
//     increasing and end at the current policy (header policy_seq), so a
//     file whose current policy is behind c.PolicySeq is stale;
//   - the anchor proof is trusted by the caller-supplied digest alone: its
//     signer_id, alg and sig are not examined again. Every later proof must
//     carry exactly the previous sequence + 1, prev_policy_digest equal to
//     the previous trusted digest, the owner root equal to c (key_id and
//     public key), SignerID equal to c.OwnerRootKeyID, and a crypto/ed25519
//     signature over exactly DomainPolicyDocumentSignature || 0x00 ||
//     SignedPolicy.Document, the frozen v1 policy-document preimage;
//   - having authenticated the chain, the content signature is verified
//     with the content signing key recorded for header.author_device_id in
//     the authenticated current policy, over DomainContentSignature || 0x00
//     || ContentSigningBytes(f). No key is taken from an unauthenticated
//     proof, and ValidateFile has already required the author's principal to
//     be a writer, admin or owner of the current policy.
//
// Admin-signed transitions are not supported. A policy continuation must be
// signed by the pinned owner root; a proof signed by any other device,
// including one holding an AdminDelegation, is rejected even though the
// delegation scopes define no frozen mapping from invited, removed, promoted
// or demoted members and devices to the allowed old-to-new policy diff. There
// is no reinterpretation of a delegated transition as a root-signed one.
//
// A nil return means only that the current content signature is authorized
// under this caller-pinned checkpoint and the root-signed continuation that
// leads from it. It does not prove server freshness, content-history
// continuity through prev_digest, encryption or wrapping correctness, or
// overall vault trust. VerifyContentSignature is unchanged and remains the
// narrower pinned-key check.
//
// Errors:
//   - structural, vault-consistency and role-membership failures are
//     returned from ValidateFile unchanged; a content signer device missing
//     from the authenticated current policy is signature_shape_invalid;
//   - a header author whose principal is not a writer, admin or owner of the
//     current policy (removed or demoted) is an invalid_value with an empty
//     path, reported before the sealed revision binding;
//   - a nil c, or a checkpoint whose vault ID or root key ID is not a valid
//     identifier, whose root public key is not 32 bytes or whose digest is
//     not 32 bytes, is an invalid_value: the supplied anchor itself is
//     malformed;
//   - vault, anchor, tip, gap, link, root or admin-transition failures are
//     *Error with Code CodePolicyCheckpointFailed and an empty path;
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
		if bytes.Equal(policyDigest(&proofs[i]), c.PolicyDigest) {
			anchor = i
			break
		}
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

	// The digest of the newest policy established as trusted. The anchor is
	// trusted by the caller digest; every later proof is root-signed.
	trusted := bytes.Clone(c.PolicyDigest)
	prevSeq := c.PolicySeq
	first := 0
	if anchor >= 0 {
		// The anchor is trusted by c.PolicyDigest; its sig is unused.
		first = anchor + 1
	}
	for i := first; i < len(proofs); i++ {
		sp := &proofs[i]
		seq := sp.Policy.PolicySeq
		if prevSeq == math.MaxUint64 || seq != prevSeq+1 ||
			!bytes.Equal(sp.Policy.PrevPolicyDigest, trusted) ||
			sp.Policy.OwnerRoot.KeyID != c.OwnerRootKeyID ||
			!bytes.Equal(sp.Policy.OwnerRoot.PublicKey, c.OwnerRootPublicKey) ||
			sp.Policy.OwnerRoot.Alg != PolicySigAlgEd25519 ||
			sp.SignerID != c.OwnerRootKeyID {
			return Err("", CodePolicyCheckpointFailed)
		}
		msg := make([]byte, 0, len(DomainPolicyDocumentSignature)+1+len(sp.Document))
		msg = append(msg, DomainPolicyDocumentSignature...)
		msg = append(msg, 0)
		msg = append(msg, sp.Document...)
		if !ed25519.Verify(ed25519.PublicKey(c.OwnerRootPublicKey), msg, sp.Sig) {
			return Err(pathIndex(fieldSignedPolicyProofs, i), CodeSignatureVerifyFailed)
		}
		trusted = policyDigest(sp)
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
