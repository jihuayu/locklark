package vaultfile

import (
	"crypto/ed25519"
	"crypto/subtle"
	"sort"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// CodeAuthorSigningKeyMismatch is reported by SealAuthenticatedFile when the
// authorPrivateKey supplied by the caller is not the Ed25519 content signing
// key the authenticated current policy records for the draft header's author
// device, or is not exactly ed25519.PrivateKeySize bytes. It is one code for
// both so a caller cannot distinguish a malformed key from a foreign one, and
// it is a caller trust decision, not a structural defect of the draft. The
// path is "content_signature".
const CodeAuthorSigningKeyMismatch = "author_signing_key_mismatch"

// SealAuthenticatedFile is the package's caller-pinned authenticated full-file
// seal path. It authenticates the draft's policy chain against the caller's
// trusted PolicyCheckpoint, resolves and checks the author device in the
// now-authenticated current policy, wraps the caller's epoch VUK to exactly
// that policy's read-capable devices, encrypts db under a fresh per-snapshot
// CEK, signs the completed content and returns the canonical sealed bytes. It
// is the sealing counterpart of OpenAuthenticatedFile.
//
// draft is a builder File supplied by the caller: protocol format and
// version, the header, and the signed policy proofs. Its wire roster and
// derived fields are not trust inputs; they are overwritten on a private copy.
// vuk is the caller-owned 32-byte epoch VUK and authorPrivateKey the author
// device's Ed25519 private key. db must be an unlocked KDBX 4.1 database in
// the state SealKDBXPayload accepts.
//
// The order is fixed and is the security boundary. Every step before the
// first encryption is a pure check with no cryptographic side effect:
//
//  1. Basic inputs. A nil draft, checkpoint, db or vuk, a draft format or
//     version other than the protocol's, an invalid header (ValidateHeader)
//     and a vuk that is not exactly CEKSize bytes are rejected as an
//     invalid_value naming the offending input. draft.ContentEncoding is
//     required to be the protocol value when set; an empty value is treated as
//     the protocol value, because the draft is a builder value and not a wire
//     record.
//  2. Chain. verifyPolicyChain(draft.Header, draft.SignedPolicyProofs,
//     checkpoint) is the single policy-chain verifier and its error is
//     returned unchanged. Its deep-cloned authenticated current policy is the
//     only roster and key source for the rest of the call: a missing or wrong
//     pin, an invalid policy signature, a forbidden delegated diff or a
//     malformed or unbound proof returns nil bytes before any device
//     recipient is used.
//  3. Author. The header's author device is resolved in the authenticated
//     current policy and its principal must be a writer, admin or owner. The
//     policy's content signing key for that device must be Ed25519, and
//     authorPrivateKey must be exactly ed25519.PrivateKeySize bytes whose
//     final public-key half equals it. It must also be internally consistent:
//     the public key derived by ed25519.NewKeyFromSeed from its first
//     ed25519.SeedSize bytes must equal both that half and the policy key,
//     because PrivateKey.Public copies those trailing bytes without deriving
//     them. Any failure is CodeAuthorSigningKeyMismatch at content_signature.
//     No candidate roster or key from the draft is used.
//  4. Epoch. The header's KeyEpoch must be positive (invalid_value at
//     key_epoch). The VUK length was checked in step 1.
//  5. VUK slots. On a deep local copy of draft, VUKDeviceSlots is replaced by
//     exactly one SealVUKForDevice(vuk, checkpoint.VaultID, header.KeyEpoch,
//     deviceID, device.AgeEncryptionKey) per read-capable device of the
//     authenticated current policy, in the wire's canonical strictly
//     ascending device_id order; each call uses the authenticated policy's
//     recipient, never a carried DeviceSlot.Recipient.
//  6. CEK and payload. SealCEK(vuk, copy.Header) generates the fresh
//     per-snapshot CEK and its slot, and SealKDBXPayload(db, cek) encrypts db.
//     The returned CEK is package-owned and cleared on every return path.
//  7. Signature and file. ContentSigningBytes of the completed draft is
//     signed with authorPrivateKey over DomainContentSignature || 0x00 ||
//     those bytes, SealFile binds the revision id and content signature, and
//     the result is parsed with ParseFile. The signature is made with the
//     package-owned key derived from the validated seed, never with the
//     caller's slice.
//  8. Final verification. VerifyPolicyCheckpoint(sealed, checkpoint) must
//     accept the finished file with the caller's checkpoint before its bytes
//     are returned. This final check does not replace step 2.
//
// Stale draft fields are never trusted. On the private copy, header
// RevisionID, ContentSignature, VUKDeviceSlots, CEKSlot and KDBXCiphertext are
// reset before the roster and content are written from the authenticated
// policy and db; the proof array is rebuilt from the caller's proofs so that
// the copy shares no slice with draft. The caller's draft is never mutated:
// on success and on every error the input File's contents are unchanged.
//
// The VUK and authorPrivateKey are caller-owned: neither is modified and
// neither is retained. The package generates no VUK or epoch, creates no
// policy change or invitation, and retains no credential or private key. db is
// mutated as documented by SealKDBXPayload, which restores the caller's exact
// prior Database.Credentials pointer and contents on every return, success and
// error alike.
//
// Errors are an invalid_value for malformed basic inputs, the unchanged error
// of verifyPolicyChain, CodeAuthorSigningKeyMismatch for the author key, the
// unchanged errors of the wrapping and sealing primitives, and the unchanged
// error of ParseFile or VerifyPolicyCheckpoint. Every error returns nil bytes.
//
// Trust limits: this seals only under a policy chain the caller's checkpoint
// already anchors. It does not establish the provenance or freshness of the
// checkpoint, complete content history through prev_digest, or overall vault
// trust, and it performs no epoch or key rotation, invitation or rewrap flow.
func SealAuthenticatedFile(draft *File, db *kdbx.Database, checkpoint *PolicyCheckpoint, vuk []byte, authorPrivateKey ed25519.PrivateKey) ([]byte, error) {
	// 1. Basic inputs. Nothing here wraps, derives or encrypts.
	if draft == nil || checkpoint == nil || db == nil {
		return nil, Err("", CodeInvalidValue)
	}
	if len(vuk) != CEKSize {
		return nil, Err("", CodeInvalidValue)
	}
	if draft.Format != Format || draft.Version != Version {
		return nil, Err("", CodeInvalidValue)
	}
	if draft.ContentEncoding != "" && draft.ContentEncoding != ContentEncoding {
		return nil, Err("content_encoding", CodeInvalidValue)
	}
	// The basic input checks must not depend on the carried proofs, so the
	// header is checked on its own here; verifyPolicyChain checks it again.
	if err := ValidateHeader(&draft.Header); err != nil {
		return nil, err
	}
	if draft.Header.KeyEpoch == 0 {
		return nil, Err("key_epoch", CodeInvalidValue)
	}

	// 2. The caller-pinned policy chain. Its deep-cloned current policy is
	// the only roster and key source below.
	current, err := verifyPolicyChain(draft.Header, draft.SignedPolicyProofs, checkpoint)
	if err != nil {
		return nil, err
	}

	// 3. The author device and its content signing key, in that policy. The
	// signing key is the package-owned key derived from the caller key's
	// seed; the defer clears it on every return path, error or success.
	author := draft.Header.AuthorDeviceID
	dev := findDevice(current, author)
	if dev == nil || !current.hasRole(dev.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) ||
		dev.ContentSigningKey.Alg != SigAlgEd25519 ||
		!validEd25519Key(dev.ContentSigningKey.PublicKey) ||
		len(authorPrivateKey) != ed25519.PrivateKeySize {
		return nil, Err("content_signature", CodeAuthorSigningKeyMismatch)
	}
	signingKey, ok := validatedAuthorKey(authorPrivateKey, dev.ContentSigningKey.PublicKey)
	if !ok {
		return nil, Err("content_signature", CodeAuthorSigningKeyMismatch)
	}
	defer clear(signingKey)

	// 4. Sealing state. A positive KeyEpoch was required in step 1
	// (ValidateHeader and the explicit check above) and a 32-byte VUK before
	// it, so both are established before any wrapping or KDF work. Nothing
	// more is needed here.
	sealed := sealDraftCopy(draft)

	// 5. VUK slots for exactly the authenticated read-capable devices.
	slots, err := readCapableDeviceSlots(sealed.Header, current, checkpoint.VaultID, vuk)
	if err != nil {
		return nil, err
	}
	sealed.VUKDeviceSlots = slots

	// 6. A fresh per-snapshot CEK, then the KDBX payload under it. The CEK
	// is package-owned from here on and cleared on every return.
	cek, cekSlot, err := SealCEK(vuk, sealed.Header)
	if err != nil {
		return nil, err
	}
	defer clear(cek)
	sealed.CEKSlot = cekSlot
	ciphertext, err := SealKDBXPayload(db, cek)
	if err != nil {
		return nil, err
	}
	sealed.KDBXCiphertext = ciphertext

	// 7. The content signature and the sealed file. The draft's carried
	// content signature is zero: it is a builder value the chain never
	// authenticated, the header's revision id is about to be derived, and the
	// content signature SealFile writes below is the one that is verified.
	sealed.ContentSignature = Signature{}
	preimage, err := ContentSigningBytes(sealed)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(DomainContentSignature)+1+len(preimage))
	msg = append(msg, DomainContentSignature...)
	msg = append(msg, 0)
	msg = append(msg, preimage...)
	sig := Signature{SignerID: author, Alg: SigAlgEd25519, Sig: ed25519.Sign(signingKey, msg)}
	encoded, err := SealFile(sealed, &sig)
	if err != nil {
		return nil, err
	}
	final, err := ParseFile(encoded)
	if err != nil {
		return nil, err
	}

	// 8. The finished file must open under the same caller pin.
	if err := VerifyPolicyCheckpoint(final, checkpoint); err != nil {
		return nil, err
	}
	return encoded, nil
}

// validatedAuthorKey checks that the caller's 64-byte Ed25519 private key is
// internally consistent and is the key of policyKey, and returns a
// package-owned signing key derived from its seed when it is. ok is false for
// any malformed, inconsistent or foreign key, and then no key is returned.
//
// ed25519.PrivateKey.Public only copies the trailing public-key half; it does
// not derive it, so a key with this policy's public half and any other seed
// would pass a public-half comparison and produce invalid signatures only at
// final verification. Deriving with ed25519.NewKeyFromSeed makes the
// first-half seed the single source of the returned key, which must reproduce
// both the caller key's public half and the authenticated policy key.
//
// The caller's key is never modified or retained. On failure nothing is
// returned, so there is no derived copy to clear; on success the caller owns
// the returned slice and the function retains no other copy.
func validatedAuthorKey(privateKey ed25519.PrivateKey, policyKey ed25519.PublicKey) (ed25519.PrivateKey, bool) {
	if len(privateKey) != ed25519.PrivateKeySize || !validEd25519Key(policyKey) {
		return nil, false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	public := derived.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(privateKey[ed25519.SeedSize:], public) != 1 ||
		subtle.ConstantTimeCompare(public, policyKey) != 1 {
		clear(derived)
		return nil, false
	}
	return derived, true
}

// sealDraftCopy returns a deep local copy of the draft's builder state that
// shares no mutable storage with draft: the header bytes, every proof with its
// document, policy and signature, and the proof array itself. The derived wire
// fields are reset to nil or zero so that stale carried bytes never reach the
// encoder; the empty roster and zero CEK slot are structurally invalid, and
// that is deliberate: nothing may read those fields before SealAuthenticatedFile
// fills them from the authenticated policy and the encrypted db.
//
// The copy also receives the protocol content_encoding. The draft is a
// builder value, so an empty encoding means the protocol value and anything
// else was rejected by the caller; every encoding the copy produces is the one
// the wire check requires.
func sealDraftCopy(draft *File) *File {
	g := *draft
	g.Header.PrevDigest = cloneBytes(draft.Header.PrevDigest)
	g.Header.PolicyDigest = cloneBytes(draft.Header.PolicyDigest)
	g.Header.RevisionID = ""
	g.ContentSignature = Signature{}
	g.SignedPolicyProofs = make([]SignedPolicy, len(draft.SignedPolicyProofs))
	for i := range draft.SignedPolicyProofs {
		sp := &draft.SignedPolicyProofs[i]
		g.SignedPolicyProofs[i] = SignedPolicy{
			Policy:   *clonePolicySnapshot(&sp.Policy),
			Document: cloneBytes(sp.Document),
			SignerID: sp.SignerID,
			Alg:      sp.Alg,
			Sig:      cloneBytes(sp.Sig),
		}
	}
	g.ContentEncoding = ContentEncoding
	g.KDBXCiphertext = nil
	g.VUKDeviceSlots = nil
	g.CEKSlot = CEKSlot{}
	return &g
}

// readCapableDeviceSlots wraps vuk for exactly the read-capable devices of the
// authenticated current policy, in the wire's canonical strictly ascending
// device_id order, using each device's authenticated age recipient. The
// caller clears nothing: SealVUKForDevice retains no caller buffer.
func readCapableDeviceSlots(header Header, current *Policy, vaultID string, vuk []byte) ([]DeviceSlot, error) {
	var devices []Device
	for i := range current.Devices {
		d := &current.Devices[i]
		if current.hasRole(d.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
			devices = append(devices, *d)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].DeviceID < devices[j].DeviceID })
	if len(devices) == 0 {
		// Unreachable for a valid policy: ValidatePolicy requires at least one
		// device and every device's principal holds a read-capable role.
		return nil, Err("vuk_device_slots", CodeInvalidValue)
	}
	slots := make([]DeviceSlot, 0, len(devices))
	for i := range devices {
		slot, err := SealVUKForDevice(vuk, vaultID, header.KeyEpoch, devices[i].DeviceID, devices[i].AgeEncryptionKey)
		if err != nil {
			return nil, err
		}
		slots = append(slots, slot)
	}
	return slots, nil
}
