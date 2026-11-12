package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"strings"
	"testing"

	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// rotationFixture is a real old file, a real KDBX database sealed into it, and
// an already authorized root-signed successor policy for the rotation tests.
//
// The old file is a genuine caller-pinned file: the checkpoint is the seq 5
// anchor policy (carried as seq 6 and linked to the anchor digest), and the
// old file's current policy is the root-signed seq 7 policy, whose
// read-capable devices are device-1 (alice, owner, author), device-2 (bob,
// writer) and device-3d (dave, reader). Each device has a real generated age
// X25519 identity, and the payload is a real KDBX 4.1 database with a
// protected value and an attachment. The successor policy is the root-signed
// seq 8 that removes dave and device-3d, and the next draft is the seq 8
// builder: epoch old+1, content_seq old+1 and prev_digest equal to the raw
// FileDigest of the old file.
type rotationFixture struct {
	keys   *cpKeys
	chain  *cpChain
	p7     *Policy
	p8     *Policy
	next   *File
	dev1   *age.X25519Identity
	dev2   *age.X25519Identity
	dev3d  *age.X25519Identity
	vuk    []byte
	oldEnc []byte
	old    *File
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	fx := newSealFixture(t)

	// The seq 7 policy is the fixture's seq 6 policy with every device given a
	// real generated identity. Its predecessor digest is linked below, once the
	// carried seq 6 policy is final.
	p7 := clonePolicy(fx.chain.policies[1])
	p7.PolicySeq = 7
	p7.Devices = []Device{p7.Devices[0], p7.Devices[1], p7.Devices[2]}
	p7.Devices[0].AgeEncryptionKey = fx.dev1.Recipient().String()
	p7.Devices[1].AgeEncryptionKey = fx.dev2.Recipient().String()
	p7.Devices[2].AgeEncryptionKey = fx.dev3d.Recipient().String()
	// The carried chain is exactly the caller's pinned anchor policy (seq 5),
	// its seq 6 successor p6, and the seq 7 policy p7.
	pin := clonePolicy(fx.initial)
	p6 := clonePolicy(pin)
	p6.PolicySeq = pin.PolicySeq + 1
	p6.PrevPolicyDigest = PolicyDigest(pin)
	// The carried seq 6 document is the link p7 names as its predecessor.
	p7.PrevPolicyDigest = policyDigestOf(p6)
	if err := ValidatePolicy(p7); err != nil {
		t.Fatalf("seq 7 policy is invalid: %v", err)
	}
	c := fx.chain
	// c.policies mirrors the carried proofs one to one: finalize takes the
	// header's policy sequence from its last entry.
	c.policies = []*Policy{pin, p6, p7}
	*c.f = File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:    p7.VaultID,
			KeyEpoch:   3,
			ContentSeq: 42,
			PrevDigest: digest("content-41"),
			OpID:       "op-0042",
			PolicySeq:  p7.PolicySeq,
			// Placeholder; finalize binds the final proof's digest.
			PolicyDigest:   make([]byte, 32),
			AuthorDeviceID: "device-1",
		},
		ContentEncoding: ContentEncoding,
	}
	for _, d := range p7.Devices {
		c.f.VUKDeviceSlots = append(c.f.VUKDeviceSlots, DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("fixture")})
	}
	c.f.CEKSlot = CEKSlot{KeyEpoch: c.f.Header.KeyEpoch, WrappedCEK: []byte("fixture")}
	c.f.KDBXCiphertext = []byte("fixture")
	// Proof 0 is the anchor, trusted by the caller's checkpoint digest alone:
	// its sig stays a placeholder, as in the shared fixture. Proofs 1 and 2 are
	// root-signed continuations.
	anchorProof := SignedPolicy{Document: docFor(pin), Policy: *clonePolicy(pin), SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x7f, ed25519.SignatureSize)}
	c.f.SignedPolicyProofs = []SignedPolicy{anchorProof, proofFor(p6, "owner-root-01", fx.keys.rootPriv), proofFor(p7, "owner-root-01", fx.keys.rootPriv)}
	// The link between the anchor and p6 is the digest of the carried anchor
	// document, which is what the chain verifier compares.
	p6.PrevPolicyDigest = policyDigest(&c.f.SignedPolicyProofs[0])
	c.f.SignedPolicyProofs[1] = proofFor(p6, "owner-root-01", fx.keys.rootPriv)
	// finalize re-seals the chain, and a sealed chain must already name its
	// final proof, exactly as the shared chain builder does.
	c.f.Header.PolicyDigest = policyDigest(&c.f.SignedPolicyProofs[2])
	c.finalize(t, fx.keys)

	// The old file: a real authenticated seal of a real payload under p7.
	oldEnc, err := SealAuthenticatedFile(builderDraft(c.f), payloadFixtureDB(t), c.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("sealing the old file: %v", err)
	}
	old, err := ParseFile(oldEnc)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyCheckpoint(old, c.anchor); err != nil {
		t.Fatalf("old file does not verify under the checkpoint: %v", err)
	}
	if old.Header.PolicySeq != 7 || old.Header.KeyEpoch != 3 || old.Header.ContentSeq != 42 {
		t.Fatalf("old file header = seq %d epoch %d content %d, want seq 7 epoch 3 content 42",
			old.Header.PolicySeq, old.Header.KeyEpoch, old.Header.ContentSeq)
	}

	// The successor policy, seq 8, removes dave and device-3d.
	p8 := clonePolicy(p7)
	p8.PolicySeq = p7.PolicySeq + 1
	p8.PrevPolicyDigest = PolicyDigest(p7)
	p8.Readers = []Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: "carol", Label: "Carol"}}
	p8.Devices = []Device{p8.Devices[0], p8.Devices[1]}
	if err := ValidatePolicy(p8); err != nil {
		t.Fatalf("successor policy is invalid: %v", err)
	}
	c.append(t, p8, "owner-root-01", fx.keys.rootPriv)

	oldDigest, err := deriveFileDigestBytes(old)
	if err != nil {
		t.Fatal(err)
	}
	next := &File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:        old.Header.VaultID,
			KeyEpoch:       old.Header.KeyEpoch + 1,
			ContentSeq:     old.Header.ContentSeq + 1,
			PrevDigest:     oldDigest,
			OpID:           "op-rotation-0043",
			PolicySeq:      p8.PolicySeq,
			PolicyDigest:   PolicyDigest(p8),
			AuthorDeviceID: "device-1",
		},
		SignedPolicyProofs: c.f.SignedPolicyProofs,
		ContentEncoding:    ContentEncoding,
		// The remaining derived wire state stays nil and zero: the draft is a
		// builder value with exactly the seal's builder contract, and the seal
		// derives the roster, CEK slot, ciphertext, revision id and content
		// signature from the authenticated next policy and the database.
	}
	return &rotationFixture{
		keys: fx.keys, chain: c, p7: p7, p8: p8, next: next,
		dev1: fx.dev1, dev2: fx.dev2, dev3d: fx.dev3d,
		vuk: fx.vuk, oldEnc: oldEnc, old: old,
	}
}

// builderDraft returns the in-memory builder File of the final proof chain f:
// the protocol format and version, a copy of f's header and signed proofs, and
// no derived wire state.
func builderDraft(f *File) *File {
	d := &File{
		Format:             f.Format,
		Version:            f.Version,
		Header:             f.Header,
		SignedPolicyProofs: f.SignedPolicyProofs,
	}
	d.Header.PrevDigest = bytes.Clone(d.Header.PrevDigest)
	d.Header.PolicyDigest = bytes.Clone(d.Header.PolicyDigest)
	d.Header.RevisionID = ""
	d.ContentSignature = Signature{}
	return d
}

// rotationOutputs is one successful rotation's result with the caller-owned
// VUK cleared by the test that owns it.
type rotationOutputs struct {
	encoded []byte
	f       *File
	vuk     []byte
}

// rotate runs RotateAuthenticatedFile on the fixture's untouched old file and
// draft and returns its outputs; the test owns and clears the returned VUK.
func (fx *rotationFixture) rotate(t *testing.T) *rotationOutputs {
	t.Helper()
	encoded, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("RotateAuthenticatedFile: %v", err)
	}
	if len(vuk) != CEKSize {
		t.Fatalf("returned VUK has %d bytes, want %d", len(vuk), CEKSize)
	}
	f, err := ParseFile(encoded)
	if err != nil {
		t.Fatalf("rotation output does not parse: %v", err)
	}
	return &rotationOutputs{encoded: encoded, f: f, vuk: vuk}
}

func mustDigest(t *testing.T, f *File) []byte {
	t.Helper()
	d, err := deriveFileDigestBytes(f)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// policyDigestOf returns the PolicyDigest of p as carried in its canonical
// document, which is what a successor's prev_policy_digest names.
func policyDigestOf(p *Policy) []byte {
	return DomainSeparated(UsagePolicyDocument, docFor(p))
}

// proofFor returns a structurally valid root-signed proof of p.
func proofFor(p *Policy, signer string, priv ed25519.PrivateKey) SignedPolicy {
	sp := SignedPolicy{Document: docFor(p), Policy: *clonePolicy(p), SignerID: signer, Alg: PolicySigAlgEd25519}
	signPolicyProof(&sp, priv)
	return sp
}

// wantVUKUnchanged checks that the caller's old VUK buffer still holds the
// exact bytes it held before a rotation.
func (fx *rotationFixture) wantVUKUnchanged(t *testing.T, before []byte) {
	t.Helper()
	if !bytes.Equal(fx.vuk, before) {
		t.Fatal("rotation modified the caller's old VUK")
	}
}

// wantRotationContent checks one opened database still carries the fixture's
// protected value, unprotected title and attachment.
func wantRotationContent(t *testing.T, db *kdbx.Database) {
	t.Helper()
	if db == nil || db.Content == nil || db.Content.Root == nil || len(db.Content.Root.Groups) != 1 {
		t.Fatal("opened database has no single root group")
	}
	entry := &db.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatalf("title = %q, want fixture", got)
	}
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("protected value = %q, want %q", got, payloadProtectedSecret)
	}
	if len(entry.Binaries) != 1 || entry.Binaries[0].Name != payloadAttachmentName {
		t.Fatalf("binary references = %+v", entry.Binaries)
	}
	binary := db.FindBinary(entry.Binaries[0].Value.ID)
	if binary == nil || !bytes.Equal(binary.Content, payloadAttachmentBytes) {
		t.Fatalf("attachment bytes did not survive: %v", binary)
	}
}

func TestRotateAuthenticatedFileRoundTrip(t *testing.T) {
	fx := newRotationFixture(t)

	// Positive first: the untouched old file opens for the source device.
	if _, db, err := OpenAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-1", fx.dev1); err != nil {
		t.Fatalf("old file does not open: %v", err)
	} else {
		wantRotationContent(t, db)
	}

	draftBefore := snapshotFile(fx.next)
	proofsBefore := snapshotFile(&File{SignedPolicyProofs: fx.chain.f.SignedPolicyProofs}).SignedPolicyProofs
	oldBefore := bytes.Clone(fx.oldEnc)
	pinBefore := *fx.chain.anchor
	pinBefore.PolicyDigest = bytes.Clone(fx.chain.anchor.PolicyDigest)
	pinBefore.OwnerRootPublicKey = bytes.Clone(fx.chain.anchor.OwnerRootPublicKey)
	authorKeyBefore := bytes.Clone(fx.keys.dev1Priv)
	vukBefore := bytes.Clone(fx.vuk)

	out := fx.rotate(t)
	defer clear(out.vuk)

	// Caller inputs are unchanged.
	wantDraftUnchanged(t, draftBefore, fx.next)
	if !bytes.Equal(fx.chain.f.SignedPolicyProofs[2].Sig, proofsBefore[2].Sig) {
		t.Fatal("rotation modified the caller's carried proofs")
	}
	if !bytes.Equal(fx.oldEnc, oldBefore) {
		t.Fatal("rotation modified the caller's old file bytes")
	}
	if !bytes.Equal(fx.chain.anchor.PolicyDigest, pinBefore.PolicyDigest) ||
		!bytes.Equal(fx.chain.anchor.OwnerRootPublicKey, pinBefore.OwnerRootPublicKey) ||
		fx.chain.anchor.PolicySeq != pinBefore.PolicySeq || fx.chain.anchor.VaultID != pinBefore.VaultID {
		t.Fatal("rotation modified the caller's checkpoint")
	}
	if !bytes.Equal(fx.keys.dev1Priv, authorKeyBefore) {
		t.Fatal("rotation modified the caller's author private key")
	}
	fx.wantVUKUnchanged(t, vukBefore)

	// The output is a real complete sealed file at epoch+1 / content_seq+1,
	// bound to the old FileDigest, under the next policy, and it verifies.
	if err := ValidateFile(out.f); err != nil {
		t.Fatalf("rotation output is not a valid sealed file: %v", err)
	}
	if err := VerifyPolicyCheckpoint(out.f, fx.chain.anchor); err != nil {
		t.Fatalf("rotation output does not verify under the checkpoint: %v", err)
	}
	h := out.f.Header
	if h.KeyEpoch != fx.old.Header.KeyEpoch+1 || h.ContentSeq != fx.old.Header.ContentSeq+1 {
		t.Fatalf("successor header = epoch %d content %d, want %d/%d",
			h.KeyEpoch, h.ContentSeq, fx.old.Header.KeyEpoch+1, fx.old.Header.ContentSeq+1)
	}
	if h.VaultID != fx.old.Header.VaultID {
		t.Fatalf("successor vault = %q, want %q", h.VaultID, fx.old.Header.VaultID)
	}
	if h.OpID == fx.old.Header.OpID {
		t.Fatal("successor reused the old op id")
	}
	oldDigest, err := deriveFileDigestBytes(fx.old)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h.PrevDigest, oldDigest) {
		t.Fatal("successor prev_digest is not the raw FileDigest of the old file")
	}
	if h.PolicySeq != fx.p8.PolicySeq || !bytes.Equal(h.PolicyDigest, PolicyDigest(fx.p8)) {
		t.Fatalf("successor policy = seq %d, want seq %d of the next policy", h.PolicySeq, fx.p8.PolicySeq)
	}
	if out.f.CEKSlot.KeyEpoch != h.KeyEpoch || len(out.f.CEKSlot.WrappedCEK) == 0 {
		t.Fatal("successor CEK slot is not bound to the successor epoch")
	}
	if bytes.Equal(out.f.CEKSlot.WrappedCEK, fx.old.CEKSlot.WrappedCEK) {
		t.Fatal("successor reused the old CEK slot")
	}
	if bytes.Equal(out.vuk, fx.vuk) {
		t.Fatal("successor reused the old VUK")
	}

	// The remaining devices open it and the content is preserved.
	for _, id := range []string{"device-1", "device-2"} {
		identity := map[string]*age.X25519Identity{"device-1": fx.dev1, "device-2": fx.dev2}[id]
		f, db, err := OpenAuthenticatedFile(out.encoded, fx.chain.anchor, id, identity)
		if err != nil {
			t.Fatalf("%s cannot open the successor: %v", id, err)
		}
		if f.Header.ContentSeq != h.ContentSeq {
			t.Fatalf("%s opened content seq %d, want %d", id, f.Header.ContentSeq, h.ContentSeq)
		}
		wantRotationContent(t, db)
	}
	if slots := out.f.VUKDeviceSlots; len(slots) != 2 ||
		slots[0].DeviceID != "device-1" || slots[1].DeviceID != "device-2" {
		t.Fatalf("successor VUK slots = %+v, want exactly device-1 and device-2", slots)
	}

	// The returned VUK is the successor epoch VUK: it opens the successor's
	// CEK, and that CEK opens the successor payload.
	cek, err := OpenCEK(out.vuk, out.f.Header, out.f.CEKSlot)
	if err != nil {
		t.Fatalf("returned VUK cannot open the successor CEK: %v", err)
	}
	db, err := OpenKDBXPayload(out.f.KDBXCiphertext, cek)
	clear(cek)
	if err != nil {
		t.Fatalf("successor CEK cannot open the successor payload: %v", err)
	}
	wantRotationContent(t, db)

	// The removed device is rejected by the new authenticated policy, with no
	// handle returned.
	f, rdb, err := OpenAuthenticatedFile(out.encoded, fx.chain.anchor, "device-3d", fx.dev3d)
	wantCodeAt(t, err, CodeInvalidValue, "device_id")
	if f != nil || rdb != nil {
		t.Fatalf("removed-device open returned file/database = %v/%v, want both nil", f, rdb)
	}

	// The removed device really learned the old VUK before the rotation: its
	// own slot in the old file opens under its identity, and that VUK opens the
	// old CEK and payload.
	oldSlot := findDeviceSlot(fx.old, "device-3d")
	if oldSlot == nil {
		t.Fatal("the old file carries no device-3d slot")
	}
	oldCurrent := &fx.old.SignedPolicyProofs[len(fx.old.SignedPolicyProofs)-1].Policy
	oldDev := findDevice(oldCurrent, "device-3d")
	if oldDev == nil {
		t.Fatal("the old file's current policy does not name device-3d")
	}
	learned, err := OpenVUKForDevice(*oldSlot, fx.chain.anchor.VaultID, fx.old.Header.KeyEpoch, "device-3d", oldDev.AgeEncryptionKey, fx.dev3d)
	if err != nil {
		t.Fatalf("device-3d cannot learn the old VUK: %v", err)
	}
	defer clear(learned)
	oldCEK, err := OpenCEK(learned, fx.old.Header, fx.old.CEKSlot)
	if err != nil {
		t.Fatalf("the learned old VUK cannot open the old CEK: %v", err)
	}
	oldDB, err := OpenKDBXPayload(fx.old.KDBXCiphertext, oldCEK)
	clear(oldCEK)
	if err != nil {
		t.Fatalf("the learned old VUK cannot open the old payload: %v", err)
	}
	wantRotationContent(t, oldDB)

	// That learned old VUK cannot open the successor CEK, which is the fresh
	// epoch boundary; the returned new VUK can, as proven above. The negative
	// is the exact crypto boundary: the long-lived learned old VUK against the
	// successor's own header and CEK slot, so only the key epoch VUK fails
	// authentication and nothing here is rejected for a wrong header, AAD or
	// slot shape. Nothing reclaims the old plaintext the device already holds
	// from old copies.
	oldVUKForOldFile := fx.vuk
	if !bytes.Equal(learned, oldVUKForOldFile) {
		t.Fatal("the device did not learn the fixture's old VUK")
	}
	staleCEK, err := OpenCEK(learned, out.f.Header, out.f.CEKSlot)
	wantCodeAt(t, err, CodeCEKEnvelopeFailed, "cek_slot")
	if staleCEK != nil {
		t.Fatalf("learned old VUK returned CEK bytes on failure: %x", staleCEK)
	}
	for name, vuk := range map[string][]byte{"fixture old VUK": fx.vuk, "learned old VUK": learned} {
		if _, err := OpenCEK(vuk, out.f.Header, out.f.CEKSlot); err == nil {
			t.Fatalf("%s opened the successor CEK", name)
		}
	}
}

// TestRotateAuthenticatedFileRemovedSourceRejected proves the new VUK is never
// handed to a device the rotation removes. The fixture's valid positive comes
// first; then the source device is device-3d, which the authenticated next
// policy does not carry.
func TestRotateAuthenticatedFileRemovedSourceRejected(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)

	// device-3d is read-capable in the authenticated old policy, so it is a
	// genuine removal by the next policy, not a device that never existed.
	if _, db, err := OpenAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-3d", fx.dev3d); err != nil || db == nil {
		t.Fatalf("device-3d cannot open the old file: %v", err)
	}
	out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-3d", fx.dev3d, fx.next, fx.keys.dev1Priv)
	wantCodeAt(t, err, CodeInvalidValue, "device_id")
	if out != nil || vuk != nil {
		t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
	}
}

// TestRotateAuthenticatedFileSourceIdentityRejected proves the source device
// must remain read-capable in the authenticated next policy under exactly the
// caller's identity: an identity whose recipient is not the next policy's
// recipient for a device still listed there is rejected, and no new VUK is
// returned.
func TestRotateAuthenticatedFileSourceIdentityRejected(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)

	// device-2 remains authorized for bob's identity, but a different
	// identity claiming device-2 is not that device.
	out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-2", fx.dev3d, fx.next, fx.keys.dev1Priv)
	wantCodeAt(t, err, CodeInvalidValue, "device_id")
	if out != nil || vuk != nil {
		t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
	}
	// An unknown device id is rejected the same way.
	out, vuk, err = RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-unknown", fx.dev1, fx.next, fx.keys.dev1Priv)
	wantCodeAt(t, err, CodeInvalidValue, "device_id")
	if out != nil || vuk != nil {
		t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
	}
}

// TestRotateAuthenticatedFileRejectsBasicInputs covers the nil and malformed
// inputs rejected before any authentication or decryption, each with nil
// outputs.
func TestRotateAuthenticatedFileRejectsBasicInputs(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)

	type inputs struct {
		old    []byte
		pin    *PolicyCheckpoint
		device string
		id     *age.X25519Identity
		draft  *File
		key    ed25519.PrivateKey
	}
	base := func() inputs {
		return inputs{
			old: fx.oldEnc, pin: fx.chain.anchor, device: "device-1", id: fx.dev1,
			draft: snapshotFile(fx.next), key: fx.keys.dev1Priv,
		}
	}
	cases := map[string]struct {
		mutate func(*inputs)
		code   string
		path   string
	}{
		"nil next draft":  {func(in *inputs) { in.draft = nil }, CodeInvalidValue, ""},
		"nil checkpoint":  {func(in *inputs) { in.pin = nil }, CodeInvalidValue, ""},
		"nil identity":    {func(in *inputs) { in.id = nil }, CodeInvalidValue, ""},
		"nil author key":  {func(in *inputs) { in.key = nil }, CodeInvalidValue, ""},
		"empty device id": {func(in *inputs) { in.device = "" }, CodeInvalidValue, ""},
		// Nil old bytes are not a basic input: the old file is parsed and
		// authenticated first, and ParseFile rejects them unchanged.
		"nil old bytes":   {func(in *inputs) { in.old = nil }, CodeInvalidJSON, ""},
		"unknown format":  {func(in *inputs) { in.draft.Format = "other" }, CodeInvalidValue, ""},
		"unknown version": {func(in *inputs) { in.draft.Version = Version + 1 }, CodeInvalidValue, ""},
		"foreign encoding": {func(in *inputs) {
			in.draft.ContentEncoding = "other"
		}, CodeInvalidValue, "content_encoding"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := base()
			c.mutate(&in)
			var before *File
			if in.draft != nil {
				before = snapshotFile(in.draft)
			}
			out, vuk, err := RotateAuthenticatedFile(in.old, in.pin, in.device, in.id, in.draft, in.key)
			wantCodeAt(t, err, c.code, c.path)
			if out != nil || vuk != nil {
				t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
			}
			if before != nil {
				wantDraftUnchanged(t, before, in.draft)
			}
		})
	}
}

// TestRotateAuthenticatedFileWrongPin proves the caller pin authenticates
// before any continuation or decryption work: each pin mismatch below is
// rejected as policy_checkpoint_failed with nil outputs.
func TestRotateAuthenticatedFileWrongPin(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)

	t.Run("digest mismatch", func(t *testing.T) {
		pin := *fx.chain.anchor
		pin.PolicyDigest = bytes.Clone(fx.chain.anchor.PolicyDigest)
		pin.PolicyDigest[0] ^= 0xff
		out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, &pin, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
		if out != nil || vuk != nil {
			t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
		}
	})

	t.Run("pin names another policy", func(t *testing.T) {
		pin := fx.chain.pin(digest("some-other-policy"), fx.chain.anchor.PolicySeq)
		out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, pin, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
		if out != nil || vuk != nil {
			t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
		}
	})
}

// TestRotateAuthenticatedFileContinuation rejects every immediate-transition
// violation with invalid_value at the naming path and nil outputs, after the
// same fixture's valid positive.
func TestRotateAuthenticatedFileContinuation(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)

	otherDigest, err := deriveFileDigestBytes(positive.f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*File)
		path   string
	}{
		// Each case keeps its derived CEK slot untouched, exactly as the
		// minimal builder draft carries none, so the named transition check is
		// the step that rejects it.
		{"stale epoch", func(f *File) { f.Header.KeyEpoch = fx.old.Header.KeyEpoch }, "key_epoch"},
		{"skipped epoch", func(f *File) { f.Header.KeyEpoch = fx.old.Header.KeyEpoch + 2 }, "key_epoch"},
		{"epoch overflow", func(f *File) { f.Header.KeyEpoch = 0 }, "key_epoch"},
		{"stale content seq", func(f *File) { f.Header.ContentSeq = fx.old.Header.ContentSeq }, "content_seq"},
		{"skipped content seq", func(f *File) { f.Header.ContentSeq = fx.old.Header.ContentSeq + 2 }, "content_seq"},
		{"content seq overflow", func(f *File) { f.Header.ContentSeq = 0; f.Header.PrevDigest = nil }, "content_seq"},
		{"wrong prev_digest", func(f *File) { f.Header.PrevDigest[0] ^= 0xff }, "prev_digest"},
		{"prev_digest of another file", func(f *File) { f.Header.PrevDigest = otherDigest }, "prev_digest"},
		{"reused op id", func(f *File) { f.Header.OpID = fx.old.Header.OpID }, "op_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			draft := snapshotFile(fx.next)
			c.mutate(draft)
			before := snapshotFile(draft)
			out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-1", fx.dev1, draft, fx.keys.dev1Priv)
			wantCodeAt(t, err, CodeInvalidValue, c.path)
			if out != nil || vuk != nil {
				t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
			}
			wantDraftUnchanged(t, before, draft)
		})
	}
}

// TestRotateAuthenticatedFileRejectsUnsupportedTransitions covers the next
// policy and author failures that must also return nil outputs, after the same
// fixture's valid positive, and the 64-bit exhaustion of an old header that
// cannot be continued.
func TestRotateAuthenticatedFileRejectsUnsupportedTransitions(t *testing.T) {
	fx := newRotationFixture(t)
	positive := fx.rotate(t)
	clear(positive.vuk)
	vukBefore := bytes.Clone(fx.vuk)
	wantRejected := func(t *testing.T, out []byte, vuk []byte, err error, code, path string) {
		t.Helper()
		wantCodeAt(t, err, code, path)
		if out != nil || vuk != nil {
			t.Fatalf("rejected rotation returned encoding/VUK = %v/%v, want both nil", out, vuk)
		}
		fx.wantVUKUnchanged(t, vukBefore)
	}

	t.Run("unauthorized next chain", func(t *testing.T) {
		draft := snapshotFile(fx.next)
		// The seq 8 proof keeps its document but not the root signature the
		// caller's pin requires.
		draft.SignedPolicyProofs[2].Sig = pf(0x60, ed25519.SignatureSize)
		out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-1", fx.dev1, draft, fx.keys.dev1Priv)
		wantRejected(t, out, vuk, err, CodeSignatureVerifyFailed, "signed_policy_proofs[2]")
	})

	t.Run("wrong author key", func(t *testing.T) {
		out, vuk, err := RotateAuthenticatedFile(fx.oldEnc, fx.chain.anchor, "device-1", fx.dev1, fx.next, fx.keys.dev2Priv)
		wantRejected(t, out, vuk, err, CodeAuthorSigningKeyMismatch, "content_signature")
	})

	t.Run("old epoch exhausted", func(t *testing.T) {
		old := snapshotFile(fx.old)
		old.Header.KeyEpoch = math.MaxUint64
		old.CEKSlot.KeyEpoch = old.Header.KeyEpoch
		oldEnc := fx.resignOld(t, old)
		if err := VerifyPolicyCheckpoint(old, fx.chain.anchor); err != nil {
			t.Fatalf("exhausted-epoch old file does not verify: %v", err)
		}
		out, vuk, err := RotateAuthenticatedFile(oldEnc, fx.chain.anchor, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
		wantRejected(t, out, vuk, err, CodeInvalidValue, "key_epoch")
	})

	t.Run("old content seq exhausted", func(t *testing.T) {
		old := snapshotFile(fx.old)
		old.Header.ContentSeq = math.MaxUint64
		out, vuk, err := RotateAuthenticatedFile(fx.resignOld(t, old), fx.chain.anchor, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
		wantRejected(t, out, vuk, err, CodeInvalidValue, "content_seq")
	})

	t.Run("unauthenticated old file", func(t *testing.T) {
		// A well-formed old file whose content signature is stale is rejected
		// by the authenticated open before its header reaches any transition
		// check: the continuation it names is skipped entirely.
		old := snapshotFile(fx.old)
		old.Header.ContentSeq = fx.old.Header.ContentSeq + 100
		old.Header.RevisionID = ""
		reseal(t, old)
		oldEnc, err := EncodeFile(old)
		if err != nil {
			t.Fatal(err)
		}
		out, vuk, err := RotateAuthenticatedFile(oldEnc, fx.chain.anchor, "device-1", fx.dev1, fx.next, fx.keys.dev1Priv)
		wantRejected(t, out, vuk, err, CodeSignatureVerifyFailed, "")
	})

	t.Run("old payload cannot be opened", func(t *testing.T) {
		tampered := snapshotFile(fx.old)
		if len(tampered.KDBXCiphertext) <= payloadFirstContentBlock {
			t.Fatalf("old ciphertext of %d bytes has no first content block", len(tampered.KDBXCiphertext))
		}
		tampered.KDBXCiphertext[payloadFirstContentBlock] ^= 0x01
		// The KDBX payload is only shape-checked by the file validation, so
		// the tampered-but-resealed file authenticates as a file and is
		// rejected by the authenticated open's KDBX decryption step.
		tamperedEnc := fx.resignOld(t, tampered)
		// The successor continues this authenticated file exactly: its
		// prev_digest is rebound to the tampered file's digest.
		draft := snapshotFile(fx.next)
		draft.Header.PrevDigest = mustDigest(t, tampered)
		out, vuk, err := RotateAuthenticatedFile(tamperedEnc, fx.chain.anchor, "device-1", fx.dev1, draft, fx.keys.dev1Priv)
		wantRejected(t, out, vuk, err, CodeKDBXPayloadInvalid, "")
	})
}

// resignOld re-seals the modified copy f with the fixture's real old author
// key (device-1) over its own content, so a negative reaches the rotation
// rather than the old file's content signature. The signature's signer and
// algorithm are kept; only its value is recomputed.
func (fx *rotationFixture) resignOld(t *testing.T, f *File) []byte {
	t.Helper()
	// The carried revision id is not a preimage input, but ContentSigningBytes
	// still requires it to be shaped, exactly as the seal requires.
	f.Header.RevisionID = strings.Repeat("0", 64)
	pre, err := ContentSigningBytes(f)
	if err != nil {
		t.Fatalf("old file content signing input: %v", err)
	}
	f.ContentSignature.Sig = ed25519.Sign(fx.keys.dev1Priv, append(append([]byte(DomainContentSignature), 0), pre...))
	// reseal re-derives revision_id from the modified content and keeps the
	// signature just computed.
	reseal(t, f)
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatalf("encoding re-signed old file: %v", err)
	}
	parsed, err := ParseFile(enc)
	if err != nil {
		t.Fatalf("re-signed old file is not structurally valid: %v", err)
	}
	*f = *parsed
	if err := VerifyPolicyCheckpoint(f, fx.chain.anchor); err != nil {
		t.Fatalf("re-signed old file does not verify: %v", err)
	}
	return enc
}

// TestRotateAuthenticatedFileFreshRandomVUK proves each rotation draws its own
// random VUK and never reuses the old one.
func TestRotateAuthenticatedFileFreshRandomVUK(t *testing.T) {
	fx := newRotationFixture(t)
	first := fx.rotate(t)
	defer clear(first.vuk)
	second := fx.rotate(t)
	defer clear(second.vuk)
	if bytes.Equal(first.vuk, second.vuk) {
		t.Fatal("two rotations returned the same VUK")
	}
	if bytes.Equal(first.vuk, fx.vuk) || bytes.Equal(second.vuk, fx.vuk) {
		t.Fatal("a rotation returned the old VUK")
	}
	// The positive: the returned fresh VUK opens the successor's own CEK.
	for name, out := range map[string]*rotationOutputs{"first": first, "second": second} {
		cek, err := OpenCEK(out.vuk, out.f.Header, out.f.CEKSlot)
		if err != nil {
			t.Fatalf("%s successor: the returned fresh VUK cannot open its CEK: %v", name, err)
		}
		clear(cek)
	}

	// The negative is exact: the old VUK against the successor's own header
	// and CEK slot is a CEK envelope failure at cek_slot and nothing else, so
	// only the key epoch VUK fails authentication and the successor is not
	// rejected for a wrong header, AAD or slot shape.
	staleCEK, err := OpenCEK(fx.vuk, second.f.Header, second.f.CEKSlot)
	wantCodeAt(t, err, CodeCEKEnvelopeFailed, "cek_slot")
	if staleCEK != nil {
		t.Fatalf("old VUK returned CEK bytes on failure: %x", staleCEK)
	}
}

// TestOwnInnerHeaderBinariesClearsRemovedBinary proves the capture-and-clear
// mechanism that owns an opened database's InnerHeader binary content: a
// binary the encoder's cleanup removes from db.Content.InnerHeader.Binaries
// before the release runs is still cleared through the reference captured
// before the seal, and so is a binary the InnerHeader still carries.
func TestOwnInnerHeaderBinariesClearsRemovedBinary(t *testing.T) {
	db := payloadFixtureDB(t)
	entry := &db.Content.Root.Groups[0].Entries[0]
	referenced := db.FindBinary(entry.Binaries[0].Value.ID)
	if referenced == nil || len(referenced.Content) == 0 {
		t.Fatalf("fixture has no referenced attachment: %v", referenced)
	}
	// An unreferenced binary the encoder drops before the release.
	unreferenced := payloadFixtureRawBinary(db, []byte("unreferenced inner header secret"), 0)
	if len(db.Content.InnerHeader.Binaries) != 2 {
		t.Fatalf("fixture InnerHeader carries %d binaries, want 2", len(db.Content.InnerHeader.Binaries))
	}

	release := ownInnerHeaderBinaries(db)
	// Before the release the data is intact.
	if !bytes.Equal(unreferenced.Content, []byte("unreferenced inner header secret")) {
		t.Fatal("the capture modified the binary content")
	}

	// Simulate the encoder's cleanupBinaries: drop the unreferenced binary from
	// the InnerHeader. Every slice header is a copy, so the dropped buffer is
	// still reachable through the local references above but no longer through
	// the database before the release runs.
	db.Content.InnerHeader.Binaries = []kdbx.Binary{*referenced}
	db.Content.InnerHeader.Binaries[0].ID = 0
	if got := db.Content.InnerHeader.Binaries; len(got) != 1 || len(got[0].Content) == len(unreferenced.Content) && &got[0].Content[0] == &unreferenced.Content[0] {
		t.Fatal("simulated cleanup did not remove the unreferenced binary from the InnerHeader")
	}

	release()

	if !allZero(unreferenced.Content) {
		t.Fatalf("removed binary content = %x, want zero after release", unreferenced.Content)
	}
	if !allZero(referenced.Content) {
		t.Fatalf("retained binary content = %x, want zero after release", referenced.Content)
	}
	// The buffers were cleared in place, not replaced, and both cleanups
	// reached the same underlying arrays.
	if !allZero(db.Content.InnerHeader.Binaries[0].Content) {
		t.Fatalf("InnerHeader binary content = %x, want zero after release", db.Content.InnerHeader.Binaries[0].Content)
	}
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
