package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"sort"
	"testing"

	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// fileSealFixture is one caller-pinned vault for the full-file seal tests. The
// caller's anchor policy (seq 5) is alice owner/admin with device-1, bob as a
// reader with device-2, and dave as a reader with device-3d. The current
// policy (seq 6) is a root-signed successor that also makes bob a writer while
// dave stays a reader, so a device principal with read access still has a real
// VUK envelope and device-3d can open the positive file. Every device carries
// a real generated age X25519 recipient and a distinct real Ed25519 content
// signing key. A test runs a positive on the untouched fixture before
// mutating anything.
type fileSealFixture struct {
	keys    *cpKeys
	initial *Policy
	chain   *cpChain
	dev1    *age.X25519Identity
	dev2    *age.X25519Identity
	dev3d   *age.X25519Identity
	vuk     []byte
}

func tGenID(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newSealFixture(t *testing.T) *fileSealFixture {
	t.Helper()
	k := newCPKeys(t)
	fx := &fileSealFixture{keys: k, dev1: tGenID(t), dev2: tGenID(t), dev3d: tGenID(t), vuk: make([]byte, CEKSize)}
	if _, err := rand.Read(fx.vuk); err != nil {
		t.Fatal(err)
	}
	dev3Key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p0 := &Policy{
		Format:           Format,
		Version:          Version,
		VaultID:          "vault-01",
		PolicySeq:        5,
		PrevPolicyDigest: digest("policy-4"),
		OwnerRoot: OwnerRoot{
			KeyID:     "owner-root-01",
			Alg:       PolicySigAlgEd25519,
			PublicKey: bytes.Clone(k.root),
			Owners:    []Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Readers: []Member{
			{PrincipalID: "bob", Label: "Bob"},
			{PrincipalID: "carol", Label: "Carol"},
			{PrincipalID: "dave", Label: "Dave"},
		},
		Admins: []Member{{PrincipalID: "alice", Label: "Alice"}},
		Owners: []Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []Device{
			{
				DeviceID:          "device-1",
				PrincipalID:       "alice",
				Label:             "Alice laptop",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev1)},
				AgeEncryptionKey:  fx.dev1.Recipient().String(),
			},
			{
				DeviceID:          "device-2",
				PrincipalID:       "bob",
				Label:             "Bob phone",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev2)},
				AgeEncryptionKey:  fx.dev2.Recipient().String(),
			},
			{
				DeviceID:          "device-3d",
				PrincipalID:       "dave",
				Label:             "Dave tablet",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: dev3Key},
				AgeEncryptionKey:  fx.dev3d.Recipient().String(),
			},
		},
	}
	if err := ValidatePolicy(p0); err != nil {
		t.Fatalf("fixture anchor policy is invalid: %v", err)
	}
	fx.initial = p0
	fx.chain = newCPChain(t, k)

	p1 := clonePolicy(p0)
	p1.Writers = []Member{{PrincipalID: "bob", Label: "Bob"}}
	fx.install(t, p1)
	return fx
}

// install replaces the carried chain with the fixture's anchor policy p0 and
// successor next, whose sequence and predecessor are set from p0. next is
// root-signed and linked to p0; the caller's pin is the digest of the p0 value
// it holds, which stays the carried anchor even when the current policy is
// the fixture's own successor.
func (fx *fileSealFixture) install(t *testing.T, next *Policy) {
	t.Helper()
	c := fx.chain
	p0 := clonePolicy(fx.initial)
	n := clonePolicy(next)
	n.PolicySeq = p0.PolicySeq + 1
	n.PrevPolicyDigest = bytes.Clone(PolicyDigest(p0))
	if err := ValidatePolicy(n); err != nil {
		t.Fatalf("fixture successor is not a valid policy: %v", err)
	}
	// The chain's header is rebuilt, never mutated in place: finalize writes
	// the embedded header and signatures bind h plus every carried proof.
	// The carried chain is exactly p0 then next, root-signed by finalize.
	c.policies = []*Policy{p0, n}
	*c.f = File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:    p0.VaultID,
			KeyEpoch:   3,
			ContentSeq: 42,
			PrevDigest: digest("content-41"),
			OpID:       "op-0042",
			PolicySeq:  n.PolicySeq,
			// Placeholder; finalize binds the current proof's digest.
			PolicyDigest:   make([]byte, 32),
			AuthorDeviceID: "device-1",
		},
		SignedPolicyProofs: make([]SignedPolicy, 2),
		ContentEncoding:    ContentEncoding,
	}
	// finalize seals the chain as it stands, so next must already carry a
	// structurally valid roster: one opaque slot per device and a CEK slot.
	// They are placeholders; the seal under test never reads them.
	for _, d := range n.Devices {
		c.f.VUKDeviceSlots = append(c.f.VUKDeviceSlots, DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("fixture")})
	}
	c.f.CEKSlot = CEKSlot{KeyEpoch: c.f.Header.KeyEpoch, WrappedCEK: []byte("fixture")}
	c.f.KDBXCiphertext = []byte("fixture")
	c.rebind(0, "owner-root-01")
	c.rebind(1, "owner-root-01")
	c.finalize(t, fx.keys)
	if !bytes.Equal(PolicyDigest(p0), policyDigest(&c.f.SignedPolicyProofs[0])) {
		t.Fatal("fixture anchor is not the carried anchor policy")
	}
	// The caller's pin is the digest of the p0 value it holds.
	c.anchor = &PolicyCheckpoint{
		VaultID:            p0.VaultID,
		OwnerRootKeyID:     p0.OwnerRoot.KeyID,
		OwnerRootPublicKey: bytes.Clone(fx.keys.root),
		PolicySeq:          p0.PolicySeq,
		PolicyDigest:       PolicyDigest(p0),
	}
	if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
		t.Fatalf("fixture checkpoint does not verify: %v", err)
	}
}

// draft is a fresh builder File for the fixture chain: the protocol format
// and version, a copy of the carried header and the signed proofs, and every
// derived wire field zero, as a writer builds it.
func (fx *fileSealFixture) draft() *File {
	f := &File{
		Format:             Format,
		Version:            Version,
		Header:             fx.chain.f.Header,
		SignedPolicyProofs: fx.chain.f.SignedPolicyProofs,
	}
	f.Header.PrevDigest = bytes.Clone(f.Header.PrevDigest)
	f.Header.PolicyDigest = bytes.Clone(f.Header.PolicyDigest)
	f.Header.RevisionID = ""
	f.ContentSignature = Signature{}
	return f
}

// wantDraftUnchanged checks that f is still equal, in every field, to before,
// the builder File value it held before the call.
func wantDraftUnchanged(t *testing.T, before, f *File) {
	t.Helper()
	if !reflect.DeepEqual(f, before) {
		t.Fatal("SealAuthenticatedFile mutated the caller's draft")
	}
}

// wantHeaderUnchanged checks that f still carries exactly the header fields
// the fixture sealed its chain with: every preimage member, not the derived
// revision id that only a builder draft leaves empty. The reference header was
// copied by value when finalize sealed the chain, so the comparison never
// re-derives a revision id or a preimage.
func (fx *fileSealFixture) wantHeaderUnchanged(t *testing.T, f *File) {
	t.Helper()
	want := fx.chain.f.Header
	want.RevisionID = f.Header.RevisionID
	want.PrevDigest = bytes.Clone(want.PrevDigest)
	want.PolicyDigest = bytes.Clone(want.PolicyDigest)
	if !reflect.DeepEqual(f.Header, want) {
		t.Fatal("SealAuthenticatedFile mutated the carried header")
	}
}

// dbWithCredentials attaches a distinctive password credential to a fresh
// unlocked payload fixture database and returns it together with the
// credential bytes to compare against. The bytes are a clone: the vendored
// encoder's cleanup may rehash a credential slice in place, so only a copy
// taken before the call can tell a restored value from a rewritten one.
func dbWithCredentials(t *testing.T) (*kdbx.Database, []byte) {
	t.Helper()
	db := payloadFixtureDB(t)
	cred := kdbx.NewPasswordCredentials("prior passphrase")
	db.Credentials = cred
	return db, bytes.Clone(cred.Passphrase)
}

// wantCredsRestored checks that db still carries exactly the pointer it had
// and credential bytes equal to want.
func wantCredsRestored(t *testing.T, db *kdbx.Database, want []byte) {
	t.Helper()
	if db.Credentials == nil || !bytes.Equal(db.Credentials.Passphrase, want) {
		t.Fatal("db.Credentials was not restored to the caller's prior value")
	}
}

// reachedKDBX reports whether SealKDBXPayload's fixed profile was installed
// on db, which happens after its package-shape check and before any KDF work.
func reachedKDBX(db *kdbx.Database) bool {
	return db.Header != nil && db.Header.FileHeaders != nil &&
		db.Header.FileHeaders.KdfParameters != nil &&
		bytes.Equal(db.Header.FileHeaders.KdfParameters.UUID, kdbx.KdfArgon2id)
}

// malformedDB is the sequencing sentinel for a path that must stop before
// SealKDBXPayload: nil Header makes SealKDBXPayload, and every precheck before
// it, report CodeKDBXPayloadInvalid without installing the profile, reading a
// credential or running the KDF.
func malformedDB(t *testing.T) (*kdbx.Database, []byte) {
	t.Helper()
	db, cred := dbWithCredentials(t)
	db.Header = nil
	return db, cred
}

// sentinelDB is the sequencing sentinel for a path that reaches
// SealKDBXPayload: an otherwise valid database whose cipher is one the
// vendored encoder does not support is rejected there as
// CodeKDBXPayloadInvalid, so the KDBX code identifies the step that caught it.
func sentinelDB(t *testing.T) (*kdbx.Database, []byte) {
	t.Helper()
	db, cred := dbWithCredentials(t)
	db.Header.FileHeaders.CipherID = []byte{0xde, 0xad, 0xbe, 0xef}
	return db, cred
}

// wantRejected checks that a rejected seal returned no bytes, that the draft
// is unchanged and that the database's prior credentials are restored.
func wantRejected(t *testing.T, out []byte, err error, before, draft *File, db *kdbx.Database, cred []byte) {
	t.Helper()
	if out != nil {
		t.Fatal("rejected SealAuthenticatedFile returned bytes")
	}
	if err == nil {
		t.Fatal("SealAuthenticatedFile returned no error")
	}
	wantDraftUnchanged(t, before, draft)
	if db != nil && cred != nil {
		wantCredsRestored(t, db, cred)
	}
}

// wantVUKSlots checks that f carries exactly one slot per want identity, in
// the wire's strict device_id order, and that the device's own identity opens
// each one through the full open path.
func wantVUKSlots(t *testing.T, encoded []byte, pin *PolicyCheckpoint, want map[string]*age.X25519Identity) {
	t.Helper()
	f, err := ParseFile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(f.VUKDeviceSlots) != len(ids) {
		t.Fatalf("VUK device slots = %+v, want exactly %v", f.VUKDeviceSlots, ids)
	}
	for i, id := range ids {
		s := f.VUKDeviceSlots[i]
		if s.DeviceID != id || s.Recipient != want[id].Recipient().String() || len(s.WrappedVUK) == 0 {
			t.Fatalf("VUK device slot %d = %+v, want device %s recipient %s", i, s, id, want[id].Recipient().String())
		}
		if _, _, err := OpenAuthenticatedFile(encoded, pin, id, want[id]); err != nil {
			t.Fatalf("device %s cannot open the sealed file: %v", id, err)
		}
	}
}

func TestSealAuthenticatedFileRoundTrip(t *testing.T) {
	fx := newSealFixture(t)
	draft := fx.draft()
	draftBefore := deepCopyFile(draft)
	vukBefore := bytes.Clone(fx.vuk)
	db, cred := dbWithCredentials(t)

	encoded, err := SealAuthenticatedFile(draft, db, fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	if encoded == nil {
		t.Fatal("SealAuthenticatedFile returned nil bytes and a nil error")
	}
	if !bytes.Equal(fx.vuk, vukBefore) {
		t.Fatal("SealAuthenticatedFile modified the caller's VUK")
	}
	wantCredsRestored(t, db, cred)
	wantDraftUnchanged(t, draftBefore, draft)
	fx.wantHeaderUnchanged(t, draft)
	// The carried proofs, each proof's document and signature included, are
	// unchanged as well.
	if !reflect.DeepEqual(draft.SignedPolicyProofs, fx.chain.f.SignedPolicyProofs) {
		t.Fatal("SealAuthenticatedFile mutated the carried policy proofs")
	}

	// The output opens immediately with the same pin, device and identity.
	f, opened, err := OpenAuthenticatedFile(encoded, fx.chain.anchor, "device-1", fx.dev1)
	if err != nil {
		t.Fatalf("OpenAuthenticatedFile of sealed bytes: %v", err)
	}
	entry := opened.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatalf("title = %q, want fixture", got)
	}
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("protected value = %q, want %q", got, payloadProtectedSecret)
	}
	if !entry.Values[1].Value.Protected.Bool {
		t.Fatal("protected flag lost")
	}
	if len(entry.Binaries) != 1 || entry.Binaries[0].Name != payloadAttachmentName {
		t.Fatalf("binary references = %+v", entry.Binaries)
	}
	binary := opened.FindBinary(entry.Binaries[0].Value.ID)
	if binary == nil || !bytes.Equal(binary.Content, payloadAttachmentBytes) {
		t.Fatalf("attachment bytes did not survive: %v", binary)
	}

	// Exactly one slot per current read device, each opening with its own
	// identity.
	wantVUKSlots(t, encoded, fx.chain.anchor, map[string]*age.X25519Identity{
		"device-1": fx.dev1, "device-2": fx.dev2, "device-3d": fx.dev3d,
	})

	// A fresh per-snapshot CEK and a fresh envelope per device for every seal.
	again, err := SealAuthenticatedFile(fx.draft(), payloadFixtureDB(t), fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("second SealAuthenticatedFile: %v", err)
	}
	second, err := ParseFile(again)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(second.CEKSlot.WrappedCEK, f.CEKSlot.WrappedCEK) {
		t.Fatal("two seals reused the same CEK slot")
	}
	if bytes.Equal(second.VUKDeviceSlots[0].WrappedVUK, f.VUKDeviceSlots[0].WrappedVUK) {
		t.Fatal("two seals reused the same VUK envelope")
	}
}

func TestSealAuthenticatedFileRejectsBasicInputs(t *testing.T) {
	type inputs struct {
		draft *File
		db    *kdbx.Database
		pin   *PolicyCheckpoint
		vuk   []byte
	}
	cases := map[string]struct {
		mutate func(*testing.T, *inputs)
		code   string
		path   string
	}{
		"nil draft":       {func(*testing.T, *inputs) {}, CodeInvalidValue, ""},
		"nil checkpoint":  {func(*testing.T, *inputs) {}, CodeInvalidValue, ""},
		"nil db":          {func(*testing.T, *inputs) {}, CodeInvalidValue, ""},
		"nil bytes vuk":   {func(*testing.T, *inputs) {}, CodeInvalidValue, ""},
		"31-byte vuk":     {func(*testing.T, *inputs) {}, CodeInvalidValue, ""},
		"unknown format":  {func(_ *testing.T, in *inputs) { in.draft.Format = "other" }, CodeInvalidValue, ""},
		"unknown version": {func(_ *testing.T, in *inputs) { in.draft.Version = 2 }, CodeInvalidValue, ""},
		"foreign encoding": {
			func(_ *testing.T, in *inputs) { in.draft.ContentEncoding = "other" }, CodeInvalidValue, "content_encoding"},
		"zero epoch": {
			func(_ *testing.T, in *inputs) { in.draft.Header.KeyEpoch = 0 }, CodeInvalidValue, "key_epoch"},
		"empty author": {
			func(_ *testing.T, in *inputs) { in.draft.Header.AuthorDeviceID = "" }, CodeInvalidValue, ""},
		"no proofs": {
			func(_ *testing.T, in *inputs) { in.draft.SignedPolicyProofs = nil }, CodeInvalidValue, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// Each case gets its own chain: the draft embeds a copy of the
			// carried header, and finalize writes the chain's header in place.
			fx := newSealFixture(t)
			db, cred := dbWithCredentials(t)
			in := inputs{draft: fx.draft(), db: db, pin: fx.chain.anchor, vuk: fx.vuk}
			c.mutate(t, &in)
			switch name {
			case "nil draft":
				in.draft = nil
			case "nil checkpoint":
				in.pin = nil
			case "nil db":
				in.db, cred = nil, nil
			case "nil bytes vuk":
				in.vuk = nil
			case "31-byte vuk":
				in.vuk = in.vuk[:CEKSize-1]
			}
			var before *File
			if in.draft != nil {
				before = deepCopyFile(in.draft)
			}
			out, err := SealAuthenticatedFile(in.draft, in.db, in.pin, in.vuk, fx.keys.dev1Priv)
			if out != nil {
				t.Fatal("rejected seal returned bytes")
			}
			wantCodeAt(t, err, c.code, c.path)
			if in.db != nil {
				wantCredsRestored(t, in.db, cred)
				if reachedKDBX(in.db) {
					t.Fatal("a basic-input rejection reached SealKDBXPayload")
				}
			}
			if before != nil {
				wantDraftUnchanged(t, before, in.draft)
			}
		})
	}
}

// sealPositive runs the untouched fixture through SealAuthenticatedFile, so a
// negative below always has a real positive of the same fixture first.
func sealPositive(t *testing.T, fx *fileSealFixture) []byte {
	t.Helper()
	encoded, err := SealAuthenticatedFile(fx.draft(), payloadFixtureDB(t), fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("positive seal: %v", err)
	}
	return encoded
}

// TestSealAuthenticatedFileWrongPin proves chain verification precedes every
// KDBX side effect. The database is the malformed sequencing sentinel, which
// SealKDBXPayload and every precheck before it report as
// CodeKDBXPayloadInvalid. Getting exactly CodePolicyCheckpointFailed, with the
// sentinel's credentials untouched and no KDF profile installed, proves the
// seal never reached KDBX work.
func TestSealAuthenticatedFileWrongPin(t *testing.T) {
	t.Run("digest mismatch", func(t *testing.T) {
		fx := newSealFixture(t)
		if _, _, err := OpenAuthenticatedFile(sealPositive(t, fx), fx.chain.anchor, "device-1", fx.dev1); err != nil {
			t.Fatalf("positive cannot open: %v", err)
		}

		pin := *fx.chain.anchor
		pin.PolicyDigest = bytes.Clone(fx.chain.anchor.PolicyDigest)
		pin.PolicyDigest[0] ^= 0xff
		db, cred := malformedDB(t)
		draft := fx.draft()
		before := deepCopyFile(draft)
		out, err := SealAuthenticatedFile(draft, db, &pin, fx.vuk, fx.keys.dev1Priv)
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
		wantRejected(t, out, err, before, draft, db, cred)
		if reachedKDBX(db) {
			t.Fatal("verifyPolicyChain did not precede SealKDBXPayload")
		}
	})

	t.Run("pin names another policy", func(t *testing.T) {
		fx := newSealFixture(t)
		sealPositive(t, fx)

		pin := *fx.chain.anchor
		pin.PolicyDigest = digest("some-other-policy")
		db, cred := malformedDB(t)
		draft := fx.draft()
		before := deepCopyFile(draft)
		out, err := SealAuthenticatedFile(draft, db, &pin, fx.vuk, fx.keys.dev1Priv)
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
		wantRejected(t, out, err, before, draft, db, cred)
		if reachedKDBX(db) {
			t.Fatal("verifyPolicyChain did not precede SealKDBXPayload")
		}
	})

	t.Run("rotated carried roster", func(t *testing.T) {
		// The successor's devices are replaced on the caller's side only, while
		// that signed policy's canonical Document keeps the original roster.
		// validateSignedPolicy must reject exactly this policy/document
		// mismatch rather than accept the new roster.
		fx := newSealFixture(t)
		sealPositive(t, fx)

		db, cred := malformedDB(t)
		draft := fx.draft()
		draft.SignedPolicyProofs = append([]SignedPolicy(nil), draft.SignedPolicyProofs...)
		last := &draft.SignedPolicyProofs[len(draft.SignedPolicyProofs)-1]
		last.Policy.Devices = last.Policy.Devices[:2]
		before := deepCopyFile(draft)
		out, err := SealAuthenticatedFile(draft, db, fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
		wantCodeAt(t, err, CodePolicyMismatch, "")
		wantRejected(t, out, err, before, draft, db, cred)
		if reachedKDBX(db) {
			t.Fatal("verifyPolicyChain did not precede SealKDBXPayload")
		}
	})
}

// TestSealAuthenticatedFileWrongAuthorKey proves the author key check sits
// between the chain and the VUK/CEK/KDBX work. The current policy authorizes
// the header's author device, but each key below is not that device's
// authenticated content signing key, including the seed-only key whose public
// half is exactly the authorized one but whose seed does not derive it. The
// sentinel database reports CodeKDBXPayloadInvalid inside SealKDBXPayload when
// the seal does reach it, so an author-key error on the same database proves
// the seal stopped earlier.
func TestSealAuthenticatedFileWrongAuthorKey(t *testing.T) {
	fx := newSealFixture(t)
	cases := map[string]ed25519.PrivateKey{
		"another real key": fx.keys.dev2Priv,
		"root key":         fx.keys.rootPriv,
		"short key":        fx.keys.dev1Priv[:ed25519.SeedSize],
		"nil key":          nil,
		"tampered key": func() ed25519.PrivateKey {
			k := bytes.Clone(fx.keys.dev1Priv)
			k[ed25519.PrivateKeySize-1] ^= 0x01
			return k
		}(),
		// Only a seed byte changes; the trailing public half, which
		// PrivateKey.Public copies, still names the authorized device key.
		"seed-only mutation": func() ed25519.PrivateKey {
			k := bytes.Clone(fx.keys.dev1Priv)
			k[0] ^= 0x01
			return k
		}(),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			sealPositive(t, fx)
			db, cred := sentinelDB(t)
			draft := fx.draft()
			before := deepCopyFile(draft)
			// The caller's key is an input like the draft and VUK: the seal
			// must not modify it, whatever it decides about it.
			keyBefore := bytes.Clone(key)
			out, err := SealAuthenticatedFile(draft, db, fx.chain.anchor, fx.vuk, key)
			if key != nil && !bytes.Equal(key, keyBefore) {
				t.Fatal("SealAuthenticatedFile modified the caller's author private key")
			}
			e, ok := AsError(err)
			if !ok || e.Code != CodeAuthorSigningKeyMismatch || e.Path != "content_signature" {
				t.Fatalf("err = %v, want %s at content_signature", err, CodeAuthorSigningKeyMismatch)
			}
			wantRejected(t, out, err, before, draft, db, cred)
			if reachedKDBX(db) {
				t.Fatal("the author key check did not precede SealKDBXPayload")
			}
		})
	}

	// Positive first, then the sentinel: the same database with the right key
	// reaches SealKDBXPayload and is rejected there as a KDBX payload, which is
	// the step the keys above never reached.
	sealPositive(t, fx)
	db, cred := sentinelDB(t)
	_, err := SealAuthenticatedFile(fx.draft(), db, fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	wantCodeAt(t, err, CodeKDBXPayloadInvalid, "")
	wantCredsRestored(t, db, cred)
}

// TestSealAuthenticatedFileRevokedPriorReader seals under a valid root-signed
// successor, seq 7, that removes a previously authorised reader and device
// from the already accepted seq 6 policy. The old device has a real age
// identity in the predecessor and a real slot in a file sealed under it, so
// the current-policy rejection is a policy decision, not a missing key.
//
// The same test then documents the boundary this policy change does not
// cross. Dave learned the epoch VUK from the seq 6 file; resealing seq 7 with
// that same VUK and epoch leaves the learned VUK able to open the new CEK and
// payload through the low-level primitives. The VUK was not cryptographically
// revoked: the removal makes only the current OpenAuthenticatedFile policy
// check reject device-3d. A real revocation needs a separate rotation to a
// fresh VUK and a protocol epoch advance, which SealAuthenticatedFile does not
// implement.
func TestSealAuthenticatedFileRevokedPriorReader(t *testing.T) {
	fx := newSealFixture(t)
	p0, p1 := fx.chain.policies[0], fx.chain.policies[1]
	if p0.PolicySeq != 5 || p1.PolicySeq != 6 {
		t.Fatalf("fixture chain is seq %d then %d, want 5 then 6", p0.PolicySeq, p1.PolicySeq)
	}
	if findDevice(p1, "device-3d") == nil || !p1.hasRole("dave", RoleReader) {
		t.Fatal("the accepted predecessor does not name dave as a reader with device-3d")
	}

	// Positive first: the seq 6 chain names dave, and device-3d opens.
	beforeEnc := sealPositive(t, fx)
	before, err := ParseFile(beforeEnc)
	if err != nil {
		t.Fatal(err)
	}
	if before.Header.PolicySeq != p1.PolicySeq {
		t.Fatalf("positive sealed policy seq = %d, want %d", before.Header.PolicySeq, p1.PolicySeq)
	}
	beforeSlot := findDeviceSlot(before, "device-3d")
	if beforeSlot == nil {
		t.Fatal("the positive file carries no device-3d slot before revocation")
	}
	if _, _, err := OpenAuthenticatedFile(beforeEnc, fx.chain.anchor, "device-3d", fx.dev3d); err != nil {
		t.Fatalf("device-3d cannot open before revocation: %v", err)
	}

	// Dave's device learns the epoch VUK and the CEK from that file, using
	// the authenticated recipient and the file's own epoch and CEK slot.
	daveVUK, err := OpenVUKForDevice(*beforeSlot, fx.chain.anchor.VaultID, before.Header.KeyEpoch, "device-3d", fx.dev3d.Recipient().String(), fx.dev3d)
	if err != nil {
		t.Fatalf("device-3d cannot open its learned VUK: %v", err)
	}
	defer clear(daveVUK)
	if !bytes.Equal(daveVUK, fx.vuk) {
		t.Fatal("device-3d learned a VUK other than the supplied epoch VUK")
	}
	daveCEK, err := OpenCEK(daveVUK, before.Header, before.CEKSlot)
	if err != nil {
		t.Fatalf("device-3d cannot open the positive CEK: %v", err)
	}
	// The learned VUK is what this test carries forward to the successor; it
	// is cleared with the CEK it opens there.
	clear(daveCEK)

	// The successor is a real seq 7: a root-signed continuation appended to
	// the accepted seq 6 policy, itself linked to p0's digest. It carries
	// p0 then p1 unchanged, removes dave from readers and device-3d from
	// devices, and is signed and wired by append and finalize.
	p2 := clonePolicy(p1)
	p2.PolicySeq = p1.PolicySeq + 1
	p2.PrevPolicyDigest = PolicyDigest(p1)
	p2.Readers = []Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: "carol", Label: "Carol"}}
	if len(p2.Devices) != 3 || p2.Devices[2].DeviceID != "device-3d" {
		t.Fatalf("unexpected fixture devices: %+v", p2.Devices)
	}
	p2.Devices = p2.Devices[:2]
	if err := ValidatePolicy(p2); err != nil {
		t.Fatalf("successor policy is not a valid policy: %v", err)
	}
	fx.chain.append(t, p2, "owner-root-01", nil)
	// finalize seals the chain as it stands, so it must already carry a
	// structurally valid roster for p2: one opaque slot per p2 device in
	// ascending order and a CEK slot. These are placeholders; the seal under
	// test overwrites every one of them from the authenticated policy.
	p2Roster := make([]DeviceSlot, 0, len(p2.Devices))
	for _, d := range p2.Devices {
		p2Roster = append(p2Roster, DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("fixture")})
	}
	keyEpoch := fx.chain.f.Header.KeyEpoch
	fx.chain.f.VUKDeviceSlots = p2Roster
	fx.chain.f.CEKSlot = CEKSlot{KeyEpoch: keyEpoch, WrappedCEK: []byte("fixture")}
	fx.chain.f.KDBXCiphertext = []byte("fixture")
	fx.chain.f.Header.RevisionID = ""
	fx.chain.f.ContentSignature = Signature{}
	fx.chain.finalize(t, fx.keys)
	if findDeviceSlot(fx.chain.f, "device-3d") != nil {
		t.Fatal("the finalize roster placeholder still names device-3d")
	}
	if got := len(fx.chain.f.SignedPolicyProofs); got != 3 {
		t.Fatalf("carried proofs = %d, want 3", got)
	}
	if !bytes.Equal(PolicyDigest(p0), policyDigest(&fx.chain.f.SignedPolicyProofs[0])) ||
		!bytes.Equal(PolicyDigest(p1), policyDigest(&fx.chain.f.SignedPolicyProofs[1])) ||
		!bytes.Equal(PolicyDigest(p2), policyDigest(&fx.chain.f.SignedPolicyProofs[2])) {
		t.Fatal("the carried chain does not carry exactly p0, p1, p2")
	}
	// The seq 5 anchor keeps its pinned placeholder bytes and the carried
	// seq 6 proof keeps the root signature the positive was sealed with.
	if !bytes.Equal(fx.chain.f.SignedPolicyProofs[0].Sig, pf(0x7f, ed25519.SignatureSize)) {
		t.Fatal("the pinned seq 5 anchor proof changed")
	}
	if bytes.Equal(fx.chain.f.SignedPolicyProofs[1].Sig, pf(0x60, ed25519.SignatureSize)) ||
		!bytes.Equal(fx.chain.f.SignedPolicyProofs[1].Sig, before.SignedPolicyProofs[1].Sig) {
		t.Fatal("the accepted seq 6 proof was not carried unchanged")
	}
	if bytes.Equal(fx.chain.f.SignedPolicyProofs[2].Sig, pf(0x60, ed25519.SignatureSize)) {
		t.Fatal("the seq 7 proof carries a placeholder, not a root signature")
	}
	if fx.chain.f.Header.PolicySeq != 7 || !bytes.Equal(fx.chain.f.Header.PolicyDigest, PolicyDigest(p2)) {
		t.Fatalf("sealed successor header is policy seq %d, want 7 bound to p2", fx.chain.f.Header.PolicySeq)
	}
	if err := VerifyPolicyCheckpoint(fx.chain.f, fx.chain.anchor); err != nil {
		t.Fatalf("successor does not verify under the pinned seq 5 anchor: %v", err)
	}

	// The old device's slot, recipient, CEK slot and ciphertext are stale
	// draft state: the seal overwrites every one of them.
	draft := fx.draft()
	draft.VUKDeviceSlots = []DeviceSlot{{
		DeviceID:   "device-3d",
		Recipient:  fx.dev3d.Recipient().String(),
		WrappedVUK: []byte("stale"),
	}}
	draft.CEKSlot = CEKSlot{KeyEpoch: draft.Header.KeyEpoch, WrappedCEK: []byte("stale")}
	draft.KDBXCiphertext = []byte("stale")
	draftBefore := deepCopyFile(draft)
	// The seal is given the same VUK and epoch dave learned: nothing rotates.
	vukBefore := bytes.Clone(fx.vuk)
	db, cred := dbWithCredentials(t)

	encoded, err := SealAuthenticatedFile(draft, db, fx.chain.anchor, daveVUK, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("seal under the successor: %v", err)
	}
	if !bytes.Equal(daveVUK, vukBefore) {
		t.Fatal("the seal modified the caller's VUK")
	}
	wantCredsRestored(t, db, cred)
	wantDraftUnchanged(t, draftBefore, draft)

	// The sealed successor is policy seq 7 and carries VUK slots exactly for
	// the current read devices; device-3d has none.
	sealed, err := ParseFile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Header.PolicySeq != p2.PolicySeq {
		t.Fatalf("sealed successor policy seq = %d, want %d", sealed.Header.PolicySeq, p2.PolicySeq)
	}
	if want := int(p0.PolicySeq) + 2; sealed.Header.PolicySeq != uint64(want) {
		t.Fatalf("sealed successor policy seq = %d, want %d", sealed.Header.PolicySeq, want)
	}
	wantVUKSlots(t, encoded, fx.chain.anchor, map[string]*age.X25519Identity{
		"device-1": fx.dev1, "device-2": fx.dev2,
	})
	if findDeviceSlot(sealed, "device-3d") != nil {
		t.Fatal("the sealed successor still carries a device-3d slot")
	}

	// The current-policy check rejects the old device with exactly
	// invalid_value at device_id, and no handle is returned.
	got, gdb, err := OpenAuthenticatedFile(encoded, fx.chain.anchor, "device-3d", fx.dev3d)
	wantCodeAt(t, err, CodeInvalidValue, "device_id")
	if got != nil || gdb != nil {
		t.Fatalf("revoked open returned file/database = %v/%v, want both nil", got, gdb)
	}

	// The boundary this test documents: that rejection is a policy decision,
	// not revocation of the learned VUK. The VUK device-3d learned from the
	// seq 6 file still opens the seq 7 CEK slot with the low-level OpenCEK and
	// then the seq 7 KDBX payload with OpenKDBXPayload, because the seal
	// reused the same VUK and epoch unchanged.
	staleCEK, err := OpenCEK(daveVUK, sealed.Header, sealed.CEKSlot)
	if err != nil {
		t.Fatalf("the learned VUK cannot open the successor CEK: %v", err)
	}
	defer clear(staleCEK)
	staleDB, err := OpenKDBXPayload(sealed.KDBXCiphertext, staleCEK)
	if err != nil {
		t.Fatalf("the learned VUK and CEK cannot open the successor payload: %v", err)
	}
	entry := staleDB.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatalf("successor payload title = %q, want fixture", got)
	}
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("successor payload protected value = %q, want %q", got, payloadProtectedSecret)
	}
	staleDB.Credentials = nil
}
