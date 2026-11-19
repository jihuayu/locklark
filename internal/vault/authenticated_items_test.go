package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// authItemsFixture is one real caller-pinned vault for the authenticated item
// adapter tests. Every key is generated. The policy is a genesis owner policy,
// the one proof is its root signature, and the pin is the caller's digest of
// that proof. The caller-built draft is a genesis content revision
// (content_seq 0, no prev_digest): the adapter computes neither.
type authItemsFixture struct {
	draft  *vaultfile.File
	pin    *vaultfile.PolicyCheckpoint
	device *age.X25519Identity
	vuk    []byte
	author ed25519.PrivateKey
}

func newAuthItemsFixture(t *testing.T) *authItemsFixture {
	t.Helper()
	genKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	}
	rootPub, rootPriv := genKey()
	authorPub, authorPriv := genKey()
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}

	policy := &vaultfile.Policy{
		Format:           vaultfile.Format,
		Version:          vaultfile.Version,
		VaultID:          "vault-auth-items",
		PolicySeq:        0,
		PrevPolicyDigest: nil,
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     "owner-root-01",
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPub),
			Owners:    []vaultfile.Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Owners: []vaultfile.Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []vaultfile.Device{{
			DeviceID:          "device-1",
			PrincipalID:       "alice",
			Label:             "Alice laptop",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authorPub)},
			AgeEncryptionKey:  device.Recipient().String(),
		}},
	}
	if err := vaultfile.ValidatePolicy(policy); err != nil {
		t.Fatalf("genesis owner policy is invalid: %v", err)
	}
	doc, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatalf("encode policy document: %v", err)
	}
	proof := vaultfile.SignedPolicy{
		Policy:   *policy,
		Document: doc,
		SignerID: "owner-root-01",
		Alg:      vaultfile.PolicySigAlgEd25519,
		Sig:      ed25519.Sign(rootPriv, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), doc...)),
	}
	policyDigest := vaultfile.PolicyDigest(policy)
	if len(policyDigest) != 32 {
		t.Fatalf("policy digest has %d bytes", len(policyDigest))
	}
	return &authItemsFixture{
		draft: &vaultfile.File{
			Format:  vaultfile.Format,
			Version: vaultfile.Version,
			Header: vaultfile.Header{
				VaultID:        policy.VaultID,
				KeyEpoch:       1,
				ContentSeq:     0,
				PrevDigest:     nil,
				OpID:           "op-caller-0007",
				PolicySeq:      policy.PolicySeq,
				PolicyDigest:   policyDigest,
				AuthorDeviceID: "device-1",
			},
			SignedPolicyProofs: []vaultfile.SignedPolicy{proof},
		},
		pin: &vaultfile.PolicyCheckpoint{
			VaultID:            policy.VaultID,
			OwnerRootKeyID:     policy.OwnerRoot.KeyID,
			OwnerRootPublicKey: bytes.Clone(rootPub),
			PolicySeq:          policy.PolicySeq,
			PolicyDigest:       bytes.Clone(policyDigest),
		},
		device: device,
		vuk:    vuk,
		author: authorPriv,
	}
}

// deepCopy returns a deep copy of x for types made only of maps, slices,
// structs, pointers, strings and comparable scalars. File has no shared state
// (no caches, mutexes or interfaces) and Item is plain data, so it is exact
// here. It exists so the snapshot is a structurally independent value: a
// reflect.DeepEqual that silently compared an alias with itself could not
// prove that the adapter left a field untouched.
func deepCopy[T any](x T) T {
	switch v := any(x).(type) {
	case []byte:
		return any(bytes.Clone(v)).(T)
	case []Item:
		out := make([]Item, len(v))
		for i := range v {
			out[i] = deepCopy(v[i])
		}
		return any(out).(T)
	case Item:
		out := v // every slice and pointer field is replaced below
		out.Attachment = bytes.Clone(v.Attachment)
		out.ImportSource = bytes.Clone(v.ImportSource)
		out.SSHSeed = bytes.Clone(v.SSHSeed)
		out.SSHPublicKey = bytes.Clone(v.SSHPublicKey)
		out.Passkey = bytes.Clone(v.Passkey)
		if v.Passkeys != nil {
			out.Passkeys = make([][]byte, len(v.Passkeys))
			for i := range v.Passkeys {
				out.Passkeys[i] = bytes.Clone(v.Passkeys[i])
			}
		}
		if v.Attachments != nil {
			out.Attachments = make([]AttachmentMeta, len(v.Attachments))
			for i := range v.Attachments {
				out.Attachments[i] = v.Attachments[i]
				out.Attachments[i].Content = bytes.Clone(v.Attachments[i].Content)
			}
		}
		if v.History != nil {
			out.History = make([]ItemHistoryEntry, len(v.History))
			for i, h := range v.History {
				out.History[i] = h
				out.History[i].Sections = deepCopy(h.Sections)
			}
		}
		if v.Sections != nil {
			out.Sections = deepCopy(v.Sections)
		}
		out.Tags = append([]string(nil), v.Tags...)
		if v.AutoSubmit != nil {
			b := *v.AutoSubmit
			out.AutoSubmit = &b
		}
		if v.TrashedAt != nil {
			at := *v.TrashedAt
			out.TrashedAt = &at
		}
		return any(out).(T)
	case []ItemSection:
		out := make([]ItemSection, len(v))
		for i, s := range v {
			out[i] = s
			out[i].Fields = append([]CustomField(nil), s.Fields...)
		}
		return any(out).(T)
	case *vaultfile.File:
		if v == nil {
			return any((*vaultfile.File)(nil)).(T)
		}
		out := *v
		out.Header.PrevDigest = bytes.Clone(v.Header.PrevDigest)
		out.Header.PolicyDigest = bytes.Clone(v.Header.PolicyDigest)
		out.SignedPolicyProofs = make([]vaultfile.SignedPolicy, len(v.SignedPolicyProofs))
		for i, sp := range v.SignedPolicyProofs {
			out.SignedPolicyProofs[i] = sp
			out.SignedPolicyProofs[i].Document = bytes.Clone(sp.Document)
			out.SignedPolicyProofs[i].Sig = bytes.Clone(sp.Sig)
			p := &out.SignedPolicyProofs[i].Policy
			q := sp.Policy
			p.PrevPolicyDigest = bytes.Clone(q.PrevPolicyDigest)
			p.OwnerRoot.Owners = append([]vaultfile.Principal(nil), q.OwnerRoot.Owners...)
			p.OwnerRoot.PublicKey = bytes.Clone(q.OwnerRoot.PublicKey)
			p.Readers = append([]vaultfile.Member(nil), q.Readers...)
			p.Writers = append([]vaultfile.Member(nil), q.Writers...)
			p.Admins = append([]vaultfile.Member(nil), q.Admins...)
			p.Owners = append([]vaultfile.Member(nil), q.Owners...)
			p.AdminDelegations = append([]vaultfile.AdminDelegation(nil), q.AdminDelegations...)
			p.Devices = append([]vaultfile.Device(nil), q.Devices...)
			for j := range p.Devices {
				p.Devices[j].ContentSigningKey.PublicKey = bytes.Clone(q.Devices[j].ContentSigningKey.PublicKey)
			}
		}
		out.KDBXCiphertext = bytes.Clone(v.KDBXCiphertext)
		out.VUKDeviceSlots = append([]vaultfile.DeviceSlot(nil), v.VUKDeviceSlots...)
		for i := range out.VUKDeviceSlots {
			out.VUKDeviceSlots[i].WrappedVUK = bytes.Clone(v.VUKDeviceSlots[i].WrappedVUK)
		}
		out.CEKSlot.WrappedCEK = bytes.Clone(v.CEKSlot.WrappedCEK)
		out.ContentSignature.Sig = bytes.Clone(v.ContentSignature.Sig)
		return any(&out).(T)
	case *vaultfile.PolicyCheckpoint:
		if v == nil {
			return any((*vaultfile.PolicyCheckpoint)(nil)).(T)
		}
		out := *v
		out.OwnerRootPublicKey = bytes.Clone(v.OwnerRootPublicKey)
		out.PolicyDigest = bytes.Clone(v.PolicyDigest)
		return any(&out).(T)
	default:
		panic("deepCopy: unsupported type")
	}
}

// authItemsFixtureItems returns synthetic items covering a history value, a
// protected attachment and a trashed item with TrashedAt. Every byte slice
// contains NUL and non-UTF-8 bytes so a text round trip would not survive.
func authItemsFixtureItems() []Item {
	attContent := []byte{'s', 'y', 'n', 0x00, 0xff, 0xfe, 't', 'h', 0x80}
	att := AttachmentMeta{
		ID: "recovery-file", FileName: "recovery.txt", Size: int64(len(attContent)),
		MIMEType: "text/plain", SHA256: AttachmentSHA256(attContent),
		Protected: true, Content: attContent,
	}
	trashedAt := time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC)
	return []Item{
		{
			ID: "login-a", Kind: "login", Title: "Example login", URL: "https://example.com/login",
			Username: "synthetic-user", Password: "synthetic-password",
			OTP: "otpauth://totp/example?secret=AAAA",
			History: []ItemHistoryEntry{{
				Timestamp: 1_700_000_000, Action: "password-change",
				Title: "Example login (old)", Username: "synthetic-old-user",
				Password: "synthetic-old-password", Notes: "synthetic old notes",
				Sections: []ItemSection{{
					ID: "credentials", Title: "Credentials",
					Fields: []CustomField{{ID: "recovery-pin", Label: "Recovery PIN", Type: FieldTypeConcealed, Value: "4821", Protected: true}},
				}},
			}},
			Attachments: []AttachmentMeta{att},
			Tags:        []string{"synthetic"},
		},
		{
			ID: "document-b", Kind: "document", Title: "Binary document",
			Filename: "fixture.bin", AttachmentProtected: true,
			// Distinct from the v2 attachment content above: KDBX binaries
			// deduplicate by digest, and both item byte slices must reach
			// the database as separate binaries.
			Attachment: []byte{'a', 0x00, 0xff, 'b', 0xc3, 0x28, 0x00, 'd'},
		},
		{
			ID: "trashed-c", Kind: "login", Title: "Trashed login",
			Username: "synthetic-trashed-user", Password: "synthetic-trashed-password",
			OTP:   "otpauth://totp/trashed?secret=BBBB",
			State: "trashed", PreviousState: "archived", TrashedAt: &trashedAt,
		},
	}
}

// authItemsFixtureMetadata is opaque metadata: it is not JSON and contains a
// NUL and invalid UTF-8.
func authItemsFixtureMetadata() []byte {
	return []byte{0x00, 0xff, '{', 'l', 'a', 'y', 'o', 'u', 't', '"', ':', 0xfe, 0x00}
}

// sealAuthItems runs the untouched fixture through SealAuthenticatedItems and
// checks the positive every negative shares: the sealed bytes open back
// through OpenAuthenticatedItems with exact metadata, item order and bytes.
func sealAuthItems(t *testing.T, fx *authItemsFixture, metadata []byte, items []Item) []byte {
	t.Helper()
	encoded, err := SealAuthenticatedItems(fx.draft, metadata, items, fx.pin, fx.vuk, fx.author)
	if err != nil {
		t.Fatalf("SealAuthenticatedItems: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("SealAuthenticatedItems returned no bytes and no error")
	}
	_, gotMeta, gotItems, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", fx.device)
	if err != nil {
		t.Fatalf("sealed file does not open: %v", err)
	}
	if !bytes.Equal(gotMeta, metadata) {
		t.Fatalf("metadata mismatch: got %x want %x", gotMeta, metadata)
	}
	if len(gotItems) != len(items) {
		t.Fatalf("item count: got %d want %d", len(gotItems), len(items))
	}
	for i := range items {
		if !reflect.DeepEqual(gotItems[i], items[i]) {
			t.Fatalf("item %d mismatch:\n got %+v\nwant %+v", i, gotItems[i], items[i])
		}
	}
	return encoded
}

// TestAuthenticatedItemsEndToEnd seals real synthetic items into a real
// caller-pinned file and opens them back, asserting exact fields and binary
// bytes and caller ownership on both sides.
func TestAuthenticatedItemsEndToEnd(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata, items := authItemsFixtureMetadata(), authItemsFixtureItems()
	if err := ValidateItems(metadata, items); err != nil {
		t.Fatalf("fixture items are invalid: %v", err)
	}

	wantDraft := deepCopy(fx.draft)
	wantMeta := bytes.Clone(metadata)
	wantItems := deepCopy(items)
	wantVUK := bytes.Clone(fx.vuk)
	wantAuthor := bytes.Clone(fx.author)
	wantPin := deepCopy(fx.pin)

	// Aliasing witnesses: every caller byte slice and the author key seed, as
	// addresses. If the adapter wrote into a caller buffer a witness would
	// change even when a later restore made a value comparison pass.
	var aliases []*byte
	witness := func(b []byte) {
		for i := range b {
			aliases = append(aliases, &b[i])
		}
	}
	witness(metadata)
	for _, it := range items {
		witness(it.Attachment)
		for _, a := range it.Attachments {
			witness(a.Content)
		}
	}
	witness(fx.vuk)
	witness(fx.author[:ed25519.SeedSize])
	before := make([]byte, len(aliases))
	for i, p := range aliases {
		before[i] = *p
	}

	encoded, err := SealAuthenticatedItems(fx.draft, metadata, items, fx.pin, fx.vuk, fx.author)
	if err != nil {
		t.Fatalf("SealAuthenticatedItems: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("SealAuthenticatedItems returned no bytes and no error")
	}

	for i, p := range aliases {
		if *p != before[i] {
			t.Fatalf("SealAuthenticatedItems wrote into caller input at witness %d", i)
		}
	}
	if !reflect.DeepEqual(fx.draft, wantDraft) {
		t.Fatal("SealAuthenticatedItems mutated the caller's draft")
	}
	if !bytes.Equal(metadata, wantMeta) || !reflect.DeepEqual(items, wantItems) {
		t.Fatal("SealAuthenticatedItems mutated caller metadata or items")
	}
	if !bytes.Equal(fx.vuk, wantVUK) || !bytes.Equal(fx.author, wantAuthor) {
		t.Fatal("SealAuthenticatedItems mutated the caller's VUK or author key")
	}
	if !reflect.DeepEqual(fx.pin, wantPin) {
		t.Fatal("SealAuthenticatedItems mutated the caller's checkpoint")
	}

	// The sealed file carries exactly the caller draft's header: its own
	// content_seq, prev_digest, op_id, vault, epoch, author and policy digest,
	// plus the revision SealAuthenticatedFile derives.
	sealed, err := vaultfile.ParseFile(encoded)
	if err != nil {
		t.Fatalf("sealed bytes do not parse: %v", err)
	}
	if sealed.Header.ContentSeq != fx.draft.Header.ContentSeq || !bytes.Equal(sealed.Header.PrevDigest, fx.draft.Header.PrevDigest) ||
		sealed.Header.OpID != fx.draft.Header.OpID || sealed.Header.VaultID != fx.draft.Header.VaultID ||
		sealed.Header.KeyEpoch != fx.draft.Header.KeyEpoch || sealed.Header.AuthorDeviceID != fx.draft.Header.AuthorDeviceID ||
		!bytes.Equal(sealed.Header.PolicyDigest, fx.draft.Header.PolicyDigest) || sealed.Header.RevisionID == "" {
		t.Fatalf("sealed header does not carry the caller draft: %+v", sealed.Header)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(sealed, fx.pin); err != nil {
		t.Fatalf("sealed file does not verify under the caller pin: %v", err)
	}

	// The VUK is wrapped for exactly the one authenticated read-capable
	// device, never for a roster carried by the draft.
	if len(sealed.VUKDeviceSlots) != 1 || sealed.VUKDeviceSlots[0].DeviceID != "device-1" {
		t.Fatalf("VUK slots are not exactly the authenticated device: %+v", sealed.VUKDeviceSlots)
	}

	f, gotMeta, gotItems, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", fx.device)
	if err != nil {
		t.Fatalf("OpenAuthenticatedItems: %v", err)
	}
	if f == nil || !bytes.Equal(gotMeta, wantMeta) {
		t.Fatalf("open returned file %v and metadata %x", f != nil, gotMeta)
	}
	if f.Header.RevisionID != sealed.Header.RevisionID || len(f.KDBXCiphertext) == 0 {
		t.Fatal("open returned a different authenticated file")
	}
	if !reflect.DeepEqual(gotItems, wantItems) {
		t.Fatalf("items mismatch:\n got %+v\nwant %+v", gotItems, wantItems)
	}
	// The private database is cleaned up before OpenAuthenticatedItems
	// returns. The returned attachment buffers must still carry exactly the
	// caller's bytes, not zeroed database copies.
	gotAttachmentBytes := callerAttachmentBytes(gotItems)
	wantAttachmentBytes := callerAttachmentBytes(items)
	if len(gotAttachmentBytes) != len(wantAttachmentBytes) {
		t.Fatalf("returned attachment count: got %d want %d", len(gotAttachmentBytes), len(wantAttachmentBytes))
	}
	for i := range wantAttachmentBytes {
		if len(gotAttachmentBytes[i]) == 0 || allZeros(gotAttachmentBytes[i]) ||
			!bytes.Equal(gotAttachmentBytes[i], wantAttachmentBytes[i]) {
			t.Fatalf("returned attachment %d was not preserved: got %x want %x", i, gotAttachmentBytes[i], wantAttachmentBytes[i])
		}
	}
	// Caller inputs are still unchanged immediately after the open and its
	// cleanup, before this test mutates any returned result.
	for i, p := range aliases {
		if *p != before[i] {
			t.Fatalf("caller input changed at witness %d after OpenAuthenticatedItems", i)
		}
	}
	if !reflect.DeepEqual(items, wantItems) || !bytes.Equal(metadata, wantMeta) {
		t.Fatal("OpenAuthenticatedItems mutated caller metadata or items")
	}
	// Exact meaningful fields, spelled out independently of DeepEqual.
	if got := gotItems[0]; got.Password != "synthetic-password" || len(got.History) != 1 ||
		got.History[0].Password != "synthetic-old-password" || got.History[0].Timestamp != 1_700_000_000 ||
		len(got.Attachments) != 1 || !got.Attachments[0].Protected {
		t.Fatalf("login item fields were not preserved: %+v", got)
	}
	if got := gotItems[1]; got.Kind != "document" || got.Filename != "fixture.bin" || !got.AttachmentProtected {
		t.Fatalf("document item fields were not preserved: %+v", got)
	}
	if got := gotItems[2]; got.State != "trashed" || got.PreviousState != "archived" || got.TrashedAt == nil ||
		!got.TrashedAt.Equal(time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("trashed item fields were not preserved: %+v", got)
	}
	// Returned metadata and item bytes are caller-owned: mutating them must
	// not change the caller's originals, and a fresh open still yields them.
	gotMeta[0] ^= 0xff
	gotItems[1].Attachment[0] ^= 0xff
	gotItems[0].Attachments[0].Content[0] ^= 0xff
	if metadata[0] == gotMeta[0] || items[1].Attachment[0] == gotItems[1].Attachment[0] ||
		items[0].Attachments[0].Content[0] == gotItems[0].Attachments[0].Content[0] {
		t.Fatal("opened metadata or items alias caller input")
	}
	f, _, again, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", fx.device)
	if err != nil || f == nil || !reflect.DeepEqual(again, wantItems) {
		t.Fatalf("reopening after mutating results: %v", err)
	}
	for i, p := range aliases {
		if *p != before[i] {
			t.Fatalf("caller input changed at witness %d after the call", i)
		}
	}
	if !reflect.DeepEqual(fx.draft, wantDraft) || !bytes.Equal(metadata, wantMeta) || !reflect.DeepEqual(items, wantItems) ||
		!bytes.Equal(fx.vuk, wantVUK) || !bytes.Equal(fx.author, wantAuthor) || !reflect.DeepEqual(fx.pin, wantPin) {
		t.Fatal("caller inputs are no longer unchanged at the end of the test")
	}
}

// TestAuthenticatedItemsWrongPin proves the open path rejects an otherwise
// valid sealed file under a wrong caller pin with exactly
// vaultfile.CodePolicyCheckpointFailed, an empty path and nil results.
func TestAuthenticatedItemsWrongPin(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata, items := authItemsFixtureMetadata(), authItemsFixtureItems()
	encoded := sealAuthItems(t, fx, metadata, items)

	for name, mutate := range map[string]func(*vaultfile.PolicyCheckpoint){
		"digest": func(c *vaultfile.PolicyCheckpoint) { c.PolicyDigest[0] ^= 0xff },
		"root":   func(c *vaultfile.PolicyCheckpoint) { c.OwnerRootPublicKey[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			pin := *fx.pin
			pin.PolicyDigest = bytes.Clone(fx.pin.PolicyDigest)
			pin.OwnerRootPublicKey = bytes.Clone(fx.pin.OwnerRootPublicKey)
			mutate(&pin)
			f, gotMeta, gotItems, err := OpenAuthenticatedItems(encoded, &pin, "device-1", fx.device)
			var ve *vaultfile.Error
			if !errors.As(err, &ve) || ve.Code != vaultfile.CodePolicyCheckpointFailed || ve.Path != "" {
				t.Fatalf("wrong pin: got %v, want %s at \"\"", err, vaultfile.CodePolicyCheckpointFailed)
			}
			if f != nil || gotMeta != nil || gotItems != nil {
				t.Fatalf("wrong pin returned results: file=%v metadata=%v items=%v", f, gotMeta, gotItems)
			}
		})
	}
	// A different age identity is also refused, because the wrong-pin proof
	// is complete without it: the positive still opens.
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", other); err == nil {
		t.Fatal("a foreign age identity opened the file")
	}

	// The wrong-pin identity is also rejected by the seal path, unchanged
	// from SealAuthenticatedFile, before any file bytes exist.
	pin := *fx.pin
	pin.PolicyDigest = bytes.Clone(fx.pin.PolicyDigest)
	pin.PolicyDigest[0] ^= 0xff
	out, err := SealAuthenticatedItems(fx.draft, metadata, items, &pin, fx.vuk, fx.author)
	var ve *vaultfile.Error
	if !errors.As(err, &ve) || ve.Code != vaultfile.CodePolicyCheckpointFailed || ve.Path != "" || out != nil {
		t.Fatalf("wrong-pin seal: got %v and %d bytes", err, len(out))
	}
}

// callerAttachmentItems returns fresh fixture items whose attachment bytes
// are unique to this test, so a database binary holding one of them cannot be
// confused with any other fixture attachment.
func callerAttachmentItems() []Item {
	items := authItemsFixtureItems()
	content := []byte{'d', 'b', 0x00, 0x91, 0xff, 'c', 'o', 'p', 'y'}
	items[0].Attachments[0].Content = content
	items[0].Attachments[0].Size = int64(len(content))
	items[0].Attachments[0].SHA256 = AttachmentSHA256(content)
	return items
}

// callerAttachmentBytes returns the caller-owned attachment byte slices of
// items, in item order.
func callerAttachmentBytes(items []Item) [][]byte {
	var out [][]byte
	for _, it := range items {
		if it.Attachment != nil {
			out = append(out, it.Attachment)
		}
		for _, a := range it.Attachments {
			out = append(out, a.Content)
		}
	}
	return out
}

// allZeros reports whether every byte of b is zero.
func allZeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TestAuthenticatedItemsClearsOwnedBinaries calls sealOwnedItemDatabase
// directly on a database built exactly as SealAuthenticatedItems builds it with
// NewItemDatabase, and proves the helper clears every database-owned
// binary-content copy on sealing success and on a wrong-pin failure alike,
// while never clearing the caller's item attachment bytes. The public
// SealAuthenticatedItems round trip is covered by the other tests here.
func TestAuthenticatedItemsClearsOwnedBinaries(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata := authItemsFixtureMetadata()
	wantItems := deepCopy(callerAttachmentItems())

	// checkCleared runs after one helper call on the same db. dbBinaries are
	// the actual InnerHeader binaries recorded before the call and populated
	// is their pre-call byte evidence, cloned so the cleared buffers cannot
	// rewrite it.
	checkCleared := func(t *testing.T, db *gokeepasslib.Database, dbBinaries, populated, wantBytes [][]byte) {
		t.Helper()
		if len(dbBinaries) != 2 || len(populated) != 2 {
			t.Fatalf("database has %d binaries with %d evidence buffers, want 2 and 2", len(dbBinaries), len(populated))
		}
		for i := range dbBinaries {
			if len(dbBinaries[i]) == 0 || !allZeros(dbBinaries[i]) {
				t.Fatalf("database binary %d recorded before the call was not cleared: %x", i, dbBinaries[i])
			}
			if !bytes.Equal(populated[i], wantBytes[i]) {
				t.Fatalf("pre-call evidence for binary %d was rewritten after the call: %x", i, populated[i])
			}
		}
		bin, ok := currentItemBinaries(db)
		if !ok {
			t.Fatal("database lost its InnerHeader binaries")
		}
		if len(*bin) != 2 {
			t.Fatalf("database carries %d binaries after the call, want 2", len(*bin))
		}
		for i := range *bin {
			if !allZeros((*bin)[i].Content) {
				t.Fatalf("database binary %d present after the call was not cleared: %x", i, (*bin)[i].Content)
			}
		}
	}

	// build returns fresh caller items, the database NewItemDatabase builds
	// from them, the database binaries recorded before the helper runs and
	// their cloned pre-call evidence.
	build := func(t *testing.T) ([]Item, [][]byte, *gokeepasslib.Database, [][]byte, [][]byte) {
		t.Helper()
		items := callerAttachmentItems()
		wantBytes := callerAttachmentBytes(items)
		db, err := NewItemDatabase(metadata, items)
		if err != nil {
			t.Fatalf("NewItemDatabase: %v", err)
		}
		bin, ok := currentItemBinaries(db)
		if !ok || len(*bin) != len(wantBytes) {
			t.Fatalf("database binaries: got %v want %d", ok, len(wantBytes))
		}
		dbBinaries := make([][]byte, len(*bin))
		populated := make([][]byte, len(*bin))
		for i := range *bin {
			// Each database binary is its own copy of exactly the caller
			// attachment bytes in item order, and it is populated before the
			// helper runs.
			if !bytes.Equal((*bin)[i].Content, wantBytes[i]) {
				t.Fatalf("database binary %d is not a copy of caller attachment %d: %x vs %x", i, i, (*bin)[i].Content, wantBytes[i])
			}
			if len(wantBytes[i]) == 0 || allZeros(wantBytes[i]) {
				t.Fatalf("caller attachment %d is not populated", i)
			}
			dbBinaries[i] = (*bin)[i].Content
			populated[i] = bytes.Clone((*bin)[i].Content)
		}
		return items, wantBytes, db, dbBinaries, populated
	}

	callerUnchanged := func(t *testing.T, items []Item, wantBytes [][]byte) {
		t.Helper()
		if !reflect.DeepEqual(items, wantItems) {
			t.Fatal("caller items changed")
		}
		got := callerAttachmentBytes(items)
		if len(got) != len(wantBytes) {
			t.Fatalf("caller attachment count: got %d want %d", len(got), len(wantBytes))
		}
		for i := range wantBytes {
			if !bytes.Equal(got[i], wantBytes[i]) || allZeros(wantBytes[i]) {
				t.Fatalf("caller attachment bytes changed at %d", i)
			}
		}
	}

	t.Run("success", func(t *testing.T) {
		items, wantBytes, db, dbBinaries, populated := build(t)
		encoded, err := sealOwnedItemDatabase(fx.draft, db, fx.pin, fx.vuk, fx.author)
		if err != nil {
			t.Fatalf("sealOwnedItemDatabase: %v", err)
		}
		if len(encoded) == 0 {
			t.Fatal("sealOwnedItemDatabase returned no bytes and no error")
		}
		checkCleared(t, db, dbBinaries, populated, wantBytes)
		callerUnchanged(t, items, wantBytes)
		// The positive reached the real sealer and produced a file carrying
		// the caller items, so the error case below cannot mask it.
		_, gotMeta, got, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", fx.device)
		if err != nil {
			t.Fatalf("sealed file does not open: %v", err)
		}
		if !bytes.Equal(gotMeta, metadata) {
			t.Fatalf("sealed metadata mismatch: got %x want %x", gotMeta, metadata)
		}
		if !reflect.DeepEqual(got, wantItems) {
			t.Fatal("sealed file does not carry the caller items")
		}
	})

	t.Run("wrong pin", func(t *testing.T) {
		items, wantBytes, db, dbBinaries, populated := build(t)
		pin := deepCopy(fx.pin)
		pin.PolicyDigest = bytes.Clone(fx.pin.PolicyDigest)
		pin.PolicyDigest[0] ^= 0xff
		encoded, err := sealOwnedItemDatabase(fx.draft, db, pin, fx.vuk, fx.author)
		var ve *vaultfile.Error
		if !errors.As(err, &ve) || ve.Code != vaultfile.CodePolicyCheckpointFailed || ve.Path != "" {
			t.Fatalf("wrong-pin seal: got %v, want %s at \"\"", err, vaultfile.CodePolicyCheckpointFailed)
		}
		if encoded != nil {
			t.Fatalf("wrong-pin seal returned %d bytes", len(encoded))
		}
		checkCleared(t, db, dbBinaries, populated, wantBytes)
		callerUnchanged(t, items, wantBytes)
	})
}

// TestAuthenticatedItemsReleasesOpenedItemDatabase calls the local cleanup
// helper directly on an owned KDBX database carrying InnerHeader binaries,
// populated credential byte slices and string values. It proves the binary and
// credential buffers are zeroed and that the database no longer references the
// decrypted content, while the caller's item bytes remain untouched. The
// strings themselves are not checked for overwriting: Go strings are immutable
// and the helper only drops their references.
func TestAuthenticatedItemsReleasesOpenedItemDatabase(t *testing.T) {
	metadata := authItemsFixtureMetadata()
	items := callerAttachmentItems()
	wantItems := deepCopy(items)
	wantAttachmentBytes := callerAttachmentBytes(items)

	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	credentials := &gokeepasslib.DBCredentials{
		Passphrase: []byte("synthetic passphrase material"),
		Key:        []byte("synthetic key-file material"),
		Windows:    []byte("synthetic windows-account material"),
	}
	db.Credentials = credentials
	passphrase, key, windows := credentials.Passphrase, credentials.Key, credentials.Windows

	bin, ok := currentItemBinaries(db)
	if !ok || len(*bin) == 0 {
		t.Fatal("owned database carries no InnerHeader binaries")
	}
	binaryBuffers := make([][]byte, len(*bin))
	for i := range *bin {
		if len((*bin)[i].Content) == 0 || allZeros((*bin)[i].Content) {
			t.Fatalf("database binary %d is not populated", i)
		}
		binaryBuffers[i] = (*bin)[i].Content
	}
	content := db.Content
	if content == nil || content.Root == nil || len(content.Root.Groups) != 1 || len(content.Root.Groups[0].Entries) == 0 {
		t.Fatal("owned database carries no decrypted string content")
	}
	hasString := false
	for _, v := range content.Root.Groups[0].Entries[0].Values {
		if v.Value.Content != "" {
			hasString = true
			break
		}
	}
	if !hasString {
		t.Fatal("owned database entry carries no string value")
	}

	releaseOpenedItemDatabase(db)

	checkZeroed := func(name string, b []byte) {
		t.Helper()
		if len(b) == 0 || !allZeros(b) {
			t.Fatalf("%s was not cleared: %x", name, b)
		}
	}
	for i := range binaryBuffers {
		checkZeroed("database binary", binaryBuffers[i])
	}
	checkZeroed("credentials passphrase", passphrase)
	checkZeroed("credentials key", key)
	checkZeroed("credentials windows", windows)
	if db.Content != nil {
		t.Fatal("database still references decrypted content")
	}
	if db.Credentials != nil {
		t.Fatal("database still references credentials")
	}
	if content.InnerHeader == nil || content.InnerHeader.Binaries != nil {
		t.Fatal("dropped content still references InnerHeader binaries")
	}

	if !reflect.DeepEqual(items, wantItems) {
		t.Fatal("cleanup mutated the caller's items")
	}
	gotAttachmentBytes := callerAttachmentBytes(items)
	if len(gotAttachmentBytes) != len(wantAttachmentBytes) {
		t.Fatalf("caller attachment count: got %d want %d", len(gotAttachmentBytes), len(wantAttachmentBytes))
	}
	for i := range wantAttachmentBytes {
		if !bytes.Equal(gotAttachmentBytes[i], wantAttachmentBytes[i]) || allZeros(wantAttachmentBytes[i]) {
			t.Fatalf("cleanup changed caller attachment bytes at %d", i)
		}
	}
}

// TestAuthenticatedItemsUnreadableDatabase opens a real authenticated file
// whose KDBX passes authentication and decryption but whose item layout
// ReadItemDatabase rejects: one root group with the wrong name. The adapter
// must return ErrSnapshot with nil outputs, and its unconditional deferred
// cleanup covers this error path. The test does not claim to observe the
// private database buffers; the direct helper test above covers those.
func TestAuthenticatedItemsUnreadableDatabase(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata, items := authItemsFixtureMetadata(), callerAttachmentItems()
	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	db.Content.Root.Groups[0].Name = itemGroup + " (unreadable)"
	encoded, err := vaultfile.SealAuthenticatedFile(fx.draft, db, fx.pin, fx.vuk, fx.author)
	if err != nil {
		t.Fatalf("seal database with unreadable item layout: %v", err)
	}

	// Prove the file authenticates and its KDBX payload decrypts: only the
	// item-database read fails.
	file, opened, err := vaultfile.OpenAuthenticatedFile(encoded, fx.pin, "device-1", fx.device)
	if err != nil || file == nil || opened == nil {
		t.Fatalf("authenticated KDBX open: file=%v database=%v err=%v", file != nil, opened != nil, err)
	}
	if gotMeta, gotItems, err := ReadItemDatabase(opened); !errors.Is(err, ErrSnapshot) || gotMeta != nil || gotItems != nil {
		t.Fatalf("ReadItemDatabase on unreadable layout = %x, %d items, %v; want nil, nil, ErrSnapshot", gotMeta, len(gotItems), err)
	}
	releaseOpenedItemDatabase(opened)

	file, gotMeta, gotItems, err := OpenAuthenticatedItems(encoded, fx.pin, "device-1", fx.device)
	if !errors.Is(err, ErrSnapshot) {
		t.Fatalf("OpenAuthenticatedItems with unreadable item layout: got %v, want ErrSnapshot", err)
	}
	if file != nil || gotMeta != nil || gotItems != nil {
		t.Fatalf("read failure returned results: file=%v metadata=%v items=%v", file, gotMeta, gotItems)
	}
}

// TestAuthenticatedItemsInvalidItemsRejected proves that invalid item input is
// rejected with ErrSnapshot before any file bytes exist, and that the caller's
// inputs are untouched. NewItemDatabase rejects nil metadata by its own API
// contract, so the nil metadata cases are included beside the ValidateItems
// cases.
func TestAuthenticatedItemsInvalidItemsRejected(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata := authItemsFixtureMetadata()
	good := authItemsFixtureItems()
	cases := map[string]func() ([]byte, []Item){
		"nil metadata":           func() ([]byte, []Item) { return nil, deepCopy(good) },
		"nil metadata and items": func() ([]byte, []Item) { return nil, nil },
		"nil items":              func() ([]byte, []Item) { return metadata, nil },
		"duplicate id": func() ([]byte, []Item) {
			in := deepCopy(good)
			in[2].ID = in[0].ID
			return metadata, in
		},
		"trashed without state": func() ([]byte, []Item) {
			in := deepCopy(good)
			in[2].State = ""
			return metadata, in
		},
		"attachment digest mismatch": func() ([]byte, []Item) {
			in := deepCopy(good)
			in[0].Attachments[0].Content[0] ^= 0xff
			return metadata, in
		},
		"metadata over budget": func() ([]byte, []Item) {
			// validItems charges len(metadata) first; one valid item no longer
			// fits the MaxPayload budget, so the item is schema-valid and the
			// rejection is the size bound alone.
			return make([]byte, MaxPayload), authItemsFixtureItems()[:1]
		},
		"unknown kind": func() ([]byte, []Item) { return metadata, []Item{{ID: "x", Kind: "bogus"}} },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			meta, items := build()
			wantDraft := deepCopy(fx.draft)
			var wantMeta, wantItems any
			if meta != nil {
				wantMeta = bytes.Clone(meta)
			}
			if items != nil {
				wantItems = deepCopy(items)
			}
			out, err := SealAuthenticatedItems(fx.draft, meta, items, fx.pin, fx.vuk, fx.author)
			if err != ErrSnapshot {
				t.Fatalf("invalid input: got %v, want exactly ErrSnapshot", err)
			}
			var ve *vaultfile.Error
			if errors.As(err, &ve) {
				t.Fatalf("invalid input reached vaultfile as %v", ve)
			}
			if out != nil {
				t.Fatal("invalid input returned file bytes")
			}
			if !reflect.DeepEqual(fx.draft, wantDraft) {
				t.Fatal("invalid-items rejection mutated the draft")
			}
			if meta != nil && !bytes.Equal(meta, wantMeta.([]byte)) {
				t.Fatal("invalid-items rejection mutated metadata")
			}
			if items != nil && !reflect.DeepEqual(items, wantItems) {
				t.Fatal("invalid-items rejection mutated items")
			}
		})
	}

	// The valid fixture in the same test seals and opens, so each rejection
	// above is a difference in the item input alone.
	sealAuthItems(t, fx, metadata, good)
}

// TestAuthenticatedItemsSealRequiresKeyEpoch proves the adapter rejects a nil
// or zero-epoch draft before writing any KDBX, with the same code and path
// SealAuthenticatedFile reports.
func TestAuthenticatedItemsSealRequiresKeyEpoch(t *testing.T) {
	fx := newAuthItemsFixture(t)
	metadata, items := authItemsFixtureMetadata(), authItemsFixtureItems()
	zero := deepCopy(fx.draft)
	zero.Header.KeyEpoch = 0
	for name, draft := range map[string]*vaultfile.File{"nil draft": nil, "zero epoch": zero} {
		t.Run(name, func(t *testing.T) {
			out, err := SealAuthenticatedItems(draft, metadata, items, fx.pin, fx.vuk, fx.author)
			var ve *vaultfile.Error
			if !errors.As(err, &ve) || ve.Code != vaultfile.CodeInvalidValue || ve.Path != "" || out != nil {
				t.Fatalf("got %v and %d bytes, want invalid_value at \"\"", err, len(out))
			}
		})
	}
	if zero.Header.KeyEpoch != 0 || fx.draft.Header.KeyEpoch != 1 {
		t.Fatal("draft inputs were mutated")
	}
}
