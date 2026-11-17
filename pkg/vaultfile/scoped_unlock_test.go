package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// scopedVault is one real caller-pinned vault for the scoped-unlock tests. It
// starts with a genesis owner policy, a root-signed proof, one read-capable
// device and a random VUK, and can append root-signed policy continuations.
// Every file is produced by the public SealAuthenticatedFile path.
type scopedVault struct {
	vaultID string

	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey

	authorPub  ed25519.PublicKey
	authorPriv ed25519.PrivateKey

	identity    *age.X25519Identity
	deviceID    string
	principalID string

	vuk []byte

	policies []*Policy
	proofs   []SignedPolicy
	pin      *PolicyCheckpoint
}

func scopedGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newScopedVault(t *testing.T, vaultID string) *scopedVault {
	t.Helper()
	rootPub, rootPriv := scopedGenKey(t)
	authorPub, authorPriv := scopedGenKey(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vuk := make([]byte, CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}

	p := &Policy{
		Format:           Format,
		Version:          Version,
		VaultID:          vaultID,
		PolicySeq:        0,
		PrevPolicyDigest: nil,
		OwnerRoot: OwnerRoot{
			KeyID:     "owner-root-01",
			Alg:       PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPub),
			Owners:    []Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Owners: []Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []Device{{
			DeviceID:          "device-1",
			PrincipalID:       "alice",
			Label:             "Alice laptop",
			ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(authorPub)},
			AgeEncryptionKey:  identity.Recipient().String(),
		}},
	}
	if err := ValidatePolicy(p); err != nil {
		t.Fatalf("genesis policy is invalid: %v", err)
	}
	v := &scopedVault{
		vaultID:    vaultID,
		rootPub:    rootPub,
		rootPriv:   rootPriv,
		authorPub:  authorPub,
		authorPriv: authorPriv,
		identity:   identity,
		deviceID:   "device-1",
		vuk:        vuk,
		policies:   []*Policy{p},
	}
	v.proofs = append(v.proofs, scopedPolicyProof(t, p, v.rootPriv))
	v.pin = &PolicyCheckpoint{
		VaultID:            p.VaultID,
		OwnerRootKeyID:     p.OwnerRoot.KeyID,
		OwnerRootPublicKey: bytes.Clone(rootPub),
		PolicySeq:          p.PolicySeq,
		PolicyDigest:       PolicyDigest(p),
	}
	return v
}

func scopedPolicyProof(t *testing.T, p *Policy, rootPriv ed25519.PrivateKey) SignedPolicy {
	t.Helper()
	doc, err := EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode policy document: %v", err)
	}
	msg := make([]byte, 0, len(DomainPolicyDocumentSignature)+1+len(doc))
	msg = append(msg, DomainPolicyDocumentSignature...)
	msg = append(msg, 0)
	msg = append(msg, doc...)
	return SignedPolicy{
		Policy:   *clonePolicySnapshot(p),
		Document: doc,
		SignerID: p.OwnerRoot.KeyID,
		Alg:      PolicySigAlgEd25519,
		Sig:      ed25519.Sign(rootPriv, msg),
	}
}

// addPolicy appends a root-signed successor to the newest policy. mutate runs
// on a deep copy and must leave a valid policy.
func (v *scopedVault) addPolicy(t *testing.T, mutate func(*Policy)) *Policy {
	t.Helper()
	last := v.policies[len(v.policies)-1]
	p := clonePolicySnapshot(last)
	p.PolicySeq = last.PolicySeq + 1
	p.PrevPolicyDigest = bytes.Clone(PolicyDigest(last))
	mutate(p)
	if err := ValidatePolicy(p); err != nil {
		t.Fatalf("successor policy is invalid: %v", err)
	}
	v.policies = append(v.policies, p)
	v.proofs = append(v.proofs, scopedPolicyProof(t, p, v.rootPriv))
	return p
}

// seal builds and seals one real content file at p under the given epoch and
// VUK. The draft carries the full proof chain from the pin anchor through p,
// so the caller's pin authenticates it.
func (v *scopedVault) seal(t *testing.T, p *Policy, epoch uint64, vuk []byte) []byte {
	t.Helper()
	idx := -1
	wantDigest := PolicyDigest(p)
	for i := range v.policies {
		if v.policies[i].PolicySeq == p.PolicySeq && bytes.Equal(PolicyDigest(v.policies[i]), wantDigest) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("seal policy is not in the fixture chain")
	}
	proofs := make([]SignedPolicy, idx+1)
	copy(proofs, v.proofs[:idx+1])
	draft := &File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:        v.vaultID,
			KeyEpoch:       epoch,
			ContentSeq:     0,
			OpID:           "op-scoped-0001",
			PolicySeq:      p.PolicySeq,
			PolicyDigest:   bytes.Clone(wantDigest),
			AuthorDeviceID: v.deviceID,
		},
		SignedPolicyProofs: proofs,
	}
	encoded, err := SealAuthenticatedFile(draft, payloadFixtureDB(t), v.pin, vuk, v.authorPriv)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	return encoded
}

func scopedCode(err error) string {
	if e, ok := AsError(err); ok {
		return e.Code
	}
	return ""
}

// releaseScopedTestDB drops the plaintext of a caller-owned test database.
func releaseScopedTestDB(db *kdbx.Database) {
	if db == nil {
		return
	}
	if db.Content != nil && db.Content.InnerHeader != nil {
		for i := range db.Content.InnerHeader.Binaries {
			clear(db.Content.InnerHeader.Binaries[i].Content)
		}
		db.Content.InnerHeader.Binaries = nil
	}
	if db.Credentials != nil {
		clear(db.Credentials.Passphrase)
		clear(db.Credentials.Key)
		clear(db.Credentials.Windows)
	}
	db.Content = nil
	db.Credentials = nil
}

func scopedOpenPassword(t *testing.T, h *ScopedUnlock, encoded []byte) {
	t.Helper()
	f, db, err := h.OpenDatabase(encoded)
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	defer releaseScopedTestDB(db)
	if f == nil || db == nil || db.Content == nil || db.Content.Root == nil ||
		len(db.Content.Root.Groups) != 1 || len(db.Content.Root.Groups[0].Entries) == 0 {
		t.Fatal("OpenDatabase returned no real opened database")
	}
	entry := db.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatal("opened database did not carry the fixture protected value")
	}
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatal("opened database did not carry the fixture title")
	}
}

func TestScopedUnlockTwoVaultsAndClose(t *testing.T) {
	a := newScopedVault(t, "vault-scoped-a")
	b := newScopedVault(t, "vault-scoped-b")
	encA := a.seal(t, a.policies[0], 1, a.vuk)
	encB := b.seal(t, b.policies[0], 1, b.vuk)

	hA, err := NewScopedUnlock(encA, a.pin, a.deviceID, a.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock(A): %v", err)
	}
	hB, err := NewScopedUnlock(encB, b.pin, b.deviceID, b.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock(B): %v", err)
	}

	// Both handles decrypt their own real KDBX payload.
	scopedOpenPassword(t, hA, encA)
	scopedOpenPassword(t, hB, encB)

	// A cannot open B's file, and across two different vaults the error is a
	// rejection rather than a nil database.
	if f, db, err := hA.OpenDatabase(encB); err == nil || f != nil || db != nil {
		t.Fatalf("A opened B: f=%v db=%v err=%v", f != nil, db != nil, err)
	}

	// Close is idempotent, clears the owned VUK and revokes later opens.
	if err := hA.Close(); err != nil {
		t.Fatalf("Close A: %v", err)
	}
	if hA.state == nil || !hA.state.closed || hA.state.ownedVUK != nil {
		t.Fatal("Close did not clear and drop the owned VUK")
	}
	if err := hA.Close(); err != nil {
		t.Fatalf("second Close A: %v", err)
	}
	if f, db, err := hA.OpenDatabase(encA); scopedCode(err) != CodeUnlockUnavailable || f != nil || db != nil {
		t.Fatalf("closed A open = f=%v db=%v code=%q, want unavailable", f != nil, db != nil, scopedCode(err))
	}

	// B is unaffected and still produces a real decryption.
	scopedOpenPassword(t, hB, encB)
}

func TestScopedUnlockRejectsUnavailableHandles(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-unavailable")
	enc := v.seal(t, v.policies[0], 1, v.vuk)

	var nilHandle *ScopedUnlock
	if f, db, err := nilHandle.OpenDatabase(enc); scopedCode(err) != CodeUnlockUnavailable || f != nil || db != nil {
		t.Fatalf("nil handle open = %v/%v/%q, want unavailable", f != nil, db != nil, scopedCode(err))
	}
	if err := nilHandle.Close(); err != nil {
		t.Fatalf("nil handle Close: %v", err)
	}

	var zero ScopedUnlock
	if f, db, err := zero.OpenDatabase(enc); scopedCode(err) != CodeUnlockUnavailable || f != nil || db != nil {
		t.Fatalf("zero handle open = %v/%v/%q, want unavailable", f != nil, db != nil, scopedCode(err))
	}
	if err := zero.Close(); err != nil {
		t.Fatalf("zero handle Close: %v", err)
	}

	h, err := NewScopedUnlock(enc, v.pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestScopedUnlockScopeBindingAndNoReunwrap(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-scope")
	p0 := v.policies[0]
	enc0 := v.seal(t, p0, 1, v.vuk)
	h0, err := NewScopedUnlock(enc0, v.pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}
	scopedOpenPassword(t, h0, enc0)

	// A key-epoch change under the same authenticated policy is rejected
	// before the cached VUK opens this file's CEK.
	encEpoch := v.seal(t, p0, 2, v.vuk)
	if f, db, err := h0.OpenDatabase(encEpoch); scopedCode(err) != CodeUnlockScopeMismatch || f != nil || db != nil {
		t.Fatalf("epoch change = %v/%v/%q, want scope mismatch", f != nil, db != nil, scopedCode(err))
	}

	// A policy continuation is fail-closed for the old handle; an explicit
	// new unlock under the same anchor accepts it and decrypts it.
	p1 := v.addPolicy(t, func(p *Policy) {
		p.Readers = []Member{{PrincipalID: "zoe", Label: "Zoe"}}
	})
	enc1 := v.seal(t, p1, 1, v.vuk)
	if f, db, err := h0.OpenDatabase(enc1); scopedCode(err) != CodeUnlockScopeMismatch || f != nil || db != nil {
		t.Fatalf("policy change on old handle = %v/%v/%q, want scope mismatch", f != nil, db != nil, scopedCode(err))
	}
	h1, err := NewScopedUnlock(enc1, v.pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("explicit re-unlock after policy change: %v", err)
	}
	scopedOpenPassword(t, h1, enc1)

	// Changing the authenticated recipient is a policy change and is
	// rejected by the old handle. The old identity cannot unwrap the new
	// slot; the new identity can and the new handle decrypts.
	newIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p2 := v.addPolicy(t, func(p *Policy) {
		p.Devices[0].AgeEncryptionKey = newIdentity.Recipient().String()
	})
	enc2 := v.seal(t, p2, 1, v.vuk)
	if f, db, err := h1.OpenDatabase(enc2); scopedCode(err) != CodeUnlockScopeMismatch || f != nil || db != nil {
		t.Fatalf("recipient change on old handle = %v/%v/%q, want scope mismatch", f != nil, db != nil, scopedCode(err))
	}
	if _, err := NewScopedUnlock(enc2, v.pin, v.deviceID, v.identity); scopedCode(err) != CodeVUKEnvelopeFailed {
		t.Fatalf("old identity on changed recipient code = %q, want envelope failure", scopedCode(err))
	}
	h2, err := NewScopedUnlock(enc2, v.pin, v.deviceID, newIdentity)
	if err != nil {
		t.Fatalf("explicit re-unlock with changed recipient: %v", err)
	}
	scopedOpenPassword(t, h2, enc2)

	// The same vault, policy, epoch, device and recipient but a different
	// VUK pass every scope check. The cached VUK is used, so CEK opening
	// fails instead of re-unwrapping the file's own slot.
	otherVUK := make([]byte, CEKSize)
	if _, err := rand.Read(otherVUK); err != nil {
		t.Fatal(err)
	}
	encOtherVUK := v.seal(t, p0, 1, otherVUK)
	if f, db, err := h0.OpenDatabase(encOtherVUK); scopedCode(err) != CodeCEKEnvelopeFailed || f != nil || db != nil {
		t.Fatalf("foreign VUK open = %v/%v/%q, want CEK envelope failure", f != nil, db != nil, scopedCode(err))
	}
}

func TestScopedUnlockRejectsBeforeDecryption(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-order")
	enc := v.seal(t, v.policies[0], 1, v.vuk)

	// Wrong owner root: the checkpoint failure precedes identity use, so a
	// nil identity is not the reported error.
	wrongRoot := *v.pin
	wrongRoot.OwnerRootPublicKey = bytes.Clone(v.pin.OwnerRootPublicKey)
	wrongRoot.OwnerRootPublicKey[0] ^= 0x01
	if _, err := NewScopedUnlock(enc, &wrongRoot, v.deviceID, nil); scopedCode(err) != CodePolicyCheckpointFailed {
		t.Fatalf("wrong root code = %q, want %q", scopedCode(err), CodePolicyCheckpointFailed)
	}

	// A stale content signature is rejected before identity use as well.
	f, err := ParseFile(enc)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	f.ContentSignature.Sig[0] ^= 0x01
	stale, err := EncodeFile(f)
	if err != nil {
		t.Fatalf("EncodeFile: %v", err)
	}
	if _, err := NewScopedUnlock(stale, v.pin, v.deviceID, nil); scopedCode(err) != CodeSignatureVerifyFailed {
		t.Fatalf("stale signature code = %q, want %q", scopedCode(err), CodeSignatureVerifyFailed)
	}

	// A valid file with a nil identity reaches the identity check only after
	// all authenticated checks pass.
	if _, err := NewScopedUnlock(enc, v.pin, v.deviceID, nil); scopedCode(err) != CodeInvalidValue {
		t.Fatalf("nil identity code = %q, want %q", scopedCode(err), CodeInvalidValue)
	}
}

func TestScopedUnlockCopiesCheckpointBinding(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-copy")
	enc := v.seal(t, v.policies[0], 1, v.vuk)
	pin := &PolicyCheckpoint{
		VaultID:            v.pin.VaultID,
		OwnerRootKeyID:     v.pin.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(v.pin.OwnerRootPublicKey),
		PolicySeq:          v.pin.PolicySeq,
		PolicyDigest:       bytes.Clone(v.pin.PolicyDigest),
	}
	h, err := NewScopedUnlock(enc, pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}

	// Mutate every caller-owned field and slice the handle could have
	// aliased. The handle's own binding must be unaffected.
	pin.VaultID = "mutated-vault"
	pin.OwnerRootKeyID = "mutated-root"
	pin.PolicySeq = 999
	for i := range pin.PolicyDigest {
		pin.PolicyDigest[i] ^= 0xff
	}
	for i := range pin.OwnerRootPublicKey {
		pin.OwnerRootPublicKey[i] ^= 0xff
	}
	scopedOpenPassword(t, h, enc)
}

func TestScopedUnlockConcurrentOpenClose(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-concurrent")
	enc := v.seal(t, v.policies[0], 1, v.vuk)
	h, err := NewScopedUnlock(enc, v.pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}

	const (
		workers   = 4
		perWorker = 3
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < perWorker; i++ {
				f, db, err := h.OpenDatabase(enc)
				if err != nil {
					if scopedCode(err) != CodeUnlockUnavailable {
						errs <- fmt.Errorf("concurrent open code %q", scopedCode(err))
					}
					continue
				}
				if f == nil || db == nil || db.Content == nil || db.Content.Root == nil {
					errs <- fmt.Errorf("concurrent open returned no database")
					releaseScopedTestDB(db)
					continue
				}
				releaseScopedTestDB(db)
			}
		}()
	}
	close(start)
	// Give some opens a chance to enter the read-locked region; Close must
	// still wait and then revoke every later open.
	time.Sleep(2 * time.Millisecond)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if _, _, err := h.OpenDatabase(enc); scopedCode(err) != CodeUnlockUnavailable {
		t.Fatalf("post-close open code = %q, want unavailable", scopedCode(err))
	}
}

func TestScopedUnlockDoesNotExposeOwnedKey(t *testing.T) {
	v := newScopedVault(t, "vault-scoped-exposure")
	enc := v.seal(t, v.policies[0], 1, v.vuk)
	h, err := NewScopedUnlock(enc, v.pin, v.deviceID, v.identity)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}

	secrets := []string{
		hex.EncodeToString(v.vuk),
		base64.StdEncoding.EncodeToString(v.vuk),
		base64.RawStdEncoding.EncodeToString(v.vuk),
		base64.RawURLEncoding.EncodeToString(v.vuk),
		string(v.vuk),
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
		out := fmt.Sprintf(format, h)
		for _, secret := range secrets {
			if secret != "" && strings.Contains(out, secret) {
				t.Fatalf("format %s exposed the owned VUK", format)
			}
		}
	}
	for _, value := range []any{h, *h} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(encoded) != "{}" {
			t.Fatal("handle JSON is not an empty object")
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("handle JSON exposed the owned VUK")
			}
		}
	}

	typ := reflect.TypeOf(*h)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath == "" {
			t.Fatalf("ScopedUnlock exposes exported field %q", typ.Field(i).Name)
		}
	}
	for _, name := range []string{"VUK", "RawVUK", "Key", "Secret", "Bytes"} {
		if _, ok := reflect.TypeOf(h).MethodByName(name); ok {
			t.Fatalf("ScopedUnlock exposes method %q", name)
		}
	}
}
