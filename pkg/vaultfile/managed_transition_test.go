package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"testing"
)

func TestVerifyManagedTransitionRootRotation(t *testing.T) {
	fx := newRotationFixture(t)
	next, err := SealAuthenticatedFile(fx.next, payloadFixtureDB(t),
		fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("root rotation setup: %v", err)
	}
	if err := VerifyManagedTransition(fx.oldEnc, next, fx.chain.anchor); err != nil {
		t.Fatalf("root rotation rejected: %v", err)
	}
}

func TestVerifyManagedTransitionDelegatedInviteReaders(t *testing.T) {
	k := newCPKeys(t)
	x := newDelegatedCP(t, k, nil, addDave)
	oldEnc, nextEnc := makeDelegatedPair(t, k, x, "device-1", x.priv)
	if err := VerifyManagedTransition(oldEnc, nextEnc, x.pin()); err != nil {
		if e, ok := AsError(err); ok {
			t.Fatalf("delegated InviteReaders transition rejected: code=%s path=%s", e.Code, e.Path)
		}
		t.Fatalf("delegated InviteReaders transition rejected: %v", err)
	}
}

func TestVerifyManagedTransitionWrongParent(t *testing.T) {
	fx := newRotationFixture(t)
	draft := builderDraft(fx.next)
	draft.Header.PrevDigest = digest("wrong-managed-parent")
	next, err := SealAuthenticatedFile(draft, payloadFixtureDB(t),
		fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("wrong-parent setup: %v", err)
	}
	err = VerifyManagedTransition(fx.oldEnc, next, fx.chain.anchor)
	wantCodeAt(t, err, CodeInvalidValue, "prev_digest")
}

func TestVerifyManagedTransitionOverflow(t *testing.T) {
	fx := newRotationFixture(t)
	old := snapshotFile(fx.old)
	old.Header.KeyEpoch = ^uint64(0)
	old.CEKSlot.KeyEpoch = old.Header.KeyEpoch
	oldEnc := fx.resignOld(t, old)
	next, err := SealAuthenticatedFile(fx.next, payloadFixtureDB(t),
		fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("overflow setup: %v", err)
	}
	err = VerifyManagedTransition(oldEnc, next, fx.chain.anchor)
	wantCodeAt(t, err, CodeInvalidValue, "key_epoch")
}

func TestVerifyManagedTransitionWrongPolicyLink(t *testing.T) {
	k := newCPKeys(t)
	x := newDelegatedCP(t, k, nil, addDave)
	oldEnc, base := makeDelegatedPair(t, k, x, "device-1", x.priv)
	nextEnc := mutateManagedNext(t, k, x, base, func(sp *SignedPolicy) {
		sp.Policy.PrevPolicyDigest = digest("wrong-policy-link")
		sp.Document = docFor(&sp.Policy)
		signPolicyProof(sp, x.priv)
	})
	err := VerifyManagedTransition(oldEnc, nextEnc, x.pin())
	wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
}

func TestVerifyManagedTransitionNewWriterAuthorRefused(t *testing.T) {
	k := newCPKeys(t)
	x := newDelegatedCP(t, k, nil, func(p *Policy) {
		p.Writers = append(p.Writers, Member{PrincipalID: "bob", Label: "Bob"})
		sort.Slice(p.Writers, func(i, j int) bool {
			return p.Writers[i].PrincipalID < p.Writers[j].PrincipalID
		})
	})
	oldEnc, nextEnc := makeDelegatedPair(t, k, x, "owner-root-01", nil)
	next, err := ParseFile(nextEnc)
	if err != nil {
		t.Fatal(err)
	}
	next.Header.AuthorDeviceID = "device-2"
	next.Header.RevisionID = ""
	next.ContentSignature = Signature{}
	pre, err := ContentSigningBytes(next)
	if err != nil {
		t.Fatal(err)
	}
	next.ContentSignature = Signature{
		SignerID: "device-2", Alg: SigAlgEd25519,
		Sig: ed25519.Sign(k.dev2Priv, append(append([]byte(DomainContentSignature), 0), pre...)),
	}
	next = sealFile(t, next, &next.ContentSignature)
	nextEnc, err = EncodeFile(next)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyManagedTransition(oldEnc, nextEnc, x.pin())
	wantCodeAt(t, err, CodePolicyCheckpointFailed, "content_signature")
}

func TestVerifyManagedTransitionUnauthorizedDelegateRefused(t *testing.T) {
	k := newCPKeys(t)
	x := newDelegatedCP(t, k, nil, addDave)
	oldEnc, base := makeDelegatedPair(t, k, x, "device-1", x.priv)
	nextEnc := mutateManagedNext(t, k, x, base, func(sp *SignedPolicy) {
		sp.SignerID = "device-2"
		sp.Alg = PolicySigAlgEd25519
		signPolicyProof(sp, x.priv2)
	})
	err := VerifyManagedTransition(oldEnc, nextEnc, x.pin())
	wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
}

func TestVerifyManagedTransitionSelfEscalationRefused(t *testing.T) {
	k := newCPKeys(t)
	x := newDelegatedCP(t, k, nil, addDave)
	oldEnc, base := makeDelegatedPair(t, k, x, "device-1", x.priv)
	nextEnc := mutateManagedNext(t, k, x, base, func(sp *SignedPolicy) {
		sp.Policy.AdminDelegations[0].Scope.RemoveMembers = true
		sp.Document = docFor(&sp.Policy)
		signPolicyProof(sp, x.priv)
	})
	err := VerifyManagedTransition(oldEnc, nextEnc, x.pin())
	wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
}

// makeDelegatedPair seals old p5 and managed p6 from the delegated fixture.
// The old file is built without decryption; the next policy authority is the
// requested signer and its policy key.
func makeDelegatedPair(t *testing.T, k *cpKeys, x *delegatedCP, signer string, policyPriv ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	vuk := make([]byte, CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}
	oldDraft := builderDraft(&File{
		Format:             Format,
		Version:            Version,
		Header:             x.c.f.Header,
		SignedPolicyProofs: []SignedPolicy{x.c.f.SignedPolicyProofs[0]},
	})
	oldDraft.Header.PolicySeq = x.p5.PolicySeq
	oldDraft.Header.PolicyDigest = PolicyDigest(x.p5)
	oldDraft.Header.ContentSeq = 42
	oldDraft.Header.PrevDigest = digest("content-41")
	oldDraft.Header.OpID = "op-managed-old"
	oldDraft.Header.KeyEpoch = 3
	oldEnc, err := SealAuthenticatedFile(oldDraft, payloadFixtureDB(t), x.pin(), vuk, k.dev1Priv)
	if err != nil {
		t.Fatalf("seal delegated old: %v", err)
	}
	old, err := ParseFile(oldEnc)
	if err != nil {
		t.Fatal(err)
	}

	x.c.rebind(1, signer)
	if policyPriv != nil {
		signPolicyProof(&x.c.f.SignedPolicyProofs[1], policyPriv)
	} else {
		signPolicyProof(&x.c.f.SignedPolicyProofs[1], k.rootPriv)
	}
	nextDraft := builderDraft(&File{
		Format:             Format,
		Version:            Version,
		Header:             x.c.f.Header,
		SignedPolicyProofs: x.c.f.SignedPolicyProofs,
	})
	nextDraft.Header.ContentSeq = old.Header.ContentSeq + 1
	nextDraft.Header.PrevDigest = mustDigest(t, old)
	nextDraft.Header.KeyEpoch = old.Header.KeyEpoch + 1
	nextDraft.Header.OpID = "op-managed-next"
	nextDraft.Header.PolicySeq = x.s.PolicySeq
	nextDraft.Header.PolicyDigest = PolicyDigest(x.s)
	nextDraft.Header.AuthorDeviceID = "device-1"
	nextEnc, err := SealAuthenticatedFile(nextDraft, payloadFixtureDB(t), x.pin(), vuk, k.dev1Priv)
	if err != nil {
		t.Fatalf("seal delegated next: %v", err)
	}
	return oldEnc, nextEnc
}

func mutateManagedNext(t *testing.T, k *cpKeys, x *delegatedCP, base []byte, mutate func(*SignedPolicy)) []byte {
	t.Helper()
	f, err := ParseFile(base)
	if err != nil {
		t.Fatal(err)
	}
	sp := &f.SignedPolicyProofs[1]
	mutate(sp)
	if !bytes.Equal(sp.Document, docFor(&sp.Policy)) {
		sp.Document = docFor(&sp.Policy)
	}
	f.Header.PolicyDigest = policyDigest(sp)
	f.Header.PolicySeq = sp.Policy.PolicySeq
	f.Header.AuthorDeviceID = "device-1"
	f.Header.RevisionID = ""
	f.ContentSignature = Signature{}
	pre, err := ContentSigningBytes(f)
	if err != nil {
		t.Fatal(err)
	}
	f.ContentSignature = Signature{
		SignerID: "device-1", Alg: SigAlgEd25519,
		Sig: ed25519.Sign(k.dev1Priv, append(append([]byte(DomainContentSignature), 0), pre...)),
	}
	*f = *sealFile(t, f, &f.ContentSignature)
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}
