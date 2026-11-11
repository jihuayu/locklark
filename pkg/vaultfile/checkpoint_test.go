package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
)

// cpKeys holds real generated Ed25519 keys for the checkpoint tests: the
// owner root, a foreign root and the two content signers.
type cpKeys struct {
	root         ed25519.PublicKey
	rootPriv     ed25519.PrivateKey
	otherRoot    ed25519.PublicKey
	otherRootPrv ed25519.PrivateKey
	dev1         ed25519.PublicKey
	dev1Priv     ed25519.PrivateKey
	dev2         ed25519.PublicKey
	dev2Priv     ed25519.PrivateKey
}

func newCPKeys(t *testing.T) *cpKeys {
	t.Helper()
	gen := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	}
	k := &cpKeys{}
	k.root, k.rootPriv = gen()
	k.otherRoot, k.otherRootPrv = gen()
	k.dev1, k.dev1Priv = gen()
	k.dev2, k.dev2Priv = gen()
	return k
}

// signPolicyProof sets sp.Sig to rootPriv's signature over exactly
// DomainPolicyDocumentSignature || 0x00 || sp.Document.
func signPolicyProof(sp *SignedPolicy, rootPriv ed25519.PrivateKey) {
	msg := append([]byte(DomainPolicyDocumentSignature+"\x00"), sp.Document...)
	sp.Alg = PolicySigAlgEd25519
	sp.Sig = ed25519.Sign(rootPriv, msg)
}

// cpChain is one synthetic vault file under construction: policies[0] is the
// caller's anchor policy and the last one is the current policy.
type cpChain struct {
	f        *File
	policies []*Policy
	anchor   *PolicyCheckpoint
}

func cpDEV1Key(k *cpKeys) PublicKey {
	return PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev1)}
}

// newCPChain builds the base two-proof chain: anchor s (alice owner/admin,
// bob and carol readers; device-1 for alice, device-2 for bob) and current
// s+1 (bob also a writer). device-1, alice's device, authors the content.
// The anchor proof carries garbage sig bytes, never a root signature.
func newCPChain(t *testing.T, k *cpKeys) *cpChain {
	t.Helper()
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
		Readers: []Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: "carol", Label: "Carol"}},
		Admins:  []Member{{PrincipalID: "alice", Label: "Alice"}},
		Owners:  []Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []Device{
			{
				DeviceID:          "device-1",
				PrincipalID:       "alice",
				Label:             "Alice laptop",
				ContentSigningKey: cpDEV1Key(k),
				AgeEncryptionKey:  ageRecipient(clientKey("device-1")),
			},
			{
				DeviceID:          "device-2",
				PrincipalID:       "bob",
				Label:             "Bob phone",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev2)},
				AgeEncryptionKey:  ageRecipient(clientKey("device-2")),
			},
		},
	}
	p1 := clonePolicy(p0)
	p1.PolicySeq = 6
	p1.Writers = []Member{{PrincipalID: "bob", Label: "Bob"}}
	p1.PrevPolicyDigest = bytes.Clone(PolicyDigest(p0))

	draft := buildDraft(t)
	draft.Header.PolicySeq = p1.PolicySeq
	draft.Header.AuthorDeviceID = "device-1"
	draft.SignedPolicyProofs = []SignedPolicy{
		{Document: docFor(p0), Policy: *clonePolicy(p0), SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x7f, 64)},
		{Document: docFor(p1), Policy: *clonePolicy(p1), SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x60, ed25519.SignatureSize)},
	}
	// Continuations chain to PolicyDigest of the carried document, which is
	// PolicyDigest of the re-parsed policy.
	c := &cpChain{f: draft, policies: []*Policy{p0, p1}}
	c.policies[1].PrevPolicyDigest = bytes.Clone(policyDigest(&draft.SignedPolicyProofs[0]))
	draft.SignedPolicyProofs[1].Policy = *clonePolicy(p1)
	draft.SignedPolicyProofs[1].Document = docFor(p1)
	c.anchor = &PolicyCheckpoint{
		VaultID:            p0.VaultID,
		OwnerRootKeyID:     p0.OwnerRoot.KeyID,
		OwnerRootPublicKey: bytes.Clone(k.root),
		PolicySeq:          p0.PolicySeq,
		PolicyDigest:       bytes.Clone(policyDigest(&draft.SignedPolicyProofs[0])),
	}
	c.finalize(t, k)
	return c
}

// append adds p as the next current policy, signed by signer with priv. p
// must already chain to the digest of the newest carried document; a nil priv
// leaves a 64-byte placeholder signature for the caller to stamp in a
// mutation. Either way the proof stays structurally valid.
func (c *cpChain) append(t *testing.T, p *Policy, signer string, priv ed25519.PrivateKey) {
	t.Helper()
	sp := SignedPolicy{Document: docFor(p), Policy: *clonePolicy(p), SignerID: signer, Alg: PolicySigAlgEd25519}
	if priv != nil {
		signPolicyProof(&sp, priv)
	} else {
		sp.Sig = pf(0x60, ed25519.SignatureSize)
	}
	c.f.SignedPolicyProofs = append(c.f.SignedPolicyProofs, sp)
	c.policies = append(c.policies, p)
	c.f.Header.PolicySeq = p.PolicySeq
}

// replaceProof re-installs policy p at proof i with the given signer, leaving
// the signature for finalize to stamp with the root.
func (c *cpChain) replaceProof(i int, p *Policy, signer string) {
	c.policies[i] = p
	c.rebind(i, signer)
}

// rebind rewrites proof i's document and policy from c.policies[i] and sets
// its signer, leaving a shaped signature for finalize. The anchor (proof 0)
// keeps 64-byte placeholder sig bytes that finalize never rewrites; later
// proofs get the 0x60 placeholder finalize stamps with the root signature.
// The proof stays structurally valid (alg and 64-byte sig) either way.
func (c *cpChain) rebind(i int, signer string) {
	p := c.policies[i]
	sp := SignedPolicy{Document: docFor(p), Policy: *clonePolicy(p), SignerID: signer, Alg: PolicySigAlgEd25519}
	if i > 0 {
		sp.Sig = pf(0x60, ed25519.SignatureSize)
	} else {
		sp.Sig = pf(0x7f, ed25519.SignatureSize)
	}
	c.f.SignedPolicyProofs[i] = sp
}

// finalize lets each proof's sig come from mutate, otherwise stamps every
// proof after the anchor with the root signature, binds the current proof as
// the header's policy, signs the content with the author key (device-1 by
// default) and seals. The anchor proof is never re-signed.
func (c *cpChain) finalize(t *testing.T, k *cpKeys, mutate ...func()) {
	t.Helper()
	for _, m := range mutate {
		m()
	}
	last := len(c.f.SignedPolicyProofs) - 1
	if bytes.Equal(c.f.SignedPolicyProofs[last].Sig, pf(0x60, ed25519.SignatureSize)) {
		signPolicyProof(&c.f.SignedPolicyProofs[last], k.rootPriv)
	}
	c.f.Header.PolicySeq = c.policies[last].PolicySeq
	c.f.Header.AuthorDeviceID = "device-1"
	c.f.Header.PolicyDigest = policyDigest(&c.f.SignedPolicyProofs[last])
	c.f.Header.RevisionID = ""
	priv := k.dev1Priv
	if c.f.Header.AuthorDeviceID != "device-1" {
		priv = k.dev2Priv
	}
	cs := append([]byte(DomainContentSignature+"\x00"), mustContentSigning(t, c.f)...)
	c.f.ContentSignature = Signature{SignerID: c.f.Header.AuthorDeviceID, Alg: SigAlgEd25519, Sig: ed25519.Sign(priv, cs)}
	*c.f = *sealFile(t, c.f, &c.f.ContentSignature)
}

func (c *cpChain) pin(digest []byte, seq uint64) *PolicyCheckpoint {
	a := *c.anchor
	a.OwnerRootPublicKey = bytes.Clone(a.OwnerRootPublicKey)
	a.PolicyDigest = bytes.Clone(digest)
	a.PolicySeq = seq
	return &a
}

func TestVerifyPolicyCheckpointRootChain(t *testing.T) {
	k := newCPKeys(t)
	c := newCPChain(t, k)
	if err := ValidateFile(c.f); err != nil {
		t.Fatalf("fixture is not structurally valid: %v", err)
	}

	// The anchor proof carries garbage sig bytes: trusting it by the caller
	// digest is the only reason this file verifies.
	if !bytes.Equal(c.f.SignedPolicyProofs[0].Sig, pf(0x7f, 64)) {
		t.Fatal("fixture anchor proof no longer carries garbage sig bytes")
	}
	if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
		t.Fatalf("root-signed chain with a valid content signature rejected: %v", err)
	}

	// The caller pins s+1, located in the middle of a three-proof slice
	// whose current policy is s+2: the earlier s proof precedes it.
	c = newCPChain(t, k)
	cur := clonePolicy(c.policies[1])
	cur.PolicySeq = 7
	cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
	c.append(t, cur, "owner-root-01", nil)
	c.finalize(t, k)
	if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
		t.Fatalf("three-proof chain rejected: %v", err)
	}
	mid := c.pin(policyDigest(&c.f.SignedPolicyProofs[1]), 6)
	if err := VerifyPolicyCheckpoint(c.f, mid); err != nil {
		t.Fatalf("continuation pinned at s+1 rejected: %v", err)
	}

	// The pin is read, never written: pointer-equal key and digest bytes are
	// unchanged, and the file verifies again after the call.
	a := c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
	snapshot := bytes.Clone(a.PolicyDigest)
	if err := VerifyPolicyCheckpoint(c.f, a); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PolicyDigest, snapshot) {
		t.Fatal("VerifyPolicyCheckpoint modified the caller's policy digest")
	}

	// VerifyContentSignature is unchanged: the root key is not a content key.
	wantCodeAt(t, VerifyContentSignature(c.f, "device-1", k.root), CodeSignatureVerifyFailed, "")
	if err := VerifyContentSignature(c.f, "device-1", k.dev1); err != nil {
		t.Fatalf("VerifyContentSignature semantics changed: %v", err)
	}
}

// Signatures after the anchor use exactly the frozen policy-document
// preimage. A signature over the document alone, without the NUL separator,
// under another domain, or over the policy digest is not accepted.
func TestVerifyPolicyCheckpointPolicyDomain(t *testing.T) {
	k := newCPKeys(t)
	cases := map[string]func(sp *SignedPolicy) []byte{
		"document alone":  func(sp *SignedPolicy) []byte { return sp.Document },
		"no separator":    func(sp *SignedPolicy) []byte { return append([]byte(DomainPolicyDocumentSignature), sp.Document...) },
		"content domain":  func(sp *SignedPolicy) []byte { return append([]byte(DomainContentSignature+"\x00"), sp.Document...) },
		"revision domain": func(sp *SignedPolicy) []byte { return append([]byte(DomainRevision+"\x00"), sp.Document...) },
		"policy digest":   func(sp *SignedPolicy) []byte { return PolicyDigest(&sp.Policy) },
	}
	for name, msg := range cases {
		c := newCPChain(t, k)
		last := len(c.f.SignedPolicyProofs) - 1
		c.finalize(t, k, func() {
			sp := &c.f.SignedPolicyProofs[last]
			sp.Sig = ed25519.Sign(k.rootPriv, msg(sp))
		})
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeSignatureVerifyFailed, "signed_policy_proofs[1]")

		// The exact frozen preimage is accepted.
		c = newCPChain(t, k)
		c.finalize(t, k, func() { signPolicyProof(&c.f.SignedPolicyProofs[last], k.rootPriv) })
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("%s: exact preimage rejected: %v", name, err)
		}
	}
}

func TestVerifyPolicyCheckpointNegative(t *testing.T) {
	k := newCPKeys(t)

	t.Run("anchor by digest only", func(t *testing.T) {
		c := newCPChain(t, k)

		// A same-sequence digest mismatch is rejected even though the anchor
		// signature is never examined.
		a := c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
		a.PolicyDigest[0] ^= 0xff
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodePolicyCheckpointFailed, "")

		// An anchor sequence the file does not carry is accepted only as a
		// checkpoint+1 continuation: proof 0 (seq 5) names the pinned digest
		// as its predecessor and is root-signed.
		c.finalize(t, k, func() { signPolicyProof(&c.f.SignedPolicyProofs[0], k.rootPriv) })
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("checkpoint+1 fixture does not validate: %v", err)
		}
		if err := VerifyPolicyCheckpoint(c.f, c.pin(digest("policy-4"), 4)); err != nil {
			t.Fatalf("checkpoint+1 continuation rejected: %v", err)
		}

		// A seq+1 pin whose digest is not the carried predecessor is rejected.
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.pin(digest("not-the-predecessor"), 6)), CodePolicyCheckpointFailed, "")

		// The anchor proof's own bytes are trusted as carried: a file whose
		// anchor document differs from the pinned policy yields a different
		// digest and fails.
		c = newCPChain(t, k)
		other := clonePolicy(c.policies[0])
		other.Writers = []Member{{PrincipalID: "carol", Label: "Carol"}}
		c.policies[1].PrevPolicyDigest = bytes.Clone(PolicyDigest(other))
		c.f.SignedPolicyProofs[1].Policy = *clonePolicy(c.policies[1])
		c.f.SignedPolicyProofs[1].Document = docFor(c.policies[1])
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")
	})

	t.Run("chain gap", func(t *testing.T) {
		c := newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.PolicySeq = 8 // skips 7
		next := clonePolicy(cur)
		next.PolicySeq = 9
		c.append(t, cur, "owner-root-01", k.rootPriv)
		c.replaceProof(2, next, "owner-root-01")
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")
	})

	t.Run("proofs before the checkpoint", func(t *testing.T) {
		// The caller pins s+1, the middle proof: the earlier s proof precedes
		// it and is ignored, and the chain runs from s+1 through s+2.
		c := newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		c.append(t, cur, "owner-root-01", nil)
		c.finalize(t, k)
		mid := c.pin(policyDigest(&c.f.SignedPolicyProofs[1]), 6)
		if err := VerifyPolicyCheckpoint(c.f, mid); err != nil {
			t.Fatalf("checkpoint in the middle of the proof slice rejected: %v", err)
		}

		// The ignored prefix is not authenticated: a different root in the
		// anchor itself and a garbage signature on s do not matter to a pin
		// at s+1, but a sequence change in the authenticated tail does.
		c.replaceProof(2, cur, "owner-root-01")
		c.finalize(t, k, func() { c.f.SignedPolicyProofs[0].Sig[0] ^= 0xff })
		if err := VerifyPolicyCheckpoint(c.f, mid); err != nil {
			t.Fatalf("ignored prefix influenced the pin at s+1: %v", err)
		}

		// A same-sequence mismatch ahead of the ignored prefix is still
		// rejected when the pin names the first carried proof.
		c.replaceProof(0, c.policies[0], "owner-root-01")
		c.finalize(t, k)
		a := c.pin(digest("not-the-carried-s"), 5)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodePolicyCheckpointFailed, "")
	})

	t.Run("link mismatch", func(t *testing.T) {
		// The current policy chains to a digest that is not the trusted
		// predecessor.
		c := newCPChain(t, k)
		c.policies[1].PrevPolicyDigest = digest("some-other-policy")
		c.replaceProof(1, c.policies[1], "owner-root-01")
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// A three-proof chain whose s+2 chains to a foreign digest fails at
		// the second authenticated proof.
		c = newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		cur.PrevPolicyDigest = digest("some-other-policy")
		c.append(t, cur, "owner-root-01", nil)
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// The same three-proof chain linked correctly verifies.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		c.append(t, cur, "owner-root-01", nil)
		c.finalize(t, k)
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("well-linked three-proof chain rejected: %v", err)
		}
	})

	t.Run("root substitution", func(t *testing.T) {
		// A continuation carrying a different owner root key id is rejected,
		// even when it is correctly signed by the new root.
		c := newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		cur.OwnerRoot.KeyID = "owner-root-02"
		cur.OwnerRoot.PublicKey = bytes.Clone(k.otherRoot)
		c.append(t, cur, "owner-root-02", k.otherRootPrv)
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// The same root key id with different public key bytes fails.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.OwnerRoot.PublicKey = bytes.Clone(k.otherRoot)
		c.append(t, cur, "owner-root-01", k.otherRootPrv)
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// A caller pin with a different root public key fails.
		c = newCPChain(t, k)
		a := c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
		a.OwnerRootPublicKey = bytes.Clone(k.otherRoot)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodePolicyCheckpointFailed, "")
		a = c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
		a.OwnerRootKeyID = "owner-root-02"
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodePolicyCheckpointFailed, "")

		// A continuation named by the pinned root id, linked exactly and
		// signed by the pinned root verifies on a three-proof chain.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		c.append(t, cur, "owner-root-01", nil)
		c.finalize(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("positive continuation fixture is not structurally valid: %v", err)
		}
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("root-signed continuation rejected: %v", err)
		}

		// The identical continuation, signed with a non-root key, fails the
		// signature rather than the link.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		c.append(t, cur, "owner-root-01", k.otherRootPrv)
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeSignatureVerifyFailed, "signed_policy_proofs[2]")

		// A continuation naming a signer other than the pinned root id fails,
		// even with a signature by the pinned root key.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		c.append(t, cur, "device-1", k.rootPriv)
		c.finalize(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")
	})

	t.Run("stale policy tip", func(t *testing.T) {
		c := newCPChain(t, k)

		// The checkpoint is ahead of the file's current policy.
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.pin(digest("policy-7"), 7)), CodePolicyCheckpointFailed, "")

		// A rollback to a carried policy whose predecessor is not the pinned
		// digest is not a continuation either.
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.pin(policyDigest(&c.f.SignedPolicyProofs[1]), 5)), CodePolicyCheckpointFailed, "")
	})

	t.Run("cross-vault anchor", func(t *testing.T) {
		// The positive baseline: the same-shaped root-A chain with no vault
		// change verifies, so each negative below fails on the vault, not on
		// a malformed fixture.
		c := newCPChain(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("baseline fixture is not structurally valid: %v", err)
		}
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("baseline root-A chain rejected: %v", err)
		}

		a := c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
		a.VaultID = "vault-02"
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodePolicyCheckpointFailed, "")

		// A file whose own vault differs from the pin fails, even with every
		// proof consistently renamed.
		c = newCPChain(t, k)
		for i := range c.policies {
			c.policies[i].VaultID = "vault-02"
		}
		c.replaceProof(0, c.policies[0], "owner-root-01")
		c.replaceProof(1, c.policies[1], "owner-root-01")
		c.finalize(t, k, func() { c.f.Header.VaultID = "vault-02" })
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("renamed-vault fixture is not structurally valid: %v", err)
		}
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// A file with one carried proof from another vault is rejected by
		// ValidateFile as a header mismatch before the checkpoint API runs.
		// The checkpoint API surfaces the same structural code; it never
		// reaches CodePolicyCheckpointFailed, which is the vault-independent
		// pin above.
		// finalize cannot build this fixture: its validated content preimage
		// rejects the mixed-vault policy before any assertion runs. Bind the
		// header to the current proof by hand and use the validating-free
		// preimage instead.
		c = newCPChain(t, k)
		mid := clonePolicy(c.policies[1])
		mid.VaultID = "vault-02"
		c.replaceProof(1, mid, "owner-root-01")
		last := len(c.f.SignedPolicyProofs) - 1
		cur := &c.f.SignedPolicyProofs[last]
		signPolicyProof(cur, k.rootPriv)
		c.f.Header.PolicySeq = cur.Policy.PolicySeq
		c.f.Header.PolicyDigest = policyDigest(cur)
		c.f.Header.RevisionID = ""
		msg, err := contentSigningBytes(c.f, false)
		if err != nil {
			t.Fatalf("mixed-vault content preimage: %v", err)
		}
		cs := append([]byte(DomainContentSignature+"\x00"), msg...)
		c.f.ContentSignature = Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: ed25519.Sign(k.dev1Priv, cs)}
		sealNegativeFixture(t, c.f)
		if g := c.f.Header.VaultID; g != "vault-01" {
			t.Fatalf("header vault = %q, want vault-01", g)
		}
		if g := c.f.SignedPolicyProofs[last].Policy.VaultID; g != "vault-02" {
			t.Fatalf("current proof vault = %q, want vault-02", g)
		}
		wantCodeAt(t, ValidateFile(c.f), CodeHeaderMismatch, "")
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeHeaderMismatch, "")
	})

	t.Run("revoked author", func(t *testing.T) {
		// The positive baseline: the base chain is valid and accepted, so
		// each negative below fails on the author rule, not on a malformed
		// fixture.
		c := newCPChain(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("baseline fixture is not structurally valid: %v", err)
		}
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("baseline chain rejected: %v", err)
		}

		// revokeAuthor installs p as the current policy, root-signed and
		// linked to the carried anchor, binds the header to it, and seals
		// with a valid content signature by the real device-1 key even
		// though its principal can no longer write.
		revokeAuthor := func(p *Policy) {
			t.Helper()
			p.PolicySeq = 6
			p.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[0]))
			c.replaceProof(1, p, "owner-root-01")
			signPolicyProof(&c.f.SignedPolicyProofs[1], k.rootPriv)
			c.f.Header.PolicySeq = p.PolicySeq
			c.f.Header.PolicyDigest = policyDigest(&c.f.SignedPolicyProofs[1])
			c.f.Header.AuthorDeviceID = "device-1"
			c.f.Header.RevisionID = ""
			msg, err := contentSigningBytes(c.f, false)
			if err != nil {
				t.Fatalf("revoked-author content preimage: %v", err)
			}
			cs := append([]byte(DomainContentSignature+"\x00"), msg...)
			c.f.ContentSignature = Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: ed25519.Sign(k.dev1Priv, cs)}
			sealNegativeFixture(t, c.f)
		}

		// alice is demoted to reader in the current policy, keeping her
		// device and its slot: the author-role rule rejects the file.
		c = newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.Writers = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Admins = nil
		cur.Owners = nil
		cur.Readers = []Member{{PrincipalID: "alice", Label: "Alice"}, {PrincipalID: "bob", Label: "Bob"}}
		revokeAuthor(cur)
		if d := findDevice(&c.f.SignedPolicyProofs[1].Policy, "device-1"); d == nil || d.PrincipalID != "alice" {
			t.Fatal("demotion fixture dropped alice's device")
		}
		wantCodeAt(t, ValidateFile(c.f), CodeInvalidValue, "")
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeInvalidValue, "")

		// alice is removed entirely: her roles, device-1 and its slot. The
		// header still names device-1 as author and the content signature is
		// device-1's, so the targeted authorization rule rejects it.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.Writers = nil
		cur.Admins = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Owners = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Readers = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Devices = []Device{cur.Devices[1]}
		slots := c.f.VUKDeviceSlots[:0]
		for _, s := range c.f.VUKDeviceSlots {
			if s.DeviceID != "device-1" {
				slots = append(slots, s)
			}
		}
		c.f.VUKDeviceSlots = slots
		revokeAuthor(cur)
		if findDevice(&c.f.SignedPolicyProofs[1].Policy, "device-1") != nil {
			t.Fatal("removal fixture kept alice's device")
		}
		for _, s := range c.f.VUKDeviceSlots {
			if s.DeviceID == "device-1" {
				t.Fatal("removal fixture kept alice's device slot")
			}
		}
		if c.f.Header.AuthorDeviceID != "device-1" || c.f.ContentSignature.SignerID != "device-1" {
			t.Fatal("removal fixture no longer authors from device-1")
		}
		wantCodeAt(t, ValidateFile(c.f), CodeInvalidValue, "")
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeInvalidValue, "")

		// A content signature by another device key is not authorized.
		c = newCPChain(t, k)
		c.finalize(t, k)
		cs := append([]byte(DomainContentSignature+"\x00"), mustContentSigning(t, c.f)...)
		c.f.ContentSignature.Sig = ed25519.Sign(k.dev2Priv, cs)
		if c.f.ContentSignature.SignerID != "device-1" || c.f.ContentSignature.Alg != SigAlgEd25519 {
			t.Fatal("wrong-content-key fixture no longer names device-1 with Ed25519")
		}
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("wrong-content-key fixture is not structurally valid: %v", err)
		}
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeSignatureVerifyFailed, "")
	})

	t.Run("admin-signed transition", func(t *testing.T) {
		// device-2 gets its own policy signing key, distinct from the root
		// and content keys, recorded in every carried policy.
		dev2Pub, dev2Priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dev2PolicyKey := &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: dev2Pub}

		// The predecessor at seq 6 is edited and root-signed so its digest
		// changes: device-2's principal bob is an admin and the owner root
		// grants device-2 the frozen InviteReaders scope, unexpired.
		c := newCPChain(t, k)
		pre := clonePolicy(c.policies[1])
		for i := range pre.Devices {
			if pre.Devices[i].DeviceID == "device-2" {
				pre.Devices[i].PolicySigningKey = dev2PolicyKey
			}
		}
		pre.Admins = []Member{{PrincipalID: "alice", Label: "Alice"}, {PrincipalID: "bob", Label: "Bob"}}
		pre.AdminDelegations = []AdminDelegation{{
			DelegationID:     "deleg-01",
			DelegateDevice:   "device-2",
			GrantedBy:        "owner-root-01",
			Scope:            DelegationScope{InviteReaders: true},
			ScopeNote:        "invite readers only",
			ExpiresPolicySeq: 10,
		}}
		c.replaceProof(1, pre, "owner-root-01")
		signPolicyProof(&c.f.SignedPolicyProofs[1], k.rootPriv)
		c.finalize(t, k)

		// The successor at seq 7 links to exactly that predecessor digest,
		// carries the unexpired delegation forward and invites one reader,
		// which matches the delegated InviteReaders scope.
		succ := clonePolicy(pre)
		succ.PolicySeq = 7
		succ.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		succ.Readers = append(succ.Readers, Member{PrincipalID: "dave", Label: "Dave"})
		c.append(t, succ, "device-2", dev2Priv)
		c.finalize(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("admin-signed fixture is not structurally valid: %v", err)
		}
		// The successor proves are really signed by device-2's policy key.
		sp := &c.f.SignedPolicyProofs[2]
		if !ed25519.Verify(pre.Devices[1].PolicySigningKey.PublicKey,
			append([]byte(DomainPolicyDocumentSignature+"\x00"), sp.Document...), sp.Sig) {
			t.Fatal("successor proof is not signed by device-2's policy key")
		}
		// The delegation is well-formed and the diff matches its scope, but
		// the package has no scope-to-diff rule: only the signer counts.
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// The same transition signed by the pinned root is accepted: the
		// rejection above is the delegated signer, not the policy change.
		c.replaceProof(2, succ, "owner-root-01")
		signPolicyProof(&c.f.SignedPolicyProofs[2], k.rootPriv)
		c.finalize(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("root-signed fixture is not structurally valid: %v", err)
		}
		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("root-signed transition rejected: %v", err)
		}
	})

	t.Run("inputs", func(t *testing.T) {
		c := newCPChain(t, k)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, nil), CodeInvalidValue, "")
		wantCodeAt(t, VerifyPolicyCheckpoint(nil, c.anchor), CodeInvalidValue, "")

		// A malformed supplied anchor is invalid_value.
		for _, bad := range []func(*PolicyCheckpoint){
			func(a *PolicyCheckpoint) { a.VaultID = "" },
			func(a *PolicyCheckpoint) { a.OwnerRootKeyID = "" },
			func(a *PolicyCheckpoint) { a.OwnerRootPublicKey = a.OwnerRootPublicKey[:16] },
			func(a *PolicyCheckpoint) { a.PolicyDigest = a.PolicyDigest[:16] },
		} {
			a := c.pin(c.anchor.PolicyDigest, c.anchor.PolicySeq)
			bad(a)
			wantCodeAt(t, VerifyPolicyCheckpoint(c.f, a), CodeInvalidValue, "")
		}

		// Structural failures pass through ValidateFile unchanged.
		stale := deepCopyFile(c.f)
		stale.Header.OpID = "op-0043"
		wantCodeAt(t, VerifyPolicyCheckpoint(stale, c.anchor), CodeInvalidValue, "revision_id")

		if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
			t.Fatalf("negative inputs altered the good file: %v", err)
		}
	})
}

// TestVerifyPolicyCheckpointAnchorRootBinding pins the anchor policy's owner
// root to the caller checkpoint. A carried anchor whose digest is pinned may
// name another root B while the next policy links to it and returns to the
// pinned root A, signed by A: the file is structurally valid and its tail is
// root-A-signed, but the A -> B -> A transition at the anchor was never
// authorized by the caller's pin.
func TestVerifyPolicyCheckpointAnchorRootBinding(t *testing.T) {
	k := newCPKeys(t)

	// The original root-A fixture is the baseline: valid and accepted.
	c := newCPChain(t, k)
	if err := ValidateFile(c.f); err != nil {
		t.Fatalf("baseline fixture is not structurally valid: %v", err)
	}
	if err := VerifyPolicyCheckpoint(c.f, c.anchor); err != nil {
		t.Fatalf("baseline root-A chain rejected: %v", err)
	}

	// Replace the carried anchor policy's root with generated root B and
	// recompute its canonical document. The anchor signature is not verified
	// by the trust API; it stays 64-byte shaped data.
	c = newCPChain(t, k)
	bAnchor := clonePolicy(c.policies[0])
	bAnchor.OwnerRoot.PublicKey = bytes.Clone(k.otherRoot)
	c.replaceProof(0, bAnchor, "owner-root-01")
	// rebind leaves the anchor with a 64-byte placeholder sig; finalize never
	// rewrites the anchor, so the trust API only ever sees shaped bytes.
	bDigest := policyDigest(&c.f.SignedPolicyProofs[0])
	if bytes.Equal(bDigest, c.anchor.PolicyDigest) {
		t.Fatal("replaced anchor digest did not change")
	}

	// The successor at s+1 links to the root-B anchor digest, returns to root
	// A, and is really signed by root A over the frozen policy domain.
	succ := clonePolicy(c.policies[1])
	succ.OwnerRoot.PublicKey = bytes.Clone(k.root)
	succ.PrevPolicyDigest = bytes.Clone(bDigest)
	c.replaceProof(1, succ, "owner-root-01")
	c.finalize(t, k)
	if err := ValidateFile(c.f); err != nil {
		t.Fatalf("inconsistent-root fixture is not structurally valid: %v", err)
	}
	if !bytes.Equal(c.f.SignedPolicyProofs[0].Sig, pf(0x7f, ed25519.SignatureSize)) {
		t.Fatal("anchor signature was rewritten")
	}
	for i := 1; i < len(c.f.SignedPolicyProofs); i++ {
		sp := &c.f.SignedPolicyProofs[i]
		msg := append([]byte(DomainPolicyDocumentSignature+"\x00"), sp.Document...)
		if !ed25519.Verify(k.root, msg, sp.Sig) {
			t.Fatalf("proof %d is not signed by root A", i)
		}
	}
	cur := &c.f.SignedPolicyProofs[len(c.f.SignedPolicyProofs)-1]
	if !bytes.Equal(c.f.Header.PolicyDigest, policyDigest(cur)) {
		t.Fatal("header does not name the successor policy")
	}
	cmsg := append([]byte(DomainContentSignature+"\x00"), mustContentSigning(t, c.f)...)
	if !ed25519.Verify(k.dev1, cmsg, c.f.ContentSignature.Sig) {
		t.Fatal("content is not signed by device-1's key")
	}

	// The caller still pins root A, now together with the root-B anchor
	// digest: the anchor root differs from the pin, so the digest is not
	// trusted and the chain fails closed.
	pin := c.pin(bDigest, c.anchor.PolicySeq)
	if !bytes.Equal(pin.OwnerRootPublicKey, k.root) {
		t.Fatal("pin does not carry root A")
	}
	wantCodeAt(t, VerifyPolicyCheckpoint(c.f, pin), CodePolicyCheckpointFailed, "")
}

// inviteKeys holds real generated key material for the InviteReaders diff
// tests: the owner-root signing key, two generated policy signing keys, one
// content signing key per device id and the age recipients of those ids.
type inviteKeys struct {
	root      ed25519.PublicKey
	prv       ed25519.PrivateKey
	policyKey ed25519.PublicKey
	adminKey  ed25519.PublicKey
	dev       map[string]ed25519.PublicKey
	ageOf     map[string]string
}

func newInviteKeys(t *testing.T) *inviteKeys {
	t.Helper()
	k := &inviteKeys{dev: map[string]ed25519.PublicKey{}, ageOf: map[string]string{}}
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k.root, k.prv = pub, prv
	pub, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k.policyKey = pub
	pub, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k.adminKey = pub
	for _, id := range []string{"device-0", "device-a0", "device-a1", "device-a2", "device-a3", "device-a4", "device-b0", "device-z0"} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.dev[id] = pub
		k.ageOf[id] = ageRecipient(clientKey("invite-" + id))
	}
	return k
}

func (k *inviteKeys) device(t *testing.T, id, principal, label string) Device {
	t.Helper()
	pub, ok := k.dev[id]
	if !ok {
		t.Fatalf("no generated key for %s", id)
	}
	return Device{
		DeviceID:          id,
		PrincipalID:       principal,
		Label:             label,
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(pub)},
		AgeEncryptionKey:  k.ageOf[id],
	}
}

// inviteOldPolicy is a structurally valid predecessor: seq 5, alice owner
// and root owner; alice and bob admins; bob and carol readers; device-a0 for
// alice, device-a1 for bob and device-a2 for carol, all sorting after both
// reader ids. Bob's device-a1 carries a generated policy signing key and is
// the delegate of the active grant, which invites readers until 20; Carol's
// device-a2 is the delegate of the grant that expires at policy seq 7, after
// the successor seq 6.
func inviteOldPolicy(t *testing.T, k *inviteKeys) *Policy {
	t.Helper()
	p := &Policy{
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
		Readers: []Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: "carol", Label: "Carol"}},
		Admins:  []Member{{PrincipalID: "alice", Label: "Alice"}, {PrincipalID: "bob", Label: "Bob"}},
		Owners:  []Member{{PrincipalID: "alice", Label: "Alice"}},
		AdminDelegations: []AdminDelegation{
			{DelegationID: "deleg-active", DelegateDevice: "device-a1", GrantedBy: "owner-root-01",
				Scope: DelegationScope{InviteReaders: true}, ScopeNote: "readers only", ExpiresPolicySeq: 20},
			{DelegationID: "deleg-expiring", DelegateDevice: "device-a2", GrantedBy: "owner-root-01",
				Scope: DelegationScope{InviteReaders: true, RemoveMembers: true}, ScopeNote: "ends later", ExpiresPolicySeq: 7},
		},
		Devices: []Device{
			k.device(t, "device-a0", "alice", "Alice laptop"),
			k.withPolicyKey(k.device(t, "device-a1", "bob", "Bob phone"), k.adminKey),
			k.device(t, "device-a2", "carol", "Carol desktop"),
		},
	}
	return p
}

// withPolicyKey returns d carrying a generated policy signing key, as an
// admin-capable delegate device does.
func (k *inviteKeys) withPolicyKey(d Device, pub ed25519.PublicKey) Device {
	d.PolicySigningKey = &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: bytes.Clone(pub)}
	return d
}

// inviteNext derives a valid successor of old: seq+1 linked to old's digest,
// with next applied and the sorted arrays re-frozen. next receives a deep
// copy of old and mutates only the roles, devices, delegations or seq it
// means to change; the root and digest are left to this helper. Like a real
// admin client, the helper drops every grant that expires at the successor
// seq, because ValidatePolicy rejects a grant carried at its own expiry; it
// does so after next, for whatever seq next ends at.
func inviteNext(old *Policy, next func(p *Policy)) *Policy {
	p := clonePolicy(old)
	p.PolicySeq = old.PolicySeq + 1
	p.PrevPolicyDigest = bytes.Clone(PolicyDigest(old))
	next(p)
	p.AdminDelegations = slices.DeleteFunc(p.AdminDelegations, func(d AdminDelegation) bool {
		return d.ExpiresPolicySeq == p.PolicySeq
	})
	slices.SortFunc(p.Readers, func(a, b Member) int { return strings.Compare(a.PrincipalID, b.PrincipalID) })
	slices.SortFunc(p.Devices, func(a, b Device) int { return strings.Compare(a.DeviceID, b.DeviceID) })
	slices.SortFunc(p.AdminDelegations, func(a, b AdminDelegation) int { return strings.Compare(a.DelegationID, b.DelegationID) })
	return p
}

func inviteReader(id, label string) Member { return Member{PrincipalID: id, Label: label} }

// TestInviteReadersPolicyDiff pins the InviteReaders old-to-new predicate.
// Every policy handed to it - the predecessor old and the successor next of
// every case, positive or negative - must pass ValidatePolicy first, so each
// negative below fails only on the diff itself and not on any structural or
// order rule. Each negative changes exactly one target relative to the
// approved transition built by newReaders (plus, where a new reader is needed
// for the target to be representable at all, exactly that reader addition).
func TestInviteReadersPolicyDiff(t *testing.T) {
	k := newInviteKeys(t)
	old := inviteOldPolicy(t, k)

	// newReaders adds ann, dan and zed: ann and dan sort before every old
	// reader id, zed after, so the ids interleave with the old ones.
	newReaders := func(p *Policy) {
		p.Readers = append(p.Readers, inviteReader("ann", "Ann"), inviteReader("dan", "Dan"), inviteReader("zed", "Zed"))
	}
	// newDevices gives ann two devices - device-b0 sorts after the old
	// devices and device-0 sorts before every old device id - and dan one
	// (device-a3 sorts among the old devices). zed gets none.
	newDevices := func(p *Policy) {
		p.Devices = append(p.Devices,
			k.device(t, "device-b0", "ann", "Ann phone"),
			k.device(t, "device-0", "ann", "Ann laptop"),
			k.device(t, "device-a3", "dan", "Dan laptop"))
	}
	// withoutDevice removes the device with id from p, if present.
	withoutDevice := func(p *Policy, id string) {
		p.Devices = slices.DeleteFunc(p.Devices, func(d Device) bool { return d.DeviceID == id })
	}
	// readerRemovalOld is the case-specific predecessor of the reader-removal
	// negative: carol is still an old reader, but with no device and no
	// delegation to device-a2, so removing her leaves next fully valid.
	readerRemovalOld := func() *Policy {
		p := clonePolicy(old)
		withoutDevice(p, "device-a2")
		p.AdminDelegations = slices.DeleteFunc(p.AdminDelegations, func(d AdminDelegation) bool {
			return d.DelegationID == "deleg-expiring"
		})
		return p
	}
	// exactExpiryOld is the case-specific predecessor of the exact-expiry
	// pair: deleg-expiring now expires exactly at the successor seq 6, while
	// old itself stays valid.
	exactExpiryOld := func() *Policy {
		p := clonePolicy(old)
		for i := range p.AdminDelegations {
			if p.AdminDelegations[i].DelegationID == "deleg-expiring" {
				p.AdminDelegations[i].ExpiresPolicySeq = 6
			}
		}
		return p
	}
	// expiringGrant returns old's deleg-expiring grant, restated with expiry.
	expiringGrant := func(expiry uint64) AdminDelegation {
		for _, d := range old.AdminDelegations {
			if d.DelegationID == "deleg-expiring" {
				d.ExpiresPolicySeq = expiry
				return d
			}
		}
		t.Fatal("old fixture has no deleg-expiring grant")
		return AdminDelegation{}
	}

	type inviteCase struct {
		name string
		// setup, when set, derives a case-specific old from the shared
		// predecessor before next is built from it.
		setup func() *Policy
		next  func(p *Policy)
	}

	positives := []inviteCase{
		{name: "one reader no devices", next: func(p *Policy) {
			p.Readers = append(p.Readers, inviteReader("ann", "Ann"))
		}},
		{name: "multiple readers no devices", next: newReaders},
		{name: "multiple readers with devices for each", next: func(p *Policy) {
			newReaders(p)
			newDevices(p)
		}},
		{name: "devices only for some new readers", next: func(p *Policy) {
			// ann has two devices and dan one, zed none: the approved device
			// count per new reader is 0..N.
			newReaders(p)
			newDevices(p)
		}},
		{name: "exact-expiry cleanup keeps active grant", next: func(p *Policy) {
			newReaders(p)
			newDevices(p)
		}},
		{name: "delegation dropped exactly at its expiry", setup: exactExpiryOld, next: func(p *Policy) {
			// The helper drops deleg-expiring because it expires at next's
			// own seq 6; the active grant is carried unchanged.
			newReaders(p)
			newDevices(p)
		}},
	}

	negatives := []inviteCase{
		{name: "no reader addition", next: func(p *Policy) {}},
		{name: "new device for old principal", next: func(p *Policy) {
			newReaders(p)
			p.Devices = append(p.Devices, k.device(t, "device-b0", "bob", "Bob tablet"))
		}},
		{name: "writer role for new reader", next: func(p *Policy) {
			newReaders(p)
			p.Writers = []Member{inviteReader("ann", "Ann")}
		}},
		{name: "admin role for new reader", next: func(p *Policy) {
			newReaders(p)
			p.Admins = append(p.Admins, inviteReader("dan", "Dan"))
		}},
		{name: "owner role for new reader", next: func(p *Policy) {
			newReaders(p)
			p.Owners = append(p.Owners, inviteReader("zed", "Zed"))
		}},
		{name: "root owner for new reader", next: func(p *Policy) {
			newReaders(p)
			p.OwnerRoot.Owners = append(p.OwnerRoot.Owners, Principal{PrincipalID: "zed", Label: "Zed"})
		}},
		{name: "existing reader label changed", next: func(p *Policy) {
			newReaders(p)
			p.Readers[0].Label = "Robert"
		}},
		{name: "existing reader label rewritten after sorting", next: func(p *Policy) {
			// ann sorts first, so the changed bob entry is no longer at the
			// old index: the diff must match readers by principal ID.
			newReaders(p)
			for i := range p.Readers {
				if p.Readers[i].PrincipalID == "bob" {
					p.Readers[i].Label = "Bobby"
				}
			}
		}},
		{name: "reader removed", setup: readerRemovalOld, next: func(p *Policy) {
			// carol, a reader with no device and no delegation, is removed:
			// no replacement reader is added and the remaining old devices
			// are untouched.
			for _, d := range p.Devices {
				if d.PrincipalID == "carol" {
					t.Fatalf("reader-removal old has a device for carol: %s", d.DeviceID)
				}
			}
			newReaders(p)
			p.Readers = slices.DeleteFunc(p.Readers, func(m Member) bool { return m.PrincipalID == "carol" })
		}},
		{name: "existing device label mutated", next: func(p *Policy) {
			newReaders(p)
			for i := range p.Devices {
				if p.Devices[i].DeviceID == "device-a1" {
					p.Devices[i].Label = "Bob's other phone"
				}
			}
		}},
		{name: "existing device content key mutated", next: func(p *Policy) {
			newReaders(p)
			for i := range p.Devices {
				if p.Devices[i].DeviceID == "device-a2" {
					p.Devices[i].ContentSigningKey.PublicKey[0] ^= 0xff
				}
			}
		}},
		{name: "existing device age key mutated", next: func(p *Policy) {
			newReaders(p)
			for i := range p.Devices {
				if p.Devices[i].DeviceID == "device-a0" {
					p.Devices[i].AgeEncryptionKey = k.ageOf["device-b0"]
				}
			}
		}},
		{name: "existing device removed", next: func(p *Policy) {
			// device-a0 is named by no delegation, so this isolates removal.
			newReaders(p)
			withoutDevice(p, "device-a0")
		}},
		{name: "existing device moved to a new reader", next: func(p *Policy) {
			// Same device id and keys, now ann's: old devices are never
			// re-owned or edited.
			newReaders(p)
			for i := range p.Devices {
				if p.Devices[i].DeviceID == "device-a2" {
					p.Devices[i].PrincipalID = "ann"
				}
			}
		}},
		{name: "existing device policy key added", next: func(p *Policy) {
			newReaders(p)
			for i := range p.Devices {
				if p.Devices[i].DeviceID == "device-a0" {
					p.Devices[i].PolicySigningKey = &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: bytes.Clone(k.policyKey)}
				}
			}
		}},
		{name: "new device for old principal among new device owners", next: func(p *Policy) {
			// ann and dan get devices; carol, an old reader, gets one too,
			// sorted next to them.
			newReaders(p)
			newDevices(p)
			p.Devices = append(p.Devices, k.device(t, "device-a4", "carol", "Carol tablet"))
		}},
		{name: "root key mutated", next: func(p *Policy) {
			newReaders(p)
			p.OwnerRoot.PublicKey[0] ^= 0xff
		}},
		{name: "root owners mutated", next: func(p *Policy) {
			newReaders(p)
			p.OwnerRoot.Owners[0].Label = "Alicia"
		}},
		{name: "wrong next seq skips ahead", next: func(p *Policy) {
			// deleg-expiring expires at 7, so the helper drops it and next
			// stays structurally valid; the sequence gap is the only defect.
			newReaders(p)
			p.PolicySeq = 7
		}},
		{name: "old policy seq reused", next: func(p *Policy) {
			// seq 5 is old's own seq, which also makes it a non-genesis
			// policy whose prev digest must still be a digest.
			newReaders(p)
			p.PolicySeq = 5
		}},
		{name: "wrong prev digest", next: func(p *Policy) {
			newReaders(p)
			p.PrevPolicyDigest = digest("policy-4")
		}},
		{name: "active delegation dropped", next: func(p *Policy) {
			newReaders(p)
			p.AdminDelegations = slices.DeleteFunc(p.AdminDelegations, func(d AdminDelegation) bool {
				return d.DelegationID == "deleg-active"
			})
		}},
		{name: "active delegation scope changed", next: func(p *Policy) {
			newReaders(p)
			for i := range p.AdminDelegations {
				if p.AdminDelegations[i].DelegationID == "deleg-active" {
					p.AdminDelegations[i].Scope.RemoveMembers = true
				}
			}
		}},
		{name: "active delegation expiry changed", next: func(p *Policy) {
			newReaders(p)
			for i := range p.AdminDelegations {
				if p.AdminDelegations[i].DelegationID == "deleg-active" {
					p.AdminDelegations[i].ExpiresPolicySeq = 21
				}
			}
		}},
		{name: "delegation added", next: func(p *Policy) {
			newReaders(p)
			p.AdminDelegations = append(p.AdminDelegations, AdminDelegation{
				DelegationID: "deleg-new", DelegateDevice: "device-a0", GrantedBy: "owner-root-01",
				Scope: DelegationScope{InviteReaders: true}, ScopeNote: "readers only",
			})
		}},
		{name: "expiring delegation edited instead of dropped", setup: exactExpiryOld, next: func(p *Policy) {
			// deleg-expiring expires exactly at next's seq 6. The edit below
			// runs after the helper's drop and re-extends it to 20, so next
			// stays structurally valid and only the edit is forbidden.
			newReaders(p)
			p.AdminDelegations = append(p.AdminDelegations, expiringGrant(20))
		}},
	}

	run := func(t *testing.T, tc inviteCase) (*Policy, *Policy) {
		t.Helper()
		prev := old
		if tc.setup != nil {
			prev = tc.setup()
		}
		if err := ValidatePolicy(prev); err != nil {
			t.Fatalf("%s: old policy invalid: %v", tc.name, err)
		}
		next := inviteNext(prev, tc.next)
		if err := ValidatePolicy(next); err != nil {
			t.Fatalf("%s: next policy invalid: %v", tc.name, err)
		}
		return prev, next
	}

	for _, tc := range positives {
		t.Run(tc.name, func(t *testing.T) {
			prev, next := run(t, tc)
			if !inviteReadersPolicyDiff(prev, next) {
				t.Errorf("approved transition rejected")
			}
		})
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			prev, next := run(t, tc)
			if tc.name == "wrong next seq skips ahead" {
				// The only rejected rule is the sequence gap: next is at 7,
				// the expiring grant was dropped exactly there, and the
				// active grant is still carried unchanged.
				if next.PolicySeq != 7 {
					t.Fatalf("skip-ahead next seq = %d, want 7", next.PolicySeq)
				}
				for _, d := range next.AdminDelegations {
					if d.ExpiresPolicySeq <= next.PolicySeq {
						t.Fatalf("delegation %s expires at %d in next seq %d", d.DelegationID, d.ExpiresPolicySeq, next.PolicySeq)
					}
				}
				if len(next.AdminDelegations) != 1 || next.AdminDelegations[0] != prev.AdminDelegations[0] {
					t.Fatal("skip-ahead next does not carry the active grant unchanged")
				}
			}
			if inviteReadersPolicyDiff(prev, next) {
				t.Errorf("forbidden transition accepted")
			}
		})
	}
}
