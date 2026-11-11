package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
		{Document: docFor(p1), Policy: *clonePolicy(p1), SignerID: "owner-root-01"},
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
// leaves the signature unset for the caller to stamp in a mutation.
func (c *cpChain) append(t *testing.T, p *Policy, signer string, priv ed25519.PrivateKey) {
	t.Helper()
	sp := SignedPolicy{Document: docFor(p), Policy: *clonePolicy(p), SignerID: signer}
	if priv != nil {
		signPolicyProof(&sp, priv)
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
// its signer, leaving the signature for finalize.
func (c *cpChain) rebind(i int, signer string) {
	p := c.policies[i]
	sp := SignedPolicy{Document: docFor(p), Policy: *clonePolicy(p), SignerID: signer}
	if i > 0 {
		sp.Sig = pf(0x60, 64)
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
	switch {
	case bytes.Equal(c.f.SignedPolicyProofs[last].Sig, pf(0x60, 64)):
		signPolicyProof(&c.f.SignedPolicyProofs[last], k.rootPriv)
	case last > 0 && c.f.SignedPolicyProofs[last].Sig == nil:
		signPolicyProof(&c.f.SignedPolicyProofs[last], k.rootPriv)
		for i := 1; i < last; i++ {
			signPolicyProof(&c.f.SignedPolicyProofs[i], k.rootPriv)
		}
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

// finalizeNegative finalizes f and, when it is rejected by the wire rules on
// purpose, binds the revision id directly so the failure under test is not a
// stale revision id.
func (c *cpChain) finalizeNegative(t *testing.T, k *cpKeys, mutate ...func()) {
	t.Helper()
	c.finalize(t, k, mutate...)
	if err := ValidateFile(c.f); err != nil {
		sealNegativeFixture(t, c.f)
	}
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

		// An anchor sequence the file does not carry is missing.
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.pin(digest("policy-4"), 4)), CodePolicyCheckpointFailed, "")

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

		// A continuation signed with a non-root key fails the signature.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.PolicySeq = 7
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
		c := newCPChain(t, k)
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

		// A proof from another vault is rejected even when the header keeps
		// the pinned vault and a later proof returns to it.
		c = newCPChain(t, k)
		mid := clonePolicy(c.policies[1])
		mid.VaultID = "vault-02"
		c.replaceProof(1, mid, "owner-root-01")
		// The content preimage requires the header digest to name the carried
		// mid policy, which ValidateFile itself then reject as a vault
		// mismatch; bind the revision directly so the sealed state is reached.
		c.finalize(t, k)
		c.f.Header.VaultID = "vault-01"
		sealNegativeFixture(t, c.f)
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")
	})

	t.Run("revoked author", func(t *testing.T) {
		// alice is demoted to reader in the current policy: the author-role
		// rule rejects the file.
		c := newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.Writers = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Admins = nil
		cur.Owners = nil
		cur.Readers = []Member{{PrincipalID: "alice", Label: "Alice"}, {PrincipalID: "bob", Label: "Bob"}}
		c.replaceProof(1, cur, "owner-root-01")
		c.finalizeNegative(t, k)
		wantCode(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeInvalidValue)

		// alice is removed entirely; her device is dropped with her.
		c = newCPChain(t, k)
		cur = clonePolicy(c.policies[1])
		cur.Writers = nil
		cur.Admins = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Owners = []Member{{PrincipalID: "bob", Label: "Bob"}}
		cur.Devices = cur.Devices[1:]
		c.replaceProof(1, cur, "owner-root-01")
		c.finalizeNegative(t, k)
		wantCode(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeInvalidValue)

		// A content signature by another device key is not authorized.
		c = newCPChain(t, k)
		c.finalize(t, k, func() {
			cs := append([]byte(DomainContentSignature+"\x00"), mustContentSigning(t, c.f)...)
			c.f.ContentSignature.Sig = ed25519.Sign(k.dev2Priv, cs)
		})
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodeSignatureVerifyFailed, "")
	})

	t.Run("admin-signed transition", func(t *testing.T) {
		// The base current policy carries a valid admin delegation to
		// device-2; its continuation s+2 is signed by device-2, not the root.
		c := newCPChain(t, k)
		cur := clonePolicy(c.policies[1])
		cur.PolicySeq = 7
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		cur.PrevPolicyDigest = bytes.Clone(policyDigest(&c.f.SignedPolicyProofs[1]))
		cur.AdminDelegations = []AdminDelegation{{
			DelegationID:     "deleg-01",
			DelegateDevice:   "device-2",
			GrantedBy:        "owner-root-01",
			Scope:            DelegationScope{InviteReaders: true, RemoveMembers: true},
			ScopeNote:        "restricted",
			ExpiresPolicySeq: 10,
		}}
		c.append(t, cur, "device-2", nil)
		// The delegated scope is well-formed; this package has no mapping from
		// scope flags to an allowed policy diff, so only the signer counts.
		sp := &c.f.SignedPolicyProofs[2]
		sp.Sig = ed25519.Sign(k.dev2Priv, append([]byte(DomainPolicyDocumentSignature+"\x00"), sp.Document...))
		c.finalize(t, k)
		if err := ValidateFile(c.f); err != nil {
			t.Fatalf("admin-signed fixture is not structurally valid: %v", err)
		}
		wantCodeAt(t, VerifyPolicyCheckpoint(c.f, c.anchor), CodePolicyCheckpointFailed, "")

		// The same transition signed by the root is accepted: the rejection
		// above is the delegated signer, not the policy change.
		c.finalize(t, k, func() { signPolicyProof(&c.f.SignedPolicyProofs[2], k.rootPriv) })
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
	// rebind clears the anchor alg and sig for the caller to stamp; finalize
	// leaves the anchor alone, so the trust API never sees them.
	c.f.SignedPolicyProofs[0].Alg = PolicySigAlgEd25519
	c.f.SignedPolicyProofs[0].Sig = pf(0x7f, ed25519.SignatureSize)
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
