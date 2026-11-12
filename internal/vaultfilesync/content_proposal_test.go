package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// contentProposalKey is one real generated device key pair and its real age
// X25519 recipient.
type contentProposalKey struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	recipient string
}

// contentProposalFixture is a real caller-pinned ordinary-content base. The
// pinned current policy is p (seq 5); pNext (seq 6) is a fully valid,
// root-signed successor that adds writer eve and device-4.
type contentProposalFixture struct {
	checkpoint   *vaultfile.PolicyCheckpoint
	current      *vaultfile.Policy
	next         *vaultfile.Policy
	nextProof    vaultfile.SignedPolicy
	base         []byte
	baseFile     *vaultfile.File
	keys         map[string]contentProposalKey
	baseRevision vaultfilebackend.Revision
	operationID  string
}

const contentProposalCiphertext = "content-proposal-synthetic-sealed-ciphertext"

func newContentProposalFixture(t *testing.T) *contentProposalFixture {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]contentProposalKey)
	for _, id := range []string{"device-1", "device-2", "device-3", "device-4"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = contentProposalKey{pub: pub, priv: priv, recipient: identity.Recipient().String()}
	}
	device := func(id, principal, label string) vaultfile.Device {
		return vaultfile.Device{
			DeviceID:          id,
			PrincipalID:       principal,
			Label:             label,
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(keys[id].pub)},
			AgeEncryptionKey:  keys[id].recipient,
		}
	}

	current := &vaultfile.Policy{
		Format:           vaultfile.Format,
		Version:          vaultfile.Version,
		VaultID:          "vault-01",
		PolicySeq:        5,
		PrevPolicyDigest: bytes.Repeat([]byte{0x11}, 32),
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     "owner-root-01",
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPub),
			Owners:    []vaultfile.Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Readers: []vaultfile.Member{{PrincipalID: "carol", Label: "Carol"}},
		Writers: []vaultfile.Member{{PrincipalID: "bob", Label: "Bob"}},
		Admins:  []vaultfile.Member{{PrincipalID: "alice", Label: "Alice"}},
		Owners:  []vaultfile.Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []vaultfile.Device{
			device("device-1", "alice", "Alice laptop"),
			device("device-2", "bob", "Bob phone"),
			device("device-3", "carol", "Carol reader"),
		},
	}
	if err := vaultfile.ValidatePolicy(current); err != nil {
		t.Fatalf("current policy: %v", err)
	}

	next := contentProposalClonePolicy(t, current)
	next.PolicySeq = current.PolicySeq + 1
	next.PrevPolicyDigest = vaultfile.PolicyDigest(current)
	next.Writers = []vaultfile.Member{
		{PrincipalID: "bob", Label: "Bob"},
		{PrincipalID: "eve", Label: "Eve"},
	}
	next.Devices = append(next.Devices, device("device-4", "eve", "Eve laptop"))
	if err := vaultfile.ValidatePolicy(next); err != nil {
		t.Fatalf("next policy: %v", err)
	}
	nextProof := contentProposalProof(t, next, current.OwnerRoot.KeyID, rootPriv)

	pin := &vaultfile.PolicyCheckpoint{
		VaultID:            current.VaultID,
		OwnerRootKeyID:     current.OwnerRoot.KeyID,
		OwnerRootPublicKey: bytes.Clone(rootPub),
		PolicySeq:          current.PolicySeq,
		PolicyDigest:       vaultfile.PolicyDigest(current),
	}

	header := vaultfile.Header{
		VaultID:        current.VaultID,
		KeyEpoch:       3,
		ContentSeq:     42,
		PrevDigest:     bytes.Repeat([]byte{0x22}, 32),
		OpID:           "op-base-42",
		PolicySeq:      current.PolicySeq,
		PolicyDigest:   vaultfile.PolicyDigest(current),
		AuthorDeviceID: "device-1",
	}
	baseProof := contentProposalProof(t, current, current.OwnerRoot.KeyID, rootPriv)
	base, baseFile := contentProposalBuildFile(t, current, []vaultfile.SignedPolicy{baseProof}, header, keys["device-1"].priv)
	if err := vaultfile.VerifyPolicyCheckpoint(baseFile, pin); err != nil {
		t.Fatalf("fixture base does not verify under its pin: %v", err)
	}
	return &contentProposalFixture{
		checkpoint:   pin,
		current:      current,
		next:         next,
		nextProof:    nextProof,
		base:         base,
		baseFile:     baseFile,
		keys:         keys,
		baseRevision: vaultfilebackend.Revision("revision-42"),
		operationID:  "op-candidate-43",
	}
}

// baselineCandidate builds a fully valid ordinary successor of fx.base under
// the same current policy and with the correct prev_digest.
func (fx *contentProposalFixture) baselineCandidate(t *testing.T) ([]byte, *vaultfile.File) {
	t.Helper()
	return fx.candidateWith(t, nil)
}

// candidateWith builds and seals a valid candidate, applying one isolated
// header mutation before sealing. A header mutation only changes a field the
// specific case intends; the file is re-signed with a real Ed25519 signature.
func (fx *contentProposalFixture) candidateWith(t *testing.T, mutate func(*vaultfile.Header)) ([]byte, *vaultfile.File) {
	t.Helper()
	header := fx.baseFile.Header
	header.ContentSeq = fx.baseFile.Header.ContentSeq + 1
	header.PrevDigest = contentProposalFileDigestBytes(t, fx.baseFile)
	header.OpID = fx.operationID
	if mutate != nil {
		mutate(&header)
	}
	return contentProposalBuildFile(t, fx.current, fx.baseFile.SignedPolicyProofs, header, fx.keys["device-1"].priv)
}

// contentProposalBuildFile constructs a complete real sealed file from the
// named current policy, the carried proofs and a header. It signs the content
// with a real Ed25519 key and seals through vaultfile.SealFile, then parses
// the canonical bytes back.
func contentProposalBuildFile(
	t *testing.T,
	current *vaultfile.Policy,
	proofs []vaultfile.SignedPolicy,
	header vaultfile.Header,
	authorPriv ed25519.PrivateKey,
) ([]byte, *vaultfile.File) {
	t.Helper()
	header.RevisionID = ""
	header.PrevDigest = bytes.Clone(header.PrevDigest)
	header.PolicyDigest = bytes.Clone(header.PolicyDigest)
	f := &vaultfile.File{
		Format:             vaultfile.Format,
		Version:            vaultfile.Version,
		Header:             header,
		SignedPolicyProofs: append([]vaultfile.SignedPolicy(nil), proofs...),
		ContentEncoding:    vaultfile.ContentEncoding,
		KDBXCiphertext:     []byte(contentProposalCiphertext),
	}
	for i := range current.Devices {
		d := &current.Devices[i]
		f.VUKDeviceSlots = append(f.VUKDeviceSlots, vaultfile.DeviceSlot{
			DeviceID:   d.DeviceID,
			Recipient:  d.AgeEncryptionKey,
			WrappedVUK: []byte("wrapped-vuk"),
		})
	}
	f.CEKSlot = vaultfile.CEKSlot{KeyEpoch: header.KeyEpoch, WrappedCEK: []byte("wrapped-cek")}

	preimage, err := vaultfile.ContentSigningBytes(f)
	if err != nil {
		t.Fatalf("content signing preimage: %v", err)
	}
	msg := append([]byte(vaultfile.DomainContentSignature+"\x00"), preimage...)
	sig := &vaultfile.Signature{
		SignerID: header.AuthorDeviceID,
		Alg:      vaultfile.SigAlgEd25519,
		Sig:      ed25519.Sign(authorPriv, msg),
	}
	encoded, err := vaultfile.SealFile(f, sig)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	parsed, err := vaultfile.ParseFile(encoded)
	if err != nil {
		t.Fatalf("parse sealed file: %v", err)
	}
	return encoded, parsed
}

// contentProposalProof returns a real root-signed proof of p.
func contentProposalProof(t *testing.T, p *vaultfile.Policy, signer string, priv ed25519.PrivateKey) vaultfile.SignedPolicy {
	t.Helper()
	doc, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode policy document: %v", err)
	}
	msg := append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), doc...)
	return vaultfile.SignedPolicy{
		Policy:   *contentProposalClonePolicy(t, p),
		Document: doc,
		SignerID: signer,
		Alg:      vaultfile.PolicySigAlgEd25519,
		Sig:      ed25519.Sign(priv, msg),
	}
}

func contentProposalClonePolicy(t *testing.T, p *vaultfile.Policy) *vaultfile.Policy {
	t.Helper()
	doc, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode policy: %v", err)
	}
	clone, err := vaultfile.ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("parse policy clone: %v", err)
	}
	return clone
}

// contentProposalFileDigestBytes returns the raw 32 FileDigest bytes of f.
func contentProposalFileDigestBytes(t *testing.T, f *vaultfile.File) []byte {
	t.Helper()
	digest, err := vaultfile.FileDigest(f)
	if err != nil {
		t.Fatalf("file digest: %v", err)
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 32 {
		t.Fatalf("file digest is not 32 raw bytes: %v", err)
	}
	return raw
}

// contentProposalVerifyCandidate independently parses candidate and proves it
// authenticates under pin. Every file-level negative calls it first, so the
// verifier's rejection is not caused by an unrelated malformed structure.
func contentProposalVerifyCandidate(t *testing.T, candidate []byte, pin *vaultfile.PolicyCheckpoint) *vaultfile.File {
	t.Helper()
	parsed, err := vaultfile.ParseFile(candidate)
	if err != nil {
		t.Fatalf("candidate does not parse: %v", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(parsed, pin); err != nil {
		t.Fatalf("candidate does not verify under its own pin: %v", err)
	}
	return parsed
}

func contentProposalWantRejected(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrContentProposalRejected) {
		t.Fatalf("err = %v, want ErrContentProposalRejected", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rejection wrapped a context error: %v", err)
	}
}

func contentProposalProposal(fx *contentProposalFixture, bytes []byte) vaultfilejournal.Proposal {
	return vaultfilejournal.Proposal{
		Generation:       1,
		OperationID:      fx.operationID,
		ExpectedRevision: fx.baseRevision,
		Bytes:            bytes,
	}
}

func TestContentProposalVerifierAcceptsOrdinarySuccessorAndSnapshotsPin(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, candidateFile := fx.baselineCandidate(t)
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
	if candidateFile.Header.PrevDigest == nil ||
		!bytes.Equal(candidateFile.Header.PrevDigest, contentProposalFileDigestBytes(t, fx.baseFile)) {
		t.Fatal("positive candidate does not carry the raw FileDigest of the base")
	}

	baseBefore := bytes.Clone(fx.base)
	proposal := contentProposalProposal(fx, candidate)
	proposalBefore := bytes.Clone(proposal.Bytes)

	// Mutate every part of the caller's checkpoint after construction,
	// including both cloned byte slices in place. The verifier must still use
	// its construction-time snapshot.
	fx.checkpoint.VaultID = "vault-other"
	fx.checkpoint.OwnerRootKeyID = "owner-root-other"
	for i := range fx.checkpoint.OwnerRootPublicKey {
		fx.checkpoint.OwnerRootPublicKey[i] ^= 0xff
	}
	fx.checkpoint.PolicySeq = 999
	for i := range fx.checkpoint.PolicyDigest {
		fx.checkpoint.PolicyDigest[i] ^= 0xff
	}

	if err := verifier(context.Background(), fx.base, fx.baseRevision, proposal); err != nil {
		t.Fatalf("verifier rejected the valid positive after caller checkpoint mutation: %v", err)
	}
	if !bytes.Equal(fx.base, baseBefore) {
		t.Fatal("verifier mutated the base bytes")
	}
	if !bytes.Equal(proposal.Bytes, proposalBefore) {
		t.Fatal("verifier mutated the proposal bytes")
	}
}

func TestContentProposalVerifierConstructionAndContext(t *testing.T) {
	if _, err := NewContentProposalVerifier(nil); err == nil {
		t.Fatal("NewContentProposalVerifier accepted a nil checkpoint")
	}

	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, _ := fx.baselineCandidate(t)
	proposal := contentProposalProposal(fx, candidate)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier(cancelled, fx.base, fx.baseRevision, proposal); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: err = %v, want context.Canceled", err)
	} else if err != context.Canceled {
		t.Fatalf("cancelled context was wrapped: %v", err)
	}
}

func TestContentProposalVerifierRejectsRevisionMismatch(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, _ := fx.baselineCandidate(t)
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)

	proposal := contentProposalProposal(fx, candidate)
	proposal.ExpectedRevision = "revision-other"
	err = verifier(context.Background(), fx.base, fx.baseRevision, proposal)
	contentProposalWantRejected(t, err)
	if strings.Contains(err.Error(), string(fx.baseRevision)) ||
		strings.Contains(err.Error(), string(proposal.ExpectedRevision)) {
		t.Fatalf("rejection message embeds an opaque revision: %v", err)
	}

	for _, revision := range []vaultfilebackend.Revision{
		"",
		vaultfilebackend.Revision(strings.Repeat("r", vaultfilebackend.MaxRevisionSize+1)),
	} {
		proposal := contentProposalProposal(fx, candidate)
		proposal.ExpectedRevision = revision
		contentProposalWantRejected(t, verifier(context.Background(), fx.base, revision, proposal))
	}
}

func TestContentProposalVerifierRejectsOperationIDMismatch(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, _ := fx.baselineCandidate(t)
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)

	proposal := contentProposalProposal(fx, candidate)
	proposal.OperationID = "op-other"
	err = verifier(context.Background(), fx.base, fx.baseRevision, proposal)
	contentProposalWantRejected(t, err)
	if strings.Contains(err.Error(), proposal.OperationID) || strings.Contains(err.Error(), fx.operationID) {
		t.Fatalf("rejection message embeds an operation ID: %v", err)
	}
}

func TestContentProposalVerifierRejectsEpochMismatch(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, candidateFile := fx.candidateWith(t, func(h *vaultfile.Header) {
		h.KeyEpoch = fx.baseFile.Header.KeyEpoch + 1
	})
	if candidateFile.Header.KeyEpoch == fx.baseFile.Header.KeyEpoch {
		t.Fatal("epoch mutation did not take effect")
	}
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
	contentProposalWantRejected(t, verifier(context.Background(), fx.base, fx.baseRevision, contentProposalProposal(fx, candidate)))
}

func TestContentProposalVerifierRejectsContentSequence(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		fx := newContentProposalFixture(t)
		verifier, err := NewContentProposalVerifier(fx.checkpoint)
		if err != nil {
			t.Fatalf("NewContentProposalVerifier: %v", err)
		}
		candidate, candidateFile := fx.candidateWith(t, func(h *vaultfile.Header) {
			h.ContentSeq = fx.baseFile.Header.ContentSeq + 2
		})
		if candidateFile.Header.ContentSeq != fx.baseFile.Header.ContentSeq+2 {
			t.Fatal("content sequence skip mutation did not take effect")
		}
		contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
		contentProposalWantRejected(t, verifier(context.Background(), fx.base, fx.baseRevision, contentProposalProposal(fx, candidate)))
	})

	t.Run("overflow", func(t *testing.T) {
		fx := newContentProposalFixture(t)
		verifier, err := NewContentProposalVerifier(fx.checkpoint)
		if err != nil {
			t.Fatalf("NewContentProposalVerifier: %v", err)
		}

		// R itself is at the maximum content sequence. The otherwise valid
		// wrapped successor cannot be issued from it.
		overflowHeader := fx.baseFile.Header
		overflowHeader.ContentSeq = math.MaxUint64
		overflowHeader.PrevDigest = bytes.Repeat([]byte{0x33}, 32)
		overflowHeader.OpID = "op-overflow-base"
		overflowBase, overflowBaseFile := contentProposalBuildFile(t, fx.current, fx.baseFile.SignedPolicyProofs, overflowHeader, fx.keys["device-1"].priv)
		contentProposalVerifyCandidate(t, overflowBase, fx.checkpoint)
		if overflowBaseFile.Header.ContentSeq != math.MaxUint64 {
			t.Fatal("overflow base is not at MaxUint64")
		}

		candidateHeader := overflowBaseFile.Header
		candidateHeader.ContentSeq = 0
		candidateHeader.PrevDigest = nil
		candidateHeader.OpID = fx.operationID
		candidate, candidateFile := contentProposalBuildFile(t, fx.current, fx.baseFile.SignedPolicyProofs, candidateHeader, fx.keys["device-1"].priv)
		if candidateFile.Header.ContentSeq != 0 || candidateFile.Header.PrevDigest != nil {
			t.Fatal("overflow candidate is not the wrapped content sequence")
		}
		contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
		contentProposalWantRejected(t, verifier(context.Background(), overflowBase, fx.baseRevision, contentProposalProposal(fx, candidate)))
	})
}

func TestContentProposalVerifierRejectsPreviousDigestMismatch(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	candidate, candidateFile := fx.candidateWith(t, func(h *vaultfile.Header) {
		h.PrevDigest = bytes.Repeat([]byte{0x99}, 32)
	})
	if bytes.Equal(candidateFile.Header.PrevDigest, contentProposalFileDigestBytes(t, fx.baseFile)) {
		t.Fatal("previous digest mutation did not take effect")
	}
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
	contentProposalWantRejected(t, verifier(context.Background(), fx.base, fx.baseRevision, contentProposalProposal(fx, candidate)))
}

func TestContentProposalVerifierRejectsRootSignedPolicyChange(t *testing.T) {
	fx := newContentProposalFixture(t)
	verifier, err := NewContentProposalVerifier(fx.checkpoint)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}

	// The successor policy adds writer eve and her device-4, is root-signed,
	// and the candidate content is signed by the newly added writer device-4.
	proofs := append([]vaultfile.SignedPolicy(nil), fx.baseFile.SignedPolicyProofs...)
	proofs = append(proofs, fx.nextProof)
	header := fx.baseFile.Header
	header.ContentSeq = fx.baseFile.Header.ContentSeq + 1
	header.PrevDigest = contentProposalFileDigestBytes(t, fx.baseFile)
	header.OpID = fx.operationID
	header.PolicySeq = fx.next.PolicySeq
	header.PolicyDigest = vaultfile.PolicyDigest(fx.next)
	header.AuthorDeviceID = "device-4"
	candidate, candidateFile := contentProposalBuildFile(t, fx.next, proofs, header, fx.keys["device-4"].priv)

	if fx.nextProof.SignerID != fx.current.OwnerRoot.KeyID {
		t.Fatalf("successor proof signer = %q, want the root key ID", fx.nextProof.SignerID)
	}
	if candidateFile.ContentSignature.SignerID != "device-4" {
		t.Fatalf("candidate author = %q, want device-4", candidateFile.ContentSignature.SignerID)
	}
	if contentProposalCanAuthor(fx.current, "device-4") {
		t.Fatal("the base policy unexpectedly authorizes the newly added writer")
	}
	if !contentProposalCanAuthor(fx.next, "device-4") {
		t.Fatal("the successor policy does not authorize the newly added writer")
	}

	// Independently prove this is a fully valid root-signed policy transition
	// that authenticates under the same caller pin.
	contentProposalVerifyCandidate(t, candidate, fx.checkpoint)
	contentProposalWantRejected(t, verifier(context.Background(), fx.base, fx.baseRevision, contentProposalProposal(fx, candidate)))
}
