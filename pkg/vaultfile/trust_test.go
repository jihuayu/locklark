package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestVerifyContentSignaturePinnedKey is a synthetic smoke test of the
// pinned-key content signature check: a real generated Ed25519 key pair signs
// the frozen preimage, and a changed signature or a wrong pinned key fails
// while the file stays structurally valid.
func TestVerifyContentSignaturePinnedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// The synthetic policy records the generated public key for device-1, so
	// the file's carried policy names exactly the pinned key.
	p := clonePolicy(&buildDraft(t).SignedPolicyProofs[0].Policy)
	p.Devices[0].ContentSigningKey.PublicKey = bytes.Clone(pub)
	draft := buildDraft(t)
	setPolicy(draft, p)

	msg := append([]byte(DomainContentSignature+"\x00"), mustContentSigning(t, draft)...)
	draft.ContentSignature = Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: ed25519.Sign(priv, msg)}
	sealed := sealFile(t, draft, &draft.ContentSignature)

	if err := VerifyContentSignature(sealed, "device-1", pub); err != nil {
		t.Fatalf("valid content signature rejected: %v", err)
	}

	// A changed signature over the same (still structurally valid) file fails.
	changed := deepCopyFile(sealed)
	changed.ContentSignature.Sig[0] ^= 0xff
	if err := ValidateFile(changed); err != nil {
		t.Fatalf("changed-signature file is no longer structurally valid: %v", err)
	}
	wantCodeAt(t, VerifyContentSignature(changed, "device-1", pub), CodeSignatureVerifyFailed, "")

	// A wrong pinned key fails, even though it is a well-formed key.
	wantCodeAt(t, VerifyContentSignature(sealed, "device-1", otherPub), CodeSignatureVerifyFailed, "")

	// A malformed pinned key is rejected by length, not by a panic.
	wantCodeAt(t, VerifyContentSignature(sealed, "device-1", pub[:16]), CodeSignatureVerifyFailed, "")

	// The pinned signer must be the author device.
	wantCodeAt(t, VerifyContentSignature(sealed, "device-2", pub), CodeSignatureVerifyFailed, "")

	// Structural errors propagate unchanged: a stale revision id is not a
	// signature failure.
	stale := deepCopyFile(sealed)
	stale.Header.OpID = "op-0043"
	wantCodeAt(t, VerifyContentSignature(stale, "device-1", pub), CodeInvalidValue, "revision_id")
}
