package vaultfile

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/age"
)

// openFixture is a genuine sealed file for the full-file open path. Its
// current policy belongs to a real owner root and carries the generated age
// X25519 recipient for device-1, whose real VUK slot and CEK slot wrap the key
// that seals a real KDBX payload with one protected field and one attachment.
type openFixture struct {
	chain    *cpChain
	identity *age.X25519Identity
	encoded  []byte
}

func newOpenFixture(t *testing.T) *openFixture {
	t.Helper()
	k := newCPKeys(t)
	c := newCPChain(t, k)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Put the generated identity's recipient in the authenticated current
	// policy. The anchor still carries its original recipient; the current
	// proof is root-signed, so this is an ordinary authenticated policy
	// continuation.
	p := clonePolicy(c.policies[1])
	if len(p.Devices) != 2 || p.Devices[0].DeviceID != "device-1" || p.Devices[1].DeviceID != "device-2" {
		t.Fatalf("unexpected fixture devices: %+v", p.Devices)
	}
	p.Devices[0].AgeEncryptionKey = identity.Recipient().String()
	c.policies[1] = p
	c.rebind(1, "owner-root-01")

	// Seal the CEK under exactly the header the file will carry after
	// finalize. Only revision_id is added afterwards, and it is deliberately
	// outside the CEK wrapping AAD.
	c.f.Header.PolicySeq = p.PolicySeq
	c.f.Header.PolicyDigest = policyDigest(&c.f.SignedPolicyProofs[1])
	c.f.Header.AuthorDeviceID = "device-1"

	vuk := make([]byte, CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}
	defer clear(vuk)

	slot1, err := SealVUKForDevice(vuk, c.f.Header.VaultID, c.f.Header.KeyEpoch, p.Devices[0].DeviceID, p.Devices[0].AgeEncryptionKey)
	if err != nil {
		t.Fatalf("sealing device-1 VUK slot: %v", err)
	}
	slot2, err := SealVUKForDevice(vuk, c.f.Header.VaultID, c.f.Header.KeyEpoch, p.Devices[1].DeviceID, p.Devices[1].AgeEncryptionKey)
	if err != nil {
		t.Fatalf("sealing device-2 VUK slot: %v", err)
	}
	c.f.VUKDeviceSlots = []DeviceSlot{slot1, slot2}

	cek, cekSlot, err := SealCEK(vuk, c.f.Header)
	if err != nil {
		t.Fatalf("sealing CEK: %v", err)
	}
	defer clear(cek)
	ciphertext, err := SealKDBXPayload(payloadFixtureDB(t), cek)
	if err != nil {
		t.Fatalf("sealing KDBX payload: %v", err)
	}
	c.f.CEKSlot = cekSlot
	c.f.KDBXCiphertext = ciphertext

	c.finalize(t, k)
	encoded, err := EncodeFile(c.f)
	if err != nil {
		t.Fatalf("encoding sealed fixture: %v", err)
	}
	return &openFixture{chain: c, identity: identity, encoded: encoded}
}

func TestOpenAuthenticatedFileRoundTrip(t *testing.T) {
	fx := newOpenFixture(t)
	if err := VerifyPolicyCheckpoint(fx.chain.f, fx.chain.anchor); err != nil {
		t.Fatalf("fixture checkpoint does not verify: %v", err)
	}

	f, db, err := OpenAuthenticatedFile(fx.encoded, fx.chain.anchor, "device-1", fx.identity)
	if err != nil {
		t.Fatalf("OpenAuthenticatedFile: %v", err)
	}
	if f == nil || db == nil {
		t.Fatalf("opened file/database = %v/%v, want both non-nil", f, db)
	}
	if err := ValidateFile(f); err != nil {
		t.Fatalf("returned file is not valid: %v", err)
	}
	if f.Header.VaultID != fx.chain.anchor.VaultID {
		t.Fatalf("returned vault = %q, want %q", f.Header.VaultID, fx.chain.anchor.VaultID)
	}
	if db.Content == nil || db.Content.Root == nil || len(db.Content.Root.Groups) != 1 {
		t.Fatal("opened database has no single root group")
	}
	entry := db.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("protected value = %q, want %q", got, payloadProtectedSecret)
	}
	if !entry.Values[1].Value.Protected.Bool {
		t.Fatal("protected flag lost")
	}
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatalf("title = %q, want fixture", got)
	}
	if len(entry.Binaries) != 1 || entry.Binaries[0].Name != payloadAttachmentName {
		t.Fatalf("binary references = %+v", entry.Binaries)
	}
	binary := db.FindBinary(entry.Binaries[0].Value.ID)
	if binary == nil || !bytes.Equal(binary.Content, payloadAttachmentBytes) {
		t.Fatalf("attachment bytes did not survive: %v", binary)
	}
}

// TestOpenAuthenticatedFileNegativeOrder pins the required order. Both
// negatives are structurally valid and canonically encoded files; each target
// is the only stale input, so the asserted code identifies the step that
// caught it. The tampered-ciphertext case would be kdbx_payload_invalid if
// KDBX decryption ran before the content signature check.
func TestOpenAuthenticatedFileNegativeOrder(t *testing.T) {
	t.Run("stale content signature", func(t *testing.T) {
		fx := newOpenFixture(t)
		tampered := deepCopyFile(fx.chain.f)
		tampered.KDBXCiphertext[len(tampered.KDBXCiphertext)-1] ^= 0xff
		// Re-derive the revision id for the tampered ciphertext but keep the
		// old content signature: ParseFile still accepts the canonical file,
		// and VerifyPolicyCheckpoint must be the step that rejects it.
		reseal(t, tampered)
		encoded, err := EncodeFile(tampered)
		if err != nil {
			t.Fatalf("encoding tampered fixture: %v", err)
		}

		f, db, err := OpenAuthenticatedFile(encoded, fx.chain.anchor, "device-1", fx.identity)
		wantCodeAt(t, err, CodeSignatureVerifyFailed, "")
		if f != nil || db != nil {
			t.Fatalf("failed open returned file/database = %v/%v, want both nil", f, db)
		}
	})

	t.Run("mismatched checkpoint", func(t *testing.T) {
		fx := newOpenFixture(t)
		pin := *fx.chain.anchor
		pin.PolicyDigest = bytes.Clone(fx.chain.anchor.PolicyDigest)
		pin.PolicyDigest[0] ^= 0xff

		f, db, err := OpenAuthenticatedFile(fx.encoded, &pin, "device-1", fx.identity)
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
		if f != nil || db != nil {
			t.Fatalf("failed open returned file/database = %v/%v, want both nil", f, db)
		}
	})
}
