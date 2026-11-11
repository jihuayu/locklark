package vaultfile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// These tests exercise the CEK envelope only: a real AES-256-GCM round trip
// under a random VUK, fresh randomness per seal, binding of every header
// member except the derived revision_id, and the one generic envelope
// failure code. Every targeted negative proves the valid fixture first.

// cekFixture is a valid header plus a random VUK.
type cekFixture struct {
	vuk    []byte
	header Header
}

func newCEKFixture(t *testing.T) cekFixture {
	t.Helper()
	vuk := make([]byte, CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal(err)
	}
	return cekFixture{
		vuk: vuk,
		header: Header{
			VaultID:        "vault-cek",
			KeyEpoch:       3,
			ContentSeq:     42,
			PrevDigest:     pf(0x21, 32),
			OpID:           "op-cek-42",
			PolicySeq:      7,
			PolicyDigest:   pf(0x31, 32),
			AuthorDeviceID: "device-1",
		},
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, CEKSize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// sealFixture seals with the fixture and proves the round trip, so a negative
// case can rely on the fixture being valid.
func sealFixture(t *testing.T, fx cekFixture) ([]byte, CEKSlot) {
	t.Helper()
	cek, slot, err := SealCEK(fx.vuk, fx.header)
	if err != nil {
		t.Fatalf("SealCEK: %v", err)
	}
	if len(cek) != CEKSize {
		t.Fatalf("cek length %d, want %d", len(cek), CEKSize)
	}
	if slot.KeyEpoch != fx.header.KeyEpoch {
		t.Fatalf("slot key epoch %d, want %d", slot.KeyEpoch, fx.header.KeyEpoch)
	}
	if len(slot.WrappedCEK) != WrappedCEKSize {
		t.Fatalf("wrapped length %d, want %d", len(slot.WrappedCEK), WrappedCEKSize)
	}
	opened, err := OpenCEK(fx.vuk, fx.header, slot)
	if err != nil {
		t.Fatalf("OpenCEK: %v", err)
	}
	if !bytes.Equal(opened, cek) {
		t.Fatal("opened CEK differs from sealed CEK")
	}
	clear(opened)
	return cek, slot
}

func wantCEKEnvelopeFailed(t *testing.T, err error) {
	t.Helper()
	wantCodeAt(t, err, CodeCEKEnvelopeFailed, "cek_slot")
}

func TestCEKRoundTrip(t *testing.T) {
	fx := newCEKFixture(t)
	cek, _ := sealFixture(t, fx)
	defer clear(cek)
}

func TestCEKSealFreshRandomness(t *testing.T) {
	// Probabilistic but over 2^255-to-one: two fresh 32-byte CEKs colliding
	// would mean the generator is broken.
	fx := newCEKFixture(t)
	cek1, slot1 := sealFixture(t, fx)
	defer clear(cek1)
	cek2, slot2 := sealFixture(t, fx)
	defer clear(cek2)
	if bytes.Equal(cek1, cek2) {
		t.Fatal("two seals produced the same CEK")
	}
	if bytes.Equal(slot1.WrappedCEK, slot2.WrappedCEK) {
		t.Fatal("two seals produced the same wrapped CEK")
	}
	// Each wrapped slot opens to its own CEK, and neither to the other's.
	o1, err := OpenCEK(fx.vuk, fx.header, slot1)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(o1)
	o2, err := OpenCEK(fx.vuk, fx.header, slot2)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(o2)
	if !bytes.Equal(o1, cek1) || !bytes.Equal(o2, cek2) {
		t.Fatal("opened CEKs do not match their seals")
	}
}

func TestCEKRejectsWrongVUK(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	wrong := randomKey(t)
	if bytes.Equal(wrong, fx.vuk) {
		t.Fatal("random keys collided")
	}
	got, err := OpenCEK(wrong, fx.header, slot)
	if got != nil {
		t.Fatal("OpenCEK returned a CEK on failure")
	}
	wantCEKEnvelopeFailed(t, err)
}

func TestCEKRejectsWrongVaultID(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	h := fx.header
	h.VaultID = "vault-cek-other"
	if err := ValidateHeader(&h); err != nil {
		t.Fatalf("modified header invalid: %v", err)
	}
	got, err := OpenCEK(fx.vuk, h, slot)
	if got != nil {
		t.Fatal("OpenCEK returned a CEK on failure")
	}
	wantCEKEnvelopeFailed(t, err)
}

func TestCEKRejectsWrongKeyEpoch(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	// Both the header and the slot move to the next epoch, so the slot epoch
	// check passes and the failure is AAD authentication, not that check.
	h := fx.header
	h.KeyEpoch = fx.header.KeyEpoch + 1
	slot.KeyEpoch = h.KeyEpoch
	if err := ValidateHeader(&h); err != nil {
		t.Fatalf("modified header invalid: %v", err)
	}
	got, err := OpenCEK(fx.vuk, h, slot)
	if got != nil {
		t.Fatal("OpenCEK returned a CEK on failure")
	}
	wantCEKEnvelopeFailed(t, err)
}

func TestCEKRejectsSlotEpochMismatch(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	for _, epoch := range []uint64{0, fx.header.KeyEpoch + 1} {
		s := slot
		s.KeyEpoch = epoch
		got, err := OpenCEK(fx.vuk, fx.header, s)
		if got != nil {
			t.Fatalf("slot epoch %d: OpenCEK returned a CEK on failure", epoch)
		}
		wantCEKEnvelopeFailed(t, err)
	}
}

func TestCEKRejectsTamperedWrappedBytes(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	// One bit in each region: nonce prefix, ciphertext, tag.
	for _, i := range []int{0, cekAEADNonceSize, len(slot.WrappedCEK) - 1} {
		s := slot
		s.WrappedCEK = bytes.Clone(slot.WrappedCEK)
		s.WrappedCEK[i] ^= 0x01
		got, err := OpenCEK(fx.vuk, fx.header, s)
		if got != nil {
			t.Fatalf("tampered byte %d: OpenCEK returned a CEK on failure", i)
		}
		wantCEKEnvelopeFailed(t, err)
	}
}

func TestCEKRejectsMalformedWrappedBytes(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	long := make([]byte, MaxWrappedKeyLength+1)
	cases := map[string][]byte{
		"nil":      nil,
		"empty":    {},
		"short":    slot.WrappedCEK[:WrappedCEKSize-1],
		"long":     append(bytes.Clone(slot.WrappedCEK), 0),
		"over max": long,
	}
	for name, wrapped := range cases {
		s := CEKSlot{KeyEpoch: slot.KeyEpoch, WrappedCEK: wrapped}
		got, err := OpenCEK(fx.vuk, fx.header, s)
		if got != nil {
			t.Fatalf("%s: OpenCEK returned a CEK on failure", name)
		}
		wantCEKEnvelopeFailed(t, err)
	}
}

func TestCEKRejectsHeaderMemberChanges(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	// Every non-derived member except vault_id and key_epoch (covered above)
	// is changed in a structurally valid way. revision_id is excluded: it is
	// derived and deliberately not bound (TestCEKIgnoresRevisionID).
	cases := map[string]func(*Header){
		"content_seq": func(h *Header) { h.ContentSeq++ },
		"prev_digest": func(h *Header) { h.PrevDigest = pf(0x22, 32) },
		"op_id":       func(h *Header) { h.OpID = "op-cek-43" },
		"policy_seq":  func(h *Header) { h.PolicySeq++ },
		"policy_digest": func(h *Header) {
			h.PolicyDigest = pf(0x32, 32)
		},
		"author_device_id": func(h *Header) { h.AuthorDeviceID = "device-2" },
		"prev_digest dropped": func(h *Header) {
			// content_seq 0 makes a nil prev_digest valid.
			h.ContentSeq = 0
			h.PrevDigest = nil
		},
	}
	for name, mutate := range cases {
		h := fx.header
		// Clone slice members so a mutation cannot alias the fixture.
		h.PrevDigest = bytes.Clone(fx.header.PrevDigest)
		h.PolicyDigest = bytes.Clone(fx.header.PolicyDigest)
		mutate(&h)
		if err := ValidateHeader(&h); err != nil {
			t.Fatalf("%s: modified header invalid: %v", name, err)
		}
		got, err := OpenCEK(fx.vuk, h, slot)
		if got != nil {
			t.Fatalf("%s: OpenCEK returned a CEK on failure", name)
		}
		wantCEKEnvelopeFailed(t, err)
	}
}

func TestCEKIgnoresRevisionID(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	// A valid-shaped derived revision id, as it would be present after
	// sealing, neither changes the AAD nor the open result: the CEK is
	// sealed before the revision id exists.
	h := fx.header
	h.RevisionID = hex.EncodeToString(pf(0x77, 32))
	if err := ValidateHeader(&h); err != nil {
		t.Fatalf("modified header invalid: %v", err)
	}
	got, err := OpenCEK(fx.vuk, h, slot)
	if err != nil {
		t.Fatalf("OpenCEK with revision id: %v", err)
	}
	defer clear(got)
	if !bytes.Equal(got, cek) {
		t.Fatal("opened CEK differs from sealed CEK")
	}
	aadDraft, err := cekWrappingAAD(&fx.header)
	if err != nil {
		t.Fatal(err)
	}
	aadSealed, err := cekWrappingAAD(&h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aadDraft, aadSealed) {
		t.Fatal("revision_id changed the wrapping AAD")
	}
	if bytes.Contains(aadSealed, []byte(`"revision_id"`)) {
		t.Fatal("wrapping AAD contains revision_id")
	}
}

func TestCEKSealRejectsInvalidInput(t *testing.T) {
	fx := newCEKFixture(t)
	cases := map[string]struct {
		vuk        []byte
		h          Header
		code, path string
	}{
		"short vuk":           {vuk: fx.vuk[:CEKSize-1], h: fx.header, code: CodeInvalidValue},
		"long vuk":            {vuk: append(bytes.Clone(fx.vuk), 0), h: fx.header, code: CodeInvalidValue},
		"nil vuk":             {vuk: nil, h: fx.header, code: CodeInvalidValue},
		"zero epoch":          {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.KeyEpoch = 0 }), code: CodeInvalidValue, path: "key_epoch"},
		"empty vault id":      {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.VaultID = "" }), code: CodeInvalidValue},
		"invalid vault id":    {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.VaultID = "Vault CEK" }), code: CodeInvalidValue},
		"empty op id":         {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.OpID = "" }), code: CodeInvalidValue},
		"empty author device": {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.AuthorDeviceID = "" }), code: CodeInvalidValue},
		"empty policy digest": {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.PolicyDigest = nil }), code: CodeInvalidValue},
		"short policy digest": {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.PolicyDigest = pf(0x31, 31) }), code: CodeInvalidValue},
		"short prev digest":   {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.PrevDigest = pf(0x21, 16) }), code: CodeInvalidValue},
		"genesis prev digest": {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.ContentSeq = 0 }), code: CodeInvalidValue},
		"malformed revision":  {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.RevisionID = "xyz" }), code: CodeInvalidValue},
	}
	for name, c := range cases {
		cek, slot, err := SealCEK(c.vuk, c.h)
		e, ok := AsError(err)
		if !ok || e.Code != c.code || e.Path != c.path {
			t.Fatalf("%s: expected %s at %q, got %v", name, c.code, c.path, err)
		}
		if cek != nil {
			t.Fatalf("%s: SealCEK returned a CEK on failure", name)
		}
		if slot.KeyEpoch != 0 || slot.WrappedCEK != nil {
			t.Fatalf("%s: SealCEK returned a slot on failure", name)
		}
	}
	// The fixture itself still seals after every rejection.
	cek, _ := sealFixture(t, fx)
	clear(cek)
}

func TestCEKOpenRejectsInvalidInput(t *testing.T) {
	fx := newCEKFixture(t)
	cek, slot := sealFixture(t, fx)
	defer clear(cek)
	cases := map[string]struct {
		vuk        []byte
		h          Header
		code, path string
	}{
		"short vuk":           {vuk: fx.vuk[:CEKSize-1], h: fx.header, code: CodeInvalidValue},
		"long vuk":            {vuk: append(bytes.Clone(fx.vuk), 0), h: fx.header, code: CodeInvalidValue},
		"zero epoch":          {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.KeyEpoch = 0 }), code: CodeInvalidValue, path: "key_epoch"},
		"invalid vault id":    {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.VaultID = "" }), code: CodeInvalidValue},
		"invalid author":      {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.AuthorDeviceID = "" }), code: CodeInvalidValue},
		"short policy digest": {vuk: fx.vuk, h: withField(fx.header, func(h *Header) { h.PolicyDigest = pf(0x31, 1) }), code: CodeInvalidValue},
	}
	for name, c := range cases {
		got, err := OpenCEK(c.vuk, c.h, slot)
		e, ok := AsError(err)
		if !ok || e.Code != c.code || e.Path != c.path {
			t.Fatalf("%s: expected %s at %q, got %v", name, c.code, c.path, err)
		}
		if got != nil {
			t.Fatalf("%s: OpenCEK returned a CEK on failure", name)
		}
	}
}

func withField(h Header, mutate func(*Header)) Header {
	h.PrevDigest = bytes.Clone(h.PrevDigest)
	h.PolicyDigest = bytes.Clone(h.PolicyDigest)
	mutate(&h)
	return h
}
