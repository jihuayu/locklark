package vaultfile

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

// These tests exercise the VUK device-slot envelope only, with real generated
// age X25519 identities and real age ciphertext: the exact plaintext layout,
// a positive round trip, the caller's expected recipient as the trust source,
// one generic envelope failure code, bounded and authenticated reads, and the
// max-identifier size boundary. Every targeted negative proves the valid
// fixture first.

// vukFixture is a valid VUK, caller context and one generated age identity.
type vukFixture struct {
	vuk       []byte
	vaultID   string
	epoch     uint64
	deviceID  string
	identity  *age.X25519Identity
	recipient string
}

// newVUKFixture returns a fixture for deviceID; the vault id and epoch are
// fixed so two fixtures differ only in their generated identity and device.
func newVUKFixture(t *testing.T, deviceID string) vukFixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return vukFixture{
		vuk:       randomKey(t),
		vaultID:   "vault-vuk",
		epoch:     3,
		deviceID:  deviceID,
		identity:  id,
		recipient: id.Recipient().String(),
	}
}

// sealVUK seals with the fixture and proves the round trip, so a negative
// case can rely on the fixture being valid.
func sealVUK(t *testing.T, fx vukFixture) DeviceSlot {
	t.Helper()
	slot, err := SealVUKForDevice(fx.vuk, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient)
	if err != nil {
		t.Fatalf("SealVUKForDevice: %v", err)
	}
	if slot.DeviceID != fx.deviceID || slot.Recipient != fx.recipient {
		t.Fatalf("slot names %q/%q, want %q/%q", slot.DeviceID, slot.Recipient, fx.deviceID, fx.recipient)
	}
	if len(slot.WrappedVUK) > MaxWrappedKeyLength {
		t.Fatalf("wrapped length %d over MaxWrappedKeyLength", len(slot.WrappedVUK))
	}
	got, err := OpenVUKForDevice(slot, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	if err != nil {
		t.Fatalf("OpenVUKForDevice: %v", err)
	}
	if !bytes.Equal(got, fx.vuk) {
		t.Fatal("opened VUK differs from sealed VUK")
	}
	clear(got)
	return slot
}

// agePlaintext wraps plaintext with exactly one X25519 recipient, as a
// non-conforming envelope fixture for the layout, context and size negatives.
func agePlaintext(t *testing.T, plaintext []byte, recipient string) []byte {
	t.Helper()
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func vukContextBytes(t *testing.T, vaultID string, epoch uint64, deviceID string) []byte {
	t.Helper()
	ctx, err := vukContext(vaultID, epoch, deviceID)
	if err != nil {
		t.Fatalf("vukContext: %v", err)
	}
	return ctx
}

func TestVUKRoundTrip(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	sealVUK(t, fx)
}

func TestVUKFreshEnvelopePerSeal(t *testing.T) {
	// age generates a fresh file key per envelope, so two seals of the same
	// VUK to the same device differ in bytes while both open to the VUK.
	fx := newVUKFixture(t, "device-vuk-1")
	s1 := sealVUK(t, fx)
	s2 := sealVUK(t, fx)
	if bytes.Equal(s1.WrappedVUK, s2.WrappedVUK) {
		t.Fatal("two seals produced the same wrapped VUK")
	}
}

// TestVUKPlaintextLayout pins the exact binary plaintext of the envelope:
// the purpose label followed by one NUL, the two uint16-big-endian lengths,
// the uint64-big-endian epoch, the IDs and the 32-byte VUK.
func TestVUKPlaintextLayout(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	r, n, err := age.DecryptReaderAt(bytes.NewReader(slot.WrappedVUK), int64(len(slot.WrappedVUK)), fx.identity)
	if err != nil {
		t.Fatalf("age decrypt: %v", err)
	}
	plain, err := io.ReadAll(io.NewSectionReader(r, 0, n))
	if err != nil {
		t.Fatalf("age read: %v", err)
	}
	defer clear(plain)

	var want []byte
	want = append(want, []byte(DomainVUKDeviceWrapping)...)
	want = append(want, 0x00)
	want = append(want, 0x00, byte(len(fx.vaultID)))
	want = append(want, fx.vaultID...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 0x03)
	want = append(want, 0x00, byte(len(fx.deviceID)))
	want = append(want, fx.deviceID...)
	want = append(want, fx.vuk...)
	if !bytes.Equal(plain, want) {
		t.Fatalf("plaintext layout mismatch:\n got %x\nwant %x", plain, want)
	}
	if len(plain) != len(DomainVUKDeviceWrapping)+1+2+len(fx.vaultID)+8+2+len(fx.deviceID)+CEKSize {
		t.Fatalf("plaintext length %d", len(plain))
	}
}

// TestVUKRejectsWrongContext covers every context member: one expected value
// differs from the sealed ones. The wrong-vault, wrong-epoch and same-length
// wrong-device-context cases pass the slot metadata check and the
// plaintext-size check and fail only on the authenticated-prefix comparison.
// The separate "wrong device in slot only" case fails the slot metadata check
// before decryption.
func TestVUKRejectsWrongContext(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	// Same-length valid IDs, so the expected plaintext length equals the
	// sealed one: only the authenticated vault or device bytes differ.
	wrongVault := "vault-xuk"
	wrongDevice := "device-vuk-2"
	if len(wrongVault) != len(fx.vaultID) || wrongVault == fx.vaultID {
		t.Fatalf("wrong vault id %q must be a different %d-byte id", wrongVault, len(fx.vaultID))
	}
	if len(wrongDevice) != len(fx.deviceID) || wrongDevice == fx.deviceID {
		t.Fatalf("wrong device id %q must be a different %d-byte id", wrongDevice, len(fx.deviceID))
	}
	// The slot, identity and caller agree on wrongDevice, vault and epoch, so
	// the slot binding passes, but the authenticated plaintext embeds the
	// sealed device id: only the embedded device-context check can reject.
	sub := DeviceSlot{DeviceID: wrongDevice, Recipient: fx.recipient}
	sub.WrappedVUK = agePlaintext(t, vukPlaintextBytes(t, fx, fx.deviceID), fx.recipient)
	cases := map[string]struct {
		slot    DeviceSlot
		vaultID string
		epoch   uint64
		device  string
	}{
		"wrong vault":               {slot: slot, vaultID: wrongVault, epoch: fx.epoch, device: fx.deviceID},
		"wrong epoch":               {slot: slot, vaultID: fx.vaultID, epoch: fx.epoch + 1, device: fx.deviceID},
		"wrong device in context":   {slot: sub, vaultID: fx.vaultID, epoch: fx.epoch, device: wrongDevice},
		"wrong device in slot only": {slot: slot, vaultID: fx.vaultID, epoch: fx.epoch, device: wrongDevice},
	}
	for _, c := range cases {
		// Copy the slot into this scope: the loop variable is reused, so a
		// pointer into it would alias storage the previous call cleared.
		slot := c.slot
		slot.WrappedVUK = bytes.Clone(c.slot.WrappedVUK)
		openVUKEnvelopeFailed(t, slot, c.vaultID, c.epoch, c.device, fx.recipient, fx.identity)
	}
}

func vukPlaintextBytes(t *testing.T, fx vukFixture, deviceID string) []byte {
	t.Helper()
	p, err := vukPlaintext(fx.vuk, fx.vaultID, fx.epoch, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(p)
	return bytes.Clone(p)
}

func TestVUKRejectsExpectedRecipientMismatch(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	other := newVUKFixture(t, "device-vuk-2")
	// The caller expects another (valid) recipient than the slot and
	// identity carry.
	openVUKEnvelopeFailed(t, slot, fx.vaultID, fx.epoch, fx.deviceID, other.recipient, fx.identity)
	openVUKEnvelopeFailed(t, slot, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, other.identity)
}

func TestVUKRejectsWrongIdentityRecipient(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	// A different identity whose recipient is still a canonical age X25519
	// recipient opens only if it is the expected one; it is not.
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if other.Recipient().String() != fx.recipient {
		openVUKEnvelopeFailed(t, slot, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, other)
	} else {
		t.Fatal("generated identities collided")
	}
	// The other identity with its own expected recipient fails the slot
	// recipient binding.
	openVUKEnvelopeFailed(t, slot, fx.vaultID, fx.epoch, fx.deviceID, other.Recipient().String(), other)
}

func TestVUKRejectsSlotSubstitution(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	other := newVUKFixture(t, "device-vuk-2")

	// Another device's slot moved under the expected device id.
	otherSlot, err := SealVUKForDevice(fx.vuk, fx.vaultID, fx.epoch, other.deviceID, other.recipient)
	if err != nil {
		t.Fatal(err)
	}
	sub := otherSlot
	sub.DeviceID = fx.deviceID
	openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	// The caller's own slot with an envelope that carries another device's
	// authenticated context.
	sub = slot
	sub.WrappedVUK = agePlaintext(t, vukPlaintextBytes(t, fx, fx.deviceID+"-2"), fx.recipient)
	openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	// The slot recipient rewritten to another expected recipient.
	sub = slot
	sub.Recipient = other.recipient
	openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, other.recipient, other.identity)
	// A slot device id differing from the caller's expectation.
	sub = slot
	sub.DeviceID = other.deviceID
	openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
}

func TestVUKRejectsTamperedCiphertext(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	// One bit in the header, the payload start, the middle and the final tag.
	n := len(slot.WrappedVUK)
	for _, i := range []int{0, 3, n / 2, n - 1} {
		sub := slot
		sub.WrappedVUK = bytes.Clone(slot.WrappedVUK)
		sub.WrappedVUK[i] ^= 0x01
		openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	}
}

func TestVUKRejectsAppendedTrailingBytes(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	for _, tail := range [][]byte{{0x00}, bytes.Clone(slot.WrappedVUK), []byte("age-encryption.org/v1/X25519")} {
		sub := slot
		sub.WrappedVUK = append(bytes.Clone(slot.WrappedVUK), tail...)
		openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	}
}

func TestVUKRejectsMalformedCiphertext(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	oversize := make([]byte, MaxWrappedKeyLength+1)
	copy(oversize, slot.WrappedVUK)
	cases := map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"oversize":  oversize,
		"truncated": slot.WrappedVUK[:len(slot.WrappedVUK)-1],
		"junk":      []byte("not an age envelope"),
	}
	for _, wrapped := range cases {
		sub := slot
		sub.WrappedVUK = wrapped
		openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	}
}

// TestVUKRejectsNonConformingPlaintext covers envelopes whose plaintext is
// not the conforming domain label, NUL separator, context and VUK layout. Its
// fixtures are short VUK (the VUK one byte short of CEKSize), long VUK (the
// conforming plaintext plus one extra trailing zero byte), context-only
// plaintext (the domain label, NUL and context with no VUK), wrong domain (an
// equal-length purpose label replaced in place), missing NUL (the separator
// byte replaced in place by 'x') and no domain (the context and VUK with no
// domain label or separator). Only the wrong-domain and missing-NUL cases
// preserve the plaintext length and reach the authenticated-prefix comparison;
// the short-VUK, long-VUK, context-only and no-domain cases intentionally
// reach plaintext-size rejection instead.
func TestVUKRejectsNonConformingPlaintext(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	sealVUK(t, fx)
	ctx := vukContextBytes(t, fx.vaultID, fx.epoch, fx.deviceID)
	prefix := append(append([]byte(DomainVUKDeviceWrapping), 0), ctx...)
	// A different valid purpose label of exactly the same byte length: the CEK
	// label made up to the VUK label length with a "-others" suffix, so only
	// the label bytes differ.
	if len(DomainVUKDeviceWrapping)-len(DomainCEKWrapping) != len("-others") {
		t.Fatalf("domain labels are %d and %d bytes", len(DomainVUKDeviceWrapping), len(DomainCEKWrapping))
	}
	otherDomain := DomainCEKWrapping + "-others"
	if len(otherDomain) != len(DomainVUKDeviceWrapping) || otherDomain == DomainVUKDeviceWrapping {
		t.Fatalf("domain %q is %d bytes, want a different %d", otherDomain, len(otherDomain), len(DomainVUKDeviceWrapping))
	}
	// The NUL separator replaced in place by a nonzero byte: the length is
	// unchanged and only the separator byte differs.
	noNUL := bytes.Clone(prefix)
	noNUL[len(DomainVUKDeviceWrapping)] = 'x'
	cases := map[string][]byte{
		"short VUK":    append(bytes.Clone(prefix), fx.vuk[:CEKSize-1]...),
		"long VUK":     append(append(bytes.Clone(prefix), fx.vuk...), 0),
		"context only": bytes.Clone(prefix),
		"wrong domain": append(append([]byte(otherDomain), 0), append(ctx, fx.vuk...)...),
		"no NUL":       append(noNUL, fx.vuk...),
		"no domain":    append(append([]byte{}, ctx...), fx.vuk...),
	}
	for _, plaintext := range cases {
		sub := DeviceSlot{
			DeviceID:   fx.deviceID,
			Recipient:  fx.recipient,
			WrappedVUK: agePlaintext(t, plaintext, fx.recipient),
		}
		openVUKEnvelopeFailed(t, sub, fx.vaultID, fx.epoch, fx.deviceID, fx.recipient, fx.identity)
	}
}

// TestVUKMaxIdentifierBoundary seals and opens at exactly MaxIDLength and
// MaxDeviceIDLength. The exact plaintext is 279 bytes, the envelope fits one
// age chunk and stays within MaxWrappedKeyLength.
func TestVUKMaxIdentifierBoundary(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	fx.vaultID = strings.Repeat("v", MaxIDLength)
	fx.deviceID = strings.Repeat("d", MaxDeviceIDLength)
	fx.epoch = ^uint64(0)
	// At these limits the plaintext is the 42-byte purpose label, the 1-byte
	// NUL, 2 + 64 + 8 + 2 + 128 bytes of context and the 32-byte VUK:
	// 42 + 1 + (2 + 64 + 8 + 2 + 128) + 32 = 279 bytes, one unchunked age chunk.
	if len(DomainVUKDeviceWrapping) != 42 {
		t.Fatalf("DomainVUKDeviceWrapping is %d bytes, want 42", len(DomainVUKDeviceWrapping))
	}
	wantLen := len(DomainVUKDeviceWrapping) + 1 + (2 + MaxIDLength + 8 + 2 + MaxDeviceIDLength) + CEKSize
	if wantLen != 279 {
		t.Fatalf("max plaintext length %d, want 279", wantLen)
	}
	slot := sealVUK(t, fx)
	if len(slot.WrappedVUK) > MaxWrappedKeyLength {
		t.Fatalf("max-ID slot length %d over %d", len(slot.WrappedVUK), MaxWrappedKeyLength)
	}
	// sealVUK already proved the round trip; the envelope also decodes to
	// exactly this plaintext length.
	r, n, err := age.DecryptReaderAt(bytes.NewReader(slot.WrappedVUK), int64(len(slot.WrappedVUK)), fx.identity)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(io.NewSectionReader(r, 0, n))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if len(plain) != wantLen {
		t.Fatalf("max plaintext length %d, want %d", len(plain), wantLen)
	}
	// One byte over either limit is rejected structurally, not by the
	// envelope.
	if _, err := SealVUKForDevice(fx.vuk, fx.vaultID+"v", fx.epoch, fx.deviceID, fx.recipient); err == nil {
		t.Fatal("vault id over MaxIDLength accepted")
	}
	if _, err := SealVUKForDevice(fx.vuk, fx.vaultID, fx.epoch, fx.deviceID+"d", fx.recipient); err == nil {
		t.Fatal("device id over MaxDeviceIDLength accepted")
	}
}

func TestVUKSealRejectsInvalidInput(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	cases := map[string]struct {
		vuk                 []byte
		vaultID             string
		epoch               uint64
		deviceID, recipient string
		code, path          string
	}{
		"nil vuk":            {vuk: nil, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue},
		"short vuk":          {vuk: fx.vuk[:CEKSize-1], vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue},
		"long vuk":           {vuk: append(bytes.Clone(fx.vuk), 0), vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue},
		"empty vault":        {vuk: fx.vuk, vaultID: "", epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue, path: "vault_id"},
		"invalid vault":      {vuk: fx.vuk, vaultID: "Vault VUK", epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue, path: "vault_id"},
		"long vault":         {vuk: fx.vuk, vaultID: strings.Repeat("v", MaxIDLength+1), epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue, path: "vault_id"},
		"zero epoch":         {vuk: fx.vuk, vaultID: fx.vaultID, epoch: 0, deviceID: fx.deviceID, recipient: fx.recipient, code: CodeInvalidValue, path: "key_epoch"},
		"empty device":       {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: "", recipient: fx.recipient, code: CodeInvalidValue, path: "device_id"},
		"long device":        {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: strings.Repeat("d", MaxDeviceIDLength+1), recipient: fx.recipient, code: CodeInvalidValue, path: "device_id"},
		"empty recipient":    {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: "", code: CodeInvalidValue, path: "recipient"},
		"identity recipient": {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.identity.String(), code: CodeInvalidValue, path: "recipient"},
		"uppercased":         {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: strings.ToUpper(fx.recipient), code: CodeInvalidValue, path: "recipient"},
		"checksum":           {vuk: fx.vuk, vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: ageRecipientCorruptChecksum(fx.recipient), code: CodeInvalidValue, path: "recipient"},
	}
	for name, c := range cases {
		slot, err := SealVUKForDevice(c.vuk, c.vaultID, c.epoch, c.deviceID, c.recipient)
		if e, ok := AsError(err); !ok || e.Code != c.code || e.Path != c.path {
			t.Fatalf("%s: expected %s at %q, got %v", name, c.code, c.path, err)
		}
		if slot.DeviceID != "" || slot.Recipient != "" || slot.WrappedVUK != nil {
			t.Fatalf("%s: SealVUKForDevice returned a slot on failure", name)
		}
	}
	// The fixture itself still seals after every rejection.
	sealVUK(t, fx)
}

func TestVUKOpenRejectsInvalidInput(t *testing.T) {
	fx := newVUKFixture(t, "device-vuk-1")
	slot := sealVUK(t, fx)
	other := newVUKFixture(t, "device-vuk-2")
	cases := map[string]struct {
		vaultID             string
		epoch               uint64
		deviceID, recipient string
		identity            *age.X25519Identity
		code, path          string
	}{
		"empty vault":        {vaultID: "", epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, identity: fx.identity, code: CodeInvalidValue, path: "vault_id"},
		"long vault":         {vaultID: strings.Repeat("v", MaxIDLength+1), epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, identity: fx.identity, code: CodeInvalidValue, path: "vault_id"},
		"zero epoch":         {vaultID: fx.vaultID, epoch: 0, deviceID: fx.deviceID, recipient: fx.recipient, identity: fx.identity, code: CodeInvalidValue, path: "key_epoch"},
		"empty device":       {vaultID: fx.vaultID, epoch: fx.epoch, deviceID: "", recipient: fx.recipient, identity: fx.identity, code: CodeInvalidValue, path: "device_id"},
		"long device":        {vaultID: fx.vaultID, epoch: fx.epoch, deviceID: strings.Repeat("d", MaxDeviceIDLength+1), recipient: fx.recipient, identity: fx.identity, code: CodeInvalidValue, path: "device_id"},
		"empty recipient":    {vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: "", identity: fx.identity, code: CodeInvalidValue, path: "recipient"},
		"non age recipient":  {vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: "not-a-recipient", identity: fx.identity, code: CodeInvalidValue, path: "recipient"},
		"nil identity":       {vaultID: fx.vaultID, epoch: fx.epoch, deviceID: fx.deviceID, recipient: fx.recipient, identity: nil, code: CodeInvalidValue, path: "identity"},
		"valid other device": {vaultID: other.vaultID, epoch: other.epoch, deviceID: other.deviceID, recipient: other.recipient, identity: other.identity, code: CodeVUKEnvelopeFailed, path: "vuk_device_slot"},
	}
	for _, c := range cases {
		openVUK(t, slot, c.vaultID, c.epoch, c.deviceID, c.recipient, c.identity, c.code, c.path)
	}
}

// openVUK opens and fails closed: the returned VUK must be nil and the error
// must be exactly the expected code at the expected path.
//
// It is not inlined so that OpenVUKForDevice's own stack frame, and any
// buffer Go may hand out from a frame whose deferred clear runs later, is
// never shared with the caller's frame.
//
//go:noinline
func openVUK(t *testing.T, slot DeviceSlot, vaultID string, epoch uint64, deviceID, recipient string, identity *age.X25519Identity, code, path string) []byte {
	t.Helper()
	got, err := OpenVUKForDevice(slot, vaultID, epoch, deviceID, recipient, identity)
	if got != nil {
		t.Fatal("OpenVUKForDevice returned a non-nil VUK on failure")
	}
	wantCodeAt(t, err, code, path)
	return got
}

// openVUKEnvelopeFailed calls openVUK for the one generic envelope code.
//
//go:noinline
func openVUKEnvelopeFailed(t *testing.T, slot DeviceSlot, vaultID string, epoch uint64, deviceID, recipient string, identity *age.X25519Identity) []byte {
	t.Helper()
	return openVUK(t, slot, vaultID, epoch, deviceID, recipient, identity, CodeVUKEnvelopeFailed, "vuk_device_slot")
}
