package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"
)

// The tests here pin purpose separation: the owner-root Ed25519 key and every
// device key (content signing, optional policy signing, age X25519 encryption)
// are distinct global key material within one policy. The comparison is over
// the raw 32 public-key bytes, so one key occupies both roles whichever
// encoding each role carries it in.

// sepPolicyDevice returns a device with distinct key material of its own, so
// cross-device reuse can be tested. Every key derives from id, whose last
// byte differs between fixture devices.
func sepPolicyDevice(id, principal, label string) Device {
	seed := id[len(id)-1]
	return Device{
		DeviceID:          id,
		PrincipalID:       principal,
		Label:             label,
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x71+seed, 32)},
		PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x81+seed, 32)},
		AgeEncryptionKey:  ageRecipient(clientKey("device-" + id[len("device-"):])),
	}
}

// sepPolicy is the vector policy with two more devices (device-3 of alice and
// device-4 of carol), every key distinct, in the frozen wire order.
func sepPolicy() *Policy {
	p := buildPolicy()
	p.Devices = append(p.Devices,
		sepPolicyDevice("device-3", "alice", "Alice tablet"),
		sepPolicyDevice("device-4", "carol", "Carol desktop"),
	)
	return p
}

// sepFile is a sealed file carrying sepPolicy, with a VUK slot per device.
func sepFile(t *testing.T) *File {
	t.Helper()
	f := buildFile(t)
	setPolicy(f, sepPolicy())
	slots := make([]DeviceSlot, 0, len(f.SignedPolicyProofs[0].Policy.Devices))
	for _, d := range f.SignedPolicyProofs[0].Policy.Devices {
		slots = append(slots, DeviceSlot{
			DeviceID:   d.DeviceID,
			Recipient:  d.AgeEncryptionKey,
			WrappedVUK: []byte("synthetic-age-wrapped-" + d.DeviceID),
		})
	}
	f.VUKDeviceSlots = slots
	reseal(t, f)
	return f
}

// rawAgeRecipient returns the age X25519 recipient whose payload is exactly
// the 32 raw bytes k. The string is built with this package's test-only
// Bech32 encoder (age's internal one is not importable), must be accepted by
// age.ParseX25519Recipient, and must decode back through this package's
// extractor to exactly k. That equality is the premise of the collision
// tests: the fixture bytes are the bytes purpose separation compares.
func rawAgeRecipient(t *testing.T, k []byte) string {
	t.Helper()
	if len(k) != 32 {
		t.Fatalf("raw key length %d, want 32", len(k))
	}
	r, err := bech32Encode("age", k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.ParseX25519Recipient(r); err != nil {
		t.Fatalf("age.ParseX25519Recipient(%q) = %v, want nil", r, err)
	}
	got, err := ageX25519RecipientBytes(r)
	if err != nil {
		t.Fatalf("ageX25519RecipientBytes(%q) = %v, want nil", r, err)
	}
	if !bytes.Equal(got[:], k) {
		t.Fatalf("ageX25519RecipientBytes(%q) = %x, want %x", r, got, k)
	}
	return r
}

// wantPurposeRejected asserts that p is rejected by ValidatePolicy as an
// invalid value and that f, carrying p, is rejected identically by the file
// encoder. Purpose separation is a policy rule, so every embedding site
// inherits it.
func wantPurposeRejected(t *testing.T, f *File, p *Policy, what string) {
	t.Helper()
	if err := ValidatePolicy(p); err == nil {
		t.Fatalf("%s: ValidatePolicy accepted reused key material", what)
	} else {
		wantCode(t, err, CodeInvalidValue)
	}
	setPolicy(f, p)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
}

func TestPurposeSeparationRootMatchesDevice(t *testing.T) {
	rootKey := func(p *Policy) []byte { return p.OwnerRoot.PublicKey }

	// 1. The owner-root key may not be a device content signing key.
	f := sepFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[1].ContentSigningKey.PublicKey = append([]byte(nil), rootKey(&p)...)
	wantPurposeRejected(t, f, &p, "root equals device content key")

	// 2. The owner-root key may not be a device policy signing key.
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	ps := *p.Devices[1].PolicySigningKey
	ps.PublicKey = append([]byte(nil), rootKey(&p)...)
	p.Devices[1].PolicySigningKey = &ps
	wantPurposeRejected(t, f, &p, "root equals device policy key")

	// The root may not be an age X25519 recipient either: the same 32 raw
	// bytes behind the age encoding are one key.
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[1].AgeEncryptionKey = rawAgeRecipient(t, rootKey(&p))
	wantPurposeRejected(t, f, &p, "root equals age recipient bytes")
}

func TestPurposeSeparationDeviceKeysAgainstAge(t *testing.T) {
	// 3. A device content signing key and a device policy signing key may not
	// equal the decoded age X25519 recipient bytes, on the same device or on
	// another one.
	f := sepFile(t)
	p := f.SignedPolicyProofs[0].Policy
	raw, err := ageX25519RecipientBytes(p.Devices[0].AgeEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	p.Devices[0].ContentSigningKey.PublicKey = raw[:]
	wantPurposeRejected(t, f, &p, "device content key equals own age bytes")

	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[2].ContentSigningKey.PublicKey = raw[:]
	wantPurposeRejected(t, f, &p, "device content key equals another device's age bytes")

	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	ps := *p.Devices[0].PolicySigningKey
	ps.PublicKey = raw[:]
	p.Devices[0].PolicySigningKey = &ps
	wantPurposeRejected(t, f, &p, "device policy key equals own age bytes")

	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	ps = *p.Devices[3].PolicySigningKey
	ps.PublicKey = raw[:]
	p.Devices[3].PolicySigningKey = &ps
	wantPurposeRejected(t, f, &p, "device policy key equals another device's age bytes")

	// The raw fixture is also valid Ed25519-shaped key material: age's parser
	// accepts any 32-byte payload without a curve check, so only the
	// cross-role comparison catches this reuse.
	if !validEd25519Key(raw[:]) {
		t.Fatal("age payload is not shaped as an Ed25519 public key")
	}
}

func TestPurposeSeparationAcrossDevices(t *testing.T) {
	f := sepFile(t)
	p := f.SignedPolicyProofs[0].Policy

	// Age recipient bytes reused on another device (age to age).
	raw, err := ageX25519RecipientBytes(p.Devices[3].AgeEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	p.Devices[0].AgeEncryptionKey = rawAgeRecipient(t, raw[:])
	wantPurposeRejected(t, f, &p, "age recipient reused across devices")

	// Age recipient bytes reused as another device's content signing key
	// (age to signing) as the raw extracted bytes. The string forms of the two
	// roles differ, so a display string comparison would let this through.
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[2].ContentSigningKey.PublicKey = raw[:]
	wantPurposeRejected(t, f, &p, "age bytes reused as another device's content key")

	// Content signing key reused on another device (signing to signing).
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[3].ContentSigningKey.PublicKey = append([]byte(nil), p.Devices[0].ContentSigningKey.PublicKey...)
	wantPurposeRejected(t, f, &p, "content key reused across devices")

	// Policy signing key reused on another device (signing to signing).
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	ps := *p.Devices[3].PolicySigningKey
	ps.PublicKey = append([]byte(nil), p.Devices[0].PolicySigningKey.PublicKey...)
	p.Devices[3].PolicySigningKey = &ps
	wantPurposeRejected(t, f, &p, "policy key reused across devices")

	// Content signing key reused as a policy signing key on another device.
	f = sepFile(t)
	p = f.SignedPolicyProofs[0].Policy
	ps = *p.Devices[3].PolicySigningKey
	ps.PublicKey = append([]byte(nil), p.Devices[0].ContentSigningKey.PublicKey...)
	p.Devices[3].PolicySigningKey = &ps
	wantPurposeRejected(t, f, &p, "content key reused as policy key")
}

func TestPurposeSeparationDistinctKeysAccepted(t *testing.T) {
	f := sepFile(t)
	p := f.SignedPolicyProofs[0].Policy
	// Every device has both signing keys and an age key; devices are
	// alice, bob, alice, carol.
	if len(p.Devices) != 4 || p.Devices[1].PolicySigningKey == nil || p.Devices[3].PolicySigningKey == nil {
		t.Fatalf("unexpected fixture shape: %d devices", len(p.Devices))
	}
	if err := ValidatePolicy(&p); err != nil {
		t.Fatalf("distinct keys rejected: %v", err)
	}
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("file with distinct keys rejected: %v", err)
	}

	// A device without a policy signing key is accepted too: the optional
	// role simply claims no key.
	p.Devices[0].PolicySigningKey = nil
	if err := ValidatePolicy(&p); err != nil {
		t.Fatalf("device without policy key rejected: %v", err)
	}
}

func TestPurposePrivateKeyRejected(t *testing.T) {
	// A private key is never valid in a public-key member, whatever its
	// position in the policy.
	f := sepFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[0].ContentSigningKey.PublicKey = make([]byte, ed25519.PrivateKeySize)
	wantPurposeRejected(t, f, &p, "private key in content member")
}

func TestAgeRecipientBytesExtract(t *testing.T) {
	// Fixed real age recipients, generated by age and pinned here: the
	// extractor must recover exactly these raw bytes.
	const (
		dev1 = "age1uv0c0kv2p69wyr5cq55lhze0q0kv9nc4z0408uuzpsxsc8jaav3qwrwm3g"
		dev2 = "age1zzj02uwye37dq6reqwdf4mxvq6yuwvel03u8uz4sc06z2rhzpdvs8lv05a"
	)
	id1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	generated := id1.Recipient().String()
	for _, s := range []string{dev1, dev2, generated} {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			t.Fatalf("fixture %q rejected by age: %v", s, err)
		}
		if r.String() != s {
			t.Fatalf("fixture %q is not age's canonical output %q", s, r.String())
		}
		k, err := ageX25519RecipientBytes(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := canonicalAgeRecipient(&k); got != s {
			t.Fatalf("%q decoded and re-encoded to %q", s, got)
		}
	}
	// The pinned payload of dev1 is the X25519 public key of the vector
	// fixture's own scalar, which age derives by clamping.
	pub, err := curve25519.X25519(clientKey("device-1"), curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ageX25519RecipientBytes(dev1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k[:], pub) {
		t.Fatalf("dev1 payload does not match its pinned X25519 scalar")
	}
	k2, err := ageX25519RecipientBytes(dev2)
	if err != nil {
		t.Fatal(err)
	}
	if k == k2 {
		t.Fatal("distinct recipients decoded to the same bytes")
	}
	if _, err := ageX25519RecipientBytes(generated); err != nil {
		t.Fatalf("generated recipient: %v", err)
	}
}

func TestAgeRecipientBytesInvalidChecksumGate(t *testing.T) {
	const dev1 = "age1uv0c0kv2p69wyr5cq55lhze0q0kv9nc4z0408uuzpsxsc8jaav3qwrwm3g"
	bad := ageRecipientCorruptChecksum(dev1)
	if bad == dev1 {
		t.Fatal("checksum mutation left the recipient unchanged")
	}
	// The age parser itself must reject it: the extractor never runs on a
	// string that did not pass age's validation.
	if _, err := age.ParseX25519Recipient(bad); err == nil {
		t.Fatalf("age accepted %q, the test premise is wrong", bad)
	}
	if _, err := ageX25519RecipientBytes(bad); err == nil {
		t.Fatalf("extractor accepted %q", bad)
	}
	if validAgeX25519Recipient(bad) {
		t.Fatalf("validAgeX25519Recipient accepted %q", bad)
	}
	// The payload extractor checks shape only: if it were reached with the
	// same data part (checksum last character is outside it), it returns the
	// bytes. That is exactly why the age gate is required first.
	var k [32]byte
	if err := decodeAgeRecipientPayload(dev1, &k); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	short := dev1[:len(dev1)-1]
	if err := decodeAgeRecipientPayload(short, &k); err == nil {
		t.Fatal("payload extractor accepted a truncated recipient")
	}
	if strings.HasPrefix(short, AgeX25519RecipientPrefix) == false {
		t.Fatal("test premise: truncated fixture lost the age prefix")
	}
}
