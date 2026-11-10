package vaultfile

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func TestAgeRecipientRealIdentityAccepted(t *testing.T) {
	// A real X25519 identity's public recipient is 62 characters with a
	// genuine bech32 checksum.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient().String()
	if len(r) != len(AgeX25519RecipientPrefix)+58 {
		t.Fatalf("unexpected recipient length %d for %q", len(r), r)
	}
	if !validAgeX25519Recipient(r) {
		t.Fatalf("real age recipient %q rejected", r)
	}

	// The same recipient must pass through a whole policy and file.
	f := buildFile()
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[0].AgeEncryptionKey = r
	f.SignedPolicyProofs[0].Document = docFor(&p)
	f.SignedPolicyProofs[0].Policy = p
	f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[0])
	f.VUKDeviceSlots[0].Recipient = r
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("file with real recipient rejected: %v", err)
	}
}

func TestAgeRecipientNegative(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient().String()

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"checksum flipped", ageRecipientCorruptChecksum(r)},
		{"synthetic 4-char checksum", "age1" + r[4:len(r)-2] + "qq"},
		{"truncated", r[:len(r)-1]},
		{"extended", r + "q"},
		{"uppercased", strings.ToUpper(r)},
		{"wrong hrp", "agx" + r[3:]},
		{"identity", id.String()},
		{"identity lowercased", strings.ToLower(id.String())},
		{"private key as X25519 text", "AGE-SECRET-KEY-1" + r[4:]},
		{"not bech32", "age1notavalidrecipient"},
		{"all zero point", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpnqs"},
	} {
		if tc.in == r {
			t.Fatalf("%s: test input equals the valid recipient", tc.name)
		}
		if validAgeX25519Recipient(tc.in) {
			t.Errorf("%s: %q accepted", tc.name, tc.in)
		}
	}

	// Negative inputs must also be rejected at every embedding site.
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"checksum", ageRecipientCorruptChecksum(r)},
		{"identity", id.String()},
	} {
		f := buildFile()
		p := f.SignedPolicyProofs[0].Policy
		p.Devices[0].AgeEncryptionKey = tc.in
		setPolicy(f, &p)
		_, err := EncodeFile(f)
		wantCode(t, err, CodeInvalidValue)

		// Same bad text in both the policy and the slot must not slip past
		// the equality binding either.
		f = buildFile()
		p = f.SignedPolicyProofs[0].Policy
		p.Devices[0].AgeEncryptionKey = tc.in
		setPolicy(f, &p)
		f.VUKDeviceSlots[0].Recipient = tc.in
		_, err = EncodeFile(f)
		wantCode(t, err, CodeInvalidValue)
	}
}
