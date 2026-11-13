package vaultfile

import (
	"bytes"
	"testing"
)

// TestClonePolicySnapshotIsIndependent clones a fully populated policy and
// then mutates every mutable reference reachable from the copy, proving that
// the source policy is unchanged. The want snapshot is taken before any
// mutation of the copy so the test never reads the source through the copy.
func TestClonePolicySnapshotIsIndependent(t *testing.T) {
	src := buildPolicy()
	// A second device without a policy signing key keeps the nil pointer case.
	src.Devices = append(src.Devices, Device{
		DeviceID:          "device-3",
		PrincipalID:       "carol",
		Label:             "Carol tablet",
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x41, 32)},
		AgeEncryptionKey:  ageRecipient(clientKey("device-3")),
	})
	doc, err := EncodePolicyDocument(src)
	if err != nil {
		t.Fatal(err)
	}
	want := clonePolicy(src)

	c := clonePolicySnapshot(src)
	if c == nil || c == src {
		t.Fatal("clone is nil or the source pointer")
	}
	// The untouched clone must match the source in every field, including
	// the nil-ness of every slice, byte slice and optional key pointer.
	if !equalPolicySnapshot(c, src) {
		t.Fatal("untouched clone differs from the source")
	}
	if !equalPolicySnapshot(src, want) {
		t.Fatal("cloning changed the source")
	}
	if c.Devices[0].PolicySigningKey == src.Devices[0].PolicySigningKey {
		t.Fatal("clone shares key pointers with the source")
	}

	// Byte slices.
	c.PrevPolicyDigest[0] ^= 0xff
	c.OwnerRoot.PublicKey[0] ^= 0xff
	c.Devices[0].ContentSigningKey.PublicKey[0] ^= 0xff
	c.Devices[0].PolicySigningKey.PublicKey[0] ^= 0xff
	c.Devices[0].PolicySigningKey.Alg = "mutated"
	c.Devices[1].PolicySigningKey = nil
	c.Devices[2].PolicySigningKey = &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x99, 32)}

	// Value structs and slice elements.
	c.OwnerRoot.Owners[0].Label = "mutated"
	c.OwnerRoot.Owners[0].PrincipalID = "mutated"
	c.Readers[0].Label = "mutated"
	c.Writers[0].PrincipalID = "mutated"
	c.Admins[0].Label = "mutated"
	c.Owners[0].PrincipalID = "mutated"
	c.AdminDelegations[0].Scope.InviteReaders = false
	c.AdminDelegations[0].DelegationID = "mutated"
	c.AdminDelegations[0].ExpiresPolicySeq = 99
	c.Devices[0].DeviceID = "mutated"
	c.Devices[0].AgeEncryptionKey = "mutated"
	c.Devices[0].ContentSigningKey.Alg = "mutated"

	// Reslicing, appending and reordering the copy must not reach the source.
	c.Readers[0] = Member{PrincipalID: "mutated"}
	c.Readers = append(c.Readers, Member{PrincipalID: "extra"})
	c.Writers = c.Writers[:0]
	c.AdminDelegations = nil
	c.OwnerRoot.Owners = append(c.OwnerRoot.Owners, Principal{PrincipalID: "extra"})
	c.Devices = c.Devices[:0]

	if !equalPolicySnapshot(src, want) {
		t.Fatal("source policy changed through the clone")
	}
	srcDoc, err := EncodePolicyDocument(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srcDoc, doc) {
		t.Fatal("source policy document changed through the clone")
	}
	if c == src || len(src.Readers) != 1 || src.Readers[0].PrincipalID != "carol" ||
		len(src.Devices) != 3 || src.Devices[0].PolicySigningKey.Alg != PolicySigAlgEd25519 ||
		src.Devices[2].PolicySigningKey != nil {
		t.Fatal("source policy fields changed through the clone")
	}
}

// TestClonePolicySnapshotNil covers the nil source.
func TestClonePolicySnapshotNil(t *testing.T) {
	if got := clonePolicySnapshot(nil); got != nil {
		t.Fatalf("clonePolicySnapshot(nil) = %v, want nil", got)
	}
}

// TestClonePolicySnapshotPreservesNil reports that nil and non-nil empty
// slices keep their nil-ness across the clone.
func TestClonePolicySnapshotPreservesNil(t *testing.T) {
	c := clonePolicySnapshot(&Policy{Readers: []Member{}})
	if c == nil {
		t.Fatal("clone is nil")
	}
	if c.PrevPolicyDigest != nil || c.Writers != nil || c.Admins != nil ||
		c.Owners != nil || c.AdminDelegations != nil || c.Devices != nil ||
		c.OwnerRoot.PublicKey != nil || c.OwnerRoot.Owners != nil {
		t.Fatal("nil slices or bytes became non-nil")
	}
	if c.Readers == nil || len(c.Readers) != 0 {
		t.Fatal("non-nil empty slice did not stay non-nil empty")
	}
}

// equalPolicySnapshot reports whether a and b are identical in every field,
// including the nil-ness of every slice, byte slice and optional key pointer.
func equalPolicySnapshot(a, b *Policy) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Format != b.Format || a.Version != b.Version ||
		a.VaultID != b.VaultID || a.PolicySeq != b.PolicySeq {
		return false
	}
	if !equalBytes(a.PrevPolicyDigest, b.PrevPolicyDigest) ||
		!equalBytes(a.OwnerRoot.PublicKey, b.OwnerRoot.PublicKey) {
		return false
	}
	if a.OwnerRoot.KeyID != b.OwnerRoot.KeyID || a.OwnerRoot.Alg != b.OwnerRoot.Alg {
		return false
	}
	if !equalSlices(a.OwnerRoot.Owners, b.OwnerRoot.Owners) ||
		!equalSlices(a.Readers, b.Readers) || !equalSlices(a.Writers, b.Writers) ||
		!equalSlices(a.Admins, b.Admins) || !equalSlices(a.Owners, b.Owners) ||
		!equalSlices(a.AdminDelegations, b.AdminDelegations) {
		return false
	}
	if (a.Devices == nil) != (b.Devices == nil) || len(a.Devices) != len(b.Devices) {
		return false
	}
	for i := range a.Devices {
		x, y := &a.Devices[i], &b.Devices[i]
		if x.DeviceID != y.DeviceID || x.PrincipalID != y.PrincipalID ||
			x.Label != y.Label || x.AgeEncryptionKey != y.AgeEncryptionKey {
			return false
		}
		if !equalTestPublicKey(&x.ContentSigningKey, &y.ContentSigningKey) ||
			!equalTestPublicKey(x.PolicySigningKey, y.PolicySigningKey) {
			return false
		}
	}
	return true
}

// equalTestPublicKey reports whether both keys are nil or both are non-nil
// with the same algorithm and public key bytes.
func equalTestPublicKey(a, b *PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Alg == b.Alg && equalBytes(a.PublicKey, b.PublicKey)
}

// equalBytes reports whether both are nil or both are non-nil with equal
// content.
func equalBytes(a, b []byte) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return bytes.Equal(a, b)
}

// equalSlices reports whether both slices have the same nil-ness and equal,
// order-preserving elements.
func equalSlices[T comparable](a, b []T) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
