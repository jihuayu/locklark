package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"filippo.io/age"
)

func TestVaultFileOwnerCapsulePublicAndDigest(t *testing.T) {
	first, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("OWNER_CAPSULE_GENERATE_FAILED")
	}
	second, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("OWNER_CAPSULE_GENERATE_FAILED")
	}
	records := []vaultFileOwnerRecord{first, second}
	defer clearVaultFileOwners(records)
	sort.Slice(records, func(i, j int) bool { return records[i].VaultID < records[j].VaultID })
	digest, err := vaultFileOwnersDigest(records)
	if err != nil || !validVaultFileOwners(records) || !digestOK(digest) {
		t.Fatal("OWNER_CAPSULE_DIGEST_INVALID")
	}
	cloned := cloneVaultFileOwners(records)
	defer clearVaultFileOwners(cloned)
	cloneDigest, err := vaultFileOwnersDigest(cloned)
	if err != nil || cloneDigest != digest || &cloned[0].OwnerRootSeed[0] == &records[0].OwnerRootSeed[0] {
		t.Fatal("OWNER_CAPSULE_CLONE_NOT_INDEPENDENT")
	}
	projection, err := vaultFileOwnerPublic(records[0])
	if err != nil || projection.VaultID != records[0].VaultID || projection.OwnerRootKeyID != records[0].OwnerRootKeyID ||
		projection.RecoveryDeviceID != records[0].RecoveryDeviceID {
		t.Fatal("OWNER_CAPSULE_PUBLIC_PROJECTION_FAILED")
	}
	rootPub, err := hex.DecodeString(projection.OwnerRootPublicKey)
	if err != nil || len(rootPub) != ed25519.PublicKeySize {
		t.Fatal("OWNER_CAPSULE_ROOT_PUBLIC_INVALID")
	}
	signPub, err := hex.DecodeString(projection.RecoveryContentSigningPublicKey)
	if err != nil || len(signPub) != ed25519.PublicKeySize || bytes.Equal(rootPub, signPub) {
		t.Fatal("OWNER_CAPSULE_SIGNING_PUBLIC_INVALID")
	}
	message := []byte("owned-capsule-public-verification")
	rootKey := ed25519.NewKeyFromSeed(records[0].OwnerRootSeed)
	signKey := ed25519.NewKeyFromSeed(records[0].RecoverySigningSeed)
	defer clear(rootKey)
	defer clear(signKey)
	if !ed25519.Verify(rootPub, message, ed25519.Sign(rootKey, message)) ||
		!ed25519.Verify(signPub, message, ed25519.Sign(signKey, message)) {
		t.Fatal("OWNER_CAPSULE_PUBLIC_KEY_MISMATCH")
	}
	device, err := age.ParseX25519Identity(string(records[0].RecoveryAgeIdentity))
	if err != nil || device.Recipient().String() != projection.RecoveryAgeRecipient {
		t.Fatal("OWNER_CAPSULE_RECIPIENT_MISMATCH")
	}
	raw, err := json.Marshal(projection)
	if err != nil || bytes.Contains(raw, records[0].OwnerRootSeed) ||
		bytes.Contains(raw, records[0].RecoverySigningSeed) ||
		bytes.Contains(raw, records[0].RecoveryAgeIdentity) {
		t.Fatal("OWNER_CAPSULE_PUBLIC_LEAK")
	}
	cloned[0].OwnerRootSeed[0] ^= 1
	changed, err := vaultFileOwnersDigest(cloned)
	if err != nil || changed == digest {
		t.Fatal("OWNER_CAPSULE_DIGEST_DID_NOT_BIND_SEED")
	}
}

func TestVaultFileOwnerCapsuleRejectsMalformedCollection(t *testing.T) {
	record, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("OWNER_CAPSULE_GENERATE_FAILED")
	}
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	if _, err := vaultFileOwnersDigest(nil); err == nil {
		t.Fatal("OWNER_CAPSULE_EMPTY_DIGEST_ACCEPTED")
	}
	duplicate := cloneVaultFileOwners([]vaultFileOwnerRecord{record, record})
	defer clearVaultFileOwners(duplicate)
	if validVaultFileOwners(duplicate) {
		t.Fatal("OWNER_CAPSULE_DUPLICATE_ACCEPTED")
	}
	invalid := cloneVaultFileOwners([]vaultFileOwnerRecord{record})
	defer clearVaultFileOwners(invalid)
	invalid[0].RecoveryAgeIdentity[0] ^= 1
	if validVaultFileOwners(invalid) {
		t.Fatal("OWNER_CAPSULE_BAD_AGE_ACCEPTED")
	}
	invalid[0].RecoveryAgeIdentity = bytes.Clone(record.RecoveryAgeIdentity)
	invalid[0].RecoverySigningSeed = bytes.Clone(record.OwnerRootSeed)
	if validVaultFileOwners(invalid) {
		t.Fatal("OWNER_CAPSULE_KEY_REUSE_ACCEPTED")
	}
	tooMany := make([]vaultFileOwnerRecord, maxVaultFileOwnerRecords+1)
	if validVaultFileOwners(tooMany) {
		t.Fatal("OWNER_CAPSULE_COUNT_LIMIT_ACCEPTED")
	}
}
