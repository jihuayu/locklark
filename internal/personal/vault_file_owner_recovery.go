package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"filippo.io/age"
)

// VaultFileOwnershipPublic is unpublished, local recovery material's public
// enrollment projection. It is neither a signed policy nor remote authority.
type VaultFileOwnershipPublic struct {
	VaultID                         string `json:"vault_id"`
	OwnerRootKeyID                  string `json:"owner_root_key_id"`
	OwnerRootPublicKey              string `json:"owner_root_public_key"`
	RecoveryDeviceID                string `json:"recovery_device_id"`
	RecoveryAgeRecipient            string `json:"recovery_age_recipient"`
	RecoveryContentSigningPublicKey string `json:"recovery_content_signing_public_key"`
}

const (
	maxVaultFileOwnerRecords   = 64
	maxVaultFileOwnerBytes     = 64 << 10
	maxVaultFileOwnerAgeBytes  = 128
	vaultFileOwnerDigestDomain = "locklark/personal/vault-file-owner-digest/v1\x00"
)

// The seeds and age identity belong only to the authenticated personal store
// and its encrypted, signed backup payload. No exported API returns them.
type vaultFileOwnerRecord struct {
	VaultID             string
	OwnerRootKeyID      string
	OwnerRootSeed       []byte
	RecoveryDeviceID    string
	RecoverySigningSeed []byte
	RecoveryAgeIdentity []byte
}

func clearVaultFileOwners(records []vaultFileOwnerRecord) {
	for i := range records {
		clear(records[i].OwnerRootSeed)
		clear(records[i].RecoverySigningSeed)
		clear(records[i].RecoveryAgeIdentity)
	}
}

func cloneVaultFileOwners(records []vaultFileOwnerRecord) []vaultFileOwnerRecord {
	out := make([]vaultFileOwnerRecord, len(records))
	for i, record := range records {
		out[i] = record
		out[i].OwnerRootSeed = bytes.Clone(record.OwnerRootSeed)
		out[i].RecoverySigningSeed = bytes.Clone(record.RecoverySigningSeed)
		out[i].RecoveryAgeIdentity = bytes.Clone(record.RecoveryAgeIdentity)
	}
	return out
}

func validVaultFileOwners(records []vaultFileOwnerRecord) bool {
	if len(records) > maxVaultFileOwnerRecords {
		return false
	}
	previous := ""
	for _, record := range records {
		if !idOK(record.VaultID) || record.VaultID <= previous ||
			!idOK(record.OwnerRootKeyID) || !idOK(record.RecoveryDeviceID) ||
			len(record.OwnerRootSeed) != ed25519.SeedSize || len(record.RecoverySigningSeed) != ed25519.SeedSize ||
			len(record.RecoveryAgeIdentity) == 0 || len(record.RecoveryAgeIdentity) > maxVaultFileOwnerAgeBytes {
			return false
		}
		previous = record.VaultID
		device, err := age.ParseX25519Identity(string(record.RecoveryAgeIdentity))
		if err != nil || device.Recipient() == nil {
			return false
		}
		root := ed25519.NewKeyFromSeed(record.OwnerRootSeed)
		signer := ed25519.NewKeyFromSeed(record.RecoverySigningSeed)
		separate := !bytes.Equal(root.Public().(ed25519.PublicKey), signer.Public().(ed25519.PublicKey))
		clear(root)
		clear(signer)
		if !separate {
			return false
		}
	}
	return true
}

func vaultFileOwnersDigest(records []vaultFileOwnerRecord) (string, error) {
	if len(records) == 0 || !validVaultFileOwners(records) {
		return "", invalid
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	if len(raw) > maxVaultFileOwnerBytes {
		return "", ErrArchiveLimit
	}
	h := sha256.New()
	_, _ = h.Write([]byte(vaultFileOwnerDigestDomain))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func vaultFileOwnerPublic(record vaultFileOwnerRecord) (VaultFileOwnershipPublic, error) {
	if !validVaultFileOwners([]vaultFileOwnerRecord{record}) {
		return VaultFileOwnershipPublic{}, invalid
	}
	device, err := age.ParseX25519Identity(string(record.RecoveryAgeIdentity))
	if err != nil {
		return VaultFileOwnershipPublic{}, invalid
	}
	root := ed25519.NewKeyFromSeed(record.OwnerRootSeed)
	signer := ed25519.NewKeyFromSeed(record.RecoverySigningSeed)
	defer clear(root)
	defer clear(signer)
	return VaultFileOwnershipPublic{VaultID: record.VaultID, OwnerRootKeyID: record.OwnerRootKeyID,
		OwnerRootPublicKey: hex.EncodeToString(root.Public().(ed25519.PublicKey)),
		RecoveryDeviceID:   record.RecoveryDeviceID, RecoveryAgeRecipient: device.Recipient().String(),
		RecoveryContentSigningPublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey))}, nil
}

func newVaultFileOwnerRecord() (vaultFileOwnerRecord, error) {
	var record vaultFileOwnerRecord
	var err error
	if record.VaultID, err = randomID(); err != nil {
		return record, err
	}
	if record.OwnerRootKeyID, err = randomID(); err != nil {
		return record, err
	}
	if record.RecoveryDeviceID, err = randomID(); err != nil {
		return record, err
	}
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return record, err
	}
	defer clear(root)
	record.OwnerRootSeed = bytes.Clone(root.Seed())
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		clearVaultFileOwners([]vaultFileOwnerRecord{record})
		return vaultFileOwnerRecord{}, err
	}
	defer clear(signer)
	record.RecoverySigningSeed = bytes.Clone(signer.Seed())
	device, err := age.GenerateX25519Identity()
	if err != nil {
		clearVaultFileOwners([]vaultFileOwnerRecord{record})
		return vaultFileOwnerRecord{}, err
	}
	record.RecoveryAgeIdentity = []byte(device.String())
	return record, nil
}
