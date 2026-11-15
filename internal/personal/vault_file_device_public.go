package personal

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
)

// VaultFileDevicePublic contains only the existing local device's public
// enrollment values. It is not a vault-file grant or a policy checkpoint.
type VaultFileDevicePublic struct {
	AgeRecipient            string `json:"age_recipient"`
	ContentSigningPublicKey string `json:"content_signing_public_key"`
}

var ErrVaultFileFullFactorRequired = errors.New("fresh full-factor unlock required for vault-file device enrollment")

// VaultFileDevicePublic authenticates the same active personal Session that
// owns the local identity. It never returns an age identity or signing seed.
func (s *Session) VaultFileDevicePublic() (VaultFileDevicePublic, error) {
	var out VaultFileDevicePublic
	if s == nil {
		return out, ErrSessionLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return out, err
	}
	var candidate *auditCache
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, "vault-file.device-public", s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		device, err := age.ParseX25519Identity(auth.identity.Device)
		if err != nil {
			return invalid
		}
		signer := ed25519.NewKeyFromSeed(auth.identity.Signing)
		defer clear(signer)
		out = VaultFileDevicePublic{
			AgeRecipient:            device.Recipient().String(),
			ContentSigningPublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		}
		candidate = auth.nextCache
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return VaultFileDevicePublic{}, err
	}
	if closeErr != nil {
		return VaultFileDevicePublic{}, ErrCommandClose
	}
	if err := s.active(false); err != nil {
		return VaultFileDevicePublic{}, err
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileDevicePublic{}, ErrVaultFileFullFactorRequired
	}
	s.setAuditCache(candidate)
	return out, nil
}
