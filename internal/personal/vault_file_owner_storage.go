package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"io"
	"math"
)

var ErrVaultFileOwnership = errors.New("vault-file ownership custody unavailable")

const (
	vaultFileOwnerPrepareAction = "vault-file.owner.prepare"
	vaultFileOwnerRestoreAction = "vault-file.owner.restore"
	vaultFileOwnerListAction    = "vault-file.owner.list"
)

var vaultFileOwnerKey = []byte("vault-file-owners/v1")
var vaultFileOwnerLabel = []byte("locklark/personal/vault-file-owners/v1\x00")

func latestVaultFileOwnerDigest(rows []Event) string {
	latest := ""
	for _, event := range rows {
		if event.Action == vaultFileOwnerPrepareAction || event.Action == vaultFileOwnerRestoreAction {
			latest = event.Link
		}
	}
	return latest
}

// The last signed chain is the live personal device's history. Older chains
// are anchored by vault.restore, but their old custody ciphertext is not a
// record in the newly restored device's database.
func validateBackupVaultFileOwners(p *payload) error {
	if p == nil || len(p.Chains) == 0 {
		return invalid
	}
	expected := latestVaultFileOwnerDigest(p.Chains[len(p.Chains)-1].Events)
	if expected == "" && len(p.VaultFileOwners) == 0 {
		return nil
	}
	if expected == "" || len(p.VaultFileOwners) == 0 {
		return invalid
	}
	actual, err := vaultFileOwnersDigest(p.VaultFileOwners)
	if err != nil || actual != expected {
		return invalid
	}
	return nil
}

func loadVaultFileOwners(b *bolt.Bucket, i identity, rows []Event) ([]vaultFileOwnerRecord, error) {
	expected := latestVaultFileOwnerDigest(rows)
	raw := b.Get(vaultFileOwnerKey)
	if expected == "" && raw == nil {
		return nil, nil // pre-feature personal vault
	}
	if expected == "" || raw == nil || len(raw) > maxVaultFileOwnerBytes+64 {
		return nil, invalid
	}
	a, err := auditCipher(i)
	if err != nil {
		return nil, invalid
	}
	plain, err := a.Open(nil, nil, raw, vaultFileOwnerLabel)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	if len(plain) > maxVaultFileOwnerBytes {
		return nil, invalid
	}
	var records []vaultFileOwnerRecord
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&records) != nil || decoder.Decode(new(any)) != io.EOF || len(records) == 0 {
		clearVaultFileOwners(records)
		return nil, invalid
	}
	canonical, err := json.Marshal(records)
	if err != nil || !bytes.Equal(canonical, plain) {
		clear(canonical)
		clearVaultFileOwners(records)
		return nil, invalid
	}
	clear(canonical)
	actual, err := vaultFileOwnersDigest(records)
	if err != nil || actual != expected {
		clearVaultFileOwners(records)
		return nil, invalid
	}
	return records, nil
}

func saveVaultFileOwners(b *bolt.Bucket, i identity, records []vaultFileOwnerRecord) error {
	if _, err := vaultFileOwnersDigest(records); err != nil {
		return err
	}
	a, err := auditCipher(i)
	if err != nil {
		return invalid
	}
	sealed, err := sealedJSON(a, vaultFileOwnerLabel, records)
	if err != nil || len(sealed) > maxVaultFileOwnerBytes+64 {
		return invalid
	}
	return b.Put(vaultFileOwnerKey, sealed)
}

// PrepareVaultFileOwnership creates only unpublished owner and recovery-device
// custody for a caller-persisted local vault ID. An exact retry authenticates
// the same records and returns the same public projection without generating
// another key or changing the snapshot. The ID is a selector, not authority.
func (s *Session) PrepareVaultFileOwnership(vaultID string) (VaultFileOwnershipPublic, error) {
	if s == nil {
		return VaultFileOwnershipPublic{}, ErrSessionLocked
	}
	if !idOK(vaultID) {
		return VaultFileOwnershipPublic{}, ErrVaultFileOwnership
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileOwnershipPublic{}, ErrVaultFileFullFactorRequired
	}
	var projection VaultFileOwnershipPublic
	mutated := false
	db, err := existing(s.path)
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerPrepareAction, s, true)
		if err != nil {
			return err
		}
		defer auth.clear()
		if s.active(false) != nil || s.requireFreshFullFactor() != nil {
			return ErrSessionLocked
		}
		b := tx.Bucket(bucket)
		records, err := loadVaultFileOwners(b, auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer func() { clearVaultFileOwners(records) }()
		index := 0
		for index < len(records) && records[index].VaultID < vaultID {
			index++
		}
		if index < len(records) && records[index].VaultID == vaultID {
			projection, err = vaultFileOwnerPublic(records[index])
			return err
		}
		if len(records) >= maxVaultFileOwnerRecords {
			return ErrArchiveLimit
		}
		record, err := newVaultFileOwnerRecord()
		if err != nil {
			return ErrVaultFileOwnership
		}
		defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
		record.VaultID = vaultID
		projection, err = vaultFileOwnerPublic(record)
		if err != nil {
			return ErrVaultFileOwnership
		}
		records = append(records, vaultFileOwnerRecord{})
		copy(records[index+1:], records[index:])
		records[index] = record
		if err := saveVaultFileOwners(b, auth.identity, records); err != nil {
			return err
		}
		digest, err := vaultFileOwnersDigest(records)
		if err != nil {
			return err
		}
		if auth.snapshot.Epoch == math.MaxUint64 {
			return ErrVaultFileOwnership
		}
		snapshot, err := seal(b, auth.identity, auth.snapshot.Epoch+1, auth.items)
		if err != nil {
			return err
		}
		_, err = appendLinked(b, auth.identity, auth.tip, snapshot, vaultFileOwnerPrepareAction, "", "succeeded", "", digest)
		if err != nil {
			return err
		}
		if s.active(false) != nil {
			return ErrSessionLocked
		}
		if s.requireFreshFullFactor() != nil {
			return ErrVaultFileFullFactorRequired
		}
		mutated = true
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if closeErr != nil {
		return VaultFileOwnershipPublic{}, ErrCommandClose
	}
	if s.active(false) != nil {
		return VaultFileOwnershipPublic{}, ErrSessionLocked
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileOwnershipPublic{}, ErrVaultFileFullFactorRequired
	}
	if mutated {
		s.clearAuditCache()
	}
	return projection, nil
}

// VaultFileOwnerships reads only public projections of unpublished custody
// records after full-factor authentication. It never returns a private key.
func (s *Session) VaultFileOwnerships() ([]VaultFileOwnershipPublic, error) {
	if s == nil {
		return nil, ErrSessionLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return nil, err
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	var projections []VaultFileOwnershipPublic
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer clearVaultFileOwners(records)
		for _, record := range records {
			projection, err := vaultFileOwnerPublic(record)
			if err != nil {
				return err
			}
			projections = append(projections, projection)
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, ErrCommandClose
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	return projections, nil
}
