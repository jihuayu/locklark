package personal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func ownerCustodySource(t *testing.T) (string, []byte, string, *Session, VaultFileOwnershipPublic) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.ll")
	key := bytes.Repeat([]byte{0x53}, 16)
	password := "owned-custody-factor"
	if Create(path, password, key) != nil {
		t.Fatal("OWNER_NEGATIVE_CREATE_FAILED")
	}
	session, err := UnlockSession(path, []byte(password), key, 0)
	if err != nil {
		t.Fatal("OWNER_NEGATIVE_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	selector, err := randomID()
	if err != nil {
		t.Fatal("OWNER_NEGATIVE_SELECTOR_FAILED")
	}
	public, err := session.PrepareVaultFileOwnership(selector)
	if err != nil {
		t.Fatal("OWNER_NEGATIVE_PREPARE_FAILED")
	}
	return path, key, password, session, public
}

func TestVaultFileOwnerCustodyRequiresFreshFullFactors(t *testing.T) {
	path, key, password, session, public := ownerCustodySource(t)
	if wrong, err := UnlockSession(path, []byte(password+"-wrong"), key, 0); err == nil || wrong != nil {
		t.Fatal("OWNER_FACTOR_WRONG_PASSWORD_ACCEPTED")
	}
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 0xff
	if wrong, err := UnlockSession(path, []byte(password), wrongKey, 0); err == nil || wrong != nil {
		t.Fatal("OWNER_FACTOR_WRONG_SECRET_ACCEPTED")
	}
	session.mu.Lock()
	session.fullUnlock = time.Time{}
	session.mu.Unlock()
	if _, err := session.PrepareVaultFileOwnership(public.VaultID); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("OWNER_FACTOR_QUICK_REPLAY_ACCEPTED")
	}
	if projections, err := session.VaultFileOwnerships(); !errors.Is(err, ErrVaultFileFullFactorRequired) || len(projections) != 0 {
		t.Fatal("OWNER_FACTOR_QUICK_LIST_ACCEPTED")
	}
	session.mu.Lock()
	session.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	session.mu.Unlock()
	newSelector, err := randomID()
	if err != nil {
		t.Fatal("OWNER_FACTOR_SELECTOR_FAILED")
	}
	if _, err := session.PrepareVaultFileOwnership(newSelector); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("OWNER_FACTOR_EXPIRED_PREPARE_ACCEPTED")
	}
}

func TestVaultFileOwnerCustodyRejectsMissingAndStaleRecord(t *testing.T) {
	for _, mode := range []string{"deleted", "stale", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			path, key, password, session, _ := ownerCustodySource(t)
			var old []byte
			if mode == "stale" {
				db, err := existingWithReadOnly(path, true)
				if err != nil {
					t.Fatal("OWNER_NEGATIVE_DB_OPEN_FAILED")
				}
				if db.View(func(tx *bolt.Tx) error { old = bytes.Clone(tx.Bucket(bucket).Get(vaultFileOwnerKey)); return nil }) != nil || db.Close() != nil {
					t.Fatal("OWNER_NEGATIVE_OLD_RECORD_FAILED")
				}
				selector, err := randomID()
				if err != nil {
					t.Fatal("OWNER_NEGATIVE_SECOND_SELECTOR_FAILED")
				}
				if _, err := session.PrepareVaultFileOwnership(selector); err != nil {
					t.Fatal("OWNER_NEGATIVE_SECOND_PREPARE_FAILED")
				}
			}
			db, err := existing(path)
			if err != nil {
				t.Fatal("OWNER_NEGATIVE_DB_OPEN_FAILED")
			}
			err = db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucket)
				switch mode {
				case "deleted":
					return b.Delete(vaultFileOwnerKey)
				case "stale":
					return b.Put(vaultFileOwnerKey, old)
				default:
					return b.Put(vaultFileOwnerKey, bytes.Repeat([]byte{0x7f}, maxVaultFileOwnerBytes+65))
				}
			})
			if err != nil || db.Close() != nil {
				t.Fatal("OWNER_NEGATIVE_MUTATION_FAILED")
			}
			if _, err := session.VaultFileOwnerships(); err == nil {
				t.Fatal("OWNER_NEGATIVE_RECORD_ACCEPTED")
			}
			archive := filepath.Join(t.TempDir(), "refused.llb")
			if _, err := Backup(path, archive, password, key); err == nil {
				t.Fatal("OWNER_NEGATIVE_BACKUP_ACCEPTED")
			}
			if _, err := os.Stat(archive); !os.IsNotExist(err) {
				t.Fatal("OWNER_NEGATIVE_BACKUP_PUBLISHED")
			}
		})
	}
}

func TestVaultFileOwnerCustodyRejectsAuditTailRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.ll")
	key := bytes.Repeat([]byte{0x62}, 16)
	password := "owned-rollback-factor"
	if Create(path, password, key) != nil {
		t.Fatal("OWNER_ROLLBACK_CREATE_FAILED")
	}
	session, err := UnlockSession(path, []byte(password), key, 0)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_UNLOCK_FAILED")
	}
	defer session.Lock()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_DB_OPEN_FAILED")
	}
	var oldTip, oldSnapshot []byte
	var oldCount uint64
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, "audit.list", session, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		b := tx.Bucket(bucket)
		oldTip = bytes.Clone(b.Get(tipKey))
		oldSnapshot = bytes.Clone(b.Get(snapshotKey))
		oldCount = auth.tip.Count
		return nil
	})
	if err != nil || db.Close() != nil {
		t.Fatal("OWNER_ROLLBACK_BASE_SNAPSHOT_FAILED")
	}
	selector, err := randomID()
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_SELECTOR_FAILED")
	}
	if _, err := session.PrepareVaultFileOwnership(selector); err != nil {
		t.Fatal("OWNER_ROLLBACK_PREPARE_FAILED")
	}
	db, err = existing(path)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_DB_REOPEN_FAILED")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if bytes.Equal(b.Get(snapshotKey), oldSnapshot) {
			return errors.New("snapshot did not advance")
		}
		if err := b.Delete(vaultFileOwnerKey); err != nil {
			return err
		}
		if err := b.Bucket(eventsKey).Delete(binary.BigEndian.AppendUint64(nil, oldCount+1)); err != nil {
			return err
		}
		return b.Put(tipKey, oldTip)
	})
	if err != nil || db.Close() != nil {
		t.Fatal("OWNER_ROLLBACK_MUTATION_FAILED")
	}
	if _, err := session.VaultFileOwnerships(); err == nil {
		t.Fatal("OWNER_ROLLBACK_TAIL_ACCEPTED")
	}
	archive := filepath.Join(t.TempDir(), "refused.llb")
	if _, err := Backup(path, archive, password, key); err == nil {
		t.Fatal("OWNER_ROLLBACK_BACKUP_ACCEPTED")
	}
}

func TestVaultFileOwnerCustodyOldSixFieldArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.ll")
	archive := filepath.Join(t.TempDir(), "legacy-six.llb")
	restored := filepath.Join(t.TempDir(), "restored.ll")
	key := bytes.Repeat([]byte{0x71}, 16)
	newKey := bytes.Repeat([]byte{0x72}, 16)
	password := "owned-six-field-factor"
	if Create(path, password, key) != nil {
		t.Fatal("OWNER_SIX_CREATE_FAILED")
	}
	session, err := UnlockSession(path, []byte(password), key, 0)
	if err != nil {
		t.Fatal("OWNER_SIX_UNLOCK_FAILED")
	}
	if _, err := session.CreateVault("Owned sub vault", "", "", v2Gate(t, session)); err != nil {
		t.Fatal("OWNER_SIX_SUBVAULT_FAILED")
	}
	session.Lock()
	kit, err := Backup(path, archive, password, key)
	if err != nil {
		t.Fatal("OWNER_SIX_BACKUP_FAILED")
	}
	// Independently spell the six-member pre-custody body schema, including a
	// populated Vaults member. The actual archive is signed and encrypted.
	type sixFieldPayload struct {
		Generation  string
		Epoch       uint64
		Items       []vault.Item
		Chains      []Chain
		Vaults      []vault.VaultMeta  `json:",omitempty"`
		Attachments []backupAttachment `json:",omitempty"`
	}
	p, err := decodeArchive(archive, password, key, kit)
	if err != nil || len(p.Vaults) == 0 || len(p.VaultFileOwners) != 0 {
		t.Fatal("OWNER_SIX_DECODE_FAILED")
	}
	oldJSON, err := json.Marshal(sixFieldPayload{p.Generation, p.Epoch, p.Items, p.Chains, p.Vaults, p.Attachments})
	if err != nil {
		t.Fatal("OWNER_SIX_OLD_SCHEMA_FAILED")
	}
	currentJSON, err := json.Marshal(p)
	if err != nil || !bytes.Equal(oldJSON, currentJSON) {
		t.Fatal("OWNER_SIX_CANONICAL_CHANGED")
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal("OWNER_SIX_ARCHIVE_READ_FAILED")
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		t.Fatal("OWNER_SIX_ENVELOPE_FAILED")
	}
	share, err := account.Unwrap(password, key, env.Share)
	if err != nil {
		t.Fatal("OWNER_SIX_SHARE_FAILED")
	}
	defer clear(share)
	a, err := aeadBackup(share, kit, env.Generation)
	if err != nil {
		t.Fatal("OWNER_SIX_AEAD_FAILED")
	}
	plain, err := a.Open(nil, nil, env.Data, []byte(backupDomain+"/"+env.Generation))
	if err != nil {
		t.Fatal("OWNER_SIX_DECRYPT_FAILED")
	}
	defer clear(plain)
	var signed struct{ Body json.RawMessage }
	if json.Unmarshal(plain, &signed) != nil || !bytes.Equal(signed.Body, oldJSON) {
		t.Fatal("OWNER_SIX_SIGNED_BODY_CHANGED")
	}
	if Restore(archive, restored, password, key, kit, newKey) != nil {
		t.Fatal("OWNER_SIX_RESTORE_FAILED")
	}
	newSession, err := UnlockSession(restored, []byte(password), newKey, 0)
	if err != nil {
		t.Fatal("OWNER_SIX_RESTORED_UNLOCK_FAILED")
	}
	defer newSession.Lock()
	owners, err := newSession.VaultFileOwnerships()
	if err != nil || len(owners) != 0 {
		t.Fatal("OWNER_SIX_LEGACY_CUSTODY_INVALID")
	}
}

func TestVaultFileOwnerCustodyCollectionCountBoundary(t *testing.T) {
	records := make([]vaultFileOwnerRecord, maxVaultFileOwnerRecords+1)
	for i := range records {
		record, err := newVaultFileOwnerRecord()
		if err != nil {
			t.Fatal("OWNER_COUNT_GENERATE_FAILED")
		}
		records[i] = record
	}
	defer clearVaultFileOwners(records)
	sort.Slice(records, func(i, j int) bool { return records[i].VaultID < records[j].VaultID })
	if _, err := vaultFileOwnersDigest(records[:maxVaultFileOwnerRecords]); err != nil {
		t.Fatal("OWNER_COUNT_MAX_REJECTED")
	}
	if _, err := vaultFileOwnersDigest(records); err == nil {
		t.Fatal("OWNER_COUNT_OVER_MAX_ACCEPTED")
	}
}

func TestVaultFileOwnerCustodySignedArchiveTamper(t *testing.T) {
	path, key, password, session, _ := ownerCustodySource(t)
	session.Lock()
	archive := filepath.Join(t.TempDir(), "source.llb")
	kit, err := Backup(path, archive, password, key)
	if err != nil {
		t.Fatal("OWNER_TAMPER_BACKUP_FAILED")
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal("OWNER_TAMPER_ARCHIVE_READ_FAILED")
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		t.Fatal("OWNER_TAMPER_ENVELOPE_FAILED")
	}
	share, err := account.Unwrap(password, key, env.Share)
	if err != nil {
		t.Fatal("OWNER_TAMPER_SHARE_FAILED")
	}
	defer clear(share)
	a, err := aeadBackup(share, kit, env.Generation)
	if err != nil {
		t.Fatal("OWNER_TAMPER_AEAD_FAILED")
	}
	plain, err := a.Open(nil, nil, env.Data, []byte(backupDomain+"/"+env.Generation))
	if err != nil {
		t.Fatal("OWNER_TAMPER_DECRYPT_FAILED")
	}
	defer clear(plain)
	var signed signedBackup
	if json.Unmarshal(plain, &signed) != nil || len(signed.Body.VaultFileOwners) != 1 {
		t.Fatal("OWNER_TAMPER_BODY_FAILED")
	}
	defer clearVaultFileOwners(signed.Body.VaultFileOwners)
	originalSignature := bytes.Clone(signed.Signature)
	for _, mode := range []string{"deleted", "changed"} {
		t.Run(mode, func(t *testing.T) {
			modified := signed
			modified.Body.VaultFileOwners = cloneVaultFileOwners(signed.Body.VaultFileOwners)
			defer clearVaultFileOwners(modified.Body.VaultFileOwners)
			if mode == "deleted" {
				modified.Body.VaultFileOwners = nil
			} else {
				modified.Body.VaultFileOwners[0].OwnerRootSeed[0] ^= 1
			}
			if !bytes.Equal(modified.Signature, originalSignature) {
				t.Fatal("OWNER_TAMPER_SIGNATURE_CHANGED")
			}
			changed, err := json.Marshal(modified)
			if err != nil {
				t.Fatal("OWNER_TAMPER_MARSHAL_FAILED")
			}
			defer clear(changed)
			envelopeCopy := env
			envelopeCopy.Data = a.Seal(nil, nil, changed, []byte(backupDomain+"/"+env.Generation))
			tampered, err := json.Marshal(envelopeCopy)
			if err != nil {
				t.Fatal("OWNER_TAMPER_REWRAP_FAILED")
			}
			newHash := sha256.Sum256(tampered)
			newKit := kit[:58] + b32.EncodeToString(newHash[:])
			pathTampered := filepath.Join(t.TempDir(), "tampered.llb")
			if os.WriteFile(pathTampered, tampered, 0600) != nil {
				t.Fatal("OWNER_TAMPER_WRITE_FAILED")
			}
			dest := filepath.Join(t.TempDir(), "refused.ll")
			if Restore(pathTampered, dest, password, key, newKit, bytes.Repeat([]byte{0x64}, 16)) == nil {
				t.Fatal("OWNER_TAMPER_ACCEPTED")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("OWNER_TAMPER_DEST_CREATED")
			}
		})
	}
}

func TestVaultFileOwnerCustodyRestoreCleansProductTempOnTransactionFailure(t *testing.T) {
	path, key, password, session, _ := ownerCustodySource(t)
	session.Lock()
	archive := filepath.Join(t.TempDir(), "source.llb")
	kit, err := Backup(path, archive, password, key)
	if err != nil {
		t.Fatal("OWNER_CLEANUP_BACKUP_FAILED")
	}
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal("OWNER_CLEANUP_ARCHIVE_READ_FAILED")
	}
	destDir := t.TempDir()
	dest := filepath.Join(destDir, "restored.ll")
	if afterOwnerRestoreWriteTestFault != nil {
		t.Fatal("OWNER_CLEANUP_FAULT_ALREADY_SET")
	}
	injected := errors.New("owned restore transaction failure")
	reached, sawProductTemp := false, false
	afterOwnerRestoreWriteTestFault = func() error {
		reached = true
		matches, err := filepath.Glob(filepath.Join(destDir, ".locklark-personal-*"))
		sawProductTemp = err == nil && len(matches) == 1
		return injected
	}
	defer func() { afterOwnerRestoreWriteTestFault = nil }()
	err = Restore(archive, dest, password, key, kit, bytes.Repeat([]byte{0x65}, 16))
	if !reached || !sawProductTemp || !errors.Is(err, injected) {
		t.Fatal("OWNER_CLEANUP_REAL_RESTORE_FAULT_NOT_REACHED")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("OWNER_CLEANUP_DEST_CREATED")
	}
	matches, err := filepath.Glob(filepath.Join(destDir, ".locklark-personal-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("OWNER_CLEANUP_PRODUCT_TEMP_REMAINED")
	}
	after, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("OWNER_CLEANUP_SOURCE_ARCHIVE_CHANGED")
	}
}

func TestVaultFileOwnerCustodyRestoreBoltTransactionRollback(t *testing.T) {
	path, key, password, session, _ := ownerCustodySource(t)
	session.Lock()
	archive := filepath.Join(t.TempDir(), "source.llb")
	kit, err := Backup(path, archive, password, key)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_BACKUP_FAILED")
	}
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_ARCHIVE_READ_FAILED")
	}
	p, err := decodeArchive(archive, password, key, kit)
	if err != nil || len(p.VaultFileOwners) != 1 {
		t.Fatal("OWNER_ROLLBACK_ARCHIVE_DECODE_FAILED")
	}
	defer clearVaultFileOwners(p.VaultFileOwners)
	// This direct bbolt fixture proves rollback of the chain, capsule and
	// second snapshot. Product temporary-file cleanup is tested separately.
	temp := filepath.Join(t.TempDir(), ".owned-restore-temp")
	db, err := bolt.Open(temp, 0600, nil)
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_TEMP_OPEN_FAILED")
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("OWNER_ROLLBACK_DEVICE_FAILED")
	}
	i := identity{Device: device.String(), Signing: make([]byte, 32), Audit: make([]byte, 32), AuditEncryption: make([]byte, 32)}
	defer i.clear()
	for _, part := range [][]byte{i.Signing, i.Audit, i.AuditEncryption} {
		if _, err := rand.Read(part); err != nil {
			t.Fatal("OWNER_ROLLBACK_IDENTITY_FAILED")
		}
	}
	injected := errors.New("owned rollback")
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(bucket)
		if err != nil {
			return err
		}
		if _, err := b.CreateBucket(eventsKey); err != nil {
			return err
		}
		if err := initializeRecovered(b, i, p); err != nil {
			return err
		}
		if b.Get(vaultFileOwnerKey) == nil || b.Get(snapshotKey) == nil || b.Get(tipKey) == nil {
			return errors.New("recovery writes missing before rollback")
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatal("OWNER_ROLLBACK_INJECTION_NOT_REACHED")
	}
	if db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucket) != nil {
			return invalid
		}
		return nil
	}) != nil || db.Close() != nil {
		t.Fatal("OWNER_ROLLBACK_TRANSACTION_PERSISTED")
	}
	after, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("OWNER_ROLLBACK_SOURCE_ARCHIVE_CHANGED")
	}
}
