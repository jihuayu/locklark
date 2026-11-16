package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	bolt "go.etcd.io/bbolt"
)

func testVaultFileOwnerRecord(t *testing.T, session *Session, path, vaultID string) vaultFileOwnerRecord {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal("OWNER_TEST_DB_OPEN_FAILED")
	}
	var found vaultFileOwnerRecord
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, session, false)
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
			if record.VaultID == vaultID {
				found = cloneVaultFileOwners([]vaultFileOwnerRecord{record})[0]
				return nil
			}
		}
		return invalid
	})
	if db.Close() != nil || err != nil {
		t.Fatal("OWNER_TEST_RECORD_AUTH_FAILED")
	}
	return found
}

func signedVaultFilePolicy(t *testing.T, policy *vaultfile.Policy, rootSeed []byte) vaultfile.SignedPolicy {
	t.Helper()
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("OWNER_TEST_POLICY_DOCUMENT_FAILED")
	}
	key := ed25519.NewKeyFromSeed(rootSeed)
	defer clear(key)
	message := append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...)
	return vaultfile.SignedPolicy{Policy: *policy, Document: document, SignerID: policy.OwnerRoot.KeyID,
		Alg: vaultfile.PolicySigAlgEd25519, Sig: ed25519.Sign(key, message)}
}

func testVaultFileOwnerGenesis(t *testing.T, owner vaultFileOwnerRecord) ([]byte, vaultfile.PolicyCheckpoint, *vaultfile.Policy) {
	t.Helper()
	authorPub, authorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("OWNER_TEST_AUTHOR_CREATE_FAILED")
	}
	defer clear(authorKey)
	authorAge, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("OWNER_TEST_AUTHOR_AGE_FAILED")
	}
	recoveryPublic, err := vaultFileOwnerPublic(owner)
	if err != nil {
		t.Fatal("OWNER_TEST_RECOVERY_PUBLIC_FAILED")
	}
	recoverySigning, err := hex.DecodeString(recoveryPublic.RecoveryContentSigningPublicKey)
	if err != nil {
		t.Fatal("OWNER_TEST_RECOVERY_SIGNING_FAILED")
	}
	rootPublic, err := hex.DecodeString(recoveryPublic.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("OWNER_TEST_ROOT_PUBLIC_FAILED")
	}
	policy := &vaultfile.Policy{Format: vaultfile.Format, Version: vaultfile.Version,
		VaultID: owner.VaultID, PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: owner.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: rootPublic, Owners: []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}}},
		Writers: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}, {PrincipalID: "recovery", Label: "Recovery"}},
		Owners:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{
			{DeviceID: "author-device", PrincipalID: "owner", Label: "Author",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: authorPub},
				AgeEncryptionKey:  authorAge.Recipient().String()},
			{DeviceID: owner.RecoveryDeviceID, PrincipalID: "recovery", Label: "Recovery",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: recoverySigning},
				AgeEncryptionKey:  recoveryPublic.RecoveryAgeRecipient},
		},
	}
	sort.Slice(policy.Devices, func(i, j int) bool { return policy.Devices[i].DeviceID < policy.Devices[j].DeviceID })
	if vaultfile.ValidatePolicy(policy) != nil {
		t.Fatal("OWNER_TEST_POLICY_INVALID")
	}
	pin := vaultfile.PolicyCheckpoint{VaultID: owner.VaultID, OwnerRootKeyID: owner.OwnerRootKeyID,
		OwnerRootPublicKey: rootPublic, PolicySeq: 0, PolicyDigest: vaultfile.PolicyDigest(policy)}
	proof := signedVaultFilePolicy(t, policy, owner.OwnerRootSeed)
	db, err := vault.NewItemDatabase([]byte(`{"owned":"recovery-test"}`), []vault.Item{{
		ID: "owned-recovery-item", Kind: "login", Title: "Owned recovery baseline", Password: "fixture-hidden",
	}})
	if err != nil {
		t.Fatal("OWNER_TEST_DATABASE_FAILED")
	}
	vuk := make([]byte, vaultfile.CEKSize)
	defer clear(vuk)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("OWNER_TEST_VUK_FAILED")
	}
	draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
		Header: vaultfile.Header{VaultID: owner.VaultID, KeyEpoch: 1, ContentSeq: 0,
			OpID: "owned-recovery-genesis", PolicySeq: 0, PolicyDigest: pin.PolicyDigest,
			AuthorDeviceID: "author-device"}, SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
	sealed, err := vaultfile.SealAuthenticatedFile(draft, db, &pin, vuk, authorKey)
	if err != nil {
		t.Fatal("OWNER_TEST_GENESIS_SEAL_FAILED")
	}
	return sealed, pin, policy
}

func TestVaultFileOwnerCustodyBackupRestoreAndManagedTransition(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.ll")
	archive := filepath.Join(root, "backup.llb")
	restored := filepath.Join(root, "restored.ll")
	oldKey := bytes.Repeat([]byte{0x39}, 16)
	newKey := bytes.Repeat([]byte{0x4a}, 16)
	password := []byte("owned-custody-factor")
	if Create(source, string(password), oldKey) != nil {
		t.Fatal("OWNER_TEST_SOURCE_CREATE_FAILED")
	}
	if _, err := AddLogin(source, string(password), oldKey, "Owned login", "owned-user", "fixture-hidden"); err != nil {
		t.Fatal("OWNER_TEST_SOURCE_ITEM_FAILED")
	}
	active, err := UnlockSession(source, password, oldKey, 0)
	if err != nil {
		t.Fatal("OWNER_TEST_SOURCE_UNLOCK_FAILED")
	}
	beforeRows, err := active.List("active")
	if err != nil || len(beforeRows) != 1 {
		t.Fatal("OWNER_TEST_SOURCE_REVISION_FAILED")
	}
	selector, err := randomID()
	if err != nil {
		t.Fatal("OWNER_TEST_SELECTOR_FAILED")
	}
	public, err := active.PrepareVaultFileOwnership(selector)
	if err != nil {
		t.Fatal("OWNER_TEST_PREPARE_FAILED")
	}
	if public.VaultID != selector {
		t.Fatal("OWNER_TEST_SELECTOR_CHANGED")
	}
	afterRows, err := active.List("active")
	if err != nil || len(afterRows) != 1 || afterRows[0].Revision != beforeRows[0].Revision {
		t.Fatal("OWNER_TEST_ITEM_REVISION_CHANGED")
	}
	beforeReplay := make([][]byte, 3)
	personalDB, err := existingWithReadOnly(source, true)
	if err != nil {
		t.Fatal("OWNER_TEST_REPLAY_DB_OPEN_FAILED")
	}
	err = personalDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		beforeReplay[0] = bytes.Clone(b.Get(snapshotKey))
		beforeReplay[1] = bytes.Clone(b.Get(tipKey))
		beforeReplay[2] = bytes.Clone(b.Get(vaultFileOwnerKey))
		return nil
	})
	if err != nil || personalDB.Close() != nil {
		t.Fatal("OWNER_TEST_REPLAY_SNAPSHOT_FAILED")
	}
	replayed, err := active.PrepareVaultFileOwnership(selector)
	if err != nil || !reflect.DeepEqual(replayed, public) {
		t.Fatal("OWNER_TEST_REPLAY_PUBLIC_CHANGED")
	}
	personalDB, err = existingWithReadOnly(source, true)
	if err != nil {
		t.Fatal("OWNER_TEST_REPLAY_DB_REOPEN_FAILED")
	}
	err = personalDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if !bytes.Equal(beforeReplay[0], b.Get(snapshotKey)) || !bytes.Equal(beforeReplay[1], b.Get(tipKey)) ||
			!bytes.Equal(beforeReplay[2], b.Get(vaultFileOwnerKey)) {
			return invalid
		}
		return nil
	})
	if err != nil || personalDB.Close() != nil {
		t.Fatal("OWNER_TEST_REPLAY_MUTATED_STATE")
	}
	listed, err := active.VaultFileOwnerships()
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], public) {
		t.Fatal("OWNER_TEST_SOURCE_PUBLIC_MISMATCH")
	}
	oldDevice, err := active.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("OWNER_TEST_OLD_DEVICE_PUBLIC_FAILED")
	}
	original := testVaultFileOwnerRecord(t, active, source, public.VaultID)
	sealed, pin, oldPolicy := testVaultFileOwnerGenesis(t, original)
	clearVaultFileOwners([]vaultFileOwnerRecord{original})
	active.Lock()
	kit, err := Backup(source, archive, string(password), oldKey)
	if err != nil {
		t.Fatal("OWNER_TEST_BACKUP_FAILED")
	}
	archived, err := decodeArchive(archive, string(password), oldKey, kit)
	if err != nil || len(archived.VaultFileOwners) != 1 || validateBackupVaultFileOwners(archived) != nil {
		t.Fatal("OWNER_TEST_PUBLISHED_ARCHIVE_CUSTODY_FAILED")
	}
	clearVaultFileOwners(archived.VaultFileOwners)
	if Restore(archive, restored, string(password), oldKey, kit, newKey) != nil {
		t.Fatal("OWNER_TEST_RESTORE_FAILED")
	}
	newSession, err := UnlockSession(restored, password, newKey, 0)
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_UNLOCK_FAILED")
	}
	defer newSession.Lock()
	restoredPublic, err := newSession.VaultFileOwnerships()
	if err != nil || len(restoredPublic) != 1 || !reflect.DeepEqual(restoredPublic[0], public) {
		t.Fatal("OWNER_TEST_RESTORED_PUBLIC_MISMATCH")
	}
	restoredDB, err := existingWithReadOnly(restored, true)
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_DB_OPEN_FAILED")
	}
	err = restoredDB.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, newSession, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		if auth.snapshot.Epoch != archived.Epoch+2 {
			return invalid
		}
		return nil
	})
	if err != nil || restoredDB.Close() != nil {
		t.Fatal("OWNER_TEST_RESTORED_EPOCH_BINDING_FAILED")
	}
	recovery := testVaultFileOwnerRecord(t, newSession, restored, public.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{recovery})
	recoveryAge, err := age.ParseX25519Identity(string(recovery.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_AGE_INVALID")
	}
	if _, db, err := vaultfile.OpenAuthenticatedFile(sealed, &pin, recovery.RecoveryDeviceID, recoveryAge); err != nil || db == nil {
		t.Fatal("OWNER_TEST_RESTORED_OLD_FILE_OPEN_FAILED")
	}
	next := *oldPolicy
	next.PolicySeq = 1
	next.PrevPolicyDigest = bytes.Clone(pin.PolicyDigest)
	next.Writers = append(append([]vaultfile.Member(nil), oldPolicy.Writers...), vaultfile.Member{PrincipalID: "restored", Label: "Restored"})
	restoredDevice, err := newSession.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_DEVICE_PUBLIC_FAILED")
	}
	if restoredDevice == oldDevice {
		t.Fatal("OWNER_TEST_PERSONAL_IDENTITY_WAS_CLONED")
	}
	restoredSigning, err := hex.DecodeString(restoredDevice.ContentSigningPublicKey)
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_DEVICE_SIGNING_INVALID")
	}
	newDeviceID, err := randomID()
	if err != nil {
		t.Fatal("OWNER_TEST_RESTORED_DEVICE_ID_FAILED")
	}
	next.Devices = append(append([]vaultfile.Device(nil), oldPolicy.Devices...), vaultfile.Device{
		DeviceID: newDeviceID, PrincipalID: "restored", Label: "Restored",
		ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: restoredSigning},
		AgeEncryptionKey:  restoredDevice.AgeRecipient,
	})
	sort.Slice(next.Devices, func(i, j int) bool { return next.Devices[i].DeviceID < next.Devices[j].DeviceID })
	if vaultfile.ValidatePolicy(&next) != nil {
		t.Fatal("OWNER_TEST_SUCCESSOR_POLICY_INVALID")
	}
	proof := signedVaultFilePolicy(t, &next, recovery.OwnerRootSeed)
	oldFile, err := vaultfile.ParseFile(sealed)
	if err != nil {
		t.Fatal("OWNER_TEST_OLD_FILE_PARSE_FAILED")
	}
	digest, err := vaultfile.FileDigest(oldFile)
	if err != nil {
		t.Fatal("OWNER_TEST_OLD_FILE_DIGEST_FAILED")
	}
	parentDigest, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal("OWNER_TEST_PARENT_DIGEST_FAILED")
	}
	draft := &vaultfile.File{Format: oldFile.Format, Version: oldFile.Version,
		SignedPolicyProofs: append(append([]vaultfile.SignedPolicy(nil), oldFile.SignedPolicyProofs...), proof),
		Header:             oldFile.Header}
	draft.Header.KeyEpoch++
	draft.Header.ContentSeq++
	draft.Header.PolicySeq++
	draft.Header.PolicyDigest = vaultfile.PolicyDigest(&next)
	draft.Header.PrevDigest = parentDigest
	draft.Header.RevisionID = ""
	draft.Header.OpID = "owned-recovered-reenrollment"
	draft.Header.AuthorDeviceID = recovery.RecoveryDeviceID
	recoverySigner := ed25519.NewKeyFromSeed(recovery.RecoverySigningSeed)
	defer clear(recoverySigner)
	rotated, newVUK, err := vaultfile.RotateAuthenticatedFile(sealed, &pin, recovery.RecoveryDeviceID,
		recoveryAge, draft, recoverySigner)
	defer clear(newVUK)
	if err != nil || vaultfile.VerifyManagedTransition(sealed, rotated, &pin) != nil {
		t.Fatal("OWNER_TEST_MANAGED_RECOVERY_FAILED")
	}
	if _, db, err := vaultfile.OpenAuthenticatedFile(rotated, &pin, recovery.RecoveryDeviceID, recoveryAge); err != nil || db == nil {
		t.Fatal("OWNER_TEST_ROTATED_RECOVERY_OPEN_FAILED")
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatal("OWNER_TEST_PUBLISHED_BACKUP_MISSING")
	}
}
