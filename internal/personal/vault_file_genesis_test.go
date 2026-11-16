package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

type genesisProducerFixture struct {
	personal, archive, oldArchive, journal string
	password, key, kit, oldKit             []byte
	owner                                  VaultFileOwnershipPublic
	session                                *Session
}

func newGenesisProducerFixture(t *testing.T) genesisProducerFixture {
	t.Helper()
	dir := t.TempDir()
	private := filepath.Join(dir, "intent")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal("GENESIS_PRIVATE_PARENT_FAILED")
	}
	f := genesisProducerFixture{personal: filepath.Join(dir, "personal.ll"),
		archive: filepath.Join(dir, "published.llb"), oldArchive: filepath.Join(dir, "old.llb"),
		journal:  filepath.Join(private, "genesis.journal"),
		password: []byte("genesis-full-factor"), key: bytes.Repeat([]byte{0x37}, 16)}
	if err := Create(f.personal, string(f.password), f.key); err != nil {
		t.Fatal("GENESIS_PERSONAL_CREATE_FAILED")
	}
	old, err := PrepareBackup(f.personal, f.oldArchive, string(f.password), f.key)
	if err != nil || old.Publish() != nil {
		t.Fatal("GENESIS_OLD_BACKUP_PUBLISH_FAILED")
	}
	f.oldKit = []byte(old.Material())
	old.Close()
	f.session, err = UnlockSession(f.personal, f.password, f.key, time.Minute)
	if err != nil {
		t.Fatal("GENESIS_FULL_UNLOCK_FAILED")
	}
	t.Cleanup(f.session.Lock)
	selector, err := randomID()
	if err != nil {
		t.Fatal("GENESIS_SELECTOR_FAILED")
	}
	f.owner, err = f.session.PrepareVaultFileOwnership(selector)
	if err != nil {
		t.Fatal("GENESIS_CUSTODY_PREPARE_FAILED")
	}
	backup, err := PrepareBackup(f.personal, f.archive, string(f.password), f.key)
	if err != nil || backup.Publish() != nil {
		t.Fatal("GENESIS_BACKUP_PUBLISH_FAILED")
	}
	f.kit = []byte(backup.Material())
	backup.Close()
	return f
}

func (f genesisProducerFixture) request() VaultFileGenesisRequest {
	return VaultFileGenesisRequest{VaultID: f.owner.VaultID, Name: "owned-genesis",
		IntentPath: f.journal, ArchivePath: f.archive}
}

func loadProducedGenesis(t *testing.T, path string) vaultfilejournal.GenesisIntent {
	t.Helper()
	j, err := vaultfilejournal.OpenExistingIntent(path)
	if err != nil {
		t.Fatal("GENESIS_INTENT_OPEN_FAILED")
	}
	intent, loadErr := j.Load()
	if loadErr != nil || j.Close() != nil {
		t.Fatal("GENESIS_INTENT_LOAD_FAILED")
	}
	return intent
}

func TestVaultFileGenesisProducerPublishedRecoveryAndExactRetry(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("genesis intent persistence is unsupported on this platform")
	}
	f := newGenesisProducerFixture(t)
	// A later unrelated custody record does not invalidate the archived A.
	otherID, err := randomID()
	if err != nil {
		t.Fatal("GENESIS_OTHER_SELECTOR_FAILED")
	}
	if _, err := f.session.PrepareVaultFileOwnership(otherID); err != nil {
		t.Fatal("GENESIS_OTHER_CUSTODY_FAILED")
	}
	first, err := f.session.PrepareVaultFileGenesis(f.request(), f.password, f.key, f.kit)
	if err != nil {
		_, statErr := os.Lstat(f.journal)
		t.Fatalf("GENESIS_PRODUCER_FAILED: %v, inode_exists=%t", err, statErr == nil)
	}
	if first.Ownership != f.owner || first.PolicyDigest == "" {
		t.Fatal("GENESIS_PRODUCER_PROJECTION_FAILED")
	}
	intent := loadProducedGenesis(t, f.journal)
	defer clear(intent.SealedBytes)
	rootPublic, err := hex.DecodeString(f.owner.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("GENESIS_ROOT_PUBLIC_INVALID")
	}
	pin := &vaultfile.GenesisRootPin{VaultID: f.owner.VaultID,
		OwnerRootKeyID: f.owner.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootPublic)}
	checkpoint, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin)
	if err != nil || first.PolicyDigest != hex.EncodeToString(checkpoint.PolicyDigest) ||
		intent.PolicySeq != 0 || intent.OperationID == "" || intent.Name != f.request().Name {
		t.Fatal("GENESIS_REAL_FILE_NOT_PINNED")
	}
	record := testVaultFileOwnerRecord(t, f.session, f.personal, f.owner.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	recoveryAge, err := age.ParseX25519Identity(string(record.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("GENESIS_RECOVERY_IDENTITY_INVALID")
	}
	_, metadata, items, err := vault.OpenAuthenticatedItems(intent.SealedBytes, checkpoint, record.RecoveryDeviceID, recoveryAge)
	defer clear(metadata)
	defer clearAuthenticatedItems(items)
	if err != nil || len(metadata) != 0 || len(items) != 0 {
		t.Fatal("GENESIS_RECOVERY_OPEN_FAILED")
	}
	repeated, err := f.session.PrepareVaultFileGenesis(f.request(), f.password, f.key, f.kit)
	if err != nil || !reflect.DeepEqual(repeated, first) {
		t.Fatal("GENESIS_EXACT_RETRY_FAILED")
	}
	reloaded := loadProducedGenesis(t, f.journal)
	defer clear(reloaded.SealedBytes)
	if !sameVaultFileGenesisIntent(intent, reloaded) {
		t.Fatal("GENESIS_RETRY_RESEALED")
	}
	oldRequest := f.request()
	oldRequest.ArchivePath = f.oldArchive
	if _, err := f.session.PrepareVaultFileGenesis(oldRequest, f.password, f.key, f.oldKit); !errors.Is(err, ErrVaultFileGenesisRecovery) {
		t.Fatal("GENESIS_EXISTING_INTENT_ACCEPTED_OLD_ARCHIVE")
	}
	f.session.Lock()
	restored := filepath.Join(filepath.Dir(f.personal), "restored.ll")
	newKey := bytes.Repeat([]byte{0x49}, 16)
	if Restore(f.archive, restored, string(f.password), f.key, string(f.kit), newKey) != nil {
		t.Fatal("GENESIS_BACKUP_RESTORE_FAILED")
	}
	restoredSession, err := UnlockSession(restored, f.password, newKey, time.Minute)
	if err != nil {
		t.Fatal("GENESIS_RESTORED_UNLOCK_FAILED")
	}
	defer restoredSession.Lock()
	restoredOwner := testVaultFileOwnerRecord(t, restoredSession, restored, f.owner.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{restoredOwner})
	restoredRecovery, err := age.ParseX25519Identity(string(restoredOwner.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("GENESIS_RESTORED_RECOVERY_IDENTITY_INVALID")
	}
	_, restoredMetadata, restoredItems, err := vault.OpenAuthenticatedItems(intent.SealedBytes, checkpoint, restoredOwner.RecoveryDeviceID, restoredRecovery)
	defer clear(restoredMetadata)
	defer clearAuthenticatedItems(restoredItems)
	if err != nil || len(restoredMetadata) != 0 || len(restoredItems) != 0 {
		t.Fatal("GENESIS_RESTORED_CUSTODY_CANNOT_OPEN_ORIGINAL_G")
	}
	recovered, err := restoredSession.PrepareVaultFileGenesis(f.request(), f.password, f.key, f.kit)
	if !errors.Is(err, ErrVaultFileGenesisIntent) || recovered != (VaultFileGenesisPublic{}) {
		t.Fatal("GENESIS_RESTORED_NEW_IDENTITY_ACCEPTED_OLD_AUTHOR")
	}
	final := loadProducedGenesis(t, f.journal)
	defer clear(final.SealedBytes)
	if !sameVaultFileGenesisIntent(intent, final) {
		t.Fatal("GENESIS_RESTORED_RETRY_CHANGED_INTENT")
	}
}

func TestVaultFileGenesisRetryRejectsRootSignedForeignLocalRoster(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("genesis intent persistence is unsupported on this platform")
	}
	f := newGenesisProducerFixture(t)
	record := testVaultFileOwnerRecord(t, f.session, f.personal, f.owner.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	material, err := f.session.loadVaultFileGenesisMaterial(f.owner.VaultID, record)
	if err != nil {
		t.Fatal("GENESIS_CURRENT_IDENTITY_FAILED")
	}
	defer material.clear()
	rootPublic, err := hex.DecodeString(f.owner.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("GENESIS_ROOT_PUBLIC_INVALID")
	}
	pin := &vaultfile.GenesisRootPin{VaultID: f.owner.VaultID,
		OwnerRootKeyID: f.owner.OwnerRootKeyID, OwnerRootPublicKey: ed25519.PublicKey(rootPublic)}
	recoveryAge, err := age.ParseX25519Identity(string(record.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("GENESIS_RECOVERY_IDENTITY_INVALID")
	}
	for _, tc := range []struct {
		name string
		seal func(string) (vaultfilejournal.GenesisIntent, error)
	}{
		{name: "wrong-local-author", seal: func(name string) (vaultfilejournal.GenesisIntent, error) {
			wrongSeed := bytes.Repeat([]byte{0x58}, ed25519.SeedSize)
			defer clear(wrongSeed)
			return sealVaultFileGenesis(name, record, wrongSeed, material.localRecipient, pin)
		}},
		{name: "extra-reader-role", seal: func(name string) (vaultfilejournal.GenesisIntent, error) {
			policy, err := vaultFileGenesisExpectedPolicy(record, material.localSigning, material.localRecipient, pin)
			if err != nil {
				return vaultfilejournal.GenesisIntent{}, err
			}
			policy.Readers = []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}}
			localSigner := ed25519.NewKeyFromSeed(material.localSigning)
			rootSigner := ed25519.NewKeyFromSeed(record.OwnerRootSeed)
			defer clear(localSigner)
			defer clear(rootSigner)
			return sealVaultFileGenesisPolicy(name, record, policy, localSigner, rootSigner, pin)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private := filepath.Join(filepath.Dir(f.personal), tc.name)
			if err := os.Mkdir(private, 0700); err != nil {
				t.Fatal("GENESIS_PRIVATE_PARENT_FAILED")
			}
			req := f.request()
			req.IntentPath = filepath.Join(private, "genesis.journal")
			intent, err := tc.seal(req.Name)
			if err != nil {
				t.Fatalf("GENESIS_ROOT_SIGNED_FIXTURE_FAILED: %v", err)
			}
			defer clear(intent.SealedBytes)
			checkpoint, err := vaultfile.VerifyGenesis(intent.SealedBytes, pin)
			if err != nil || !bytes.Equal(checkpoint.PolicyDigest, intent.PolicyDigest) {
				t.Fatal("GENESIS_FIXTURE_CRYPTO_INVALID")
			}
			_, metadata, items, err := vault.OpenAuthenticatedItems(intent.SealedBytes, checkpoint, record.RecoveryDeviceID, recoveryAge)
			defer clear(metadata)
			defer clearAuthenticatedItems(items)
			if err != nil || len(metadata) != 0 || len(items) != 0 {
				t.Fatal("GENESIS_FIXTURE_RECOVERY_OPEN_FAILED")
			}
			if err := vaultfilejournal.CreateNewGenesisIntent(req.IntentPath, intent); err != nil {
				t.Fatal("GENESIS_FOREIGN_INTENT_CREATE_FAILED")
			}
			got, err := f.session.PrepareVaultFileGenesis(req, f.password, f.key, f.kit)
			if !errors.Is(err, ErrVaultFileGenesisIntent) || got != (VaultFileGenesisPublic{}) {
				t.Fatal("GENESIS_FOREIGN_LOCAL_ROSTER_ACCEPTED")
			}
			stored := loadProducedGenesis(t, req.IntentPath)
			defer clear(stored.SealedBytes)
			if !sameVaultFileGenesisIntent(intent, stored) {
				t.Fatal("GENESIS_FOREIGN_INTENT_CHANGED")
			}
		})
	}
}

func TestVaultFileGenesisProducerRejectsUnrecoverableArchiveBeforeIntent(t *testing.T) {
	f := newGenesisProducerFixture(t)
	req := f.request()
	foreignPersonal := filepath.Join(t.TempDir(), "foreign.ll")
	foreignArchive := filepath.Join(filepath.Dir(foreignPersonal), "foreign.llb")
	foreignPassword := []byte("foreign-full-factor")
	foreignKey := bytes.Repeat([]byte{0x62}, 16)
	if Create(foreignPersonal, string(foreignPassword), foreignKey) != nil {
		t.Fatal("GENESIS_FOREIGN_PERSONAL_CREATE_FAILED")
	}
	foreignSession, err := UnlockSession(foreignPersonal, foreignPassword, foreignKey, time.Minute)
	if err != nil {
		t.Fatal("GENESIS_FOREIGN_PERSONAL_UNLOCK_FAILED")
	}
	if _, err := foreignSession.PrepareVaultFileOwnership(req.VaultID); err != nil {
		t.Fatal("GENESIS_FOREIGN_CUSTODY_FAILED")
	}
	foreignSession.Lock()
	foreignBackup, err := PrepareBackup(foreignPersonal, foreignArchive, string(foreignPassword), foreignKey)
	if err != nil || foreignBackup.Publish() != nil {
		t.Fatal("GENESIS_FOREIGN_BACKUP_FAILED")
	}
	foreignKit := []byte(foreignBackup.Material())
	foreignBackup.Close()
	if _, err := f.session.PrepareVaultFileGenesis(VaultFileGenesisRequest{VaultID: req.VaultID,
		Name: req.Name, IntentPath: req.IntentPath, ArchivePath: foreignArchive},
		foreignPassword, foreignKey, foreignKit); !errors.Is(err, ErrVaultFileGenesisRecovery) {
		t.Fatal("GENESIS_SAME_ID_FOREIGN_PRIVATE_CUSTODY_ACCEPTED")
	}
	cases := []struct {
		name, archive string
		kit           []byte
		vaultID       string
	}{
		{name: "old archive", archive: f.oldArchive, kit: f.oldKit, vaultID: f.owner.VaultID},
		{name: "wrong kit", archive: f.archive, kit: f.oldKit, vaultID: f.owner.VaultID},
		{name: "foreign vault", archive: f.archive, kit: f.kit, vaultID: "ffffffffffffffffffffffffffffffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := req
			bad.ArchivePath = tc.archive
			bad.VaultID = tc.vaultID
			if _, err := f.session.PrepareVaultFileGenesis(bad, f.password, f.key, tc.kit); !errors.Is(err, ErrVaultFileGenesisRecovery) {
				t.Fatal("GENESIS_UNRECOVERABLE_ARCHIVE_ACCEPTED")
			}
			if _, err := os.Lstat(f.journal); !os.IsNotExist(err) {
				t.Fatal("GENESIS_REFUSAL_CREATED_INTENT")
			}
		})
	}
	f.session.mu.Lock()
	f.session.fullUnlock = time.Time{}
	f.session.mu.Unlock()
	if _, err := f.session.PrepareVaultFileGenesis(req, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("GENESIS_QUICK_UNLOCK_ACCEPTED")
	}
	f.session.mu.Lock()
	f.session.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	f.session.mu.Unlock()
	if _, err := f.session.PrepareVaultFileGenesis(req, f.password, f.key, f.kit); !errors.Is(err, ErrVaultFileFullFactorRequired) {
		t.Fatal("GENESIS_EXPIRED_UNLOCK_ACCEPTED")
	}
	if _, err := os.Lstat(f.journal); !os.IsNotExist(err) {
		t.Fatal("GENESIS_FACTOR_REFUSAL_CREATED_INTENT")
	}
	fresh, err := UnlockSession(f.personal, f.password, f.key, time.Minute)
	if err != nil {
		t.Fatal("GENESIS_CANCELLATION_UNLOCK_FAILED")
	}
	defer fresh.Lock()
	fresh.RequestLock()
	if _, err := fresh.PrepareVaultFileGenesis(req, f.password, f.key, f.kit); !errors.Is(err, ErrSessionLocked) {
		t.Fatal("GENESIS_REQUEST_LOCK_ACCEPTED")
	}
	if _, err := os.Lstat(f.journal); !os.IsNotExist(err) {
		t.Fatal("GENESIS_CANCELLED_CREATED_INTENT")
	}
}

func TestVaultFileGenesisSelectedCustodyRequiresEveryPrivateField(t *testing.T) {
	owner, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("GENESIS_PRIVATE_RECORD_FIXTURE_FAILED")
	}
	defer clearVaultFileOwners([]vaultFileOwnerRecord{owner})
	if !sameVaultFileGenesisOwner(owner, owner) {
		t.Fatal("GENESIS_PRIVATE_RECORD_CONTROL_FAILED")
	}
	for _, field := range []string{"vault id", "root id", "root seed", "recovery id", "recovery signing seed", "recovery age identity"} {
		t.Run(field, func(t *testing.T) {
			changed := cloneVaultFileOwners([]vaultFileOwnerRecord{owner})[0]
			defer func() { clearVaultFileOwners([]vaultFileOwnerRecord{changed}) }()
			switch field {
			case "vault id":
				changed.VaultID = flipGenesisHexID(changed.VaultID)
			case "root id":
				changed.OwnerRootKeyID = flipGenesisHexID(changed.OwnerRootKeyID)
			case "root seed":
				changed.OwnerRootSeed[0] ^= 1
			case "recovery id":
				changed.RecoveryDeviceID = flipGenesisHexID(changed.RecoveryDeviceID)
			case "recovery signing seed":
				changed.RecoverySigningSeed[0] ^= 1
			case "recovery age identity":
				identity, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal("GENESIS_ALTERNATE_AGE_FAILED")
				}
				clear(changed.RecoveryAgeIdentity)
				changed.RecoveryAgeIdentity = []byte(identity.String())
			}
			if sameVaultFileGenesisOwner(owner, changed) {
				t.Fatal("GENESIS_PRIVATE_FIELD_CHANGE_ACCEPTED")
			}
		})
	}
}

func flipGenesisHexID(id string) string {
	b := []byte(id)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}
