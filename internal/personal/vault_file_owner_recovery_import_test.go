//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

const ownerRecoveryImportTargetName = "owned-recovery-import"

type ownerRecoveryImportFixture struct {
	destSession *Session
	destPath    string
	destDevice  VaultFileDevicePublic
	owner       vaultFileOwnerRecord
	public      VaultFileOwnershipPublic
	expected    vaultfile.PolicyCheckpoint
	artifact    []byte
	factor      *VaultFileBackupRecoveryFactor
	binding     VaultFileBackupCustodyRestoreSourceBinding
	target      VaultFileBackupCustodyRestoreTarget
}

func newOwnerRecoveryImportFixture(t *testing.T, label string) *ownerRecoveryImportFixture {
	t.Helper()
	sourcePath, _, _, sourceSession, public := ownerCustodySource(t)
	owner := testVaultFileOwnerRecord(t, sourceSession, sourcePath, public.VaultID)
	sealed, pin, _ := testVaultFileOwnerGenesis(t, owner)

	root := filepath.Join(t.TempDir(), "backend")
	backend, err := vaultfilebackend.OpenDir(root)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_BACKEND_CREATE_FAILED")
	}
	createErr := backend.CreateIfAbsent(context.Background(), ownerRecoveryImportTargetName, sealed)
	closeErr := backend.Close()
	if createErr != nil || closeErr != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_TARGET_WRITE_FAILED")
	}
	backend, err = vaultfilebackend.OpenExistingDir(root)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_BACKEND_OPEN_FAILED")
	}
	read, readErr := backend.Read(context.Background(), ownerRecoveryImportTargetName)
	readCloseErr := backend.Close()
	if readErr != nil || readCloseErr != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_TARGET_READ_FAILED")
	}
	defer clear(read.Bytes)
	if !bytes.Equal(read.Bytes, sealed) || len(read.Revision) == 0 {
		t.Fatal("OWNER_RECOVERY_IMPORT_TARGET_MISMATCH")
	}

	source := VaultFileBackupCustodySource{
		VaultID:         owner.VaultID,
		Current:         bytes.Clone(sealed),
		JournalRevision: string(read.Revision),
		BackendRevision: string(read.Revision),
		ContentSeq:      0,
		Checkpoint:      cloneVaultFileCheckpoint(&pin),
	}
	source.SourceIdentity = VaultFileBackupCustodySourceIdentity(source)
	binding := VaultFileBackupCustodyRestoreSourceBinding{
		VaultID:         source.VaultID,
		SourceIdentity:  source.SourceIdentity,
		JournalRevision: source.JournalRevision,
		BackendRevision: source.BackendRevision,
		OriginRevision:  source.OriginRevision,
		ContentSeq:      source.ContentSeq,
	}
	artifact, factor, projection, _, err := sealVaultFileBackupCustody(context.Background(), source, owner, pin)
	source.Clear()
	clear(sealed)
	if err != nil || factor == nil || projection != public {
		t.Fatal("OWNER_RECOVERY_IMPORT_ARTIFACT_FAILED")
	}

	destPath := filepath.Join(t.TempDir(), "destination.ll")
	destPassword := []byte("owner-recovery-import-" + label)
	destKey := bytes.Repeat([]byte{0x5b}, 16)
	if Create(destPath, string(destPassword), destKey) != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_DEST_CREATE_FAILED")
	}
	destSession, err := UnlockSession(destPath, destPassword, destKey, 0)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_DEST_UNLOCK_FAILED")
	}
	clear(destPassword)
	clear(destKey)
	destDevice, err := destSession.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_DEST_DEVICE_FAILED")
	}
	if _, err := destSession.VaultFileOwnerships(); err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_DEST_CLEAN_FAILED")
	}
	f := &ownerRecoveryImportFixture{
		destSession: destSession, destPath: destPath,
		destDevice: destDevice, owner: owner, public: public,
		expected: pin, artifact: artifact, factor: factor, binding: binding,
		target: VaultFileBackupCustodyRestoreTarget{Root: root, Name: ownerRecoveryImportTargetName},
	}
	t.Cleanup(f.clear)
	return f
}

func (f *ownerRecoveryImportFixture) clear() {
	if f == nil {
		return
	}
	if f.destSession != nil {
		f.destSession.Lock()
	}
	clear(f.artifact)
	clear(f.expected.OwnerRootPublicKey)
	clear(f.expected.PolicyDigest)
	clearVaultFileOwners([]vaultFileOwnerRecord{f.owner})
	if f.factor != nil {
		f.factor.Clear()
	}
	*f = ownerRecoveryImportFixture{}
}

func ownerRecoveryState(t *testing.T, session *Session, path string) (uint64, uint64) {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_STATE_OPEN_FAILED")
	}
	var epoch, count uint64
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, session, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		epoch, count = auth.snapshot.Epoch, auth.tip.Count
		return nil
	})
	if err != nil || db.Close() != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_STATE_AUTH_FAILED")
	}
	return epoch, count
}

func ownerRecoveryRestoreEvents(t *testing.T, session *Session, path string) int {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_EVENTS_OPEN_FAILED")
	}
	var count int
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, session, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		for _, event := range auth.rows {
			if event.Action == vaultFileOwnerRestoreAction {
				count++
			}
		}
		return nil
	})
	if err != nil || db.Close() != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_EVENTS_AUTH_FAILED")
	}
	return count
}

func TestVaultFileOwnerRecoveryImportIsExactAndIdempotent(t *testing.T) {
	f := newOwnerRecoveryImportFixture(t, "idempotent")
	beforeEpoch, _ := ownerRecoveryState(t, f.destSession, f.destPath)
	projection, err := f.destSession.RestoreVaultFileBackupCustodyOwner(context.Background(),
		f.artifact, f.expected, f.factor, f.binding, f.target)
	if err != nil || projection != f.public {
		t.Fatalf("OWNER_RECOVERY_IMPORT_FAILED: %v", err)
	}
	importedEpoch, _ := ownerRecoveryState(t, f.destSession, f.destPath)
	if importedEpoch != beforeEpoch+1 || ownerRecoveryRestoreEvents(t, f.destSession, f.destPath) != 1 {
		t.Fatal("OWNER_RECOVERY_IMPORT_NOT_RECOVERY_SPECIFIC")
	}
	imported := testVaultFileOwnerRecord(t, f.destSession, f.destPath, f.public.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{imported})
	if !sameVaultFileGenesisOwner(imported, f.owner) {
		t.Fatal("OWNER_RECOVERY_IMPORT_PRIVATE_OWNER_MISMATCH")
	}
	if owners, err := f.destSession.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != f.public {
		t.Fatal("OWNER_RECOVERY_IMPORT_PUBLIC_MISMATCH")
	}
	if device, err := f.destSession.VaultFileDevicePublic(); err != nil || device != f.destDevice {
		t.Fatal("OWNER_RECOVERY_IMPORT_DEVICE_CHANGED")
	}

	// The exact retry authenticates the same private owner and appends no
	// snapshot advancement or event.
	again, err := f.destSession.RestoreVaultFileBackupCustodyOwner(context.Background(),
		f.artifact, f.expected, f.factor, f.binding, f.target)
	if err != nil || again != f.public {
		t.Fatalf("OWNER_RECOVERY_IMPORT_RETRY_FAILED: %v", err)
	}
	afterEpoch, _ := ownerRecoveryState(t, f.destSession, f.destPath)
	if afterEpoch != importedEpoch || ownerRecoveryRestoreEvents(t, f.destSession, f.destPath) != 1 {
		t.Fatal("OWNER_RECOVERY_IMPORT_RETRY_ADVANCED_STATE")
	}
	if owners, err := f.destSession.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != f.public {
		t.Fatal("OWNER_RECOVERY_IMPORT_RETRY_DUPLICATED")
	}
}

func TestVaultFileOwnerRecoveryImportLockOrCancelBeforeCommitRollsBack(t *testing.T) {
	for _, mode := range []string{"lock", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnerRecoveryImportFixture(t, mode)
			beforeEpoch, _ := ownerRecoveryState(t, f.destSession, f.destPath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			vaultFileOwnerRecoveryBeforeCommitForTest = func() {
				if mode == "lock" {
					f.destSession.RequestLock()
				} else {
					cancel()
				}
			}
			defer func() { vaultFileOwnerRecoveryBeforeCommitForTest = nil }()

			projection, err := f.destSession.RestoreVaultFileBackupCustodyOwner(ctx,
				f.artifact, f.expected, f.factor, f.binding, f.target)
			if projection != (VaultFileOwnershipPublic{}) {
				t.Fatal("OWNER_RECOVERY_IMPORT_FAULT_LIMIT_RETURNED_OWNER")
			}
			if mode == "lock" {
				if !errors.Is(err, ErrSessionLocked) {
					t.Fatalf("OWNER_RECOVERY_IMPORT_LOCK_ACCEPTED: %v", err)
				}
			} else if !errors.Is(err, ErrVaultFileBackupCustodyCanceled) {
				t.Fatalf("OWNER_RECOVERY_IMPORT_CANCEL_ACCEPTED: %v", err)
			}

			// The destination store is reopened from disk; a rolled-back failure
			// must leave the exact pre-import owner list, epoch and device.
			reopened, err := UnlockSession(f.destPath, []byte("owner-recovery-import-"+mode),
				bytes.Repeat([]byte{0x5b}, 16), 0)
			if err != nil {
				t.Fatal("OWNER_RECOVERY_IMPORT_FAULT_REOPEN_FAILED")
			}
			defer reopened.Lock()
			if owners, err := reopened.VaultFileOwnerships(); err != nil || len(owners) != 0 {
				t.Fatal("OWNER_RECOVERY_IMPORT_FAULT_DURABLE_OWNER")
			}
			epoch, _ := ownerRecoveryState(t, reopened, f.destPath)
			if epoch != beforeEpoch || ownerRecoveryRestoreEvents(t, reopened, f.destPath) != 0 {
				t.Fatal("OWNER_RECOVERY_IMPORT_FAULT_ADVANCED_STATE")
			}
			if device, err := reopened.VaultFileDevicePublic(); err != nil || device != f.destDevice {
				t.Fatal("OWNER_RECOVERY_IMPORT_FAULT_DEVICE_CHANGED")
			}
		})
	}
}

func TestVaultFileOwnerRecoveryImportPreservesUnrelatedOwnerRecord(t *testing.T) {
	f := newOwnerRecoveryImportFixture(t, "unrelated")
	selector, err := randomID()
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_SELECTOR_FAILED")
	}
	unrelatedPublic, err := f.destSession.PrepareVaultFileOwnership(selector)
	if err != nil {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_PREPARE_FAILED")
	}
	unrelated := testVaultFileOwnerRecord(t, f.destSession, f.destPath, selector)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{unrelated})

	if projection, err := f.destSession.RestoreVaultFileBackupCustodyOwner(context.Background(),
		f.artifact, f.expected, f.factor, f.binding, f.target); err != nil || projection != f.public {
		t.Fatalf("OWNER_RECOVERY_IMPORT_UNRELATED_RESTORE_FAILED: %v", err)
	}
	owners, err := f.destSession.VaultFileOwnerships()
	if err != nil || len(owners) != 2 {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_COUNT_MISMATCH")
	}
	foundPublic, foundUnrelated := false, false
	for _, owner := range owners {
		foundPublic = foundPublic || owner == f.public
		foundUnrelated = foundUnrelated || owner == unrelatedPublic
	}
	if !foundPublic || !foundUnrelated {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_RECORD_LOST")
	}
	after := testVaultFileOwnerRecord(t, f.destSession, f.destPath, selector)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{after})
	if !sameVaultFileGenesisOwner(unrelated, after) {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_PRIVATE_RECORD_CHANGED")
	}
	imported := testVaultFileOwnerRecord(t, f.destSession, f.destPath, f.public.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{imported})
	if !sameVaultFileGenesisOwner(imported, f.owner) {
		t.Fatal("OWNER_RECOVERY_IMPORT_UNRELATED_IMPORT_MISMATCH")
	}
}
