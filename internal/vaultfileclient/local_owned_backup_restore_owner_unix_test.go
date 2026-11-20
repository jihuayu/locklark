//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func localRestoreOwnerDevice(t *testing.T, session *personal.Session) personal.VaultFileDevicePublic {
	t.Helper()
	device, err := session.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_DEVICE_FAILED")
	}
	return device
}

func localRestoreOwnerSource(t *testing.T, session *personal.Session) personal.VaultFileOwnershipPublic {
	t.Helper()
	owners, err := session.VaultFileOwnerships()
	if err != nil || len(owners) != 1 {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_LIST_FAILED")
	}
	return owners[0]
}

func TestLocalOwnedBackupRestoreOwnerImportsCleanAccountAndReopens(t *testing.T) {
	sourcePassword := []byte("local-restore-owner-source")
	sourceKey := bytes.Repeat([]byte{0x2d}, 16)
	destPassword := []byte("local-restore-owner-destination")
	destKey := bytes.Repeat([]byte{0x6e}, 16)
	defer clear(sourcePassword)
	defer clear(sourceKey)
	defer clear(destPassword)
	defer clear(destKey)

	fx := newLocalCustodyFileFixture(t, "restore-owner", sourcePassword, sourceKey,
		localFirstWriteSecret+"-restore-owner")
	transfer := newLocalRestorePreflightFixture(t, fx, "owner")

	sourceOwnership := localRestoreOwnerSource(t, fx.v.session)
	sourceDevice := localRestoreOwnerDevice(t, fx.v.session)

	// The producer session, original config and original personal database are
	// all made unavailable before the supported restore operation is called.
	fx.v.session.Lock()
	if fx.v.session.Unlocked() {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_SESSION_LIVE")
	}
	if err := os.Remove(fx.v.config); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_CONFIG_REMOVE_FAILED")
	}
	if err := os.Remove(fx.v.manifest.PersonalFile); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_DATABASE_REMOVE_FAILED")
	}

	sourceTarget, sourceRevision := localRestorePreflightTarget(t, fx.v)
	defer clear(sourceTarget)
	if sourceRevision != vaultfilebackend.Revision(transfer.saved.BackendRevision) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_TARGET_MISMATCH")
	}

	dest := localIsolationCreation(t, "restore-owner-destination", destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_DESTINATION_UNLOCK_FAILED")
	}
	defer destination.Lock()
	destDevice := localRestoreOwnerDevice(t, destination)
	if destDevice == sourceDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_DEVICE_REUSED")
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil || len(owners) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_DESTINATION_NOT_CLEAN")
	}
	restored, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator, destination)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_RESTORE_FAILED")
	}
	if restored != sourceOwnership {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_PROJECTION_MISMATCH")
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sourceOwnership {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_PUBLISHED_MISMATCH")
	}
	if after := localRestoreOwnerDevice(t, destination); after != destDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_DESTINATION_DEVICE_CHANGED")
	}

	// The original provider object is read-only to the operation.
	target, revision := localRestorePreflightTarget(t, fx.v)
	defer clear(target)
	if revision != sourceRevision || !bytes.Equal(target, sourceTarget) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_TARGET_CHANGED")
	}
	if _, err := os.Lstat(fx.v.manifest.PersonalFile); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SOURCE_DATABASE_RECREATED")
	}

	// Lock and reopen the destination only from the durable store.
	destination.Lock()
	reopened, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_REOPEN_FAILED")
	}
	defer reopened.Lock()
	if owners, err := reopened.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sourceOwnership {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_REOPENED_MISMATCH")
	}
	if after := localRestoreOwnerDevice(t, reopened); after != destDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_REOPENED_DEVICE_CHANGED")
	}

	// An exact retry proves the same private owner without new material,
	// another record, another device or a changed source target.
	if again, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator, reopened); err != nil || again != sourceOwnership {
		t.Fatalf("LOCAL_OWNED_BACKUP_RESTORE_OWNER_RETRY_FAILED: %v", err)
	}
	if owners, err := reopened.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sourceOwnership {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_RETRY_LIST_MISMATCH")
	}
	if after := localRestoreOwnerDevice(t, reopened); after != destDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_RETRY_DEVICE_CHANGED")
	}
	if again, revision := localRestorePreflightTarget(t, fx.v); revision != sourceRevision ||
		!bytes.Equal(again, sourceTarget) {
		clear(again)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_RETRY_SOURCE_TARGET_CHANGED")
	} else {
		clear(again)
	}
}

func TestLocalOwnedBackupRestoreOwnerRefusesScopeTargetOwnerAndCancel(t *testing.T) {
	passwordA := []byte("local-restore-owner-scope-a")
	keyA := bytes.Repeat([]byte{0x31}, 16)
	passwordB := []byte("local-restore-owner-scope-b")
	keyB := bytes.Repeat([]byte{0x72}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	a := newLocalCustodyFileFixture(t, "restore-owner-scope-a", passwordA, keyA,
		localFirstWriteSecret+"-restore-owner-scope-a")
	b := newLocalCustodyFileFixture(t, "restore-owner-scope-b", passwordB, keyB,
		localFirstWriteSecret+"-restore-owner-scope-b")
	ta := newLocalRestorePreflightFixture(t, a, "owner-scope-a")
	tb := newLocalRestorePreflightFixture(t, b, "owner-scope-b")
	sourceOwnership := localRestoreOwnerSource(t, a.v.session)
	sourceTarget, sourceRevision := localRestorePreflightTarget(t, a.v)
	defer clear(sourceTarget)

	destPassword := []byte("local-restore-owner-scope-dest")
	destKey := bytes.Repeat([]byte{0x45}, 16)
	defer clear(destPassword)
	defer clear(destKey)
	dest := localIsolationCreation(t, "restore-owner-scope-dest", destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SCOPE_UNLOCK_FAILED")
	}
	defer destination.Lock()
	destDevice := localRestoreOwnerDevice(t, destination)

	localRestoreOwnerRefuse := func(code string, category error, ownership personal.VaultFileOwnershipPublic, err error) {
		t.Helper()
		if !errors.Is(err, category) || ownership != (personal.VaultFileOwnershipPublic{}) {
			t.Fatal(code)
		}
	}
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, tb.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_CHECKPOINT_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, b.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_FACTOR_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongVault := ta.pin
	wrongVault.VaultID = tb.saved.VaultID
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongVault, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_VAULT_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongDigest := ta.pin
	wrongDigest.ArtifactSHA256[0] ^= 0xff
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongDigest, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_FILE_DIGEST_ACCEPTED",
		ErrLocalOwnedBackupConflict, personal.VaultFileOwnershipPublic{}, err)

	// Every independently issued source field is binding, not merely part of the
	// artifact digest. Each mutation keeps the authentic artifact, digest/factor
	// and locator, and must refuse before touching the empty destination.
	wrongIdentity := ta.pin
	wrongIdentity.SourceIdentity[0] ^= 0xff
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongIdentity, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_SOURCE_IDENTITY_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongJournal := ta.pin
	wrongJournal.JournalRevision += "-wrong"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongJournal, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_JOURNAL_REVISION_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongBackend := ta.pin
	wrongBackend.BackendRevision += "-wrong"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongBackend, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_BACKEND_REVISION_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongOrigin := ta.pin
	wrongOrigin.OriginRevision += "-wrong"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongOrigin, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_ORIGIN_REVISION_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	wrongContent := ta.pin
	wrongContent.ContentSeq++
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongContent, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_WRONG_CONTENT_SEQ_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)

	// A source-binding mismatch must be decided before the local target is
	// opened, so a missing locator still yields the review refusal.
	bindingBeforeTargetRoot := ta.locator.Root + "-binding-absent"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, wrongIdentity, ta.expected, a.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: bindingBeforeTargetRoot, Name: ta.locator.Name},
		destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_BINDING_TOUCHED_TARGET",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	if _, err := os.Lstat(bindingBeforeTargetRoot); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_BINDING_CREATED_TARGET")
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil || len(owners) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_BINDING_REFUSALS_WROTE_DESTINATION")
	}

	absentName := a.v.manifest.Name + "-absent"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: ta.locator.Root, Name: absentName}, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_MISSING_TARGET_ACCEPTED",
		ErrLocalOwnedBackupConflict, personal.VaultFileOwnershipPublic{}, err)
	backend, backendErr := vaultfilebackend.OpenExistingDir(ta.locator.Root)
	if backendErr != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_MISSING_OPEN_FAILED")
	}
	_, readErr := backend.Read(context.Background(), absentName)
	closeErr := backend.Close()
	if !errors.Is(readErr, vaultfilebackend.ErrNotFound) || closeErr != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_MISSING_TARGET_CREATED")
	}
	missingRoot := ta.locator.Root + "-absent"
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: missingRoot, Name: ta.locator.Name}, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_MISSING_ROOT_ACCEPTED",
		ErrLocalOwnedBackupConflict, personal.VaultFileOwnershipPublic{}, err)
	if _, err := os.Lstat(missingRoot); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_MISSING_ROOT_CREATED")
	}

	if current, err := destination.VaultFileOwnerships(); err != nil || len(current) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_REFUSALS_WROTE_DESTINATION")
	}
	// A different existing private record for the same vault ID is never
	// overwritten, and no second record is appended.
	sibling, err := destination.PrepareVaultFileOwnership(sourceOwnership.VaultID)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SIBLING_PREPARE_FAILED")
	}
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: ta.locator.Root, Name: ta.locator.Name}, destination)
	if !errors.Is(err, ErrLocalOwnedBackupReview) {
		t.Fatalf("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SIBLING_ACCEPTED: %v", err)
	}
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SIBLING_ACCEPTED",
		ErrLocalOwnedBackupReview, personal.VaultFileOwnershipPublic{}, err)
	if owners, err := destination.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sibling || owners[0] == sourceOwnership {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SIBLING_REPLACED")
	}
	if after := localRestoreOwnerDevice(t, destination); after != destDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_SIBLING_DEVICE_CHANGED")
	}

	// The same authenticated bytes at a different opaque revision are a target
	// conflict, not an install.
	sameBytesRevision := localFirstRewriteBackend(t, a.v.manifest,
		a.settled.record.SuccessorBytes)
	if sameBytesRevision == sourceRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_NEW_REVISION_NOT_NEW")
	}
	_, err = RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_NEW_REVISION_ACCEPTED",
		ErrLocalOwnedBackupConflict, personal.VaultFileOwnershipPublic{}, err)
	rewritten, rewrittenRevision := localRestorePreflightTarget(t, a.v)
	if rewrittenRevision == sourceRevision || !bytes.Equal(rewritten, sourceTarget) {
		clear(rewritten)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_REWRITE_TARGET_CHANGED")
	}
	clear(rewritten)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RestoreTransferredLocalOwnedBackupOwner(canceled,
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destination)
	localRestoreOwnerRefuse("LOCAL_OWNED_BACKUP_RESTORE_OWNER_CANCEL_ACCEPTED",
		ErrLocalOwnedBackupCanceled, personal.VaultFileOwnershipPublic{}, err)
	if owners, err := destination.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sibling {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_CANCEL_MUTATED")
	}
	if after := localRestoreOwnerDevice(t, destination); after != destDevice {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_OWNER_CANCEL_DEVICE_CHANGED")
	}
}
