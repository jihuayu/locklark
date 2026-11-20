//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

func localManagedJournalPrivateDir(t *testing.T, root, label string) string {
	t.Helper()
	dir := filepath.Join(root, "managed-journal-"+label)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DIR_FAILED")
	}
	return dir
}

func localManagedJournalFileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_FILE_READ_FAILED")
	}
	defer clear(raw)
	return sha256.Sum256(raw)
}

func localManagedJournalExpectCurrentAccount(t *testing.T, destination *personal.Session,
	ownership personal.VaultFileOwnershipPublic, device personal.VaultFileDevicePublic) {
	t.Helper()
	owners, err := destination.VaultFileOwnerships()
	if err != nil || !localManagedJournalOwnersContain(owners, ownership) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_OWNER_CHANGED")
	}
	after, err := destination.VaultFileDevicePublic()
	if err != nil || after != device {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DEVICE_CHANGED")
	}
}

func localManagedJournalExpectPristine(t *testing.T, path string, base []byte,
	revision vaultfilebackend.Revision) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(path)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_OPEN_FAILED")
	}
	state, loadErr := j.LoadState()
	_, preparedErr := j.LoadPrepared()
	_, auditErr := j.LoadRebaseAudit(0)
	_, bindingErr := j.LoadManagedSuccessorBinding()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil || state.Generation != 0 ||
		!bytes.Equal(state.BaseBytes, base) ||
		!bytes.Equal(state.WorkingBytes, base) ||
		state.RemoteRevision != revision ||
		!errors.Is(preparedErr, vaultfilejournal.ErrEmpty) ||
		!errors.Is(auditErr, vaultfilejournal.ErrEmpty) ||
		!errors.Is(bindingErr, vaultfilejournal.ErrEmpty) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_STATE_NOT_PRISTINE")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("LOCAL_MANAGED_JOURNAL_NOT_PRIVATE_REGULAR")
	}
}

func localManagedJournalRefuse(t *testing.T, code string, category error,
	initialization LocalOwnedBackupManagedJournalInitialization, err error) {
	t.Helper()
	if !errors.Is(err, category) || initialization != (LocalOwnedBackupManagedJournalInitialization{}) {
		t.Fatalf("%s: %v", code, err)
	}
}

func TestLocalOwnedBackupManagedJournalInitializesPristineBaseline(t *testing.T) {
	sourcePassword := []byte("local-managed-journal-source")
	sourceKey := bytes.Repeat([]byte{0x2a}, 16)
	destPassword := []byte("local-managed-journal-destination")
	destKey := bytes.Repeat([]byte{0x5b}, 16)
	defer clear(sourcePassword)
	defer clear(sourceKey)
	defer clear(destPassword)
	defer clear(destKey)

	fx := newLocalCustodyFileFixture(t, "managed-journal", sourcePassword, sourceKey,
		localFirstWriteSecret+"-managed-journal")
	transfer := newLocalRestorePreflightFixture(t, fx, "managed")

	sourceOwnership := localRestoreOwnerSource(t, fx.v.session)
	fx.v.session.Lock()
	if err := os.Remove(fx.v.config); err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SOURCE_CONFIG_REMOVE_FAILED")
	}
	if err := os.Remove(fx.v.manifest.PersonalFile); err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SOURCE_DATABASE_REMOVE_FAILED")
	}

	dest := localIsolationCreation(t, "managed-journal-destination", destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile,
		destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DESTINATION_UNLOCK_FAILED")
	}
	defer destination.Lock()
	restored, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator, destination)
	if err != nil || restored != sourceOwnership {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_OWNER_RESTORE_FAILED: %v", err)
	}
	deviceBefore := localRestoreOwnerDevice(t, destination)
	databaseBefore := localManagedJournalFileDigest(t, dest.proposal.PersonalFile)
	targetBefore, revisionBefore := localRestorePreflightTarget(t, fx.v)
	defer clear(targetBefore)
	if revisionBefore != vaultfilebackend.Revision(transfer.saved.BackendRevision) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SOURCE_REVISION_MISMATCH")
	}

	journalPath := filepath.Join(
		localManagedJournalPrivateDir(t, dest.root, "positive"), "managed.journal")
	initialization, err := InitializeTransferredLocalOwnedBackupManagedJournal(
		context.Background(), transfer.path, transfer.pin, transfer.expected,
		fx.factor, transfer.locator, destination, journalPath)
	if err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_INITIALIZE_FAILED: %v", err)
	}
	if initialization.VaultID != fx.v.manifest.VaultID ||
		initialization.VaultID != transfer.saved.VaultID ||
		initialization.OwnerRootKeyID != fx.expected.OwnerRootKeyID ||
		initialization.Generation != 0 ||
		initialization.BaseSHA256 != sha256.Sum256(targetBefore) ||
		initialization.BackendRevision != revisionBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_RESULT_MISMATCH")
	}
	for _, value := range []any{initialization, &initialization} {
		formatted := fmt.Sprintf("%v|%+v|%#v", value, value, value)
		if formatted != localOwnedBackupManagedJournalRedacted+"|"+
			localOwnedBackupManagedJournalRedacted+"|"+localOwnedBackupManagedJournalRedacted {
			t.Fatal("LOCAL_MANAGED_JOURNAL_FORMAT_NOT_REDACTED")
		}
	}
	encoded, err := initialization.MarshalJSON()
	if err != nil || string(encoded) != "{}" {
		t.Fatal("LOCAL_MANAGED_JOURNAL_JSON_NOT_REDACTED")
	}

	localManagedJournalExpectPristine(t, journalPath, targetBefore, revisionBefore)
	targetAfter, revisionAfter := localRestorePreflightTarget(t, fx.v)
	defer clear(targetAfter)
	if revisionAfter != revisionBefore || !bytes.Equal(targetAfter, targetBefore) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_INITIALIZATION_MUTATED_BACKEND")
	}
	localManagedJournalExpectCurrentAccount(t, destination, sourceOwnership, deviceBefore)
	if owners, err := destination.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sourceOwnership {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SINGLE_OWNER_CHANGED")
	}
	if after := localManagedJournalFileDigest(t, dest.proposal.PersonalFile); after != databaseBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_INITIALIZATION_MUTATED_ACCOUNT")
	}

	// The existing managed publisher consumes this exact generation-zero
	// journal without a second construction path.
	baseFile, err := vaultfile.ParseFile(targetBefore)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_BASE_PARSE_FAILED")
	}
	pin := personal.VaultFileManagedDeviceSuccessorPin{
		Checkpoint:      cloneLocalOwnedBackupCustodyCheckpoint(fx.expected),
		KeyEpoch:        baseFile.Header.KeyEpoch,
		ContentSeq:      baseFile.Header.ContentSeq,
		SealedSHA256:    sha256.Sum256(targetBefore),
		BackendRevision: revisionBefore,
	}
	target := personal.VaultFileManagedDeviceSuccessorTarget{
		Root: transfer.locator.Root,
		Name: transfer.locator.Name,
	}
	receipt, err := destination.PublishVaultFileManagedDeviceSuccessor(
		context.Background(), journalPath, target, pin)
	if err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_PUBLISH_FAILED: %v", err)
	}
	defer receipt.Clear()
	if !receipt.Signed || !receipt.LocallyObserved ||
		receipt.BaseRevision != revisionBefore ||
		receipt.BaseSHA256 != sha256.Sum256(targetBefore) ||
		receipt.SuccessorRevision == "" ||
		receipt.SuccessorRevision == revisionBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_PUBLISH_RECEIPT_INVALID")
	}
}

func localManagedJournalOwnersEqual(a, b []personal.VaultFileOwnershipPublic) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func localManagedJournalOwnersContain(owners []personal.VaultFileOwnershipPublic,
	want personal.VaultFileOwnershipPublic) bool {
	for _, owner := range owners {
		if owner == want {
			return true
		}
	}
	return false
}

func TestLocalOwnedBackupManagedJournalInitializesTwoScopedOwners(t *testing.T) {
	passwordA := []byte("local-managed-journal-dual-source-a")
	passwordB := []byte("local-managed-journal-dual-source-b")
	keyA := bytes.Repeat([]byte{0x21}, 16)
	keyB := bytes.Repeat([]byte{0x63}, 16)
	destPassword := []byte("local-managed-journal-dual-destination")
	destKey := bytes.Repeat([]byte{0x75}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)
	defer clear(destPassword)
	defer clear(destKey)

	a := newLocalCustodyFileFixture(t, "managed-journal-dual-a", passwordA, keyA,
		localFirstWriteSecret+"-managed-journal-dual-a")
	b := newLocalCustodyFileFixture(t, "managed-journal-dual-b", passwordB, keyB,
		localFirstWriteSecret+"-managed-journal-dual-b")
	ta := newLocalRestorePreflightFixture(t, a, "dual-a")
	tb := newLocalRestorePreflightFixture(t, b, "dual-b")
	ownershipA := localRestoreOwnerSource(t, a.v.session)
	ownershipB := localRestoreOwnerSource(t, b.v.session)
	if ownershipA.VaultID == ownershipB.VaultID ||
		ownershipA.OwnerRootPublicKey == ownershipB.OwnerRootPublicKey {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_SOURCES_NOT_INDEPENDENT")
	}
	a.v.session.Lock()
	b.v.session.Lock()

	dest := localIsolationCreation(t, "managed-journal-dual-destination",
		destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile,
		destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_DESTINATION_UNLOCK_FAILED")
	}
	defer destination.Lock()
	for _, restore := range []struct {
		transfer *localRestorePreflightFixture
		factor   *personal.VaultFileBackupRecoveryFactor
	}{
		{ta, a.factor},
		{tb, b.factor},
	} {
		if _, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
			restore.transfer.path, restore.transfer.pin, restore.transfer.expected,
			restore.factor, restore.transfer.locator, destination); err != nil {
			t.Fatalf("LOCAL_MANAGED_JOURNAL_DUAL_OWNER_RESTORE_FAILED: %v", err)
		}
	}
	ownersBefore, err := destination.VaultFileOwnerships()
	if err != nil || len(ownersBefore) != 2 ||
		!localManagedJournalOwnersContain(ownersBefore, ownershipA) ||
		!localManagedJournalOwnersContain(ownersBefore, ownershipB) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_OWNERS_NOT_COPRESENT")
	}
	deviceBefore := localRestoreOwnerDevice(t, destination)
	databaseBefore := localManagedJournalFileDigest(t, dest.proposal.PersonalFile)
	targetA, revisionA := localRestorePreflightTarget(t, a.v)
	defer clear(targetA)
	targetB, revisionB := localRestorePreflightTarget(t, b.v)
	defer clear(targetB)
	if revisionA != vaultfilebackend.Revision(ta.saved.BackendRevision) ||
		revisionB != vaultfilebackend.Revision(tb.saved.BackendRevision) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_SOURCE_REVISION_MISMATCH")
	}
	artifactABefore := localManagedJournalFileDigest(t, ta.path)
	artifactBBefore := localManagedJournalFileDigest(t, tb.path)

	journalDir := localManagedJournalPrivateDir(t, dest.root, "dual")
	journalA := filepath.Join(journalDir, "a.journal")
	journalB := filepath.Join(journalDir, "b.journal")
	initializationA, err := InitializeTransferredLocalOwnedBackupManagedJournal(
		context.Background(), ta.path, ta.pin, ta.expected, a.factor,
		ta.locator, destination, journalA)
	if err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_DUAL_A_INITIALIZE_FAILED: %v", err)
	}
	if initializationA.VaultID != ownershipA.VaultID ||
		initializationA.OwnerRootKeyID != ownershipA.OwnerRootKeyID ||
		initializationA.BaseSHA256 != sha256.Sum256(targetA) ||
		initializationA.BackendRevision != revisionA {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_RESULT_MISMATCH")
	}
	localManagedJournalExpectPristine(t, journalA, targetA, revisionA)
	if _, err := os.Lstat(journalB); !os.IsNotExist(err) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_B_CREATED_EARLY")
	}
	localManagedJournalExpectCurrentAccount(t, destination, ownershipA, deviceBefore)
	if current, err := destination.VaultFileOwnerships(); err != nil ||
		!localManagedJournalOwnersEqual(current, ownersBefore) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_CHANGED_OWNERS")
	}
	if after := localManagedJournalFileDigest(t, dest.proposal.PersonalFile); after != databaseBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_MUTATED_ACCOUNT")
	}
	targetBAfterA, revisionBAfterA := localRestorePreflightTarget(t, b.v)
	defer clear(targetBAfterA)
	if revisionBAfterA != revisionB || !bytes.Equal(targetBAfterA, targetB) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_MUTATED_SIBLING_TARGET")
	}

	initializationB, err := InitializeTransferredLocalOwnedBackupManagedJournal(
		context.Background(), tb.path, tb.pin, tb.expected, b.factor,
		tb.locator, destination, journalB)
	if err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_DUAL_B_INITIALIZE_FAILED: %v", err)
	}
	if initializationB.VaultID != ownershipB.VaultID ||
		initializationB.OwnerRootKeyID != ownershipB.OwnerRootKeyID ||
		initializationB.BaseSHA256 != sha256.Sum256(targetB) ||
		initializationB.BackendRevision != revisionB {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_B_RESULT_MISMATCH")
	}
	localManagedJournalExpectPristine(t, journalB, targetB, revisionB)
	localManagedJournalExpectPristine(t, journalA, targetA, revisionA)
	targetAAfter, revisionAAfter := localRestorePreflightTarget(t, a.v)
	defer clear(targetAAfter)
	if revisionAAfter != revisionA || !bytes.Equal(targetAAfter, targetA) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_B_MUTATED_SIBLING_TARGET")
	}
	localManagedJournalExpectCurrentAccount(t, destination, ownershipA, deviceBefore)
	if after := localManagedJournalFileDigest(t, dest.proposal.PersonalFile); after != databaseBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_B_MUTATED_ACCOUNT")
	}
	if localManagedJournalFileDigest(t, ta.path) != artifactABefore ||
		localManagedJournalFileDigest(t, tb.path) != artifactBBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_MUTATED_ORIGINAL_ARTIFACTS")
	}

	// Publishing the A successor from its dedicated journal selects A's exact
	// owner record in the dual-vault account and leaves B's journal and target
	// untouched.
	baseFile, err := vaultfile.ParseFile(targetA)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_BASE_PARSE_FAILED")
	}
	receipt, err := destination.PublishVaultFileManagedDeviceSuccessor(
		context.Background(), journalA,
		personal.VaultFileManagedDeviceSuccessorTarget{
			Root: ta.locator.Root, Name: ta.locator.Name,
		},
		personal.VaultFileManagedDeviceSuccessorPin{
			Checkpoint:      cloneLocalOwnedBackupCustodyCheckpoint(ta.expected),
			KeyEpoch:        baseFile.Header.KeyEpoch,
			ContentSeq:      baseFile.Header.ContentSeq,
			SealedSHA256:    sha256.Sum256(targetA),
			BackendRevision: revisionA,
		})
	if err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_DUAL_A_PUBLISH_FAILED: %v", err)
	}
	defer receipt.Clear()
	if !receipt.Signed || !receipt.LocallyObserved ||
		receipt.VaultID != ownershipA.VaultID ||
		receipt.BaseRevision != revisionA ||
		receipt.SuccessorRevision == "" ||
		receipt.SuccessorRevision == revisionA {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_PUBLISH_RECEIPT_INVALID")
	}
	localManagedJournalExpectPristine(t, journalB, targetB, revisionB)
	targetBAfterPublish, revisionBAfterPublish := localRestorePreflightTarget(t, b.v)
	defer clear(targetBAfterPublish)
	if revisionBAfterPublish != revisionB ||
		!bytes.Equal(targetBAfterPublish, targetB) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_PUBLISH_MUTATED_SIBLING_TARGET")
	}
	if localManagedJournalFileDigest(t, ta.path) != artifactABefore ||
		localManagedJournalFileDigest(t, tb.path) != artifactBBefore {
		t.Fatal("LOCAL_MANAGED_JOURNAL_DUAL_A_PUBLISH_MUTATED_ORIGINAL_ARTIFACTS")
	}
}

func TestLocalOwnedBackupManagedJournalRefusesUnscopedAndExistingDestinations(t *testing.T) {
	passwordA := []byte("local-managed-journal-scope-a")
	passwordB := []byte("local-managed-journal-scope-b")
	keyA := bytes.Repeat([]byte{0x3c}, 16)
	keyB := bytes.Repeat([]byte{0x7d}, 16)
	destPassword := []byte("local-managed-journal-scope-destination")
	destKey := bytes.Repeat([]byte{0x4e}, 16)
	destPasswordB := []byte("local-managed-journal-scope-destination-b")
	destKeyB := bytes.Repeat([]byte{0x6f}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)
	defer clear(destPassword)
	defer clear(destKey)
	defer clear(destPasswordB)
	defer clear(destKeyB)

	a := newLocalCustodyFileFixture(t, "managed-journal-scope-a", passwordA, keyA,
		localFirstWriteSecret+"-managed-journal-scope-a")
	b := newLocalCustodyFileFixture(t, "managed-journal-scope-b", passwordB, keyB,
		localFirstWriteSecret+"-managed-journal-scope-b")
	ta := newLocalRestorePreflightFixture(t, a, "scope-a")
	tb := newLocalRestorePreflightFixture(t, b, "scope-b")

	destA := localIsolationCreation(t, "managed-journal-scope-destination", destPassword, destKey)
	destinationA, err := personal.UnlockSession(destA.proposal.PersonalFile,
		destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SCOPE_UNLOCK_FAILED")
	}
	defer destinationA.Lock()
	if _, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destinationA); err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_SCOPE_RESTORE_FAILED: %v", err)
	}
	journalDir := localManagedJournalPrivateDir(t, destA.root, "refusals")
	pathFor := func(name string) string { return filepath.Join(journalDir, name) }

	wrongPin := ta.pin
	wrongPin.BackendRevision += "-wrong"
	out, err := InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, wrongPin, ta.expected, a.factor, ta.locator, destinationA, pathFor("wrong-pin"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_WRONG_PIN_ACCEPTED",
		ErrLocalOwnedBackupReview, out, err)

	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, ta.pin, ta.expected, b.factor, ta.locator, destinationA, pathFor("wrong-factor"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_WRONG_FACTOR_ACCEPTED",
		ErrLocalOwnedBackupReview, out, err)

	// A destination account carrying the other restored vault is a
	// cross-vault/owner mismatch, never a second journal initialization.
	destB := localIsolationCreation(t, "managed-journal-scope-destination-b",
		destPasswordB, destKeyB)
	destinationB, err := personal.UnlockSession(destB.proposal.PersonalFile,
		destPasswordB, destKeyB, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_SCOPE_B_UNLOCK_FAILED")
	}
	defer destinationB.Lock()
	if _, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		tb.path, tb.pin, tb.expected, b.factor, tb.locator, destinationB); err != nil {
		t.Fatalf("LOCAL_MANAGED_JOURNAL_SCOPE_B_RESTORE_FAILED: %v", err)
	}
	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destinationB, pathFor("wrong-account"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_WRONG_ACCOUNT_ACCEPTED",
		ErrLocalOwnedBackupReview, out, err)

	missingLocator := ta.locator
	missingLocator.Name += "-absent"
	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, missingLocator, destinationA, pathFor("missing-target"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_MISSING_TARGET_ACCEPTED",
		ErrLocalOwnedBackupConflict, out, err)

	preexistingPath := pathFor("preexisting")
	preexisting := []byte("existing private journal placeholder")
	if err := os.WriteFile(preexistingPath, preexisting, 0600); err != nil {
		t.Fatal("LOCAL_MANAGED_JOURNAL_PREEXISTING_WRITE_FAILED")
	}
	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destinationA, preexistingPath)
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_PREEXISTING_ACCEPTED",
		ErrLocalOwnedBackupConflict, out, err)
	if raw, readErr := os.ReadFile(preexistingPath); readErr != nil ||
		!bytes.Equal(raw, preexisting) {
		clear(raw)
		t.Fatal("LOCAL_MANAGED_JOURNAL_PREEXISTING_CHANGED")
	} else {
		clear(raw)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(canceled,
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destinationA, pathFor("canceled"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_CANCEL_ACCEPTED",
		ErrLocalOwnedBackupCanceled, out, err)
	if _, statErr := os.Lstat(pathFor("canceled")); !os.IsNotExist(statErr) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_CANCEL_CREATED_TARGET")
	}

	// Concurrent initialization of the same exact path has exactly one
	// O_EXCL winner; the loser is a fixed conflict and the winner is pristine.
	concurrentPath := pathFor("concurrent")
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, results[index] = InitializeTransferredLocalOwnedBackupManagedJournal(
				context.Background(), ta.path, ta.pin, ta.expected, a.factor,
				ta.locator, destinationA, concurrentPath)
		}(i)
	}
	wg.Wait()
	winners, conflicts := 0, 0
	for _, result := range results {
		switch {
		case result == nil:
			winners++
		case errors.Is(result, ErrLocalOwnedBackupConflict):
			conflicts++
		default:
			t.Fatalf("LOCAL_MANAGED_JOURNAL_CONCURRENT_UNEXPECTED: %v", result)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("LOCAL_MANAGED_JOURNAL_CONCURRENT_NOT_EXCLUSIVE")
	}
	target, revision := localRestorePreflightTarget(t, a.v)
	defer clear(target)
	localManagedJournalExpectPristine(t, concurrentPath, target, revision)

	// The same authenticated bytes rewritten under a new opaque revision are
	// refused even though the content digest is unchanged.
	if sameBytesRevision := localFirstRewriteBackend(t, a.v.manifest,
		a.settled.record.SuccessorBytes); sameBytesRevision == vaultfilebackend.Revision(ta.saved.BackendRevision) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_REWRITE_REVISION_NOT_NEW")
	}
	out, err = InitializeTransferredLocalOwnedBackupManagedJournal(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator, destinationA, pathFor("new-revision"))
	localManagedJournalRefuse(t, "LOCAL_MANAGED_JOURNAL_NEW_REVISION_ACCEPTED",
		ErrLocalOwnedBackupConflict, out, err)
	if _, statErr := os.Lstat(pathFor("new-revision")); !os.IsNotExist(statErr) {
		t.Fatal("LOCAL_MANAGED_JOURNAL_NEW_REVISION_CREATED_TARGET")
	}
}
