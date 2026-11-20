//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// localCleanRecoveryVault is one transferred source artifact after its owner
// record has been restored into the clean account and its exact authenticated
// R0 has been admitted and materialized as a dedicated baseline journal. It
// retains only test-local copies used for byte assertions.
type localCleanRecoveryVault struct {
	fx       *localCustodyFileFixture
	transfer *localRestorePreflightFixture
	r0       []byte
	journal  string
	pin      personal.VaultFileManagedDeviceSuccessorPin
}

func (v *localCleanRecoveryVault) clear() {
	if v == nil {
		return
	}
	clear(v.r0)
	clear(v.pin.Checkpoint.OwnerRootPublicKey)
	clear(v.pin.Checkpoint.PolicyDigest)
	*v = localCleanRecoveryVault{}
}

// scopeManifest lets the existing journal/backend observation helper read the
// exact dedicated journal and selected named backend object for this vault.
func (v *localCleanRecoveryVault) scopeManifest() Manifest {
	return Manifest{
		Journal:     v.journal,
		BackendRoot: v.transfer.locator.Root,
		Name:        v.transfer.locator.Name,
	}
}

func localCleanRecoveryReadTarget(t *testing.T,
	locator LocalOwnedBackupRestoreBackendLocator) ([]byte, vaultfilebackend.Revision) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(locator.Root)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_TARGET_OPEN_FAILED")
	}
	result, readErr := backend.Read(context.Background(), locator.Name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil {
		clear(result.Bytes)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_TARGET_READ_FAILED")
	}
	return result.Bytes, result.Revision
}

func localCleanRecoveryAssertArtifact(t *testing.T, path string, want []byte) {
	t.Helper()
	info, statErr := os.Lstat(path)
	raw, err := os.ReadFile(path)
	if statErr != nil || err != nil || !info.Mode().IsRegular() ||
		info.Size() != int64(len(want)) ||
		sha256.Sum256(raw) != sha256.Sum256(want) ||
		!bytes.Equal(raw, want) {
		clear(raw)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_ARTIFACT_CHANGED")
	}
	clear(raw)
}

// localCleanRecoveryExpectedItems reads the source's ordinary read-only child
// projection before its account is closed. The destination projection is later
// required to equal this exact source projection, including the unique item ID.
func localCleanRecoveryExpectedItems(t *testing.T,
	fx *localCustodyFileFixture) []personal.VaultFileBaselineItem {
	t.Helper()
	target := personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: fx.v.manifest.BackendRoot, BackendName: fx.v.manifest.Name,
		Pin: cloneLocalGenesisGenesisPin(fx.v.pin),
	}
	defer clear(target.Pin.Root.OwnerRootPublicKey)
	token, items, err := fx.v.session.OpenOwnedFirstSuccessorVaultFileChild(
		fx.v.manifest.Journal, target, fx.v.checkpoint, fx.v.f.password, fx.v.f.key,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		clearLocalGenesisItems(items)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_CHILD_OPEN_FAILED")
	}
	if err := fx.v.session.LockVaultFileChild(token); err != nil {
		clearLocalGenesisItems(items)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_CHILD_CLOSE_FAILED")
	}
	return items
}

// localCleanRecoveryCloseSource makes the original account unavailable to the
// rest of the test: the live session is locked and the original config and
// personal database are removed. The transferred artifact remains a separate
// private file, and the selected backend object remains the independent target.
func localCleanRecoveryCloseSource(t *testing.T, fx *localCustodyFileFixture) {
	t.Helper()
	fx.v.session.Lock()
	if fx.v.session.Unlocked() {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_SESSION_LIVE")
	}
	if err := os.Remove(fx.v.config); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_CONFIG_REMOVE_FAILED")
	}
	if err := os.Remove(fx.v.manifest.PersonalFile); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_DATABASE_REMOVE_FAILED")
	}
	for _, path := range []string{fx.v.config, fx.v.manifest.PersonalFile} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_STILL_PRESENT")
		}
	}
}

// localCleanRecoveryPrepareTarget independently admits the transferred artifact
// against its exact selected target, then uses the normal product initializer to
// create the one dedicated generation-zero journal that the existing
// managed-successor publish path requires. The destination is the same
// already-restored full-factor account, and the initializer re-authenticates the
// exact admitted target and the owner scope for this vault before its O_EXCL
// create. The returned result and a fresh local journal read must both carry the
// independently authenticated sealed R0, opaque revision, owner root and
// generation zero; the existing publish path still re-reads and verifies the
// same base before its single CAS.
func localCleanRecoveryPrepareTarget(t *testing.T, label string, fx *localCustodyFileFixture,
	transfer *localRestorePreflightFixture, artifact, sourceTarget []byte,
	sourceRevision vaultfilebackend.Revision, destRoot string,
	destination *personal.Session) *localCleanRecoveryVault {
	t.Helper()
	localCleanRecoveryAssertArtifact(t, transfer.path, artifact)

	admission, err := AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_ADMISSION_FAILED")
	}
	if admission.VaultID != transfer.pin.VaultID ||
		admission.ArtifactSize != transfer.pin.ArtifactSize ||
		admission.ArtifactSHA256 != transfer.pin.ArtifactSHA256 ||
		admission.SourceIdentity != transfer.pin.SourceIdentity ||
		admission.CheckpointDigest != transfer.pin.CheckpointDigest ||
		admission.JournalRevision != transfer.pin.JournalRevision ||
		admission.BackendRevision != transfer.pin.BackendRevision ||
		admission.OriginRevision != transfer.pin.OriginRevision ||
		admission.ContentSeq != transfer.pin.ContentSeq ||
		admission.TargetRevision != string(sourceRevision) ||
		admission.TargetSHA256 != sha256.Sum256(sourceTarget) ||
		sourceRevision != vaultfilebackend.Revision(transfer.saved.BackendRevision) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_ADMISSION_BINDING_FAILED")
	}

	r0, revision := localCleanRecoveryReadTarget(t, transfer.locator)
	if revision != sourceRevision || !bytes.Equal(r0, sourceTarget) ||
		sha256.Sum256(r0) != admission.TargetSHA256 {
		clear(r0)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_R0_CHANGED")
	}
	parsed, err := vaultfile.ParseFile(r0)
	if err != nil || parsed.Header.VaultID != admission.VaultID ||
		parsed.Header.ContentSeq != admission.ContentSeq ||
		vaultfile.VerifyPolicyCheckpoint(parsed, &transfer.expected) != nil {
		clear(r0)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_R0_INVALID")
	}

	dir := filepath.Join(destRoot, "clean-recovery-"+label)
	if err := os.Mkdir(dir, 0700); err != nil {
		clear(r0)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_JOURNAL_DIR_FAILED")
	}
	journal := filepath.Join(dir, "managed-successor.journal")
	initialization, err := InitializeTransferredLocalOwnedBackupManagedJournal(
		context.Background(), transfer.path, transfer.pin, transfer.expected,
		fx.factor, transfer.locator, destination, journal)
	if err != nil {
		clear(r0)
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_JOURNAL_INIT_FAILED: %v", err)
	}
	if initialization.VaultID != admission.VaultID ||
		initialization.OwnerRootKeyID != transfer.expected.OwnerRootKeyID ||
		initialization.Generation != 0 ||
		initialization.BaseSHA256 != sha256.Sum256(r0) ||
		initialization.BackendRevision != revision {
		clear(r0)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_JOURNAL_INIT_BINDING_FAILED")
	}
	// A stable local read of the newly initialized file must independently show
	// exactly the authenticated sealed R0, opaque revision and generation zero,
	// with no prepared, audit or managed-successor record yet.
	localManagedJournalExpectPristine(t, journal, r0, revision)

	v := &localCleanRecoveryVault{
		fx: fx, transfer: transfer,
		r0:      bytes.Clone(r0),
		journal: journal,
		pin: personal.VaultFileManagedDeviceSuccessorPin{
			Checkpoint:      localCustodyCheckpoint(&transfer.expected),
			KeyEpoch:        parsed.Header.KeyEpoch,
			ContentSeq:      parsed.Header.ContentSeq,
			SealedSHA256:    sha256.Sum256(r0),
			BackendRevision: revision,
		},
	}
	clear(r0)
	t.Cleanup(v.clear)
	return v
}

func localCleanRecoveryAssertManagedTarget(t *testing.T, v *localCleanRecoveryVault,
	receipt personal.VaultFileManagedDeviceSuccessorReceipt, destDevice personal.VaultFileDevicePublic) {
	t.Helper()
	if !receipt.Signed || !receipt.LocallyObserved ||
		receipt.VaultID != v.fx.v.manifest.VaultID ||
		receipt.BasePolicySeq != v.transfer.expected.PolicySeq ||
		receipt.NextPolicySeq != v.transfer.expected.PolicySeq+1 ||
		receipt.BaseKeyEpoch != v.pin.KeyEpoch ||
		receipt.NextKeyEpoch != v.pin.KeyEpoch+1 ||
		receipt.BaseContentSeq != v.pin.ContentSeq ||
		receipt.NextContentSeq != v.pin.ContentSeq+1 ||
		receipt.BaseSHA256 != v.pin.SealedSHA256 ||
		receipt.BaseRevision != v.pin.BackendRevision ||
		receipt.SuccessorRevision == "" ||
		receipt.SuccessorRevision == v.pin.BackendRevision ||
		receipt.SuccessorSHA256 == ([sha256.Size]byte{}) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_RECEIPT_FAILED")
	}
	target, revision := localCleanRecoveryReadTarget(t, v.transfer.locator)
	defer clear(target)
	if revision != receipt.SuccessorRevision ||
		sha256.Sum256(target) != receipt.SuccessorSHA256 ||
		bytes.Equal(target, v.r0) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_TARGET_FAILED")
	}
	if err := vaultfile.VerifyManagedTransition(v.r0, target, &v.transfer.expected); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_TRANSITION_FAILED")
	}
	successor, err := vaultfile.ParseFile(target)
	if err != nil || successor.Header.VaultID != receipt.VaultID ||
		successor.Header.PolicySeq != receipt.NextPolicySeq ||
		successor.Header.KeyEpoch != receipt.NextKeyEpoch ||
		successor.Header.ContentSeq != receipt.NextContentSeq ||
		vaultfile.VerifyPolicyCheckpoint(successor, &receipt.Next) != nil ||
		len(successor.SignedPolicyProofs) == 0 {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_SUCCESSOR_FAILED")
	}
	policy := &successor.SignedPolicyProofs[len(successor.SignedPolicyProofs)-1].Policy
	found := ""
	for i := range policy.Devices {
		device := &policy.Devices[i]
		if device.AgeEncryptionKey != destDevice.AgeRecipient ||
			hex.EncodeToString(device.ContentSigningKey.PublicKey) != destDevice.ContentSigningPublicKey {
			continue
		}
		if found != "" {
			t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_DEVICE_AMBIGUOUS")
		}
		found = device.DeviceID
	}
	if found == "" || found != receipt.DestinationDeviceID {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_DEVICE_FAILED")
	}
}

func localCleanRecoveryAssertSettledJournal(t *testing.T, v *localCleanRecoveryVault,
	receipt personal.VaultFileManagedDeviceSuccessorReceipt) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(v.journal)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_JOURNAL_OPEN_FAILED")
	}
	state, loadErr := j.LoadState()
	_, preparedErr := j.LoadPrepared()
	binding, bindingErr := j.LoadManagedSuccessorBinding()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil ||
		!errors.Is(preparedErr, vaultfilejournal.ErrEmpty) ||
		bindingErr != nil || state.Generation != 1 ||
		state.RemoteRevision != receipt.SuccessorRevision ||
		sha256.Sum256(state.BaseBytes) != receipt.SuccessorSHA256 ||
		!bytes.Equal(state.BaseBytes, state.WorkingBytes) ||
		binding.Generation != 1 || binding.OperationID != receipt.OperationID ||
		binding.TargetDigest == ([sha256.Size]byte{}) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SETTLED_JOURNAL_FAILED")
	}
}

func localCleanRecoveryAssertItems(t *testing.T, got, want []personal.VaultFileBaselineItem,
	code string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatal(code)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(code)
		}
	}
}

func TestLocalOwnedTwoVaultCleanRecoveryReopensIndependentChildren(t *testing.T) {
	passwordA := []byte("local-clean-two-vault-a")
	keyA := bytes.Repeat([]byte{0x35}, 16)
	passwordB := []byte("local-clean-two-vault-b")
	keyB := bytes.Repeat([]byte{0x76}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	// Two source accounts and two owned vaults, each with its own artifact,
	// recovery factor and checkpoints. The shared title is deliberate: the
	// unique persisted item ID and the exact source projection prove provenance.
	fxA := newLocalCustodyFileFixture(t, "clean-recovery-a", passwordA, keyA,
		localFirstWriteSecret+"-clean-recovery-a")
	fxB := newLocalCustodyFileFixture(t, "clean-recovery-b", passwordB, keyB,
		localFirstWriteSecret+"-clean-recovery-b")
	transferA := newLocalRestorePreflightFixture(t, fxA, "clean-recovery-a")
	transferB := newLocalRestorePreflightFixture(t, fxB, "clean-recovery-b")

	sourceOwnershipA := localRestoreOwnerSource(t, fxA.v.session)
	sourceOwnershipB := localRestoreOwnerSource(t, fxB.v.session)
	sourceDeviceA := localRestoreOwnerDevice(t, fxA.v.session)
	sourceDeviceB := localRestoreOwnerDevice(t, fxB.v.session)
	expectedItemsA := localCleanRecoveryExpectedItems(t, fxA)
	defer clearLocalGenesisItems(expectedItemsA)
	expectedItemsB := localCleanRecoveryExpectedItems(t, fxB)
	defer clearLocalGenesisItems(expectedItemsB)
	if len(expectedItemsA) != 1 || len(expectedItemsB) != 1 ||
		expectedItemsA[0].Title != expectedItemsB[0].Title ||
		expectedItemsA[0].ID == expectedItemsB[0].ID ||
		expectedItemsA[0].ID != fxA.v.item.ID ||
		expectedItemsB[0].ID != fxB.v.item.ID {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_PROJECTION_FAILED")
	}
	if sourceOwnershipA.VaultID == sourceOwnershipB.VaultID {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_VAULT_REUSED")
	}

	artifactA := bytes.Clone(fxA.artifact)
	defer clear(artifactA)
	artifactB := bytes.Clone(fxB.artifact)
	defer clear(artifactB)
	if bytes.Equal(artifactA, artifactB) ||
		bytes.Contains(artifactA, fxA.material) || bytes.Contains(artifactA, fxB.material) ||
		bytes.Contains(artifactB, fxA.material) || bytes.Contains(artifactB, fxB.material) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_ARTIFACTS_NOT_INDEPENDENT")
	}
	localCleanRecoveryAssertArtifact(t, transferA.path, artifactA)
	localCleanRecoveryAssertArtifact(t, transferB.path, artifactB)

	sourceTargetA, sourceRevisionA := localRestorePreflightTarget(t, fxA.v)
	defer clear(sourceTargetA)
	sourceTargetB, sourceRevisionB := localRestorePreflightTarget(t, fxB.v)
	defer clear(sourceTargetB)
	if sourceRevisionA != vaultfilebackend.Revision(transferA.pin.BackendRevision) ||
		sourceRevisionB != vaultfilebackend.Revision(transferB.pin.BackendRevision) ||
		bytes.Equal(sourceTargetA, sourceTargetB) ||
		sourceRevisionA == sourceRevisionB {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_SOURCE_TARGETS_NOT_INDEPENDENT")
	}

	// The original accounts are made unavailable before any restore: no live
	// source Session, no original config and no original personal database.
	localCleanRecoveryCloseSource(t, fxA)
	localCleanRecoveryCloseSource(t, fxB)

	destPassword := []byte("local-clean-two-vault-destination")
	destKey := bytes.Repeat([]byte{0x57}, 16)
	defer clear(destPassword)
	defer clear(destKey)
	dest := localIsolationCreation(t, "clean-two-vault-destination", destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_DESTINATION_UNLOCK_FAILED")
	}
	defer destination.Lock()
	destDevice := localRestoreOwnerDevice(t, destination)
	if destDevice == sourceDeviceA || destDevice == sourceDeviceB {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_DESTINATION_DEVICE_REUSED")
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil || len(owners) != 0 {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_DESTINATION_NOT_CLEAN")
	}

	// Vault A's artifact and every independently trusted input stay correct for
	// vault A. Only the recovery factor is varied to vault B's factor. The
	// operation must return the typed refusal and the zero typed ownership
	// projection without writing an owner or changing either named target.
	beforeA, beforeARevision := localCleanRecoveryReadTarget(t, transferA.locator)
	defer clear(beforeA)
	beforeB, beforeBRevision := localCleanRecoveryReadTarget(t, transferB.locator)
	defer clear(beforeB)
	projection, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transferA.path, transferA.pin, transferA.expected, fxB.factor,
		transferA.locator, destination)
	if !errors.Is(err, ErrLocalOwnedBackupReview) ||
		projection != (personal.VaultFileOwnershipPublic{}) {
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CROSS_FACTOR_REFUSAL_FAILED: %v", err)
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil || len(owners) != 0 {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CROSS_FACTOR_WROTE_OWNER")
	}
	if after := localRestoreOwnerDevice(t, destination); after != destDevice {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CROSS_FACTOR_CHANGED_DEVICE")
	}
	afterA, afterARevision := localCleanRecoveryReadTarget(t, transferA.locator)
	if afterARevision != beforeARevision || !bytes.Equal(afterA, beforeA) {
		clear(afterA)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CROSS_FACTOR_CHANGED_TARGET_A")
	}
	clear(afterA)
	afterB, afterBRevision := localCleanRecoveryReadTarget(t, transferB.locator)
	if afterBRevision != beforeBRevision || !bytes.Equal(afterB, beforeB) {
		clear(afterB)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CROSS_FACTOR_CHANGED_TARGET_B")
	}
	clear(afterB)
	localCleanRecoveryAssertArtifact(t, transferA.path, artifactA)
	localCleanRecoveryAssertArtifact(t, transferB.path, artifactB)

	restoredA, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transferA.path, transferA.pin, transferA.expected, fxA.factor,
		transferA.locator, destination)
	if err != nil || restoredA != sourceOwnershipA {
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_RESTORE_A_FAILED: %v", err)
	}
	if owners, err := destination.VaultFileOwnerships(); err != nil ||
		len(owners) != 1 || owners[0] != sourceOwnershipA {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_RESTORE_A_PROJECTION_FAILED")
	}
	restoredB, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transferB.path, transferB.pin, transferB.expected, fxB.factor,
		transferB.locator, destination)
	if err != nil || restoredB != sourceOwnershipB {
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_RESTORE_B_FAILED: %v", err)
	}
	owners, err := destination.VaultFileOwnerships()
	if err != nil || len(owners) != 2 ||
		(owners[0] != sourceOwnershipA && owners[0] != sourceOwnershipB) ||
		(owners[1] != sourceOwnershipA && owners[1] != sourceOwnershipB) ||
		owners[0] == owners[1] {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_RESTORE_PROJECTIONS_FAILED")
	}
	if after := localRestoreOwnerDevice(t, destination); after != destDevice {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_DESTINATION_DEVICE_CHANGED")
	}
	localCleanRecoveryAssertArtifact(t, transferA.path, artifactA)
	localCleanRecoveryAssertArtifact(t, transferB.path, artifactB)

	// Restores are read-only on the selected targets. The R0 bytes and opaque
	// pins independently transported with each artifact remain exact.
	for _, check := range []struct {
		locator  LocalOwnedBackupRestoreBackendLocator
		target   []byte
		revision vaultfilebackend.Revision
	}{
		{transferA.locator, sourceTargetA, sourceRevisionA},
		{transferB.locator, sourceTargetB, sourceRevisionB},
	} {
		target, revision := localCleanRecoveryReadTarget(t, check.locator)
		if revision != check.revision || !bytes.Equal(target, check.target) {
			clear(target)
			t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_RESTORE_CHANGED_TARGET")
		}
		clear(target)
	}

	vaultA := localCleanRecoveryPrepareTarget(t, "a", fxA, transferA,
		artifactA, sourceTargetA, sourceRevisionA, dest.root, destination)
	vaultB := localCleanRecoveryPrepareTarget(t, "b", fxB, transferB,
		artifactB, sourceTargetB, sourceRevisionB, dest.root, destination)
	if vaultA.journal == vaultB.journal ||
		vaultA.pin.BackendRevision == vaultB.pin.BackendRevision ||
		vaultA.pin.SealedSHA256 == vaultB.pin.SealedSHA256 {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_R0_SCOPES_NOT_INDEPENDENT")
	}

	scopeA0 := localFirstObserveScope(t, vaultA.scopeManifest())
	defer scopeA0.clear()
	scopeB0 := localFirstObserveScope(t, vaultB.scopeManifest())
	defer scopeB0.clear()
	if scopeA0.revision != sourceRevisionA || scopeB0.revision != sourceRevisionB {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_BASELINE_SCOPE_FAILED")
	}

	receiptA, err := destination.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		vaultA.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferA.locator.Root, Name: transferA.locator.Name,
		}, vaultA.pin)
	if err != nil {
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_PUBLISH_A_FAILED: %v", err)
	}
	defer receiptA.Clear()
	scopeB1 := localFirstObserveScope(t, vaultB.scopeManifest())
	defer scopeB1.clear()
	scopeB0.assertSame(t, scopeB1, "LOCAL_TWO_VAULT_CLEAN_RECOVERY_B_CHANGED_BY_A_PUBLISH")
	scopeA1 := localFirstObserveScope(t, vaultA.scopeManifest())
	defer scopeA1.clear()
	if scopeA1.revision == scopeA0.revision ||
		bytes.Equal(scopeA1.journal, scopeA0.journal) ||
		bytes.Equal(scopeA1.backend, scopeA0.backend) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_A_PUBLISH_NOT_SETTLED")
	}
	localCleanRecoveryAssertManagedTarget(t, vaultA, receiptA, destDevice)
	localCleanRecoveryAssertSettledJournal(t, vaultA, receiptA)
	localCleanRecoveryAssertArtifact(t, transferA.path, artifactA)

	receiptB, err := destination.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		vaultB.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferB.locator.Root, Name: transferB.locator.Name,
		}, vaultB.pin)
	if err != nil {
		t.Fatalf("LOCAL_TWO_VAULT_CLEAN_RECOVERY_PUBLISH_B_FAILED: %v", err)
	}
	defer receiptB.Clear()
	scopeA2 := localFirstObserveScope(t, vaultA.scopeManifest())
	defer scopeA2.clear()
	scopeA1.assertSame(t, scopeA2, "LOCAL_TWO_VAULT_CLEAN_RECOVERY_A_CHANGED_BY_B_PUBLISH")
	scopeB2 := localFirstObserveScope(t, vaultB.scopeManifest())
	defer scopeB2.clear()
	if scopeB2.revision == scopeB0.revision ||
		bytes.Equal(scopeB2.journal, scopeB0.journal) ||
		bytes.Equal(scopeB2.backend, scopeB0.backend) {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_B_PUBLISH_NOT_SETTLED")
	}
	localCleanRecoveryAssertManagedTarget(t, vaultB, receiptB, destDevice)
	localCleanRecoveryAssertSettledJournal(t, vaultB, receiptB)
	localCleanRecoveryAssertArtifact(t, transferB.path, artifactB)
	if receiptA.VaultID == receiptB.VaultID ||
		receiptA.OperationID == receiptB.OperationID ||
		receiptA.SuccessorRevision == receiptB.SuccessorRevision ||
		receiptA.SuccessorSHA256 == receiptB.SuccessorSHA256 {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_MANAGED_IDENTITIES_NOT_UNIQUE")
	}

	// Lock the active destination and freshly unlock it using both factors.
	// Only the durable account, the two dedicated journals and the two selected
	// named backend objects may contribute to the reopened children.
	destination.Lock()
	fresh, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_UNLOCK_FAILED")
	}
	defer fresh.Lock()
	owners, err = fresh.VaultFileOwnerships()
	if err != nil || len(owners) != 2 ||
		(owners[0] != sourceOwnershipA && owners[0] != sourceOwnershipB) ||
		(owners[1] != sourceOwnershipA && owners[1] != sourceOwnershipB) ||
		owners[0] == owners[1] {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_OWNERS_FAILED")
	}
	if after := localRestoreOwnerDevice(t, fresh); after != destDevice {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_DEVICE_CHANGED")
	}

	tokenA, itemsA, err := fresh.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		vaultA.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferA.locator.Root, Name: transferA.locator.Name,
		}, vaultA.pin, destPassword, destKey,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_OPEN_FAILED")
	}
	defer clearLocalGenesisItems(itemsA)
	tokenB, itemsB, err := fresh.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		vaultB.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferB.locator.Root, Name: transferB.locator.Name,
		}, vaultB.pin, destPassword, destKey,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_B_OPEN_FAILED")
	}
	defer clearLocalGenesisItems(itemsB)
	localCleanRecoveryAssertItems(t, itemsA, expectedItemsA,
		"LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_PROJECTION_FAILED")
	localCleanRecoveryAssertItems(t, itemsB, expectedItemsB,
		"LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_B_PROJECTION_FAILED")

	// Read each child again through the ordinary read-only child capability and
	// prove the two independently settled effective versions are still exact.
	readA, err := fresh.ReadVaultFileChild(tokenA, personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_READ_FAILED")
	}
	defer clearLocalGenesisItems(readA)
	readB, err := fresh.ReadVaultFileChild(tokenB, personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_B_READ_FAILED")
	}
	defer clearLocalGenesisItems(readB)
	localCleanRecoveryAssertItems(t, readA, expectedItemsA,
		"LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_READ_PROJECTION_FAILED")
	localCleanRecoveryAssertItems(t, readB, expectedItemsB,
		"LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_B_READ_PROJECTION_FAILED")
	localCleanRecoveryAssertSettledJournal(t, vaultA, receiptA)
	localCleanRecoveryAssertSettledJournal(t, vaultB, receiptB)
	localCleanRecoveryAssertManagedTarget(t, vaultA, receiptA, destDevice)
	localCleanRecoveryAssertManagedTarget(t, vaultB, receiptB, destDevice)

	// Closing one child must leave the other independently current.
	if err := fresh.LockVaultFileChild(tokenA); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_CLOSE_FAILED")
	}
	if closedA, err := fresh.ReadVaultFileChild(tokenA,
		personal.VaultFileChildOptions{IncludeItemIDs: true}); !errors.Is(err, personal.ErrVaultFileScopedChild) ||
		len(closedA) != 0 {
		clearLocalGenesisItems(closedA)
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_A_READ_AFTER_CLOSE")
	}
	afterCloseB, err := fresh.ReadVaultFileChild(tokenB,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_CHILD_B_HURT_BY_A_CLOSE")
	}
	defer clearLocalGenesisItems(afterCloseB)
	localCleanRecoveryAssertItems(t, afterCloseB, expectedItemsB,
		"LOCAL_TWO_VAULT_CLEAN_RECOVERY_CHILD_B_CHANGED_BY_A_CLOSE")
	scopeA3 := localFirstObserveScope(t, vaultA.scopeManifest())
	defer scopeA3.clear()
	scopeA2.assertSame(t, scopeA3, "LOCAL_TWO_VAULT_CLEAN_RECOVERY_A_CHANGED_BY_CHILD_CLOSE")
	scopeB3 := localFirstObserveScope(t, vaultB.scopeManifest())
	defer scopeB3.clear()
	scopeB2.assertSame(t, scopeB3, "LOCAL_TWO_VAULT_CLEAN_RECOVERY_B_CHANGED_BY_CHILD_CLOSE")
	if err := fresh.LockVaultFileChild(tokenB); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CLEAN_RECOVERY_FRESH_CHILD_B_CLOSE_FAILED")
	}

	localCleanRecoveryAssertArtifact(t, transferA.path, artifactA)
	localCleanRecoveryAssertArtifact(t, transferB.path, artifactB)
}
