//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceVerifiesObservedTwoVaults(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	if bytes.Equal(ev.artifacts[0], ev.artifacts[1]) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACTS_NOT_INDEPENDENT")
	}
	localWorkspaceBackupSetReopen(t, fx)

	want, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot, fx.artifacts)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_REFERENCE_FAILED")
	}
	set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
		fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_VERIFY_FAILED")
	}
	if !reflect.DeepEqual(set, want) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DIFFERS_FROM_POINT_IN_TIME")
	}
	if set.State != LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified ||
		!set.StopWritesProofOutstanding || !set.UnknownOfflineDraftsPossible ||
		!set.NewProfileImportOutstanding || !set.CutoverOutstanding ||
		!set.CompleteWorkspaceOutstanding {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_OUTCOME_OVERCLAIMED")
	}
	if len(set.Vaults) != 2 || set.Vaults[0].VaultID >= set.Vaults[1].VaultID {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_SHAPE_FAILED")
	}
	byID := make(map[string]LocalOwnedWorkspaceBackupVault, len(set.Vaults))
	for _, vault := range set.Vaults {
		byID[vault.VaultID] = vault
	}
	for _, entry := range fx.entries {
		vault, ok := byID[entry.vaultID]
		if !ok {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_VAULT_MISSING")
		}
		if vault.VaultID != entry.pin.VaultID ||
			vault.ArtifactSize != entry.pin.ArtifactSize ||
			vault.ArtifactSHA256 != entry.pin.ArtifactSHA256 ||
			vault.CheckpointDigest != entry.pin.CheckpointDigest ||
			vault.SourceIdentity != entry.pin.SourceIdentity ||
			string(vault.JournalRevision) != entry.pin.JournalRevision ||
			string(vault.BackendRevision) != entry.pin.BackendRevision ||
			string(vault.OriginRevision) != entry.pin.OriginRevision ||
			vault.ContentSeq != entry.pin.ContentSeq {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_BINDING_FAILED")
		}
		target, revision := localFirstReadBackend(t, entry.manifest)
		if revision != vault.BackendRevision || revision != vault.JournalRevision ||
			revision != vaultfilebackend.Revision(entry.pin.BackendRevision) {
			clear(target)
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_REVISION_BINDING_FAILED")
		}
		clear(target)
	}
	localWorkspaceBackupSetAssertRedacted(t, set, fx)
	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_ARTIFACTS")
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceBlocksWriterUntilRelease(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	entry := fx.entries[0]
	current, revision := localFirstReadBackend(t, entry.manifest)
	defer clear(current)

	writer, err := vaultfilebackend.OpenExistingDir(fx.backendRoot)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_OPEN_FAILED")
	}
	defer func() { _ = writer.Close() }()

	fenceEntered := make(chan struct{})
	releaseFence := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFence) }) }
	defer release()
	var enterOnce sync.Once
	localOwnedWorkspaceBackupSetUnderFenceForTest = func() {
		enterOnce.Do(func() { close(fenceEntered) })
		<-releaseFence
	}
	defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()

	writerDone := make(chan error, 1)
	go func() {
		<-fenceEntered
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		writerDone <- writer.ReplaceIfVersion(ctx, entry.manifest.Name, revision, current)
	}()

	type result struct {
		set LocalOwnedWorkspaceBackupSet
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		resultCh <- result{set: set, err: err}
	}()

	select {
	case <-fenceEntered:
	case <-time.After(20 * time.Second):
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_NOT_ENTERED")
	}
	// The normal cooperating writer has the exact current revision and bytes.
	// While the fence is held its CAS must not complete.
	select {
	case err := <-writerDone:
		t.Fatalf("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_NOT_BLOCKED: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	release()

	got := <-resultCh
	if got.err != nil || got.set.State != LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified ||
		len(got.set.Vaults) != 2 {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DELIVERY_FAILED")
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_NOT_RELEASED")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_DID_NOT_FINISH")
	}

	after, afterRevision := localFirstReadBackend(t, entry.manifest)
	defer clear(after)
	if afterRevision == revision || !bytes.Equal(after, current) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_EFFECT_INCORRECT")
	}
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_WRITER_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceRetainsJournalsThroughDelivery(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, false)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	write := newLocalFirstWriteFixtureFor(t, fx.f, fx.f.firstConfig, fx.f.firstVaultID)

	var hookErr error
	localOwnedWorkspaceBackupSetBeforeDeliveryForTest = func() {
		// This is the ordinary writer's exact strict acceptance entry. A2 had
		// already closed this journal here, so the opener succeeded and the
		// writer could commit pending before waiting on the provider CAS.
		opened, err := vaultfilejournal.OpenExisting(write.manifest.Journal)
		if opened != nil {
			_ = opened.Close()
			hookErr = errors.New("journal opener returned a handle while fenced")
			return
		}
		if !errors.Is(err, vaultfilejournal.ErrLocked) {
			hookErr = errors.New("journal opener did not report ErrLocked while fenced")
		}
	}
	defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()

	set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
		fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
	if hookErr != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_OPEN_BOUNDARY_FAILED")
	}
	if err != nil || set.State != LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified ||
		len(set.Vaults) != 2 {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_RETENTION_DELIVERY_FAILED")
	}
	delivered := false
	for _, vault := range set.Vaults {
		if vault.VaultID != write.manifest.VaultID {
			continue
		}
		delivered = vault.JournalRevision == write.bootstrapRevision &&
			vault.BackendRevision == write.bootstrapRevision
	}
	if !delivered {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_DELIVERY_NOT_SETTLED")
	}

	writeResult, writeErr := write.write(context.Background())
	if writeErr != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_WRITER_FAILED")
	}
	if writeResult.Revision == "" || writeResult.Revision == string(write.bootstrapRevision) ||
		writeResult.JournalPath != write.manifest.Journal {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_WRITER_RESULT_INVALID")
	}
	record := localFirstReadRecord(t, write)
	backendBytes, backendRevision := localFirstReadBackend(t, write.manifest)
	defer clear(backendBytes)
	if string(record.SuccessorRevision) != writeResult.Revision ||
		backendRevision != vaultfilebackend.Revision(writeResult.Revision) ||
		!bytes.Equal(backendBytes, record.SuccessorBytes) ||
		bytes.Equal(backendBytes, write.genesis) {
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_BACKEND_MISMATCH")
	}
	clear(record.GenesisBytes)
	clear(record.SuccessorBytes)
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_ARTIFACTS")
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_JOURNAL_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceReleasesPartialJournalAcquisition(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, false)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	paths := []string{
		fx.entries[0].manifest.Journal,
		fx.entries[1].manifest.Journal,
	}
	sort.Strings(paths)
	first, second := paths[0], paths[1]
	if first == second {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_JOURNALS_NOT_DISTINCT")
	}

	var heldSecond *vaultfilejournal.Journal
	var hookErr error
	localOwnedWorkspaceBackupSetBeforeFenceForTest = func() {
		heldSecond, hookErr = vaultfilejournal.OpenExisting(second)
	}
	defer func() { localOwnedWorkspaceBackupSetBeforeFenceForTest = nil }()
	defer func() {
		if heldSecond != nil {
			_ = heldSecond.Close()
		}
	}()

	set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
		fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
	if hookErr != nil || heldSecond == nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_HOLD_FAILED")
	}
	localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_ACQUISITION_ACCEPTED",
		ErrLocalOwnedWorkspaceConflict, set, err)

	// B is still independently held. If the failed fenced acquisition leaked its
	// already-opened A handle, this real bbolt open cannot succeed.
	firstAgain, firstErr := vaultfilejournal.OpenExisting(first)
	if firstErr != nil || firstAgain == nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_FIRST_LEAKED")
	}
	if err := firstAgain.Close(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_FIRST_CLOSE_FAILED")
	}

	if err := heldSecond.Close(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_SECOND_CLOSE_FAILED")
	}
	heldSecond = nil
	secondAgain, secondErr := vaultfilejournal.OpenExisting(second)
	if secondErr != nil || secondAgain == nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_SECOND_NOT_RELEASED")
	}
	if err := secondAgain.Close(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_SECOND_CLOSE_FAILED")
	}

	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_CHANGED_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_CHANGED_ARTIFACTS")
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PARTIAL_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceRefusesChangedSource(t *testing.T) {
	t.Run("changed bytes", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		entry := fx.entries[0]
		original, _ := localFirstReadBackend(t, entry.manifest)
		changed := append([]byte(nil), original...)
		changed[len(changed)/2] ^= 0x40
		clear(original)
		localFirstRewriteBackend(t, entry.manifest, changed)
		clear(changed)
		before, beforeRevision := localFirstReadBackend(t, entry.manifest)

		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_BYTES_ACCEPTED",
			ErrLocalOwnedWorkspaceConflict, set, err)
		after, afterRevision := localFirstReadBackend(t, entry.manifest)
		if afterRevision != beforeRevision || !bytes.Equal(after, before) {
			clear(after)
			clear(before)
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_BYTES_MUTATED")
		}
		clear(after)
		clear(before)
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_BYTES_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_CHANGED_BYTES_ACTIVATED_SESSION")
		}
	})

	t.Run("same bytes new revision", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		entry := fx.entries[0]
		original, originalRevision := localFirstReadBackend(t, entry.manifest)
		newRevision := localFirstRewriteBackend(t, entry.manifest, original)
		if newRevision == originalRevision {
			clear(original)
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_REVISION_NOT_NEW")
		}
		clear(original)

		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_NEW_REVISION_ACCEPTED",
			ErrLocalOwnedWorkspaceConflict, set, err)
		after, afterRevision := localFirstReadBackend(t, entry.manifest)
		if afterRevision != newRevision {
			clear(after)
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_NEW_REVISION_MUTATED")
		}
		clear(after)
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_NEW_REVISION_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_NEW_REVISION_ACTIVATED_SESSION")
		}
	})

	t.Run("pending journal", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, false)
		write := newLocalFirstWriteFixtureFor(t, fx.f, fx.f.firstConfig, fx.f.firstVaultID)
		ctx, cancel := context.WithCancel(context.Background())
		localOwnedFirstWriteAfterPrepareForTest = cancel
		defer func() { localOwnedFirstWriteAfterPrepareForTest = nil }()
		if _, err := write.write(ctx); !errors.Is(err, ErrLocalOwnedFirstWriteIndeterminate) {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_NOT_PREPARED")
		}
		localOwnedFirstWriteAfterPrepareForTest = nil
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		pending, prepared := localFirstReadPending(t, write.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if opened, err := vaultfilejournal.OpenExistingSettledShape(write.manifest.Journal); opened != nil ||
			!errors.Is(err, vaultfilejournal.ErrPendingRecords) {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_STRUCTURAL_OPEN_ACCEPTED")
		}

		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_ACCEPTED",
			ErrLocalOwnedWorkspaceConflict, set, err)
		afterPending, afterPrepared := localFirstReadPending(t, write.manifest.Journal)
		defer clear(afterPending.BaseBytes)
		defer clear(afterPending.WorkingBytes)
		defer clear(afterPrepared.Proposal.Bytes)
		if !sameLocalOwnedFirstPrepared(prepared, afterPrepared) ||
			afterPending.Generation != pending.Generation {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_CHANGED")
		}
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_PENDING_ACTIVATED_SESSION")
		}
	})
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceRefusesReplacedProfile(t *testing.T) {
	replaceProfile := func(t *testing.T, fx *localWorkspaceBackupSetTestFixture) (string, string) {
		t.Helper()
		replacement := filepath.Join(fx.f.f.root, "fence-replaced-profile")
		copyLocalWorkspaceBackendTree(t, fx.profileDir, replacement)
		return replacement, fx.profileDir + ".moved"
	}
	refuse := func(t *testing.T, fx *localWorkspaceBackupSetTestFixture,
		ev *localWorkspaceBackupSetTestEvidence, code string, hookErr *error) {
		t.Helper()
		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		if *hookErr != nil {
			t.Fatal(code)
		}
		localWorkspaceBackupSetRefuse(t, code, ErrLocalOwnedWorkspaceConflict, set, err)
		ev.assertSourceSame(t, fx, code)
		ev.assertArtifactsSame(t, fx, code)
		if !fx.f.session.Unlocked() {
			t.Fatal(code)
		}
	}

	t.Run("immediately inside fence", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		replacement, old := replaceProfile(t, fx)
		var hookErr error
		localOwnedWorkspaceBackupSetUnderFenceForTest = func() {
			if err := os.Rename(fx.profileDir, old); err != nil {
				hookErr = err
				return
			}
			hookErr = os.Rename(replacement, fx.profileDir)
		}
		defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()
		refuse(t, fx, ev, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_PROFILE_IN_FENCE_ACCEPTED", &hookErr)
	})

	t.Run("during delivery rechecks", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		replacement, old := replaceProfile(t, fx)
		var hookErr error
		localOwnedWorkspaceBackupSetBeforeDeliveryForTest = func() {
			if err := os.Rename(fx.profileDir, old); err != nil {
				hookErr = err
				return
			}
			hookErr = os.Rename(replacement, fx.profileDir)
		}
		defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()
		refuse(t, fx, ev, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_PROFILE_DELIVERY_ACCEPTED", &hookErr)
	})
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceRefusesReplacedRoot(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	replacement := filepath.Join(fx.f.f.root, "fence-replaced-backend")
	copyLocalWorkspaceBackendTree(t, fx.backendRoot, replacement)
	oldRoot := fx.backendRoot + ".moved"
	var hookErr error
	localOwnedWorkspaceBackupSetBeforeFenceForTest = func() {
		if err := os.Rename(fx.backendRoot, oldRoot); err != nil {
			hookErr = err
			return
		}
		if err := os.Rename(replacement, fx.backendRoot); err != nil {
			hookErr = err
		}
	}
	defer func() { localOwnedWorkspaceBackupSetBeforeFenceForTest = nil }()

	set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
		fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
	if hookErr != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACE_ROOT_FAILED")
	}
	localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_ROOT_ACCEPTED",
		ErrLocalOwnedWorkspaceConflict, set, err)
	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_ROOT_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_ROOT_ARTIFACTS")
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_REPLACED_ROOT_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetMaintenanceFenceRefusesCancelLockAndDrift(t *testing.T) {
	t.Run("cancel at entry", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(ctx,
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CANCEL_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CANCEL_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_CANCEL_ARTIFACTS")
	})

	t.Run("cancel under fence", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		ctx, cancel := context.WithCancel(context.Background())
		localOwnedWorkspaceBackupSetUnderFenceForTest = cancel
		defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()
		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(ctx,
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_CANCEL_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_CANCEL_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_CANCEL_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_CANCEL_ACTIVATED_SESSION")
		}
	})

	t.Run("request lock under fence", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		localOwnedWorkspaceBackupSetUnderFenceForTest = fx.f.session.RequestLock
		defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()
		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_LOCK_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_LOCK_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_FENCED_LOCK_ARTIFACTS")
	})

	t.Run("artifact changed under fence", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		entry := fx.entries[0]
		original := mustReadFile(t, entry.pin.Path)
		defer clear(original)
		restored := false
		restore := func() {
			if restored {
				return
			}
			restored = true
			if err := os.WriteFile(entry.pin.Path, original, 0600); err != nil {
				t.Error("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_RESTORE_FAILED")
			}
		}
		localOwnedWorkspaceBackupSetUnderFenceForTest = func() {
			if err := os.Remove(entry.pin.Path); err != nil {
				t.Error("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_REMOVE_FAILED")
			}
		}
		defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()

		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		restore()
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_CHANGE_ACCEPTED",
			ErrLocalOwnedWorkspaceConflict, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_CHANGE_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_CHANGE_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_ARTIFACT_CHANGE_ACTIVATED_SESSION")
		}
	})

	t.Run("companion drift under fence", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		companion, err := CompanionPath(fx.entries[0].config)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_PATH_FAILED")
		}
		original := mustReadFile(t, companion)
		defer clear(original)
		restored := false
		restore := func() {
			if restored {
				return
			}
			restored = true
			if err := os.WriteFile(companion, original, 0600); err != nil {
				t.Error("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_RESTORE_FAILED")
			}
		}
		localOwnedWorkspaceBackupSetUnderFenceForTest = func() {
			changed := append([]byte(nil), original...)
			defer clear(changed)
			changed[len(changed)/2] ^= 0x40
			if err := os.WriteFile(companion, changed, 0600); err != nil {
				t.Error("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_WRITE_FAILED")
			}
		}
		defer func() { localOwnedWorkspaceBackupSetUnderFenceForTest = nil }()

		set, err := VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(context.Background(),
			fx.f.session, fx.profileDir, fx.backendRoot, fx.artifacts)
		restore()
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) &&
			!errors.Is(err, ErrLocalOwnedWorkspaceConflict) {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_ACCEPTED")
		}
		if !reflect.DeepEqual(set, LocalOwnedWorkspaceBackupSet{}) {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_DELIVERED")
		}
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_DRIFT_ACTIVATED_SESSION")
		}
	})
}

// copyLocalWorkspaceBackendTree copies the exact real namespace tree so a test
// can replace the established root with an equal-content directory that has a
// different inode. It does not bypass, mock or wrap the provider.
func copyLocalWorkspaceBackendTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(data)
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FENCE_COPY_ROOT_FAILED")
	}
}
