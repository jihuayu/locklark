//go:build darwin || linux

package desktop

import (
	"os"
	"sync/atomic"
	"testing"
)

func localVaultRefreshMoveManifestForFailure(t *testing.T, path string) {
	t.Helper()
	moved := path + ".refresh-failure"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_MANIFEST_MOVE_FAILED")
	}
	t.Cleanup(func() { _ = os.Rename(moved, path) })
}

// TestDesktopLocalVaultRefreshFailureDetachTracksAdoptedClose proves a real
// current-exact Summary failure hands the adopted wrapper to the tracked close
// helper instead of dropping slot.session. The tracked close worker pauses
// immediately before the idempotent wrapper Close, so the tail must remain
// unfinished while the cache/projection are already gone and the sibling B
// wrapper remains readable. Releasing the worker completes the tail.
func TestDesktopLocalVaultRefreshFailureDetachTracksAdoptedClose(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if aSlot == nil || aSlot.session == nil || bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_SETUP_FAILED")
	}
	aWrapper, bWrapper := aSlot.session, bSlot.session
	localVaultRefreshSelect(t, f, aScope)

	success := f.app.beginLocalVaultFileRefresh(aScope)
	if success == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_PRECONDITION_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if success.finiteOutcome() != localVaultFileRefreshOutcomeVerified ||
		f.app.localVaultFiles.viewVerification != localVaultFileViewFresh ||
		aSlot.summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_PRECONDITION_NOT_FRESH")
	}

	localVaultRefreshMoveManifestForFailure(t, aPath)

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	op := f.app.beginLocalVaultFileRefresh(aScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeFailed {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_NOT_STAGED")
	}
	if aSlot.closeTail != nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_INSTALLED_BEFORE_CALLBACK")
	}
	q.runDispatch(t)
	if op.finiteOutcome() != localVaultFileRefreshOutcomeFailed {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_NOT_FINITE")
	}
	tail := aSlot.closeTail
	if tail == nil || aSlot.session != nil || aSlot.summary.VaultID != "" {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_NOT_TRACKED")
	}
	if localVaultFileCloseTailFinished(tail) {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_FINISHED_EARLY")
	}
	if read, ok := f.app.readLocalVaultFileSession(aScope); ok || read.VaultID != "" {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_CACHE_STILL_READABLE")
	}
	if f.app.localVaultFiles.viewVerification != localVaultFileViewFailed ||
		f.app.localVaultFileRefreshCaption() != localVaultFileFailedCaption {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_NOT_FINITE_FEEDBACK")
	}

	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_REFRESH_FAILURE_TAIL_CLOSE_NOT_ENTERED")
	if localVaultFileCloseTailFinished(tail) {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_FINISHED_WHILE_CLOSE_PAUSED")
	}
	sibling, err := bWrapper.Summary()
	if err != nil || sibling.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_SIBLING_LOST")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_REFRESH_FAILURE_TAIL_CLOSE_STUCK")
	waitLocalVaultFileCloseTail(t, tail)
	if tail.result != localVaultFileCloseResultSucceeded {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_UNCLEAN_CLOSE")
	}
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_WRAPPER_STILL_READABLE")
	}
	if _, err := bWrapper.Summary(); err != nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_SIBLING_REMOVED")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_FAILURE_TAIL_PARENT_CHANGED")
	}
}

// TestDesktopLocalVaultRefreshFailureCancelBeforeCallbackKeepsAdoptedSlot
// cancels the view read before the failed callback is dispatched. The late
// callback must be a no-op: the tracked close seam is never entered, no tail is
// installed, and slot.session is not detached by the stale read. Normal owner
// cleanup afterwards is allowed but is not part of the tested acceptance path.
func TestDesktopLocalVaultRefreshFailureCancelBeforeCallbackKeepsAdoptedSlot(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if aSlot == nil || aSlot.session == nil || bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_SETUP_FAILED")
	}
	aWrapper, bWrapper := aSlot.session, bSlot.session
	localVaultRefreshSelect(t, f, aScope)

	success := f.app.beginLocalVaultFileRefresh(aScope)
	if success == nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_PRECONDITION_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if success.finiteOutcome() != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_PRECONDITION_NOT_FRESH")
	}

	localVaultRefreshMoveManifestForFailure(t, aPath)

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	op := f.app.beginLocalVaultFileRefresh(aScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeFailed {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_NOT_STAGED")
	}

	f.app.closeLocalVaultFileView()
	if op.finiteOutcome() != localVaultFileRefreshOutcomeCancelled {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_NOT_CANCELLED")
	}
	q.runDispatch(t)
	if aSlot.session != aWrapper || aSlot.closeTail != nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_LATE_CALLBACK_DETACHED")
	}
	select {
	case <-closeEntered:
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_TRACKED_CLOSE_ENTERED")
	default:
	}
	sibling, err := bWrapper.Summary()
	if err != nil || sibling.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_SIBLING_LOST")
	}

	// Normal owner cleanup after the acceptance assertions: this is not the
	// canceled failure callback and cannot manufacture the checked result.
	f.app.closeLocalVaultFileSession(aScope)
	if aSlot.closeTail == nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_CLEANUP_NOT_TRACKED")
	}
	cleanupTail := aSlot.closeTail
	cleanupWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_REFRESH_CANCEL_TAIL_CLEANUP_CLOSE_NOT_ENTERED")
	close(closeRelease)
	awaitLocalVaultSignal(t, cleanupWorker, "LOCAL_REFRESH_CANCEL_TAIL_CLEANUP_CLOSE_STUCK")
	waitLocalVaultFileCloseTail(t, cleanupTail)
	if cleanupTail.result != localVaultFileCloseResultSucceeded {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_CLEANUP_UNCLEAN_CLOSE")
	}
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_TAIL_CLEANED_WRAPPER_STILL_READABLE")
	}
}
