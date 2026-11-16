//go:build darwin || linux

package desktop

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func localVaultRefreshSelect(t *testing.T, f *localVaultSessionFixture, scope localVaultFileSessionScope) {
	t.Helper()
	f.app.closeLocalVaultFileView()
	f.app.localVaultFiles.selected = scope.configPath
}

func localVaultRefreshStaged(t *testing.T, op *localVaultFileRefreshOperation) localVaultFileRefreshResult {
	t.Helper()
	if op == nil {
		t.Fatal("LOCAL_REFRESH_OPERATION_MISSING")
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.ready {
		t.Fatal("LOCAL_REFRESH_RESULT_NOT_STAGED")
	}
	return localVaultFileRefreshResult{summary: op.summary, outcome: op.outcome}
}

func localVaultRefreshPendingState(t *testing.T, op *localVaultFileRefreshOperation) (bool, bool, int) {
	t.Helper()
	if op == nil {
		t.Fatal("LOCAL_REFRESH_OPERATION_MISSING")
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.ready, op.summary.VaultID == "", len(op.summary.Items)
}

// TestDesktopLocalVaultRefreshBorrowsCurrentWrapperAcrossSiblingClose proves a
// successful refresh is a real Summary of the already adopted B wrapper and
// that closing A through the existing C1 lifecycle leaves B's exact wrapper,
// its cache and the parent intact for a second real refresh.
func TestDesktopLocalVaultRefreshBorrowsCurrentWrapperAcrossSiblingClose(t *testing.T) {
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
	if aSlot == nil || bSlot == nil || aSlot.session == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_SIBLING_SETUP_FAILED")
	}
	aSession, bSession := aSlot.session, bSlot.session
	if aSession == bSession {
		t.Fatal("LOCAL_REFRESH_SIBLING_WRAPPERS_NOT_DISTINCT")
	}
	localVaultRefreshSelect(t, f, bScope)
	// Remove the cached projection so only a real wrapper Summary can restore
	// it with B's exact VaultID.
	bSlot.summary = vaultfileclient.LocalGenesisBaseline{}

	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil || op.wrapper != bSession || op.slot != bSlot {
		t.Fatal("LOCAL_REFRESH_BEGIN_DID_NOT_BORROW_EXACT_WRAPPER")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_START_CLAIMED_FRESH")
	}
	q.runLaunch(t)
	staged := localVaultRefreshStaged(t, op)
	if staged.outcome != localVaultFileRefreshOutcomeVerified ||
		staged.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_REAL_SUMMARY_MISSING")
	}
	q.runDispatch(t)
	if op.finiteOutcome() != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_SUCCESS_NOT_FINITE")
	}
	if bSlot.session != bSession || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_B_CACHE_NOT_UPDATED")
	}
	if f.app.localVaultFiles.viewVerification != localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() != localVaultFileFreshCaption {
		t.Fatal("LOCAL_REFRESH_SUCCESS_NOT_FRESH")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_BORROWED_WRAPPER_CLOSED")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_PARENT_LOCKED_WITH_CHILD")
	}

	// Close only A through the established C1 lifecycle helper.
	f.app.closeLocalVaultFileSession(aScope)
	q.drain(t)
	if _, err := aSession.Summary(); err == nil {
		t.Fatal("LOCAL_REFRESH_CLOSED_SIBLING_STILL_READS")
	}
	if bSlot.session != bSession {
		t.Fatal("LOCAL_REFRESH_SIBLING_CLOSE_LOST_B")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_SIBLING_CLOSE_LOCKED_PARENT")
	}
	parent, generation := f.app.session, f.app.generation

	op2 := f.app.beginLocalVaultFileRefresh(bScope)
	if op2 == nil || op2.wrapper != bSession || op2.slot != bSlot {
		t.Fatal("LOCAL_REFRESH_SECOND_BEGIN_DID_NOT_BORROW_SAME_WRAPPER")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op2); staged.outcome != localVaultFileRefreshOutcomeVerified ||
		staged.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_SECOND_REAL_SUMMARY_MISSING")
	}
	q.runDispatch(t)
	if op2.finiteOutcome() != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_SECOND_SUCCESS_NOT_FINITE")
	}
	if bSlot.session != bSession || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_SECOND_LOST_B")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_SECOND_WRAPPER_LOST")
	}
	if f.app.session != parent || f.app.generation != generation || !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_PARENT_CHANGED")
	}

	// Navigation discards fresh feedback; reselecting B reports only the cache.
	f.app.closeLocalVaultFileView()
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_NAVIGATION_KEPT_FRESH")
	}
	f.app.localVaultFiles.selected = bScope.configPath
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileCachedCaption {
		t.Fatal("LOCAL_REFRESH_RESELECT_DID_NOT_SHOW_CACHED")
	}
}

// TestDesktopLocalVaultRefreshHeldDispatchCancelKeepsBorrowedChild cancels a
// staged projection through closeView. The pending copy is cleared immediately,
// the adopted B wrapper stays alive, and the held callback is a no-op.
func TestDesktopLocalVaultRefreshHeldDispatchCancelKeepsBorrowedChild(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_HELD_CANCEL_SETUP_FAILED")
	}
	bSession := bSlot.session
	localVaultRefreshSelect(t, f, bScope)
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_HELD_CANCEL_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_HELD_CANCEL_NOT_STAGED")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_REFRESH_HELD_CANCEL_DISPATCH_MISSING")
	}

	f.app.closeLocalVaultFileView()
	ready, emptyID, itemCount := localVaultRefreshPendingState(t, op)
	if ready || !emptyID || itemCount != 0 {
		t.Fatal("LOCAL_REFRESH_CANCEL_RETAINED_PENDING_PROJECTION")
	}
	if op.finiteOutcome() != localVaultFileRefreshOutcomeCancelled {
		t.Fatal("LOCAL_REFRESH_CANCEL_NOT_FINITE")
	}
	if bSlot.session != bSession || bSlot.refresh != nil {
		t.Fatal("LOCAL_REFRESH_CANCEL_CLOSED_BORROWED_CHILD")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_CANCEL_LOST_BORROWED_CHILD")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_CANCEL_LOCKED_PARENT")
	}

	q.runDispatch(t)
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_STALE_CALLBACK_SET_FRESH")
	}
	if bSlot.session != bSession {
		t.Fatal("LOCAL_REFRESH_STALE_CALLBACK_REPLACED_CHILD")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_STALE_CALLBACK_LOST_CHILD")
	}
}

// TestDesktopLocalVaultRefreshStaleResultCannotReplaceChild replaces B's
// wrapper after a projection was staged. The stale callback must not close the
// replacement, set fresh feedback or change the selected scope.
func TestDesktopLocalVaultRefreshStaleResultCannotReplaceChild(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_REPLACE_SETUP_FAILED")
	}
	oldSession := bSlot.session
	localVaultRefreshSelect(t, f, bScope)
	oldOp := f.app.beginLocalVaultFileRefresh(bScope)
	if oldOp == nil {
		t.Fatal("LOCAL_REFRESH_REPLACE_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, oldOp); staged.outcome != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_REPLACE_NOT_STAGED")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_REFRESH_REPLACE_DISPATCH_MISSING")
	}
	oldDispatch := q.dispatches[0]
	q.dispatches = nil

	// No generic candidate operation is pending on the slot. The wrapper
	// replacement alone must cancel the borrowed projection.
	newOp := f.app.beginLocalVaultFileSession(bScope, []byte(f.password), f.key)
	if newOp == nil {
		t.Fatal("LOCAL_REFRESH_REPLACE_NEW_SESSION_FAILED")
	}
	if oldOp.finiteOutcome() != localVaultFileRefreshOutcomeCancelled {
		t.Fatal("LOCAL_REFRESH_REPLACE_DID_NOT_CANCEL")
	}
	q.drainLaunches(t)
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	q.runDispatch(t)
	if bSlot.session != newCandidate || bSlot.refresh != nil {
		t.Fatal("LOCAL_REFRESH_REPLACE_NEW_CHILD_NOT_ADOPTED")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_REPLACE_SET_FRESH")
	}

	oldDispatch()
	if bSlot.session != newCandidate {
		t.Fatal("LOCAL_REFRESH_STALE_REPLACED_NEW_CHILD")
	}
	if _, err := oldSession.Summary(); err == nil {
		t.Fatal("LOCAL_REFRESH_REPLACED_OLD_CHILD_STILL_READS")
	}
	if summary, err := newCandidate.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_STALE_LOST_NEW_CHILD")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_STALE_REPLACEMENT_SET_FRESH")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_REPLACEMENT_LOCKED_PARENT")
	}
}

// TestDesktopLocalVaultRefreshStaleSelectionCannotSetFresh changes the view
// sequence and selection before delivery without cancelling. The take-side
// identity check must drop the projection without touching B's exact child.
func TestDesktopLocalVaultRefreshStaleSelectionCannotSetFresh(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_SELECTION_SETUP_FAILED")
	}
	bSession := bSlot.session
	localVaultRefreshSelect(t, f, bScope)
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_SELECTION_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_SELECTION_NOT_STAGED")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_REFRESH_SELECTION_DISPATCH_MISSING")
	}
	dispatch := q.dispatches[0]
	q.dispatches = nil

	state := &f.app.localVaultFiles
	state.selected = aScope.configPath
	state.viewSequence++
	dispatch()
	if state.selected != aScope.configPath {
		t.Fatal("LOCAL_REFRESH_SELECTION_POLLUTED_OTHER_SCOPE")
	}
	if state.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() == localVaultFileFreshCaption {
		t.Fatal("LOCAL_REFRESH_STALE_SELECTION_SET_FRESH")
	}
	if bSlot.session != bSession || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_STALE_SELECTION_CHANGED_B_CACHE")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_STALE_SELECTION_CLOSED_B")
	}
}

// TestDesktopLocalVaultRefreshSummaryFailureIsFiniteAndNotFresh proves cache
// and start alone never claim fresh; an actual wrapper Summary failure clears
// only that exact current wrapper and replaces prior fresh success with finite
// failure.
func TestDesktopLocalVaultRefreshSummaryFailureIsFiniteAndNotFresh(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_SETUP_FAILED")
	}
	localVaultRefreshSelect(t, f, bScope)
	if read, ok := f.app.readLocalVaultFileSession(bScope); !ok || read.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_FAILURE_CACHE_UNAVAILABLE")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() == localVaultFileFreshCaption {
		t.Fatal("LOCAL_REFRESH_CACHE_ALONE_CLAIMED_FRESH")
	}

	success := f.app.beginLocalVaultFileRefresh(bScope)
	if success == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_PRECONDITION_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if success.finiteOutcome() != localVaultFileRefreshOutcomeVerified ||
		f.app.localVaultFiles.viewVerification != localVaultFileViewFresh {
		t.Fatal("LOCAL_REFRESH_FAILURE_PRECONDITION_NOT_FRESH")
	}

	// The next real Summary cannot revalidate its locator/journal.
	if err := os.Remove(bManifest.Journal); err != nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_JOURNAL_REMOVE_FAILED")
	}
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_FAILURE_BEGIN_FAILED")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() == localVaultFileFreshCaption {
		t.Fatal("LOCAL_REFRESH_START_LEFT_OLD_FRESH")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeFailed {
		t.Fatal("LOCAL_REFRESH_REAL_SUMMARY_FAILURE_NOT_STAGED")
	}
	q.runDispatch(t)
	if op.finiteOutcome() != localVaultFileRefreshOutcomeFailed {
		t.Fatal("LOCAL_REFRESH_FAILURE_NOT_FINITE")
	}
	if bSlot.session != nil || bSlot.summary.VaultID != "" {
		t.Fatal("LOCAL_REFRESH_FAILURE_KEPT_CURRENT_WRAPPER_CACHE")
	}
	if f.app.localVaultFiles.viewVerification != localVaultFileViewFailed ||
		f.app.localVaultFileRefreshCaption() != localVaultFileFailedCaption {
		t.Fatal("LOCAL_REFRESH_FAILURE_NOT_FINITE_FEEDBACK")
	}
	if _, ok := f.app.readLocalVaultFileSession(bScope); ok {
		t.Fatal("LOCAL_REFRESH_FAILURE_CACHE_STILL_READABLE")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_FAILURE_LOCKED_PARENT")
	}
}

// TestDesktopLocalVaultRefreshCancelBeforeStageKeepsChild cancels while the
// real Summary has returned but the worker has not staged. The late stage is
// refused and the borrowed child remains alive. It is also the single race
// case for the projection handoff.
func TestDesktopLocalVaultRefreshCancelBeforeStageKeepsChild(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_SETUP_FAILED")
	}
	bSession := bSlot.session
	localVaultRefreshSelect(t, f, bScope)

	pauseEntered := make(chan struct{})
	pauseRelease := make(chan struct{})
	var pauseOnce sync.Once
	f.app.localVaultFiles.refreshSummaryPauseForTest = func() {
		pauseOnce.Do(func() {
			close(pauseEntered)
			<-pauseRelease
		})
	}
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_BEGIN_FAILED")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_WORKER_MISSING")
	}
	worker := q.launches[0]
	q.launches = q.launches[1:]
	workerDone := make(chan struct{})
	go func() {
		worker()
		close(workerDone)
	}()
	select {
	case <-pauseEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_PAUSE_NOT_ENTERED")
	}
	f.app.cancelLocalVaultFileRefreshExact(op)
	if op.finiteOutcome() != localVaultFileRefreshOutcomeCancelled {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_NOT_FINITE")
	}
	close(pauseRelease)
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_WORKER_STUCK")
	}
	if len(q.dispatches) != 0 {
		t.Fatal("LOCAL_REFRESH_LATE_STAGE_DISPATCHED_AFTER_CANCEL")
	}
	ready, emptyID, itemCount := localVaultRefreshPendingState(t, op)
	if ready || !emptyID || itemCount != 0 {
		t.Fatal("LOCAL_REFRESH_LATE_STAGE_RETAINED_PROJECTION")
	}
	if bSlot.session != bSession || bSlot.refresh != nil {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_CLOSED_CHILD")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_LOST_CHILD")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_LATE_CANCEL_LOCKED_PARENT")
	}
}

// TestDesktopLocalVaultRefreshBusyWithholdsProjection holds the parent cache
// Busy at the delivery boundary. The projection is withheld, but B's exact
// wrapper and cache, and any sibling, are preserved.
func TestDesktopLocalVaultRefreshBusyWithholdsProjection(t *testing.T) {
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
	if aSlot == nil || bSlot == nil || aSlot.session == nil || bSlot.session == nil {
		t.Fatal("LOCAL_REFRESH_BUSY_SETUP_FAILED")
	}
	aSession, bSession := aSlot.session, bSlot.session
	if aSession == bSession {
		t.Fatal("LOCAL_REFRESH_BUSY_WRAPPERS_NOT_DISTINCT")
	}
	localVaultRefreshSelect(t, f, bScope)
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil {
		t.Fatal("LOCAL_REFRESH_BUSY_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if staged := localVaultRefreshStaged(t, op); staged.outcome != localVaultFileRefreshOutcomeVerified {
		t.Fatal("LOCAL_REFRESH_BUSY_NOT_STAGED")
	}
	release := holdDesktopParentDBBusy(t, f)
	q.runDispatch(t)
	if op.finiteOutcome() != localVaultFileRefreshOutcomeWithheld {
		t.Fatal("LOCAL_REFRESH_BUSY_NOT_WITHHELD")
	}
	if bSlot.session != bSession || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_BUSY_DROPPED_EXISTING_CHILD")
	}
	if aSlot.session != aSession {
		t.Fatal("LOCAL_REFRESH_BUSY_RETIRED_SIBLING")
	}
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() == localVaultFileFreshCaption {
		t.Fatal("LOCAL_REFRESH_BUSY_CLAIMED_FRESH")
	}
	release()
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_BUSY_LOST_CHILD")
	}
	if summary, err := aSession.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_REFRESH_BUSY_LOST_SIBLING")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_REFRESH_BUSY_LOCKED_PARENT")
	}
}
