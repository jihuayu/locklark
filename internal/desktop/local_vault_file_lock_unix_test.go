//go:build darwin || linux

package desktop

import (
	"sync/atomic"
	"testing"
	"time"
)

func waitLocalVaultFileLockDone(t *testing.T, op *localVaultFileLockOperation) {
	t.Helper()
	if op == nil {
		t.Fatal("LOCAL_LOCK_OPERATION_MISSING")
	}
	select {
	case <-op.doneSignal():
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_LOCK_COMPLETION_TIMEOUT")
	}
}

// TestDesktopLocalVaultPendingProducerLockWaitsCandidateClose holds the real
// producer factory, starts the explicit lock, then lets the factory return a
// real candidate. The producer's settlement includes the actual candidate
// Close, paused here, so the lock must remain unfinished until that real Close
// returns. This is the single critical concurrent lock case.
func TestDesktopLocalVaultPendingProducerLockWaitsCandidateClose(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)

	openEntered := make(chan struct{})
	openRelease := make(chan struct{})
	var openPaused atomic.Bool
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		if openPaused.CompareAndSwap(false, true) {
			close(openEntered)
			<-openRelease
		}
	}
	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var closePaused atomic.Bool
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		if closePaused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	producer := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if producer == nil {
		t.Fatal("LOCAL_LOCK_PENDING_PRODUCER_BEGIN_FAILED")
	}
	producerWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, openEntered, "LOCAL_LOCK_PENDING_FACTORY_NOT_ENTERED")

	lock := f.app.beginLocalVaultFileLock(scope)
	if lock == nil || lock.isDone() {
		t.Fatal("LOCAL_LOCK_PENDING_BEGIN_NOT_FINITE_PENDING")
	}
	if outcome, done := f.app.localVaultFileLockResult(scope); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_PENDING_REPORTED_BEFORE_WORKER")
	}
	lockWorker := startLocalVaultLaunchAsync(t, q)

	close(openRelease)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_PENDING_CANDIDATE_CLOSE_NOT_ENTERED")
	if lock.isDone() {
		t.Fatal("LOCAL_LOCK_PENDING_FINISHED_BEFORE_REAL_CANDIDATE_CLOSE")
	}
	if producer.isSettled() {
		t.Fatal("LOCAL_LOCK_PENDING_PRODUCER_SETTLED_BEFORE_REAL_CLOSE")
	}
	close(closeRelease)
	awaitLocalVaultSignal(t, producerWorker, "LOCAL_LOCK_PENDING_PRODUCER_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_PENDING_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := f.app.localVaultFileLockResult(scope); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_PENDING_NOT_FINITE_SUCCEEDED")
	}
}

// TestDesktopLocalVaultAdoptedLockAliasBarrierAndReopen pauses the adopted A
// wrapper Close, begins one lock, reuses it through an alias, verifies alias
// reserve refusal and sibling B refresh, then releases to a finite Locked
// result and permits a real manual reopen.
func TestDesktopLocalVaultAdoptedLockAliasBarrierAndReopen(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aliasPath, aliasManifest := desktopLocalVaultAliasConfig(t, aPath)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	aliasScope := f.scope(aliasPath, aliasManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if aSlot == nil || aSlot.session == nil || bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_LOCK_ADOPTED_SETUP_FAILED")
	}
	aWrapper, bWrapper := aSlot.session, bSlot.session

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	lock := f.app.beginLocalVaultFileLock(aScope)
	if lock == nil {
		t.Fatal("LOCAL_LOCK_ADOPTED_BEGIN_FAILED")
	}
	aCloseWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_ADOPTED_CLOSE_NOT_ENTERED")
	lockWorker := startLocalVaultLaunchAsync(t, q)
	if lock.isDone() {
		t.Fatal("LOCAL_LOCK_ADOPTED_FINISHED_WHILE_CLOSE_PAUSED")
	}
	if aSlot.closeTail == nil || aSlot.session != nil {
		t.Fatal("LOCAL_LOCK_ADOPTED_TAIL_NOT_INSTALLED")
	}

	aliasLock := f.app.beginLocalVaultFileLock(aliasScope)
	if aliasLock != lock {
		t.Fatal("LOCAL_LOCK_ALIAS_DID_NOT_REUSE_OPERATION")
	}
	if aliasSlot := f.app.localVaultFiles.sessionSlots[aliasScope]; aliasSlot == nil ||
		aliasSlot.lock != lock {
		t.Fatal("LOCAL_LOCK_ALIAS_MARKER_NOT_INSTALLED")
	}
	if op := f.app.beginLocalVaultFileSession(aliasScope, []byte(f.password), f.key); op != nil {
		t.Fatal("LOCAL_LOCK_ALIAS_GENERIC_RESERVE_NOT_BLOCKED")
	}
	if op := f.app.reserveLocalVaultFileSessionOperation(aliasScope); op != nil {
		t.Fatal("LOCAL_LOCK_ALIAS_SHARED_RESERVE_NOT_BLOCKED")
	}

	sibling, err := bWrapper.Summary()
	if err != nil || sibling.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_LOCK_SIBLING_SUMMARY_LOST")
	}
	localVaultRefreshSelect(t, f, bScope)
	refresh := f.app.beginLocalVaultFileRefresh(bScope)
	if refresh == nil {
		t.Fatal("LOCAL_LOCK_SIBLING_REFRESH_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if refresh.finiteOutcome() != localVaultFileRefreshOutcomeVerified ||
		bSlot.session != bWrapper {
		t.Fatal("LOCAL_LOCK_SIBLING_REFRESH_FAILED")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, aCloseWorker, "LOCAL_LOCK_ADOPTED_CLOSE_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_ADOPTED_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := f.app.localVaultFileLockResult(aScope); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_ADOPTED_NOT_FINITE_SUCCEEDED")
	}
	if outcome, done := f.app.localVaultFileLockResult(aliasScope); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_ALIAS_NOT_DURABLE_FINITE")
	}
	if again := f.app.beginLocalVaultFileLock(aScope); again != lock {
		t.Fatal("LOCAL_LOCK_COMPLETED_DUPLICATE_NOT_REUSED")
	}
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_LOCK_ADOPTED_WRAPPER_STILL_READABLE")
	}

	fresh := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if fresh == nil {
		t.Fatal("LOCAL_LOCK_MANUAL_REOPEN_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	freshSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if freshSlot == nil || freshSlot.session == nil || freshSlot.retiring {
		t.Fatal("LOCAL_LOCK_MANUAL_REOPEN_NOT_ADOPTED")
	}
	if outcome, done := f.app.localVaultFileLockResult(aScope); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_OLD_MARKER_ATTACHED_TO_NEW_BINDING")
	}
	if summary, err := freshSlot.session.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_LOCK_MANUAL_REOPEN_WRAPPER_LOST")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_LOCK_PARENT_CHANGED")
	}
}

// TestDesktopLocalVaultLockSameParentGenerationKeepsBarrier crosses a
// same-parent App generation while the lock is unfinished. The marker must keep
// blocking reserve, and after real completion a new-generation reopen must not
// inherit the old completed marker.
func TestDesktopLocalVaultLockSameParentGenerationKeepsBarrier(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	f.openVault(t, q, scope)

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	lock := f.app.beginLocalVaultFileLock(scope)
	if lock == nil {
		t.Fatal("LOCAL_LOCK_GEN_BEGIN_FAILED")
	}
	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_GEN_CLOSE_NOT_ENTERED")
	lockWorker := startLocalVaultLaunchAsync(t, q)

	f.app.generation++
	f.app.syncLocalVaultFileSessions()
	if op := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key); op != nil {
		t.Fatal("LOCAL_LOCK_GEN_BARRIER_DROPPED")
	}
	if op := f.app.reserveLocalVaultFileSessionOperation(scope); op != nil {
		t.Fatal("LOCAL_LOCK_GEN_SHARED_RESERVE_DROPPED")
	}
	if duplicate := f.app.beginLocalVaultFileLock(scope); duplicate != lock {
		t.Fatal("LOCAL_LOCK_GEN_ACTIVE_DUPLICATE_NOT_REUSED")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_LOCK_GEN_CLOSE_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_GEN_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := lock.finiteOutcome(); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_GEN_NOT_FINITE_SUCCEEDED")
	}
	if outcome, done := f.app.localVaultFileLockResult(scope); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_GEN_OLD_MARKER_BOUND_TO_NEW_GENERATION")
	}

	fresh := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if fresh == nil {
		t.Fatal("LOCAL_LOCK_GEN_REOPEN_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	freshSlot := f.app.localVaultFiles.sessionSlots[scope]
	if freshSlot == nil || freshSlot.session == nil ||
		freshSlot.appGeneration != f.app.generation {
		t.Fatal("LOCAL_LOCK_GEN_REOPEN_NOT_NEW_BINDING")
	}
	if outcome, done := f.app.localVaultFileLockResult(scope); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_GEN_OLD_MARKER_MARKED_NEW_BINDING")
	}
}

// TestDesktopLocalVaultLockAppLockKeepsWorker drops the UI registry while the
// adopted Close is paused. The existing worker must continue to a finite result
// after release, independent of the dropped slot map.
func TestDesktopLocalVaultLockAppLockKeepsWorker(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	f.openVault(t, q, scope)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_LOCK_APP_LOCK_SETUP_FAILED")
	}
	wrapper := slot.session

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	lock := f.app.beginLocalVaultFileLock(scope)
	if lock == nil {
		t.Fatal("LOCAL_LOCK_APP_LOCK_BEGIN_FAILED")
	}
	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_APP_LOCK_CLOSE_NOT_ENTERED")
	lockWorker := startLocalVaultLaunchAsync(t, q)

	f.app.Lock()
	if len(f.app.localVaultFiles.sessionSlots) != 0 || f.app.session != nil {
		t.Fatal("LOCAL_LOCK_APP_LOCK_RETAINED_UI_BINDING")
	}
	if lock.isDone() {
		t.Fatal("LOCAL_LOCK_APP_LOCK_FINISHED_WHILE_CLOSE_PAUSED")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_LOCK_APP_LOCK_CLOSE_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_APP_LOCK_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := lock.finiteOutcome(); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_APP_LOCK_NOT_FINITE_SUCCEEDED")
	}
	if _, err := wrapper.Summary(); err == nil {
		t.Fatal("LOCAL_LOCK_APP_LOCK_WRAPPER_STILL_READABLE")
	}
	if _, done := f.app.localVaultFileLockResult(scope); done {
		t.Fatal("LOCAL_LOCK_APP_LOCK_RETAINED_GETTER_BINDING")
	}
	q.drainLaunches(t)
}
