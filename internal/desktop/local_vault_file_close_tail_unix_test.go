//go:build darwin || linux

package desktop

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func waitLocalVaultFileCloseTail(t *testing.T, tail *localVaultFileCloseTail) {
	t.Helper()
	if tail == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_MISSING")
	}
	select {
	case <-tail.done:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_CLOSE_TAIL_TIMEOUT")
	}
}

// TestDesktopLocalVaultSessionAdoptedCloseTailInheritedAcrossAppGeneration
// pauses the real Close of an adopted wrapper, retires it, crosses a
// same-parent App generation boundary, and replaces the same scope while the
// physical close is still unfinished. The retiring entry must not be purged
// early, the replacement must inherit the exact unfinished tail, and releasing
// the real Close must finish the cumulative tail while the sibling wrapper and
// parent remain usable.
func TestDesktopLocalVaultSessionAdoptedCloseTailInheritedAcrossAppGeneration(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	f.openVault(t, q, aScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_SETUP_FAILED")
	}
	aWrapper := aSlot.session

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	f.app.closeLocalVaultFileSession(aScope)
	if aSlot.session != nil || aSlot.closeTail == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_NOT_INSTALLED_ON_RETIRE")
	}
	tail := aSlot.closeTail
	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_CLOSE_TAIL_REAL_CLOSE_NOT_ENTERED")
	if localVaultFileCloseTailFinished(tail) {
		t.Fatal("LOCAL_CLOSE_TAIL_FINISHED_WHILE_CLOSE_PAUSED")
	}

	// The retiring entry stays discoverable until the physical close chain is
	// complete, even though every producer operation already settled.
	if f.app.syncLocalVaultFileSessions() != personal.VaultFileCacheActive {
		t.Fatal("LOCAL_CLOSE_TAIL_SYNC_NOT_ACTIVE_BEFORE_GENERATION")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || !aSlot.retiring {
		t.Fatal("LOCAL_CLOSE_TAIL_PURGED_WHILE_CLOSE_PAUSED")
	}

	f.app.generation++
	if f.app.syncLocalVaultFileSessions() != personal.VaultFileCacheActive {
		t.Fatal("LOCAL_CLOSE_TAIL_SYNC_NOT_ACTIVE_AT_GENERATION")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || !aSlot.retiring ||
		localVaultFileCloseTailFinished(tail) {
		t.Fatal("LOCAL_CLOSE_TAIL_GENERATION_DROPPED_UNFINISHED_TAIL")
	}

	// Same-parent, same-scope replacement must carry the exact unfinished tail
	// across the map overwrite.
	replacement := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if replacement == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_REPLACEMENT_BEGIN_FAILED")
	}
	newSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if newSlot == nil || newSlot == aSlot || newSlot.retiring ||
		newSlot.closeTail != tail || localVaultFileCloseTailFinished(newSlot.closeTail) {
		t.Fatal("LOCAL_CLOSE_TAIL_NOT_INHERITED_BEFORE_MAP_OVERWRITE")
	}
	f.app.cancelLocalVaultFileSessionOperationExact(replacement)
	q.runLaunch(t)
	if replacement.finiteOutcome() != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_CLOSE_TAIL_REPLACEMENT_NOT_CANCELLED")
	}
	if len(q.dispatches) != 0 {
		t.Fatal("LOCAL_CLOSE_TAIL_CANCELLED_REPLACEMENT_DISPATCHED")
	}

	// The parent can still open and read an unrelated vault while A's physical
	// close chain is unfinished.
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_SIBLING_OPEN_FAILED")
	}
	bWrapper := bSlot.session

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_CLOSE_TAIL_CLOSE_WORKER_STUCK")
	waitLocalVaultFileCloseTail(t, tail)
	if tail.result != localVaultFileCloseResultSucceeded {
		t.Fatal("LOCAL_CLOSE_TAIL_UNCLEAN_PHYSICAL_CLOSE")
	}
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_CLOSE_TAIL_OLD_WRAPPER_STILL_READABLE")
	}
	bSummary, err := bWrapper.Summary()
	if err != nil || bSummary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_CLOSE_TAIL_SIBLING_WRAPPER_LOST")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_CLOSE_TAIL_PARENT_CHANGED")
	}
}

// TestDesktopLocalVaultSessionAdoptedCloseTailChainsPriorClose pauses the first
// adopted wrapper's real Close, adopts a replacement wrapper in the same slot,
// and closes it. The second tail may finish its own Close but must remain open
// until the paused prior real Close returns.
func TestDesktopLocalVaultSessionAdoptedCloseTailChainsPriorClose(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	f.openVault(t, q, scope)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_CLOSE_CHAIN_SETUP_FAILED")
	}
	firstWrapper := slot.session

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	replacement := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if replacement == nil {
		t.Fatal("LOCAL_CLOSE_CHAIN_REPLACEMENT_BEGIN_FAILED")
	}
	firstTail := slot.closeTail
	if firstTail == nil {
		t.Fatal("LOCAL_CLOSE_CHAIN_FIRST_TAIL_MISSING")
	}
	firstCloseWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_CLOSE_CHAIN_FIRST_CLOSE_NOT_ENTERED")
	q.runLaunch(t)
	q.runDispatch(t)
	if slot.session == nil || slot.session == firstWrapper {
		t.Fatal("LOCAL_CLOSE_CHAIN_SECOND_WRAPPER_NOT_ADOPTED")
	}
	secondWrapper := slot.session

	f.app.closeLocalVaultFileSession(scope)
	secondTail := slot.closeTail
	if secondTail == nil || secondTail == firstTail {
		t.Fatal("LOCAL_CLOSE_CHAIN_SECOND_TAIL_NOT_INSTALLED")
	}
	secondCloseWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultWrapperClosed(t, secondWrapper, "LOCAL_CLOSE_CHAIN_SECOND_REAL_CLOSE_STUCK")
	if localVaultFileCloseTailFinished(secondTail) {
		t.Fatal("LOCAL_CLOSE_CHAIN_FINISHED_BEFORE_PRIOR_REAL_CLOSE")
	}
	if localVaultFileCloseTailFinished(firstTail) {
		t.Fatal("LOCAL_CLOSE_CHAIN_PRIOR_FINISHED_WHILE_PAUSED")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, firstCloseWorker, "LOCAL_CLOSE_CHAIN_FIRST_CLOSE_STUCK")
	awaitLocalVaultSignal(t, secondCloseWorker, "LOCAL_CLOSE_CHAIN_SECOND_CLOSE_STUCK")
	waitLocalVaultFileCloseTail(t, secondTail)
	if secondTail.result != localVaultFileCloseResultSucceeded {
		t.Fatal("LOCAL_CLOSE_CHAIN_UNCLEAN_CUMULATIVE_CLOSE")
	}
	if _, err := firstWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_CLOSE_CHAIN_FIRST_WRAPPER_STILL_READABLE")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_CLOSE_CHAIN_PARENT_CHANGED")
	}
}

func awaitLocalVaultWrapperClosed(t *testing.T, wrapper *vaultfileclient.LocalGenesisSession, code string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := wrapper.Summary(); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(code)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestDesktopLocalVaultSessionAdoptedCloseTailAppLockKeepsWorker calls the real
// App.Lock boundary while one adopted wrapper Close is paused. The UI registry
// and cache must drop immediately, but every already-launched tracked Close
// must continue to a finite completion after release without waiting on UI
// state.
func TestDesktopLocalVaultSessionAdoptedCloseTailAppLockKeepsWorker(t *testing.T) {
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
		t.Fatal("LOCAL_CLOSE_APP_LOCK_SETUP_FAILED")
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

	f.app.Lock()
	if len(f.app.localVaultFiles.sessionSlots) != 0 ||
		f.app.localVaultFiles.sessionParent != nil {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_RETAINED_UI_REGISTRY")
	}
	if aSlot.session != nil || bSlot.session != nil ||
		aSlot.closeTail == nil || bSlot.closeTail == nil {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_DID_NOT_TRACK_DETACH")
	}
	aTail, bTail := aSlot.closeTail, bSlot.closeTail

	launches := q.launches
	q.launches = nil
	if len(launches) == 0 {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_LAUNCH_MISSING")
	}
	workersDone := make(chan struct{})
	go func() {
		var workers sync.WaitGroup
		for _, fn := range launches {
			fn := fn
			workers.Add(1)
			go func() {
				defer workers.Done()
				fn()
			}()
		}
		workers.Wait()
		close(workersDone)
	}()
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_CLOSE_APP_LOCK_CLOSE_NOT_ENTERED")
	if localVaultFileCloseTailFinished(aTail) && localVaultFileCloseTailFinished(bTail) {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_ALL_CLOSES_FINISHED_WHILE_PAUSED")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, workersDone, "LOCAL_CLOSE_APP_LOCK_WORKER_STUCK")
	waitLocalVaultFileCloseTail(t, aTail)
	waitLocalVaultFileCloseTail(t, bTail)
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_A_WRAPPER_STILL_READABLE")
	}
	if _, err := bWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_CLOSE_APP_LOCK_B_WRAPPER_STILL_READABLE")
	}
}
