package desktop

import (
	"context"
	"testing"
	"time"
)

// TestCLIRunHandlerLockStartAfterCaptureRefuses starts the production lock
// (App.lockStart, the first step of App.Lock) after handleCLIRun captured its
// unlocked session, epoch, and path and after native approval was granted, but
// before the handler's post-approval recheck.
//
// The barrier is the approval path's own dispatch sequence: the first dispatch
// (show/focus) returns, so the native approve can be delivered; the second
// (finishCLIRunApproval's invalidation) runs after that check and before the
// handler's brokerCurrent recheck, so parking it parks exactly the window under
// test. The pending review is bound to the captured session and epoch, proving
// the capture. No sleeps and no test-only hook: approving through
// approveCLIRun and running lockStart are the production calls.
func TestCLIRunHandlerLockStartAfterCaptureRefuses(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	a.brokerMu.Lock()
	captured, epoch, generation := a.brokerSession, a.brokerEpoch, a.generation
	a.brokerMu.Unlock()
	if captured == nil || !captured.Unlocked() {
		t.Fatal("fixture has no unlocked broker session")
	}

	approvalFinished := make(chan struct{})
	continueHandler := make(chan struct{})
	dispatches := 0
	a.dispatch = func(func()) {
		dispatches++
		if dispatches != 2 {
			return
		}
		close(approvalFinished)
		<-continueHandler
	}

	result := make(chan cliRunApprovalResult, 1)
	go func() {
		resp, e := a.handleCLIRun(context.Background(), desktopPeerFixture(), req)
		result <- cliRunApprovalResult{approved: desktopHasCLIPrepared(resp), err: e}
	}()
	p := waitCLIRunApprovalPending(t, a)
	a.brokerMu.Lock()
	boundSession, boundEpoch := p.session, p.epoch
	a.brokerMu.Unlock()
	if boundSession != captured || boundEpoch != epoch {
		t.Fatal("pending approval was not bound to the captured session and epoch")
	}

	a.approveCLIRun(p, true)
	select {
	case <-approvalFinished:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not reach its post-approval dispatch")
	}

	a.lockStart()
	a.brokerMu.Lock()
	revoked, newEpoch, newGeneration := a.brokerSession, a.brokerEpoch, a.generation
	a.brokerMu.Unlock()
	if revoked != nil || newEpoch != generation+1 || newGeneration != generation+1 {
		t.Fatalf("lock start did not revoke atomically: unbound=%v epoch=%d generation=%d (was %d)", revoked == nil, newEpoch, newGeneration, generation)
	}
	close(continueHandler)

	r := waitCLIRunApprovalResult(t, result)
	// A refusal is proven by its reply: no values, no partial receipt.
	if r.err != errCLIRunRefused || r.approved {
		t.Fatalf("lock start after capture: want the fixed refusal without prepared values, got %+v", r)
	}
	if a.brokerCurrent(captured, epoch) {
		t.Fatal("lock start left the captured session and epoch current")
	}
	a.Lock()
	if captured.Unlocked() {
		t.Fatal("App.Lock left the captured session unlocked")
	}
}
