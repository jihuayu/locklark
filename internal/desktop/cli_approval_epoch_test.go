package desktop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
)

type cliRunApprovalResult struct {
	approved bool
	err      error
}

func waitCLIRunApprovalPending(t *testing.T, a *App) *cliRunPending {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.brokerMu.Lock()
		p := a.cliPending
		a.brokerMu.Unlock()
		if p != nil {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatal("approval was not published")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitCLIRunApprovalResult(t *testing.T, result <-chan cliRunApprovalResult) cliRunApprovalResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("pending approval waiter did not return")
		return cliRunApprovalResult{}
	}
}

// A pending CLI approval is bound to the broker epoch it was published under.
// Advancing only the epoch, while the same session stays unlocked and the
// summary is still pending, must make the native approve a refusal.
func TestCLIRunApprovalRefusedAfterEpochAdvance(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	a.brokerMu.Lock()
	s, epoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	result := make(chan cliRunApprovalResult, 1)
	go func() {
		approved, err := a.requestCLIRunApproval(context.Background(), browserhost.Peer{}, "/fixture/vault.ll", browserhost.CLIRunScope{}, nil, s, epoch)
		result <- cliRunApprovalResult{approved: approved, err: err}
	}()
	p := waitCLIRunApprovalPending(t, a)
	if p.session != s || p.epoch != epoch {
		t.Fatal("pending approval was not bound to the current session and epoch")
	}

	a.brokerMu.Lock()
	a.brokerEpoch++
	advanced := a.brokerEpoch
	sessionCurrent := a.brokerSession == s
	pendingKept := a.cliPending == p
	a.brokerMu.Unlock()
	if advanced != epoch+1 || !sessionCurrent || !pendingKept || !s.Unlocked() {
		t.Fatal("epoch advance disturbed the session or pending review")
	}

	a.approveCLIRun(p, true)
	r := waitCLIRunApprovalResult(t, result)
	if r.approved || !errors.Is(r.err, errCLIRunRefused) {
		t.Fatal("stale approve published an approval")
	}
	a.brokerMu.Lock()
	pending := a.cliPending
	a.brokerMu.Unlock()
	if pending != nil {
		t.Fatal("stale approval left the pending summary behind")
	}
}

// A matching session and epoch still fails closed if the session itself is no
// longer unlocked, even though the broker fields were not updated.
func TestCLIRunApprovalRefusedLockedSession(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	a.brokerMu.Lock()
	s, epoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	result := make(chan cliRunApprovalResult, 1)
	go func() {
		approved, err := a.requestCLIRunApproval(context.Background(), browserhost.Peer{}, "/fixture/vault.ll", browserhost.CLIRunScope{}, nil, s, epoch)
		result <- cliRunApprovalResult{approved: approved, err: err}
	}()
	p := waitCLIRunApprovalPending(t, a)
	s.Lock()
	a.approveCLIRun(p, true)
	r := waitCLIRunApprovalResult(t, result)
	if r.approved || !errors.Is(r.err, errCLIRunRefused) {
		t.Fatal("locked session approved a pending disclosure")
	}
}
