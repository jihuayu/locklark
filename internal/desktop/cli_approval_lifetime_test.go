package desktop

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

func cliLifetimeRequest(t *testing.T, a *App) browserhost.BrokerCLIRequest {
	t.Helper()
	rows, e := a.session.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) == 0 {
		if _, e := a.session.AddLogin("Lifetime login", "lifetime-user", "lifetime-password"); e != nil {
			t.Fatal(e)
		}
		rows, e = a.session.List("active")
		if e != nil || len(rows) != 1 {
			t.Fatal("lifetime fixture rows", e)
		}
	}
	return browserhost.BrokerCLIRequest{
		V:         1,
		VaultPath: a.session.VaultPath(),
		Targets: []personal.CLIBrokerTarget{{
			Slot:     "LIFETIME",
			ID:       rows[0].ID,
			Revision: rows[0].Revision,
			Field:    "password",
		}},
	}
}

// TestCLIRunApprovalEarlierDeadlineCancelsExactPending proves the earlier
// caller deadline ends the approval, removes only that pending, and ignores a
// late click from the retired render.
func TestCLIRunApprovalEarlierDeadlineCancelsExactPending(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	session, epoch := a.brokerSession, a.brokerEpoch
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	type result struct {
		approved bool
		err      error
	}
	done := make(chan result, 1)
	go func() {
		approved, err := a.requestCLIRunApproval(ctx, browserhost.Peer{}, browserhost.BrokerCLIRequest{}, session, epoch)
		done <- result{approved: approved, err: err}
	}()

	var pending *cliRunPending
	waitUntil := time.Now().Add(2 * time.Second)
	for {
		a.brokerMu.Lock()
		pending = a.cliPending
		a.brokerMu.Unlock()
		if pending != nil {
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatal("approval was not published")
		}
		time.Sleep(time.Millisecond)
	}
	begin := time.Now()
	select {
	case out := <-done:
		if out.approved || !errors.Is(out.err, errCLIRunRefused) {
			t.Fatalf("early deadline approval = %v, %v", out.approved, out.err)
		}
		if elapsed := time.Since(begin); elapsed >= 3*time.Second {
			t.Fatalf("short caller deadline took %s", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval did not honor the short caller deadline")
	}
	a.brokerMu.Lock()
	stillPending := a.cliPending != nil
	rendered := a.approvalWinPending
	a.brokerMu.Unlock()
	if stillPending || rendered != "" {
		t.Fatalf("timeout left pending=%v rendered=%q", stillPending, rendered)
	}
	if a.approveCLIRun(pending.id, true) {
		t.Fatal("late approval accepted the retired pending id")
	}
	if _, ok := cliPendingDecision(pending); ok {
		t.Fatal("late approval signalled a retired pending")
	}

	// Old timeout cleanup must not decide or hide a replacement render.
	replacement := cliPendingBindingFixture("pending-replacement")
	setCLIPending(a, replacement, replacement.id)
	if a.approveCLIRun(pending.id, true) || a.hideApprovalWindowFor(pending.id) {
		t.Fatal("retired callback touched the replacement pending")
	}
	if replacement.decided {
		t.Fatal("retired callback decided the replacement pending")
	}
	if _, ok := cliPendingDecision(replacement); ok {
		t.Fatal("retired callback signalled the replacement pending")
	}
}

// TestHandleCLIRunLateApprovalRefused proves a callback that returns "approved"
// only after its bounded context expired cannot reach extraction or disclosure.
func TestHandleCLIRunLateApprovalRefused(t *testing.T) {
	a := dailyAppFixture(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.notifyBrowserBrokerUnlocked()
	req := cliLifetimeRequest(t, a)
	bounded := make(chan bool, 1)
	a.cliApprover = func(ctx context.Context, _ browserhost.Peer, _ browserhost.BrokerCLIRequest) (bool, error) {
		deadline, ok := ctx.Deadline()
		select {
		case bounded <- ok && time.Until(deadline) <= time.Second:
		default:
		}
		<-ctx.Done()
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	resp, err := a.handleCLIRun(ctx, browserhost.Peer{}, req)
	if !errors.Is(err, errCLIRunRefused) {
		t.Fatalf("late approval error = %v, want refused", err)
	}
	if len(resp.Values) != 0 {
		t.Fatalf("late approval disclosed %d values", len(resp.Values))
	}
	select {
	case got := <-bounded:
		if !got {
			t.Fatal("approval callback did not receive the bounded earlier deadline")
		}
	default:
		t.Fatal("approval callback did not inspect its deadline")
	}
}

// TestHandleCLIRunLateLockRefused proves a broker lock between approval and
// extraction fails closed before values are returned.
func TestHandleCLIRunLateLockRefused(t *testing.T) {
	a := dailyAppFixture(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.notifyBrowserBrokerUnlocked()
	req := cliLifetimeRequest(t, a)
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		a.notifyBrowserBrokerLocked()
		return true, nil
	}
	resp, err := a.handleCLIRun(context.Background(), browserhost.Peer{}, req)
	if !errors.Is(err, errCLIRunRefused) {
		t.Fatalf("late lock error = %v, want refused", err)
	}
	if len(resp.Values) != 0 {
		t.Fatalf("late lock disclosed %d values", len(resp.Values))
	}
}
