package desktop

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"testing/synctest"
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
	// Keep fixture/session timestamps and the real context timer in one clock
	// domain. Authenticated fixture I/O finishes before the caller budget starts;
	// host scheduling cannot consume the transient pending's observation window.
	synctest.Test(t, func(t *testing.T) {
		a := dailyAppFixture(t)
		a.notifyBrowserBrokerUnlocked()
		session, epoch := a.brokerSession, a.brokerEpoch
		req := cliLifetimeRequest(t, a)
		const callerLifetime = 300 * time.Millisecond
		if callerLifetime >= browserhost.CLIRunApprovalMaxLifetime {
			t.Fatal("caller deadline must precede the approval lifetime cap")
		}
		begin := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), callerLifetime)
		defer cancel()
		type result struct {
			approved bool
			err      error
		}
		done := make(chan result, 1)
		go func() {
			approved, err := a.requestCLIRunApproval(ctx, browserhost.Peer{}, req.VaultPath, req.Scope, req.Targets, session, epoch)
			done <- result{approved: approved, err: err}
		}()

		// Wait for the request goroutine to block on its actual decision/context
		// channels without advancing virtual time or racing a polling interval.
		synctest.Wait()
		a.brokerMu.Lock()
		pending := a.cliPending
		a.brokerMu.Unlock()
		if pending == nil || ctx.Err() != nil || !time.Now().Equal(begin) {
			t.Fatal("approval was not published before the caller deadline")
		}
		// Headless unit rendered-state fixture only: no GUI window is opened.
		// Bind the real pending's ID so timeout must retire its rendered owner.
		a.brokerMu.Lock()
		a.approvalWinPending = pending.id
		a.brokerMu.Unlock()
		time.Sleep(callerLifetime - time.Millisecond)
		synctest.Wait()
		a.brokerMu.Lock()
		current := a.cliPending == pending
		renderedCurrent := a.approvalWinPending == pending.id
		a.brokerMu.Unlock()
		if !current || !renderedCurrent || ctx.Err() != nil {
			t.Fatal("approval or rendered binding retired before the caller deadline")
		}
		select {
		case <-done:
			t.Fatal("approval returned before the caller deadline")
		default:
		}

		time.Sleep(time.Millisecond)
		synctest.Wait()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Since(begin) != callerLifetime {
			t.Fatal("the original short caller deadline did not expire")
		}
		select {
		case out := <-done:
			if out.approved || !errors.Is(out.err, errCLIRunRefused) {
				t.Fatal("early deadline did not refuse the approval")
			}
		default:
			t.Fatal("approval did not honor the short caller deadline")
		}
		a.brokerMu.Lock()
		stillPending := a.cliPending != nil
		rendered := a.approvalWinPending
		a.brokerMu.Unlock()
		if stillPending || rendered != "" {
			t.Fatal("timeout left a pending or rendered approval")
		}
		if a.approveCLIRunID(pending.id, true) {
			t.Fatal("late approval accepted the retired pending id")
		}
		if _, ok := cliPendingDecision(pending); ok {
			t.Fatal("late approval signalled a retired pending")
		}

		// Old timeout cleanup must not decide or hide a replacement render.
		replacement := cliPendingBindingFixture(t, a, "pending-replacement")
		setCLIPending(a, replacement, replacement.id)
		if a.approveCLIRunID(pending.id, true) || a.hideApprovalWindowFor(pending.id) {
			t.Fatal("retired callback touched the replacement pending")
		}
		a.brokerMu.Lock()
		replacementCurrent := a.cliPending == replacement
		replacementRendered := a.approvalWinPending == replacement.id
		a.brokerMu.Unlock()
		if !replacementCurrent || !replacementRendered {
			t.Fatal("retired callback changed the replacement pending or rendered binding")
		}
		if replacement.decided {
			t.Fatal("retired callback decided the replacement pending")
		}
		if _, ok := cliPendingDecision(replacement); ok {
			t.Fatal("retired callback signalled the replacement pending")
		}
	})
}

// TestHandleCLIRunLateApprovalRefused proves a callback that returns "approved"
// only after its bounded context expired cannot reach extraction or disclosure.
func TestHandleCLIRunLateApprovalRefused(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
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
	a, req := desktopCLIRunFixture(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
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
