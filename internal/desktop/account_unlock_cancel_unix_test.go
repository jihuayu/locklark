//go:build darwin || linux

package desktop

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDesktopAccountUnlockCancel(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	_, _ = f.createVault(t)
	_, _ = f.createVault(t)

	t.Run("non-account-busy-no-cancel", func(t *testing.T) {
		a := New()
		q := &localVaultSessionQueue{}
		q.install(a)
		a.run(func() outcome { return outcome{} })
		if _, ok := a.accountUnlockCancelToken(); ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_NON_ACCOUNT")
		}
		q.runLaunch(t)
		q.runDispatch(t)
		if a.accountUnlock != nil {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_MARKER_LEAK")
		}
	})

	t.Run("early-cancel-real", func(t *testing.T) {
		a, q := newInitialFanoutTestApp(t, f, f.settingsPath)
		a.unlock()
		token, ok := a.accountUnlockCancelToken()
		if !ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_TOKEN_MISSING")
		}
		a.cancelAccountUnlock(token)
		if a.session != nil || a.busy || a.accountUnlock != nil || a.status == "" {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_EARLY_STATE")
		}
		q.drain(t)
		if a.session != nil || a.busy || a.accountUnlock != nil ||
			len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_EARLY_REVIVED")
		}
	})

	t.Run("late-cancel-real-drains", func(t *testing.T) {
		a, q := newInitialFanoutTestApp(t, f, f.settingsPath)
		observed := make(chan struct{})
		var closedWrappers int
		var parentLocked bool
		localVaultFileInitialBatchDrainForTest = func(closed int, locked bool) {
			closedWrappers, parentLocked = closed, locked
			close(observed)
		}
		t.Cleanup(func() { localVaultFileInitialBatchDrainForTest = nil })

		a.unlock()
		token, ok := a.accountUnlockCancelToken()
		if !ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_TOKEN_MISSING")
		}
		q.runLaunch(t)
		if a.session != nil || !a.busy || a.accountUnlock == nil {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_NOT_PENDING")
		}
		a.cancelAccountUnlock(token)
		if a.session != nil || a.busy || a.accountUnlock != nil {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_STATE")
		}
		q.runDispatch(t)
		if len(q.launches) == 0 {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_DRAIN_NOT_QUEUED")
		}
		q.runLaunch(t)
		select {
		case <-observed:
		case <-time.After(5 * time.Second):
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_DRAIN_TIMEOUT")
		}
		if closedWrappers != 2 || !parentLocked {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_DRAIN_INCOMPLETE")
		}
		if a.session != nil || len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_LATE_REVIVED")
		}
	})

	t.Run("error-retry-real-chain", func(t *testing.T) {
		a := New()
		q := &localVaultSessionQueue{}
		q.install(a)
		a.generation = 3
		errSynthetic := errors.New("synthetic account unlock failure")

		a.runAccountUnlock(func(context.Context) outcome { return outcome{err: errSynthetic} })
		firstToken, ok := a.accountUnlockCancelToken()
		if !ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_ERROR_TOKEN_MISSING")
		}
		q.runLaunch(t)
		q.runDispatch(t)
		if a.accountUnlock != nil || a.busy {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_ERROR_MARKER_RETAINED")
		}
		if _, ok := a.accountUnlockCancelToken(); ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_ERROR_PREDICATE_AVAILABLE")
		}

		a.runAccountUnlock(func(context.Context) outcome { return outcome{err: errSynthetic} })
		secondToken, ok := a.accountUnlockCancelToken()
		if !ok || secondToken == firstToken {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_RETRY_TOKEN_MISMATCH")
		}
		a.cancelAccountUnlock(firstToken)
		if a.accountUnlock == nil || *a.accountUnlock != secondToken || !a.busy || a.generation != 3 {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_RETRY_CANCELED_BY_STALE")
		}
		if token, ok := a.accountUnlockCancelToken(); !ok || token != secondToken {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_RETRY_PREDICATE_LOST")
		}
		q.runLaunch(t)
		q.runDispatch(t)
		if a.accountUnlock != nil || a.busy {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_RETRY_MARKER_RETAINED")
		}
	})

	t.Run("stale-token-noop", func(t *testing.T) {
		a := New()
		a.busy = true
		a.generation = 1
		a.operationSequence = 3
		if _, ok := a.accountUnlockCancelToken(); ok {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_TOKEN_WITHOUT_ATTEMPT")
		}
		first := a.beginAccountUnlock(1, 3)
		if token, ok := a.accountUnlockCancelToken(); !ok || token != first {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_CURRENT_TOKEN_MISMATCH")
		}
		a.retireAccountUnlock(first)
		a.operationSequence = 4
		second := a.beginAccountUnlock(1, 4)
		a.cancelAccountUnlock(first)
		if a.accountUnlock == nil || *a.accountUnlock != second || a.generation != 1 || !a.busy {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_STALE_RETRY")
		}
		a.generation = 2
		a.operationSequence = 5
		third := a.beginAccountUnlock(2, 5)
		a.cancelAccountUnlock(second)
		if a.accountUnlock == nil || *a.accountUnlock != third || a.generation != 2 || !a.busy {
			t.Fatal("ACCOUNT_UNLOCK_CANCEL_STALE_NEWER_B")
		}
		a.retireAccountUnlock(third)
		a.busy = false
	})
}
