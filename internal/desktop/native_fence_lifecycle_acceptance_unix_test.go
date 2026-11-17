//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

type nativeLifecycleTestUI struct {
	launches   chan func()
	dispatches chan func()
	stop       chan struct{}
	closeOnce  sync.Once
}

func newNativeLifecycleTestUI(a *App) *nativeLifecycleTestUI {
	ui := &nativeLifecycleTestUI{
		launches:   make(chan func(), 32),
		dispatches: make(chan func(), 32),
		stop:       make(chan struct{}),
	}
	a.launch = func(fn func()) { ui.launches <- fn }
	a.dispatch = func(fn func()) { ui.dispatches <- fn }
	go func() {
		for {
			select {
			case fn := <-ui.launches:
				go fn()
			case <-ui.stop:
				return
			}
		}
	}()
	return ui
}

func (u *nativeLifecycleTestUI) close() {
	u.closeOnce.Do(func() { close(u.stop) })
}

func (u *nativeLifecycleTestUI) waitDispatch(t *testing.T, timeout time.Duration) func() {
	t.Helper()
	select {
	case fn := <-u.dispatches:
		return fn
	case <-time.After(timeout):
		t.Fatal("NATIVE_LIFECYCLE_TEST_UI_DISPATCH_TIMEOUT")
		return nil
	}
}

func (u *nativeLifecycleTestUI) drainDispatches(t *testing.T, idle time.Duration) {
	t.Helper()
	for {
		select {
		case fn := <-u.dispatches:
			fn()
		case <-time.After(idle):
			return
		}
	}
}

func newNativeLifecycleTestApp(t *testing.T, f *localVaultSessionFixture) (*App, *nativeLifecycleTestUI) {
	t.Helper()
	a := New()
	a.settingsPath = f.settingsPath
	a.path = f.personalPath
	a.password = f.password
	a.secret = f.secret
	a.session = nil
	a.deviceSecrets = nil
	a.busy = false
	ui := newNativeLifecycleTestUI(a)
	t.Cleanup(func() {
		a.Lock()
		a.stopBrowserBroker()
		ui.close()
	})
	return a, ui
}

func newNativeLifecycleOwned(t *testing.T, f *localVaultSessionFixture, attemptID uint64,
	wait time.Duration) (*nativeFenceTestHarness, *localVaultFileInitialBatch, *initialAccountUnlockOutcome) {
	t.Helper()
	batch, results := newInitialOutcomeBatch(t, f)
	initial := newInitialAccountUnlockOutcome(batch, results)
	harness := newNativeFenceTestHarness(t, wait, 100*time.Millisecond, 5*time.Second)
	nativeFenceTestClaim(t, harness.transport, attemptID, initial.metadata.uniqueChildren)
	return harness, batch, initial
}

func newNativeLifecycleAdoptionApp(f *localVaultSessionFixture, generation uint64) *App {
	a := New()
	a.settingsPath = f.settingsPath
	a.path = f.personalPath
	a.generation = generation
	a.launch = func(fn func()) { fn() }
	return a
}

func nativeLifecycleAssertDrainSummary(t *testing.T, batch *localVaultFileInitialBatch) {
	t.Helper()
	summary := batch.drainSummary()
	if summary.state != localVaultFileInitialDrainComplete ||
		summary.closedWrappers != 2 || !summary.parentLocked ||
		!summary.refsCleared || !summary.rowsCleared {
		t.Fatal("NATIVE_LIFECYCLE_TEST_DRAIN_SUMMARY_INVALID")
	}
	batch.drain()
	if again := batch.drainSummary(); again != summary {
		t.Fatal("NATIVE_LIFECYCLE_TEST_DRAIN_NOT_EXACTLY_ONCE")
	}
}

func nativeLifecycleAssertAbortCleanup(t *testing.T, harness *nativeFenceTestHarness,
	batch *localVaultFileInitialBatch, r *outcome) {
	t.Helper()
	if r.apply != nil || r.drop != nil || r.initialAccount != nil || r.err != errNativeInitialUnlockFence {
		t.Fatal("NATIVE_LIFECYCLE_TEST_ABORT_NOT_DISCARDED")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_READY_FRAME_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_CANCELLED_FRAME_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 2 1" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	nativeLifecycleAssertDrainSummary(t, batch)
}

func TestNativeInitialUnlockLifecycleAppOnceCancel(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	f.createVault(t)
	f.createVault(t)
	if _, err := f.parent.AddLogin("lifecycle-app-once", "lifecycle-user", "lifecycle-value"); err != nil {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_FIXTURE_FAILED")
	}
	t.Setenv("LOCKLARK_BROWSER_SOCKET", desktopBrokerSocket(t))

	pipes := nativeFenceFactoryNewPipes(t)
	t.Setenv(nativeFenceFactoryControlEnv, strconv.Itoa(pipes.controlIn))
	t.Setenv(nativeFenceFactoryEventEnv, strconv.Itoa(pipes.eventOut))
	pipes.transfer()
	t.Cleanup(func() {
		if transport := nativeInitialUnlockFenceForBuild(); transport != nil {
			transport.close()
		}
	})

	first, firstUI := newNativeLifecycleTestApp(t, f)
	first.unlock()
	if frame := nativeFenceTestReadFrame(t, pipes.eventIn, 10*time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_READY_FRAME_MISMATCH")
	}
	token, ok := first.accountUnlockCancelToken()
	if !ok {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_CANCEL_TOKEN_MISSING")
	}
	first.cancelAccountUnlock(token)
	firstUI.waitDispatch(t, 10*time.Second)()
	if frame := nativeFenceTestReadFrame(t, pipes.eventIn, 5*time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_CANCELLED_FRAME_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, pipes.eventIn, 5*time.Second); frame != "DRAINED 2 1" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, pipes.eventIn, time.Second)
	if first.session != nil || len(first.localVaultFiles.sessionSlots) != 0 ||
		first.busy || first.accountUnlock != nil || len(first.rows) != 0 || first.status == "" {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_LOCKED_PROJECTION_FAILED")
	}

	transport := nativeInitialUnlockFenceForBuild()
	if transport == nil {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_FACTORY_NOT_SELECTED")
	}
	if stale := transport.publishAdopted(1, 2); stale.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_STALE_ADOPT_NOT_IGNORED")
	}
	if stale := transport.publishDrained(2, 2, true); stale.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_STALE_DRAIN_NOT_IGNORED")
	}

	second, secondUI := newNativeLifecycleTestApp(t, f)
	second.unlock()
	secondUI.waitDispatch(t, 10*time.Second)()
	if second.session == nil || len(second.localVaultFiles.sessionSlots) != 2 || len(second.rows) != 1 {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_NEW_B_NOT_ADOPTED")
	}
	adopted := second.session
	if stale := transport.publishAdopted(3, 2); stale.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_LATE_NOTIFY_REVIVED_B")
	}
	if second.session != adopted {
		t.Fatal("NATIVE_LIFECYCLE_TEST_APP_LATE_NOTIFY_CHANGED_B")
	}
	secondUI.drainDispatches(t, 50*time.Millisecond)
}

func TestNativeInitialUnlockLifecycleOwnedReleaseAndAbort(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	f.createVault(t)
	f.createVault(t)
	if _, err := f.parent.AddLogin("lifecycle-owned", "owned-user", "owned-value"); err != nil {
		t.Fatal("NATIVE_LIFECYCLE_TEST_OWNED_FIXTURE_FAILED")
	}

	t.Run("released-refusal-drain", func(t *testing.T) {
		harness, batch, initial := newNativeLifecycleOwned(t, f, 9011, 2*time.Second)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		r := outcome{initialAccount: initial}
		nativeInitialUnlockFenceOwn(context.Background(), harness.transport, 9011, initial, &r, 5*time.Second)
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
			t.Fatal("NATIVE_LIFECYCLE_TEST_READY_FRAME_MISMATCH")
		}
		gate := newNativeLifecycleAdoptionApp(f, batch.generation+1)
		if parent, rows, ok := gate.adoptLocalVaultFileInitialBatch(batch); ok || parent != nil || rows != nil {
			t.Fatal("NATIVE_LIFECYCLE_TEST_GATE_REFUSAL_NOT_REFUSED")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 2 1" {
			t.Fatal("NATIVE_LIFECYCLE_TEST_REFUSAL_DRAINED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
		nativeLifecycleAssertDrainSummary(t, batch)
	})

	t.Run("released-adopt", func(t *testing.T) {
		harness, batch, initial := newNativeLifecycleOwned(t, f, 9012, 2*time.Second)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		r := outcome{initialAccount: initial}
		nativeInitialUnlockFenceOwn(context.Background(), harness.transport, 9012, initial, &r, 5*time.Second)
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
			t.Fatal("NATIVE_LIFECYCLE_TEST_READY_FRAME_MISMATCH")
		}
		gate := newNativeLifecycleAdoptionApp(f, batch.generation)
		parent, rows, ok := gate.adoptLocalVaultFileInitialBatch(batch)
		if !ok || parent == nil {
			t.Fatal("NATIVE_LIFECYCLE_TEST_GATE_ADOPTION_FAILED")
		}
		gate.session = parent
		gate.rows = loginProjection(rows)
		clearLocalVaultFileInitialRows(rows)
		initial.fence.signalAdopted()
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 2" {
			t.Fatal("NATIVE_LIFECYCLE_TEST_ADOPTED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
		if summary := batch.drainSummary(); summary.state == localVaultFileInitialDrainComplete {
			t.Fatal("NATIVE_LIFECYCLE_TEST_ADOPTED_ALSO_DRAINED")
		}
		gate.Lock()
	})

	t.Run("eof-cleanup", func(t *testing.T) {
		harness, batch, initial := newNativeLifecycleOwned(t, f, 9013, 2*time.Second)
		nativeFenceTestClose(harness.controlOut)
		r := outcome{apply: func() {}, drop: func() {}, initialAccount: initial}
		nativeInitialUnlockFenceOwn(context.Background(), harness.transport, 9013, initial, &r, 5*time.Second)
		nativeLifecycleAssertAbortCleanup(t, harness, batch, &r)
	})

	t.Run("timeout-cleanup", func(t *testing.T) {
		harness, batch, initial := newNativeLifecycleOwned(t, f, 9014, 30*time.Millisecond)
		r := outcome{apply: func() {}, drop: func() {}, initialAccount: initial}
		nativeInitialUnlockFenceOwn(context.Background(), harness.transport, 9014, initial, &r, 5*time.Second)
		nativeLifecycleAssertAbortCleanup(t, harness, batch, &r)
	})

	t.Run("protocol-error-cleanup", func(t *testing.T) {
		harness, batch, initial := newNativeLifecycleOwned(t, f, 9015, 2*time.Second)
		nativeFenceTestWrite(t, harness.controlOut, "PING\n")
		r := outcome{apply: func() {}, drop: func() {}, initialAccount: initial}
		nativeInitialUnlockFenceOwn(context.Background(), harness.transport, 9015, initial, &r, 5*time.Second)
		nativeLifecycleAssertAbortCleanup(t, harness, batch, &r)
	})
}
