//go:build darwin || linux

package desktop

import "testing"

// TestDesktopLocalVaultSessionSettledOpenedCancelPreserved pins the legal
// already-adopted settlement boundary. A later exact cancellation must not
// rewrite the Opened outcome, close the adopted child, or repeat the one-shot
// completion observer.
func TestDesktopLocalVaultSessionSettledOpenedCancelPreserved(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	op := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SETTLED_OPENED_BEGIN_FAILED")
	}
	var outcomes []localVaultFileSessionOutcome
	op.setCompletionObserver(func(outcome localVaultFileSessionOutcome) {
		outcomes = append(outcomes, outcome)
	})
	q.runLaunch(t)
	q.runDispatch(t)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil || slot.retiring || slot.operation != nil {
		t.Fatal("LOCAL_SETTLED_OPENED_ADOPT_SETUP_FAILED")
	}
	child := slot.session
	if op.finiteOutcome() != localVaultFileSessionOutcomeOpened ||
		len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeOpened {
		t.Fatal("LOCAL_SETTLED_OPENED_OBSERVER_NOT_ONCE")
	}
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeOpened)

	f.app.cancelLocalVaultFileSessionOperationExact(op)
	if op.finiteOutcome() != localVaultFileSessionOutcomeOpened {
		t.Fatal("LOCAL_SETTLED_OPENED_OUTCOME_REWRITTEN")
	}
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeOpened)
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeOpened {
		t.Fatal("LOCAL_SETTLED_OPENED_OBSERVER_REPEATED")
	}
	if f.app.localVaultFiles.sessionSlots[scope] != slot || slot.session != child {
		t.Fatal("LOCAL_SETTLED_OPENED_CHILD_REPLACED")
	}
	summary, err := child.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_SETTLED_OPENED_CHILD_CLOSED")
	}
}

// TestDesktopLocalVaultSessionSettledFailureCancelTerminalizesOneShot pins the
// other settled boundary: a no-candidate failure can settle before its UI take.
// Exact cancellation must terminalize and clear that handoff, report Cancelled
// once, and refuse the stale callback without changing a later operation.
func TestDesktopLocalVaultSessionSettledFailureCancelTerminalizesOneShot(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	op := f.app.beginLocalVaultFileSession(scope, []byte("wrong-local-factor"), []byte("fedcba0987654321"))
	if op == nil {
		t.Fatal("LOCAL_SETTLED_FAILURE_BEGIN_FAILED")
	}
	var outcomes []localVaultFileSessionOutcome
	op.setCompletionObserver(func(outcome localVaultFileSessionOutcome) {
		outcomes = append(outcomes, outcome)
	})
	q.runLaunch(t)
	if !op.isSettled() {
		t.Fatal("LOCAL_SETTLED_FAILURE_NOT_SETTLED")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SETTLED_FAILURE_UI_TAKE_NOT_HELD")
	}

	f.app.closeLocalVaultFileSession(scope)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeCancelled)
	if op.finiteOutcome() != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_SETTLED_FAILURE_OUTCOME_NOT_CANCELLED")
	}
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_SETTLED_FAILURE_OBSERVER_NOT_ONCE")
	}

	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == op {
		t.Fatal("LOCAL_SETTLED_FAILURE_NEW_BEGIN_FAILED")
	}
	q.runLaunch(t)
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	if len(q.dispatches) != 2 {
		t.Fatal("LOCAL_SETTLED_FAILURE_STALE_AND_NEW_TAKE_MISSING")
	}
	oldTake, newTake := q.dispatches[0], q.dispatches[1]
	q.dispatches = nil

	oldTake()
	if op.finiteOutcome() != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_SETTLED_FAILURE_STALE_TAKE_REWROTE_OUTCOME")
	}
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_SETTLED_FAILURE_STALE_TAKE_REPEATED_OBSERVER")
	}
	if newOp.finiteOutcome() != localVaultFileSessionOutcomeNone {
		t.Fatal("LOCAL_SETTLED_FAILURE_STALE_TAKE_FINISHED_NEW_OP")
	}
	if _, err := newCandidate.Summary(); err != nil {
		t.Fatal("LOCAL_SETTLED_FAILURE_STALE_TAKE_CLOSED_NEW_CANDIDATE")
	}

	newTake()
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session != newCandidate || slot.operation != nil {
		t.Fatal("LOCAL_SETTLED_FAILURE_NEW_OP_NOT_ADOPTED")
	}
	summary, err := newCandidate.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_SETTLED_FAILURE_NEW_CHILD_LOST")
	}
}

// TestDesktopLocalVaultSessionCompletedFailureCancelPreserved pins the
// UI-completed finite guard rather than the material settlement boundary. After
// the UI has already taken a no-candidate failure and observed Failed, a late
// exact cancel must leave Failed, keep the same one-shot observer count, and
// neither close nor finish a later operation.
func TestDesktopLocalVaultSessionCompletedFailureCancelPreserved(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	op := f.app.beginLocalVaultFileSession(scope, []byte("wrong-local-factor"), []byte("fedcba0987654321"))
	if op == nil {
		t.Fatal("LOCAL_COMPLETED_FAILURE_BEGIN_FAILED")
	}
	var outcomes []localVaultFileSessionOutcome
	op.setCompletionObserver(func(outcome localVaultFileSessionOutcome) {
		outcomes = append(outcomes, outcome)
	})
	q.runLaunch(t)
	if !op.isSettled() || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_COMPLETED_FAILURE_SETTLE_SETUP_FAILED")
	}
	oldTake := q.dispatches[0]
	q.dispatches = nil
	oldTake()
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeFailed {
		t.Fatal("LOCAL_COMPLETED_FAILURE_OBSERVER_NOT_FAILED_ONCE")
	}

	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == op {
		t.Fatal("LOCAL_COMPLETED_FAILURE_NEW_BEGIN_FAILED")
	}
	q.runLaunch(t)
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_COMPLETED_FAILURE_NEW_TAKE_MISSING")
	}
	newTake := q.dispatches[0]
	q.dispatches = nil

	f.app.cancelLocalVaultFileSessionOperationExact(op)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeFailed {
		t.Fatal("LOCAL_COMPLETED_FAILURE_CANCEL_REWROTE_OR_REPEATED_OBSERVER")
	}
	oldTake()
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	if len(outcomes) != 1 || outcomes[0] != localVaultFileSessionOutcomeFailed {
		t.Fatal("LOCAL_COMPLETED_FAILURE_STALE_TAKE_REWROTE_OR_REPEATED_OBSERVER")
	}
	if newOp.finiteOutcome() != localVaultFileSessionOutcomeNone {
		t.Fatal("LOCAL_COMPLETED_FAILURE_CANCEL_FINISHED_NEW_OP")
	}
	if _, err := newCandidate.Summary(); err != nil {
		t.Fatal("LOCAL_COMPLETED_FAILURE_CANCEL_CLOSED_NEW_CANDIDATE")
	}

	newTake()
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session != newCandidate || slot.operation != nil {
		t.Fatal("LOCAL_COMPLETED_FAILURE_NEW_OP_NOT_ADOPTED")
	}
	summary, err := newCandidate.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_COMPLETED_FAILURE_NEW_CHILD_LOST")
	}
}
