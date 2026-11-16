//go:build darwin || linux

package desktop

import (
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

// TestDesktopLocalVaultUnlockBusyCandidateWithheldThenRetry holds a real
// opened candidate dispatch until the actual parent mutex is held by Consume.
// The exact UI callback must return before release, classify the valid
// candidate as Withheld rather than a factor failure, run the normal product
// candidate Close, and allow a fresh explicit correct-input retry on the same
// frozen target.
func TestDesktopLocalVaultUnlockBusyCandidateWithheldThenRetry(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session
	f.app.localVaultFiles.selected = aPath
	aRef := localVaultUnlockRef(aPath, aManifest)
	if !f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_OPEN_REFUSED")
	}
	state := &f.app.localVaultUnlock
	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	if state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_SUBMIT_RETAINED_INPUTS")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	op := state.op
	if op == nil || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_CANDIDATE_NOT_STAGED")
	}
	candidate := localVaultSessionStagedCandidate(t, op)
	heldDispatch := q.dispatches[0]
	q.dispatches = nil

	// Prepare the real field before holding the mutex, then enter Consume. Its
	// deliver ignores the bytes entirely and waits for the explicit release.
	field := prepareLocalVaultBusyField(t, f.parent)
	entered := make(chan struct{})
	releaseCh := make(chan struct{})
	consumeDone := make(chan error, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCh) }) }
	t.Cleanup(release)
	go func() {
		consumeDone <- f.parent.Consume(field, func(_ []byte) error {
			close(entered)
			<-releaseCh
			return nil
		})
	}()
	<-entered

	// The exact UI dispatch must finish while the real parent mutex is held.
	heldDispatch()

	if op.finiteOutcome() != localVaultFileSessionOutcomeWithheld {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_NOT_FINITE_WITHHELD")
	}
	if !state.open || state.busy || state.op != nil || state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_DIALOG_STATE_INVALID")
	}
	if state.status != localVaultFileUnlockStatusWithheld {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_NOT_UNAVAILABLE_FEEDBACK")
	}
	if state.status == localVaultFileUnlockStatusFailed {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_MISATTRIBUTED_FAILURE")
	}
	if state.target.scope != aScope {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_TARGET_NOT_FROZEN")
	}
	slot := f.app.localVaultFiles.sessionSlots[aScope]
	if slot == nil || slot.operation != nil || slot.session != nil {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_ADOPTED_CANDIDATE")
	}
	// Child Summary revalidates through the parent, so only pointer identity is
	// asserted while Consume holds the real parent mutex.
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_SIBLING_CHANGED")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_CLEANUP_NOT_QUEUED")
	}
	q.runLaunch(t)
	waitLocalVaultSessionSettlement(t, op)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_CANDIDATE_READABLE")
	}

	release()
	if err := <-consumeDone; err != nil {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_CONSUME_FAILED")
	}
	if cacheState, path := f.parent.VaultFileCacheSnapshot(); cacheState != personal.VaultFileCacheActive || path == "" {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_PARENT_PROOF_CHANGED")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)

	// The frozen dialog remains open for an explicit fresh correct-input retry.
	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	if state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_RETAINED_INPUTS")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	newOp := state.op
	if newOp == nil || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_NOT_STAGED")
	}
	q.runDispatch(t)
	q.drain(t)
	if state.open || state.busy || state.op != nil || state.status != localVaultFileUnlockStatusOpened {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_NOT_OPENED")
	}
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil || aSlot.operation != nil ||
		aSlot.summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_CHILD_NOT_ADOPTED")
	}
	if aSlot.session == bSession {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_REUSED_SIBLING")
	}
	adopted := aSlot.session
	if summary, err := adopted.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_RETRY_CHILD_UNREADABLE")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)

	// A late cancel of the completed Withheld operation must not rewrite its
	// finite outcome, notify again, or disturb the fresh adopted child/dialog.
	f.app.cancelLocalVaultFileSessionOperationExact(op)
	if op.finiteOutcome() != localVaultFileSessionOutcomeWithheld {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_LATE_CANCEL_REWROTE_OUTCOME")
	}
	if state.open || state.busy || state.op != nil || state.status != localVaultFileUnlockStatusOpened {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_LATE_CANCEL_CHANGED_DIALOG")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || aSlot.session != adopted {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_LATE_CANCEL_CHANGED_CHILD")
	}
	if summary, err := adopted.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_WITHHELD_LATE_CANCEL_BROKE_CHILD")
	}
}
