//go:build darwin || linux

package desktop

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// TestDesktopLocalVaultLockRejectsUnknownScope proves a caller-supplied
// unregistered full scope cannot borrow B's stored journal to create an anchor,
// mark/detach B, or report a fabricated success. The exact registry slot is the
// only ownership source.
func TestDesktopLocalVaultLockRejectsUnknownScope(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_LOCK_UNKNOWN_SETUP_FAILED")
	}
	bWrapper := bSlot.session
	before := len(f.app.localVaultFiles.sessionSlots)

	forged := bScope
	forged.configPath = bPath + ".forged"
	if lock := f.app.beginLocalVaultFileLock(forged); lock != nil {
		t.Fatal("LOCAL_LOCK_UNKNOWN_SCOPE_ACCEPTED")
	}
	if outcome, done := f.app.localVaultFileLockResult(forged); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_UNKNOWN_GETTER_FABRICATED")
	}
	if lock := f.app.beginLocalVaultFileLock(localVaultFileSessionScope{}); lock != nil {
		t.Fatal("LOCAL_LOCK_EMPTY_SCOPE_ACCEPTED")
	}
	if outcome, done := f.app.localVaultFileLockResult(localVaultFileSessionScope{}); done ||
		outcome != localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_EMPTY_GETTER_FABRICATED")
	}
	if len(f.app.localVaultFiles.sessionSlots) != before ||
		bSlot.lock != nil || bSlot.session != bWrapper || bSlot.retiring {
		t.Fatal("LOCAL_LOCK_UNKNOWN_SCOPE_MUTATED_REGISTRY")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_LOCK_UNKNOWN_SCOPE_STARTED_WORK")
	}
	summary, err := bWrapper.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_LOCK_UNKNOWN_SCOPE_HURT_SIBLING")
	}
}

// TestDesktopLocalVaultLockBusyExistingOwnership holds the real Session.mu with
// an ignored native delivery and pauses the adopted Close. Begin(A) must still
// install the marker and start cleanup while Busy, then remain unfinished until
// the real Close releases. B stays with the same wrapper; same-journal reopen
// remains refused after the delivery releases but before the Close releases.
func TestDesktopLocalVaultLockBusyExistingOwnership(t *testing.T) {
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
		t.Fatal("LOCAL_LOCK_BUSY_SETUP_FAILED")
	}
	aWrapper, bWrapper := aSlot.session, bSlot.session

	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := f.parent.RegisterMutation(gate); err != nil {
		t.Fatal("LOCAL_LOCK_BUSY_MUTATION_GATE_FAILED")
	}
	id, revision, err := f.parent.AddItem(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, Title: "busy target",
		Password: "busy-target-value",
	}, gate)
	if err != nil {
		t.Fatal("LOCAL_LOCK_BUSY_ITEM_FAILED")
	}
	field, err := f.parent.PrepareField(personal.RevealTarget{ID: id, Revision: revision, Field: "password"}, "show")
	if err != nil {
		t.Fatal("LOCAL_LOCK_BUSY_FIELD_FAILED")
	}

	consumeEntered := make(chan struct{})
	consumeRelease := make(chan struct{})
	consumeDone := make(chan error, 1)
	go func() {
		consumeDone <- f.parent.Consume(field, func([]byte) error {
			close(consumeEntered)
			<-consumeRelease
			return nil
		})
	}()
	awaitLocalVaultSignal(t, consumeEntered, "LOCAL_LOCK_BUSY_CONSUME_NOT_ENTERED")
	if f.parent.VaultFileCacheState() != personal.VaultFileCacheBusy {
		t.Fatal("LOCAL_LOCK_BUSY_STATE_NOT_BUSY")
	}

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
	if lock == nil || lock.isDone() {
		t.Fatal("LOCAL_LOCK_BUSY_BEGIN_FAILED")
	}
	if aSlot.lock != lock || aSlot.session != nil || aSlot.closeTail == nil ||
		aSlot.summary.VaultID != "" || bSlot.session != bWrapper {
		t.Fatal("LOCAL_LOCK_BUSY_MARKER_OR_SIBLING_FAILED")
	}
	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_BUSY_CLOSE_NOT_ENTERED")
	lockWorker := startLocalVaultLaunchAsync(t, q)
	if lock.isDone() {
		t.Fatal("LOCAL_LOCK_BUSY_FINISHED_WHILE_PAUSED")
	}

	close(consumeRelease)
	if err := <-consumeDone; err != nil {
		t.Fatal("LOCAL_LOCK_BUSY_CONSUME_FAILED")
	}
	if op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key); op != nil {
		t.Fatal("LOCAL_LOCK_BUSY_REOPEN_NOT_BLOCKED")
	}
	if op := f.app.reserveLocalVaultFileSessionOperation(aScope); op != nil {
		t.Fatal("LOCAL_LOCK_BUSY_RESERVE_NOT_BLOCKED")
	}
	sibling, err := bWrapper.Summary()
	if err != nil || sibling.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_LOCK_BUSY_SIBLING_LOST")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_LOCK_BUSY_CLOSE_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_BUSY_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := f.app.localVaultFileLockResult(aScope); !done ||
		outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_LOCK_BUSY_NOT_FINITE_LOCKED")
	}
	if _, err := aWrapper.Summary(); err == nil {
		t.Fatal("LOCAL_LOCK_BUSY_WRAPPER_STILL_READABLE")
	}
}

// TestDesktopLocalVaultLockRequestedParentExistingOwnership uses RequestLock
// only as the revocation flag. The existing registered A slot must still accept
// the marker and start the tracked Close, which completes before parent.Lock is
// called for normal cleanup. No sibling-read claim is made after revocation.
func TestDesktopLocalVaultLockRequestedParentExistingOwnership(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	f.openVault(t, q, scope)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_LOCK_REQUESTED_SETUP_FAILED")
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

	f.parent.RequestLock()
	if f.parent.VaultFileCacheState() != personal.VaultFileCacheRevoked {
		t.Fatal("LOCAL_LOCK_REQUESTED_PARENT_NOT_REVOKED")
	}
	lock := f.app.beginLocalVaultFileLock(scope)
	if lock == nil || lock.isDone() {
		t.Fatal("LOCAL_LOCK_REQUESTED_BEGIN_REFUSED")
	}
	closeWorker := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_LOCK_REQUESTED_CLOSE_NOT_ENTERED")
	lockWorker := startLocalVaultLaunchAsync(t, q)
	if lock.isDone() || slot.lock != lock || slot.closeTail == nil {
		t.Fatal("LOCAL_LOCK_REQUESTED_MARKER_NOT_PENDING")
	}

	close(closeRelease)
	awaitLocalVaultSignal(t, closeWorker, "LOCAL_LOCK_REQUESTED_CLOSE_STUCK")
	awaitLocalVaultSignal(t, lockWorker, "LOCAL_LOCK_REQUESTED_WORKER_STUCK")
	waitLocalVaultFileLockDone(t, lock)
	if outcome, done := lock.finiteOutcome(); !done ||
		outcome == localVaultFileLockOutcomeUnknown {
		t.Fatal("LOCAL_LOCK_REQUESTED_NOT_FINITE")
	}
	if _, err := wrapper.Summary(); err == nil {
		t.Fatal("LOCAL_LOCK_REQUESTED_WRAPPER_STILL_READABLE")
	}
	f.parent.Lock()
}
