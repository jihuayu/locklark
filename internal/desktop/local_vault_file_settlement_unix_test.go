//go:build darwin || linux

package desktop

import (
	"sync"
	"testing"
	"time"
)

func localVaultSessionProcessingFinished(op *localVaultFileSessionOperation) bool {
	if op == nil {
		return false
	}
	return op.processingDone()
}

func assertLocalVaultSessionSettlementOpen(t *testing.T, op *localVaultFileSessionOperation, code string) {
	t.Helper()
	if op == nil || op.isSettled() {
		t.Fatal(code)
	}
	select {
	case <-op.settledSignal():
		t.Fatal(code)
	default:
	}
}

func waitLocalVaultSessionSettlement(t *testing.T, op *localVaultFileSessionOperation) {
	t.Helper()
	if op == nil {
		t.Fatal("LOCAL_SETTLEMENT_OPERATION_MISSING")
	}
	select {
	case <-op.settledSignal():
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SETTLEMENT_TIMEOUT")
	}
	if !op.isSettled() {
		t.Fatal("LOCAL_SETTLEMENT_CHANNEL_INCONSISTENT")
	}
}

// TestDesktopLocalVaultSessionSettlementWaitsForRealCandidateClose watches the
// exact staged candidate through a held UI dispatch and a product cleanup Close
// paused immediately before the real wrapper Close. Settlement must stay open
// while the candidate is merely taken or a Close is merely requested, close only
// after the real Close returns, and leave a sibling wrapper untouched.
func TestDesktopLocalVaultSessionSettlementWaitsForRealCandidateClose(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SETTLEMENT_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var pauseOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		pauseOnce.Do(func() {
			close(closeEntered)
			<-closeRelease
		})
	}

	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SETTLEMENT_BEGIN_FAILED")
	}
	q.runLaunch(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	if !localVaultSessionProcessingFinished(op) {
		t.Fatal("LOCAL_SETTLEMENT_PRODUCER_NOT_FINISHED")
	}
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_SETTLEMENT_CLOSED_BEFORE_UI_DECISION")
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SETTLEMENT_UI_DISPATCH_NOT_HELD")
	}

	f.app.closeLocalVaultFileSession(aScope)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeCancelled)
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_SETTLEMENT_CLOSED_BEFORE_CLEANUP_CLOSE")
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_SETTLEMENT_CLEANUP_CLOSE_NOT_QUEUED")
	}
	cleanupClose := q.launches[0]
	q.launches = q.launches[1:]
	closeDone := make(chan struct{})
	go func() {
		cleanupClose()
		close(closeDone)
	}()
	select {
	case <-closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SETTLEMENT_CLEANUP_CLOSE_NOT_ENTERED")
	}
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_SETTLEMENT_CLOSED_WHILE_CLEANUP_PAUSED")
	if _, err := candidate.Summary(); err != nil {
		t.Fatal("LOCAL_SETTLEMENT_CANDIDATE_CLOSED_BEFORE_RELEASE")
	}
	close(closeRelease)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SETTLEMENT_CLEANUP_CLOSE_STUCK")
	}
	waitLocalVaultSessionSettlement(t, op)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_SETTLEMENT_CANDIDATE_READABLE_AFTER_CLOSE")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_SETTLEMENT_SIBLING_SLOT_CHANGED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SETTLEMENT_SIBLING_WRAPPER_LOST")
	}
	// The held UI callback is deliberately never executed; settlement came
	// from the product cleanup Close alone.
}

// TestDesktopLocalVaultSessionSettlementCancelBeforeStageClosesLateCandidate
// cancels while the generic worker is paused before its real factory. The late
// real candidate must be Closed by the refusing worker before settlement, and
// settlement must stay open throughout the in-flight factory and paused Close.
func TestDesktopLocalVaultSessionSettlementCancelBeforeStageClosesLateCandidate(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)

	openEntered := make(chan struct{})
	openRelease := make(chan struct{})
	var openOnce sync.Once
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		openOnce.Do(func() {
			close(openEntered)
			<-openRelease
		})
	}
	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var closeOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		closeOnce.Do(func() {
			close(closeEntered)
			<-closeRelease
		})
	}

	op := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_LATE_BEGIN_FAILED")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_LATE_WORKER_NOT_QUEUED")
	}
	worker := q.launches[0]
	q.launches = q.launches[1:]
	workerDone := make(chan struct{})
	go func() {
		worker()
		close(workerDone)
	}()
	select {
	case <-openEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_LATE_OPEN_PAUSE_NOT_ENTERED")
	}
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_LATE_SETTLED_BEFORE_CANCEL")
	f.app.cancelLocalVaultFileSession(scope)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeCancelled)
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_LATE_SETTLED_WITHOUT_CANDIDATE")
	close(openRelease)
	select {
	case <-closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_LATE_CANDIDATE_CLOSE_NOT_ENTERED")
	}
	assertLocalVaultSessionSettlementOpen(t, op, "LOCAL_LATE_SETTLED_WHILE_CLOSE_PAUSED")
	close(closeRelease)
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_LATE_WORKER_STUCK")
	}
	waitLocalVaultSessionSettlement(t, op)
}
