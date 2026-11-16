//go:build darwin || linux

package desktop

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func desktopLocalVaultAliasConfig(t *testing.T, original string) (string, vaultfileclient.Manifest) {
	t.Helper()
	manifest, exists, err := vaultfileclient.ReadManifest(original)
	if err != nil || !exists || manifest.Journal == "" {
		t.Fatal("LOCAL_ORDER_ALIAS_MANIFEST_MISSING")
	}
	rawManifest, err := os.ReadFile(original)
	if err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_MANIFEST_READ_FAILED")
	}
	companionPath, err := vaultfileclient.CompanionPath(original)
	if err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_COMPANION_PATH_FAILED")
	}
	rawCompanion, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_COMPANION_READ_FAILED")
	}
	alias := filepath.Join(filepath.Dir(original), "alias-"+filepath.Base(original))
	aliasCompanion, err := vaultfileclient.CompanionPath(alias)
	if err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_COMPANION_PATH_FAILED")
	}
	if err := os.WriteFile(alias, rawManifest, 0600); err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_MANIFEST_WRITE_FAILED")
	}
	if err := os.WriteFile(aliasCompanion, rawCompanion, 0600); err != nil {
		t.Fatal("LOCAL_ORDER_ALIAS_COMPANION_WRITE_FAILED")
	}
	aliasManifest, exists, err := vaultfileclient.ReadManifest(alias)
	if err != nil || !exists || aliasManifest.VaultID != manifest.VaultID ||
		aliasManifest.Journal != manifest.Journal {
		t.Fatal("LOCAL_ORDER_ALIAS_NOT_SAME_JOURNAL")
	}
	return alias, aliasManifest
}

func startLocalVaultLaunchAsync(t *testing.T, q *localVaultSessionQueue) chan struct{} {
	t.Helper()
	if len(q.launches) == 0 {
		t.Fatal("LOCAL_ORDER_LAUNCH_MISSING")
	}
	fn := q.launches[0]
	q.launches = q.launches[1:]
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	return done
}

func awaitLocalVaultSignal(t *testing.T, ch <-chan struct{}, code string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(code)
	}
}

func localVaultSessionWaitForContains(op *localVaultFileSessionOperation, target *localVaultFileSessionOperation) bool {
	if op == nil || target == nil {
		return false
	}
	for _, pred := range op.waitFor {
		if pred == target {
			return true
		}
	}
	return false
}

func TestDesktopLocalVaultJournalOrderingAliasWaitsForOldSettlement(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aliasPath, aliasManifest := desktopLocalVaultAliasConfig(t, aPath)
	aScope := f.scope(aPath, aManifest)
	aliasScope := f.scope(aliasPath, aliasManifest)
	bScope := f.scope(bPath, bManifest)
	if aScope.configPath == aliasScope.configPath || aScope.journalPath != aliasScope.journalPath {
		t.Fatal("LOCAL_ORDER_ALIAS_SETUP_FAILED")
	}

	var openCount atomic.Int32
	oldEntered := make(chan struct{})
	releaseOld := make(chan struct{})
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		if openCount.Add(1) == 1 {
			close(oldEntered)
			<-releaseOld
		}
	}
	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		closeOnce.Do(func() {
			close(closeEntered)
			<-releaseClose
		})
	}
	waitEntered := make(chan struct{}, 4)
	f.app.localVaultFiles.sessionPredecessorWaitForTest = func() {
		waitEntered <- struct{}{}
	}

	oldOp := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_ORDER_ALIAS_OLD_BEGIN_FAILED")
	}
	oldDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, oldEntered, "LOCAL_ORDER_ALIAS_OLD_NOT_AT_FACTORY")
	f.app.closeLocalVaultFileSession(aScope)
	assertLocalVaultSessionCompleted(t, oldOp, localVaultFileSessionOutcomeCancelled)
	if slot := f.app.localVaultFiles.sessionSlots[aScope]; slot == nil || !slot.retiring {
		t.Fatal("LOCAL_ORDER_ALIAS_OLD_NOT_RETIRING")
	}

	bOp := f.app.beginLocalVaultFileSession(bScope, []byte(f.password), f.key)
	if bOp == nil {
		t.Fatal("LOCAL_ORDER_ALIAS_B_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_ORDER_ALIAS_B_NOT_ADOPTED")
	}
	bSession := bSlot.session
	bSummary, err := bSession.Summary()
	if err != nil || bSummary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_ORDER_ALIAS_B_NOT_READABLE")
	}

	newOp := f.app.beginLocalVaultFileSession(aliasScope, []byte(f.password), f.key)
	if newOp == nil || !localVaultSessionWaitForContains(newOp, oldOp) {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_DID_NOT_INHERIT")
	}
	newDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, waitEntered, "LOCAL_ORDER_ALIAS_SUCCESSOR_NOT_WAITING")
	if openCount.Load() != 2 {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_ENTERED_EARLY")
	}

	close(releaseOld)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_ORDER_ALIAS_OLD_CLEANUP_NOT_STARTED")
	if openCount.Load() != 2 {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_BYPASSED_CLEANUP")
	}
	close(releaseClose)
	awaitLocalVaultSignal(t, oldDone, "LOCAL_ORDER_ALIAS_OLD_WORKER_STUCK")
	awaitLocalVaultSignal(t, newDone, "LOCAL_ORDER_ALIAS_SUCCESSOR_STUCK")
	if openCount.Load() != 3 {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_NOT_ENTERED_AFTER_SETTLE")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_NOT_STAGED")
	}
	q.runDispatch(t)
	aliasSlot := f.app.localVaultFiles.sessionSlots[aliasScope]
	if aliasSlot == nil || aliasSlot.session == nil {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_NOT_ADOPTED")
	}
	newSummary, err := aliasSlot.session.Summary()
	if err != nil || newSummary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_ORDER_ALIAS_SUCCESSOR_NOT_READABLE")
	}
	bSummary, err = bSession.Summary()
	if err != nil || bSummary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_ORDER_ALIAS_B_LOST")
	}
}

func TestDesktopLocalVaultJournalOrderingCloseReopenInheritsTail(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)

	var openCount atomic.Int32
	oldEntered := make(chan struct{})
	releaseOld := make(chan struct{})
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		if openCount.Add(1) == 1 {
			close(oldEntered)
			<-releaseOld
		}
	}
	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		closeOnce.Do(func() {
			close(closeEntered)
			<-releaseClose
		})
	}
	waitEntered := make(chan struct{}, 2)
	f.app.localVaultFiles.sessionPredecessorWaitForTest = func() {
		waitEntered <- struct{}{}
	}

	oldOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_ORDER_REOPEN_OLD_BEGIN_FAILED")
	}
	oldSlot := oldOp.slot
	oldDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, oldEntered, "LOCAL_ORDER_REOPEN_OLD_NOT_AT_FACTORY")
	f.app.closeLocalVaultFileSession(scope)
	retiring := f.app.localVaultFiles.sessionSlots[scope]
	if retiring == nil || !retiring.retiring || retiring != oldSlot {
		t.Fatal("LOCAL_ORDER_REOPEN_TAIL_NOT_RETAINED")
	}

	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp.slot == oldSlot || !localVaultSessionWaitForContains(newOp, oldOp) {
		t.Fatal("LOCAL_ORDER_REOPEN_TAIL_NOT_INHERITED")
	}
	newDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, waitEntered, "LOCAL_ORDER_REOPEN_SUCCESSOR_NOT_WAITING")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_ENTERED_EARLY")
	}
	close(releaseOld)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_ORDER_REOPEN_OLD_CLEANUP_NOT_STARTED")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_BYPASSED_CLEANUP")
	}
	close(releaseClose)
	awaitLocalVaultSignal(t, oldDone, "LOCAL_ORDER_REOPEN_OLD_WORKER_STUCK")
	awaitLocalVaultSignal(t, newDone, "LOCAL_ORDER_REOPEN_SUCCESSOR_STUCK")
	if openCount.Load() != 2 {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_NOT_ENTERED_AFTER_SETTLE")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_NOT_STAGED")
	}
	q.runDispatch(t)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_NOT_ADOPTED")
	}
	summary, err := slot.session.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_ORDER_REOPEN_SUCCESSOR_NOT_READABLE")
	}
}

func TestDesktopLocalVaultJournalOrderingSameParentGenerationPreservesTail(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)

	var openCount atomic.Int32
	oldEntered := make(chan struct{})
	releaseOld := make(chan struct{})
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		if openCount.Add(1) == 1 {
			close(oldEntered)
			<-releaseOld
		}
	}
	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		closeOnce.Do(func() {
			close(closeEntered)
			<-releaseClose
		})
	}
	waitEntered := make(chan struct{}, 2)
	f.app.localVaultFiles.sessionPredecessorWaitForTest = func() {
		waitEntered <- struct{}{}
	}

	oldOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_ORDER_GEN_OLD_BEGIN_FAILED")
	}
	oldDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, oldEntered, "LOCAL_ORDER_GEN_OLD_NOT_AT_FACTORY")
	f.app.closeLocalVaultFileSession(scope)
	f.app.generation++
	if f.app.syncLocalVaultFileSessions() != personal.VaultFileCacheActive {
		t.Fatal("LOCAL_ORDER_GEN_SYNC_NOT_ACTIVE")
	}
	retiring := f.app.localVaultFiles.sessionSlots[scope]
	tailHasOld := false
	if retiring != nil {
		for _, op := range retiring.tail {
			if op == oldOp {
				tailHasOld = true
				break
			}
		}
	}
	if retiring == nil || !retiring.retiring || !tailHasOld {
		t.Fatal("LOCAL_ORDER_GEN_TAIL_DROPPED")
	}

	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || !localVaultSessionWaitForContains(newOp, oldOp) {
		t.Fatal("LOCAL_ORDER_GEN_TAIL_NOT_INHERITED")
	}
	newDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, waitEntered, "LOCAL_ORDER_GEN_SUCCESSOR_NOT_WAITING")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_ENTERED_EARLY")
	}
	close(releaseOld)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_ORDER_GEN_OLD_CLEANUP_NOT_STARTED")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_BYPASSED_CLEANUP")
	}
	close(releaseClose)
	awaitLocalVaultSignal(t, oldDone, "LOCAL_ORDER_GEN_OLD_WORKER_STUCK")
	awaitLocalVaultSignal(t, newDone, "LOCAL_ORDER_GEN_SUCCESSOR_STUCK")
	if openCount.Load() != 2 {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_NOT_ENTERED_AFTER_SETTLE")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_NOT_STAGED")
	}
	q.runDispatch(t)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_NOT_ADOPTED")
	}
	summary, err := slot.session.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_ORDER_GEN_SUCCESSOR_NOT_READABLE")
	}
}

func TestDesktopLocalVaultJournalOrderingCancelledMiddleCarriesBarrier(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)

	var openCount atomic.Int32
	pEntered := make(chan struct{})
	releaseP := make(chan struct{})
	f.app.localVaultFiles.sessionCandidateOpenPauseForTest = func() {
		if openCount.Add(1) == 1 {
			close(pEntered)
			<-releaseP
		}
	}
	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	f.app.localVaultFiles.sessionCandidateClosePauseForTest = func() {
		closeOnce.Do(func() {
			close(closeEntered)
			<-releaseClose
		})
	}
	waitEntered := make(chan struct{}, 4)
	f.app.localVaultFiles.sessionPredecessorWaitForTest = func() {
		waitEntered <- struct{}{}
	}
	qPostEntered := make(chan struct{})
	releaseQPost := make(chan struct{})
	var qPostOnce sync.Once
	f.app.localVaultFiles.sessionPostBarrierCancelPauseForTest = func() {
		qPostOnce.Do(func() {
			close(qPostEntered)
			<-releaseQPost
		})
	}

	pOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if pOp == nil {
		t.Fatal("LOCAL_ORDER_PQR_P_BEGIN_FAILED")
	}
	pDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, pEntered, "LOCAL_ORDER_PQR_P_NOT_AT_FACTORY")

	qOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if qOp == nil || !localVaultSessionWaitForContains(qOp, pOp) {
		t.Fatal("LOCAL_ORDER_PQR_Q_DID_NOT_WAIT_FOR_P")
	}
	qDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, waitEntered, "LOCAL_ORDER_PQR_Q_NOT_WAITING")
	f.app.closeLocalVaultFileSession(scope)
	assertLocalVaultSessionCompleted(t, qOp, localVaultFileSessionOutcomeCancelled)

	rOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if rOp == nil || !localVaultSessionWaitForContains(rOp, pOp) || !localVaultSessionWaitForContains(rOp, qOp) {
		t.Fatal("LOCAL_ORDER_PQR_R_DID_NOT_JOIN_ALL")
	}
	rDone := startLocalVaultLaunchAsync(t, q)
	awaitLocalVaultSignal(t, waitEntered, "LOCAL_ORDER_PQR_R_NOT_WAITING")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_PQR_R_ENTERED_EARLY")
	}

	close(releaseP)
	awaitLocalVaultSignal(t, closeEntered, "LOCAL_ORDER_PQR_P_CLEANUP_NOT_STARTED")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_PQR_R_BYPASSED_P_CLEANUP")
	}
	close(releaseClose)
	awaitLocalVaultSignal(t, pDone, "LOCAL_ORDER_PQR_P_WORKER_STUCK")
	awaitLocalVaultSignal(t, qPostEntered, "LOCAL_ORDER_PQR_Q_NOT_AFTER_BARRIER")
	if openCount.Load() != 1 {
		t.Fatal("LOCAL_ORDER_PQR_R_BYPASSED_Q_SETTLEMENT")
	}
	close(releaseQPost)
	awaitLocalVaultSignal(t, qDone, "LOCAL_ORDER_PQR_Q_WORKER_STUCK")
	awaitLocalVaultSignal(t, rDone, "LOCAL_ORDER_PQR_R_WORKER_STUCK")
	if openCount.Load() != 2 {
		t.Fatal("LOCAL_ORDER_PQR_R_NOT_ENTERED_AFTER_ALL")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_ORDER_PQR_R_NOT_STAGED")
	}
	q.runDispatch(t)
	slot := f.app.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil {
		t.Fatal("LOCAL_ORDER_PQR_R_NOT_ADOPTED")
	}
	summary, err := slot.session.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_ORDER_PQR_R_NOT_READABLE")
	}
}

func TestDesktopCreateReservationFailureSkipsProtocol(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	q := &localVaultSessionQueue{}
	kit, _ := prepareDesktopCreateCompletion(t, f, q)
	f.app.localCreate.scope.journalPath = ""
	f.app.localCreate.password, f.app.localCreate.secret, f.app.localCreate.kit = f.password, f.secret, kit
	launches := len(q.launches)
	f.app.localCreateComplete()
	if len(q.launches) != launches {
		t.Fatal("DESKTOP_CREATE_RESERVATION_FAILURE_LAUNCHED_PROTOCOL")
	}
	if f.app.localCreate.child != nil || f.app.localCreate.busy {
		t.Fatal("DESKTOP_CREATE_RESERVATION_FAILURE_RETAINED_OPERATION")
	}
	if !f.app.localCreate.open || f.app.localCreate.phase != "complete" ||
		f.app.localCreate.status != "创建未完成；请核查本地状态" {
		t.Fatal("DESKTOP_CREATE_RESERVATION_FAILURE_NOT_MANUAL_RETRY")
	}
}
