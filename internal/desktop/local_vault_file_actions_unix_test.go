//go:build darwin || linux

package desktop

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/oneo-me/onevra/source/theme"
)

func localVaultActionTester(f *localVaultSessionFixture) *ui.Tester {
	return ui.NewTester(func(c *ui.Context) {
		c.SetTheme(theme.Onevra(c))
		f.app.onevraLocalVaultFileView(c)
	}, 720, 640)
}

func TestDesktopLocalVaultLockActionAcceptsBusyStoredTarget(t *testing.T) {
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
		t.Fatal("LOCAL_ACTIONS_LOCK_SETUP_FAILED")
	}
	aSession, bSession := aSlot.session, bSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	bRef := localVaultNavigationRef(bPath, bManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef}
	f.app.selectLocalVaultFile(aRef)
	q.launches, q.dispatches = nil, nil

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var closeOnce sync.Once
	releaseClose := func() { closeOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(releaseClose)
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		close(closeEntered)
		<-closeRelease
	}

	field := prepareLocalVaultBusyField(t, f.parent)
	entered := make(chan struct{})
	consumeRelease := make(chan struct{})
	consumeDone := make(chan error, 1)
	var consumeOnce sync.Once
	releaseConsume := func() { consumeOnce.Do(func() { close(consumeRelease) }) }
	t.Cleanup(releaseConsume)
	go func() {
		consumeDone <- f.parent.Consume(field, func(_ []byte) error {
			close(entered)
			<-consumeRelease
			return nil
		})
	}()
	<-entered

	tester := localVaultActionTester(f)
	if err := tester.Click("锁定本地文件库"); err != nil {
		releaseConsume()
		t.Fatal("LOCAL_ACTIONS_LOCK_CLICK_FAILED")
	}
	// The click returned while the real parent mutex is still held by Consume.
	if f.app.localVaultFiles.status != localVaultFileLockStatusLocking {
		releaseConsume()
		t.Fatal("LOCAL_ACTIONS_LOCK_NOT_LOCKING")
	}
	if aSlot.session != nil || !aSlot.retiring {
		releaseConsume()
		t.Fatal("LOCAL_ACTIONS_LOCK_A_NOT_DETACHED")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		releaseConsume()
		t.Fatal("LOCAL_ACTIONS_LOCK_B_CHANGED")
	}
	op := aSlot.lock
	if op == nil {
		releaseConsume()
		t.Fatal("LOCAL_ACTIONS_LOCK_MARKER_MISSING")
	}
	releaseConsume()
	if err := <-consumeDone; err != nil {
		t.Fatal("LOCAL_ACTIONS_LOCK_CONSUME_FAILED")
	}

	if len(q.launches) != 3 {
		t.Fatal("LOCAL_ACTIONS_LOCK_WORKER_COUNT")
	}
	closeFn := q.launches[0]
	q.launches = q.launches[1:]
	closeDone := make(chan struct{})
	go func() {
		closeFn()
		close(closeDone)
	}()
	<-closeEntered
	if _, done := op.finiteOutcome(); done {
		releaseClose()
		t.Fatal("LOCAL_ACTIONS_LOCK_FINISHED_BEFORE_CLOSE")
	}
	releaseClose()
	<-closeDone
	q.runLaunch(t)
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.status != localVaultFileLockStatusLocked {
		t.Fatal("LOCAL_ACTIONS_LOCK_NOT_LOCKED")
	}
	if outcome, done := f.app.localVaultFileLockResult(aScope); !done || outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_ACTIONS_LOCK_NOT_FINITE_SUCCEEDED")
	}
	if _, err := aSession.Summary(); err == nil {
		t.Fatal("LOCAL_ACTIONS_LOCK_A_READABLE")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_ACTIONS_LOCK_B_LOST")
	}
}

func TestDesktopLocalVaultRefreshAndUnlockActionsBindControllers(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	cPath, cManifest := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	f.openVault(t, q, aScope)
	aRef := localVaultNavigationRef(aPath, aManifest)
	bRef := localVaultNavigationRef(bPath, bManifest)
	cRef := localVaultUnlockRef(cPath, cManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef, cRef}
	f.app.selectLocalVaultFile(aRef)
	q.launches, q.dispatches = nil, nil

	tester := localVaultActionTester(f)
	if err := tester.Click("刷新本地文件库"); err != nil {
		t.Fatal("LOCAL_ACTIONS_REFRESH_CLICK_FAILED")
	}
	if len(q.launches) != 1 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_ACTIONS_REFRESH_CONTROLLER_CALL_COUNT")
	}
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.refresh == nil {
		t.Fatal("LOCAL_ACTIONS_REFRESH_NOT_BOUND")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileFreshCaption {
		t.Fatal("LOCAL_ACTIONS_REFRESH_NOT_FRESH")
	}
	f.app.selectLocalVaultFile(aRef)
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileCachedCaption {
		t.Fatal("LOCAL_ACTIONS_REFRESH_BACK_NOT_CACHED")
	}

	f.app.closeLocalVaultFileView()
	f.app.localVaultFiles.selected = cPath
	q.launches, q.dispatches = nil, nil
	tester = localVaultActionTester(f)
	if err := tester.Click("解锁本地文件库"); err != nil {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_CLICK_FAILED")
	}
	if !f.app.localVaultUnlock.open ||
		f.app.localVaultUnlock.target.scope != f.scope(cPath, cManifest) {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_NOT_OPENED")
	}
	wantLabel := f.app.localVaultFileDisplayLabelFor(cRef)
	if f.app.localVaultUnlock.target.label != wantLabel {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_TARGET_LABEL_NOT_SHARED")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_QUEUED_WORK")
	}

	dialog := ui.NewTester(func(c *ui.Context) {
		c.SetTheme(theme.Onevra(c))
		f.app.onevraLocalVaultFileUnlockDialog(c)
	}, 640, 500)
	if err := dialog.Click("取消"); err != nil {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_CANCEL_CLICK_FAILED")
	}
	if f.app.localVaultUnlock.open || f.app.localVaultUnlock.busy ||
		f.app.localVaultUnlock.op != nil || f.app.localVaultUnlock.password != "" ||
		f.app.localVaultUnlock.secret != "" {
		t.Fatal("LOCAL_ACTIONS_UNLOCK_CANCEL_RETAINED_STATE")
	}
}

func TestDesktopLocalVaultLockWaitersArePerMarker(t *testing.T) {
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
		t.Fatal("LOCAL_ACTIONS_MARKER_SETUP_FAILED")
	}
	aSession, bSession := aSlot.session, bSlot.session
	f.app.localVaultFiles.refs = []localVaultFileRef{
		localVaultNavigationRef(aPath, aManifest),
		localVaultNavigationRef(bPath, bManifest),
	}

	enteredA, enteredB := make(chan struct{}), make(chan struct{})
	releaseACh, releaseBCh := make(chan struct{}), make(chan struct{})
	var releaseAOnce, releaseBOnce sync.Once
	releaseA := func() { releaseAOnce.Do(func() { close(releaseACh) }) }
	releaseB := func() { releaseBOnce.Do(func() { close(releaseBCh) }) }
	t.Cleanup(releaseA)
	t.Cleanup(releaseB)
	var closeCount atomic.Int32
	f.app.localVaultFiles.sessionAdoptedClosePauseForTest = func() {
		switch closeCount.Add(1) {
		case 1:
			close(enteredA)
			<-releaseACh
		case 2:
			close(enteredB)
			<-releaseBCh
		}
	}

	f.app.localVaultFiles.selected = aPath
	f.app.clickLocalVaultFileLockAction()
	if len(q.launches) != 3 {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_LAUNCH_COUNT")
	}
	aOp := aSlot.lock
	if aOp == nil || !aSlot.retiring || aSlot.session != nil {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_NOT_ACCEPTED")
	}

	f.app.localVaultFiles.selected = bPath
	f.app.clickLocalVaultFileLockAction()
	if len(q.launches) != 6 {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_LAUNCH_COUNT")
	}
	bOp := bSlot.lock
	if bOp == nil || bOp == aOp || !bSlot.retiring || bSlot.session != nil {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_NOT_ACCEPTED")
	}

	f.app.localVaultFiles.selected = aPath
	f.app.clickLocalVaultFileLockAction()
	if len(q.launches) != 6 || aSlot.lock != aOp {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_DUPLICATE_WAITER")
	}
	f.app.localVaultFiles.selected = bPath
	f.app.clickLocalVaultFileLockAction()
	if len(q.launches) != 6 || bSlot.lock != bOp {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_DUPLICATE_WAITER")
	}

	popLaunch := func(index int) func() {
		fn := q.launches[index]
		q.launches = append(q.launches[:index], q.launches[index+1:]...)
		return fn
	}
	closeA := popLaunch(0)
	closeADone := make(chan struct{})
	go func() {
		closeA()
		close(closeADone)
	}()
	<-enteredA
	closeB := popLaunch(2)
	closeBDone := make(chan struct{})
	go func() {
		closeB()
		close(closeBDone)
	}()
	<-enteredB
	if _, done := aOp.finiteOutcome(); done {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_DONE_EARLY")
	}
	if _, done := bOp.finiteOutcome(); done {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_DONE_EARLY")
	}

	releaseA()
	<-closeADone
	releaseB()
	<-closeBDone
	if len(q.launches) != 4 {
		t.Fatal("LOCAL_ACTIONS_MARKER_JOIN_COUNT")
	}
	q.runLaunch(t)
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.selected != bPath ||
		f.app.localVaultFiles.status != localVaultFileLockStatusLocking {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_LATE_REPAINT_OVERRIDDEN")
	}
	q.runLaunch(t)
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.status != localVaultFileLockStatusLocked {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_NOT_LOCKED")
	}
	if f.app.localVaultFiles.selected != bPath {
		t.Fatal("LOCAL_ACTIONS_MARKER_SELECTION_CHANGED")
	}
	if outcome, done := f.app.localVaultFileLockResult(aScope); !done || outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_NOT_SUCCEEDED")
	}
	if outcome, done := f.app.localVaultFileLockResult(bScope); !done || outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_NOT_SUCCEEDED")
	}
	if _, err := aSession.Summary(); err == nil {
		t.Fatal("LOCAL_ACTIONS_MARKER_A_READABLE")
	}
	if _, err := bSession.Summary(); err == nil {
		t.Fatal("LOCAL_ACTIONS_MARKER_B_READABLE")
	}
}

func TestDesktopLocalVaultWorkspaceChangeWithholdsProjection(t *testing.T) {
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
		t.Fatal("LOCAL_WORKSPACE_GATE_SETUP_FAILED")
	}
	bSession := bSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	bRef := localVaultNavigationRef(bPath, bManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef}
	f.app.selectLocalVaultFile(aRef)

	op := f.app.beginLocalVaultFileRefresh(aScope)
	if op == nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_REFRESH_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.viewVerification != localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() != localVaultFileFreshCaption {
		t.Fatal("LOCAL_WORKSPACE_GATE_FRESH_PRECONDITION_FAILED")
	}

	parent, generation := f.app.session, f.app.generation
	oldSettings := f.app.settingsPath
	otherSettings := filepath.Join(t.TempDir(), "settings.json")
	if err := f.app.ConfigureSettingsPath(otherSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_CONFIGURE_FAILED")
	}
	if f.app.session != parent || f.app.generation != generation {
		t.Fatal("LOCAL_WORKSPACE_GATE_PARENT_CHANGED")
	}
	if items := f.app.localVaultFileCurrentItems(); items != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FRESH_ITEMS_NOT_WITHHELD")
	}
	if caption := f.app.localVaultFileRefreshCaption(); caption != "" {
		t.Fatal("LOCAL_WORKSPACE_GATE_FRESH_CAPTION_NOT_WITHHELD")
	}

	if err := f.app.ConfigureSettingsPath(oldSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_RESTORE_FAILED")
	}
	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFileRefreshCaption() != localVaultFileCachedCaption {
		t.Fatal("LOCAL_WORKSPACE_GATE_CACHED_PRECONDITION_FAILED")
	}
	if err := f.app.ConfigureSettingsPath(otherSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_CACHED_CONFIGURE_FAILED")
	}
	if items := f.app.localVaultFileCurrentItems(); items != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_CACHED_ITEMS_NOT_WITHHELD")
	}
	if caption := f.app.localVaultFileRefreshCaption(); caption != "" {
		t.Fatal("LOCAL_WORKSPACE_GATE_CACHED_CAPTION_NOT_WITHHELD")
	}

	if err := f.app.ConfigureSettingsPath(oldSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_RESTORE_FAILED")
	}
	if err := os.Remove(aManifest.Journal); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_JOURNAL_REMOVE_FAILED")
	}
	failed := f.app.beginLocalVaultFileRefresh(aScope)
	if failed == nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.viewVerification != localVaultFileViewFailed ||
		f.app.localVaultFileRefreshCaption() != localVaultFileFailedCaption {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_PRECONDITION_FAILED")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_CLEANUP_COUNT")
	}
	q.runLaunch(t)
	if err := f.app.ConfigureSettingsPath(otherSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_CONFIGURE_FAILED")
	}
	if items := f.app.localVaultFileCurrentItems(); items != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_ITEMS_NOT_WITHHELD")
	}
	if caption := f.app.localVaultFileRefreshCaption(); caption != "" {
		t.Fatal("LOCAL_WORKSPACE_GATE_FAILED_CAPTION_NOT_WITHHELD")
	}

	// The display read gate is not a revocation gate: the exact stored A
	// target remains lockable while its projection is withheld from this
	// changed workspace, and B is untouched.
	f.app.localVaultFiles.selected = aPath
	q.launches, q.dispatches = nil, nil
	f.app.clickLocalVaultFileLockAction()
	if len(q.launches) != 2 {
		t.Fatal("LOCAL_WORKSPACE_GATE_LOCK_LAUNCH_COUNT")
	}
	q.runLaunch(t)
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.status != localVaultFileLockStatusLocked {
		t.Fatal("LOCAL_WORKSPACE_GATE_LOCK_NOT_LOCKED")
	}
	if outcome, done := f.app.localVaultFileLockResult(aScope); !done || outcome != localVaultFileLockOutcomeSucceeded {
		t.Fatal("LOCAL_WORKSPACE_GATE_LOCK_NOT_FINITE")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_WORKSPACE_GATE_LOCK_CHANGED_B")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_WORKSPACE_GATE_B_LOST")
	}

	if err := f.app.ConfigureSettingsPath(oldSettings); err != nil {
		t.Fatal("LOCAL_WORKSPACE_GATE_FINAL_RESTORE_FAILED")
	}
}
