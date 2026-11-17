//go:build darwin || linux

package desktop

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func localVaultUnlockRef(configPath string, manifest vaultfileclient.Manifest) localVaultFileRef {
	return localVaultFileRef{
		path:        configPath,
		vaultID:     manifest.VaultID,
		name:        "本地文件库标签",
		journalPath: manifest.Journal,
	}
}

func localVaultUnlockPair(t *testing.T, f *localVaultSessionFixture) (string, vaultfileclient.Manifest, string, vaultfileclient.Manifest) {
	t.Helper()
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	return aPath, aManifest, bPath, bManifest
}

// localVaultUnlockQuickParent converts the fixture parent into a real OS
// quick-unlock session through the existing test OS-store adapter. The returned
// session is usable for ordinary work but has no full-factor proof, so a local
// vault unlock must not refresh or fabricate one.
func localVaultUnlockQuickParent(t *testing.T, f *localVaultSessionFixture) {
	t.Helper()
	store := newFakeSystemUnlockStore()
	if err := f.parent.EnableSystemUnlock(store); err != nil {
		t.Fatal("LOCAL_UNLOCK_QUICK_ENROLL_FAILED")
	}
	f.parent.Lock()
	quick, err := personal.UnlockWithSystem(f.personalPath, store, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_UNLOCK_QUICK_UNLOCK_FAILED")
	}
	f.parent = quick
	f.app.session = quick
	t.Cleanup(quick.Lock)
}

func assertLocalVaultUnlockBUnchanged(t *testing.T, a *App, bScope localVaultFileSessionScope, bSlot *localVaultFileSessionSlot, bSession *vaultfileclient.LocalGenesisSession, bVaultID string) {
	t.Helper()
	if a.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_UNLOCK_SIBLING_SLOT_CHANGED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bVaultID {
		t.Fatal("LOCAL_UNLOCK_SIBLING_CHILD_LOST")
	}
}

func TestDesktopLocalVaultUnlockOpenCancelAndTargetRefusals(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_OPEN_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session
	generation := f.app.generation

	aRef := localVaultUnlockRef(aPath, aManifest)
	if !f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSED_VALID_TARGET")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_UNLOCK_OPEN_QUEUED_FACTORY_WORK")
	}
	state := &f.app.localVaultUnlock
	if !state.open || state.busy || state.op != nil {
		t.Fatal("LOCAL_UNLOCK_OPEN_STATE_INVALID")
	}
	if state.target.scope != f.scope(aPath, aManifest) ||
		state.target.parent != f.parent || state.target.generation != generation ||
		state.target.label != aRef.name {
		t.Fatal("LOCAL_UNLOCK_OPEN_TARGET_NOT_FROZEN")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)

	state.password, state.secret = "unlock-cancel-password", "unlock-cancel-secret"
	f.app.cancelLocalVaultFileUnlock()
	if state.open || state.busy || state.op != nil || state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_CANCEL_RETAINED_INPUTS_OR_STATE")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_UNLOCK_CANCEL_QUEUED_WORK_WITHOUT_OP")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)

	unknown := aRef
	unknown.vaultID = ""
	if f.app.openLocalVaultFileUnlock(unknown) {
		t.Fatal("LOCAL_UNLOCK_ACCEPTED_UNKNOWN_HINT")
	}
	if state.open || state.status != localVaultFileUnlockStatusUnavailable {
		t.Fatal("LOCAL_UNLOCK_UNKNOWN_HINT_STATE_NOT_REFUSED")
	}

	invalid := aRef
	invalid.path = filepath.Join(f.root, "outside.json")
	if f.app.openLocalVaultFileUnlock(invalid) {
		t.Fatal("LOCAL_UNLOCK_ACCEPTED_FOREIGN_TARGET")
	}
	if state.open || state.status != localVaultFileUnlockStatusUnavailable {
		t.Fatal("LOCAL_UNLOCK_FOREIGN_TARGET_STATE_NOT_REFUSED")
	}

	f.app.session = nil
	if f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_ACCEPTED_INACTIVE_PARENT")
	}
	if state.open || state.status != localVaultFileUnlockStatusUnavailable {
		t.Fatal("LOCAL_UNLOCK_INACTIVE_PARENT_STATE_NOT_REFUSED")
	}
	f.app.session = f.parent
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_UNLOCK_REFUSALS_QUEUED_WORK")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
}

func TestDesktopLocalVaultUnlockWrongThenCorrectOnSameParent(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	localVaultUnlockQuickParent(t, f)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_FACTOR_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session
	parent, generation := f.app.session, f.app.generation
	if _, err := parent.VaultFileOwnerships(); !errors.Is(err, personal.ErrVaultFileFullFactorRequired) {
		t.Fatal("LOCAL_UNLOCK_QUICK_PARENT_HAS_FULL_PROOF")
	}

	aScope := f.scope(aPath, aManifest)
	aRef := localVaultUnlockRef(aPath, aManifest)
	f.app.localVaultFiles.selected = aPath
	if !f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_FACTOR_OPEN_REFUSED")
	}
	state := &f.app.localVaultUnlock
	state.password = "wrong-local-unlock-password"
	state.secret = personal.FormatSecret([]byte("fedcba0987654321"))
	f.app.submitLocalVaultFileUnlock()
	if state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_SUBMIT_RETAINED_INPUT_STRINGS")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WRONG_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WRONG_DISPATCH_NOT_QUEUED")
	}
	q.runDispatch(t)
	if !state.open || state.busy || state.op != nil || state.status != localVaultFileUnlockStatusFailed {
		t.Fatal("LOCAL_UNLOCK_WRONG_NOT_FINITE_MANUAL_RETRY")
	}
	if slot := f.app.localVaultFiles.sessionSlots[aScope]; slot != nil && slot.session != nil {
		t.Fatal("LOCAL_UNLOCK_WRONG_ADOPTED_CHILD")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
	if f.app.session != parent || f.app.generation != generation {
		t.Fatal("LOCAL_UNLOCK_WRONG_REPLACED_PARENT")
	}
	if _, err := parent.VaultFileOwnerships(); !errors.Is(err, personal.ErrVaultFileFullFactorRequired) {
		t.Fatal("LOCAL_UNLOCK_WRONG_REFRESHED_FULL_PROOF")
	}

	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	if state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_RETRY_RETAINED_INPUT_STRINGS")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_CORRECT_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_CORRECT_DISPATCH_NOT_QUEUED")
	}
	q.runDispatch(t)
	q.drain(t)
	if state.open || state.busy || state.op != nil || state.status != localVaultFileUnlockStatusOpened {
		t.Fatal("LOCAL_UNLOCK_CORRECT_DID_NOT_CLOSE_DIALOG")
	}
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil || aSlot.operation != nil ||
		aSlot.summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_CORRECT_CHILD_NOT_ADOPTED")
	}
	if aSlot.session == bSession {
		t.Fatal("LOCAL_UNLOCK_CORRECT_REUSED_SIBLING_CHILD")
	}
	summary, err := aSlot.session.Summary()
	if err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_CORRECT_CHILD_UNREADABLE")
	}
	if f.app.localVaultFiles.selected != aPath {
		t.Fatal("LOCAL_UNLOCK_CORRECT_NOT_PRESENTED_THROUGH_C1")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
	if f.app.session != parent || f.app.generation != generation {
		t.Fatal("LOCAL_UNLOCK_CORRECT_REPLACED_PARENT")
	}
	if _, err := parent.VaultFileOwnerships(); !errors.Is(err, personal.ErrVaultFileFullFactorRequired) {
		t.Fatal("LOCAL_UNLOCK_CORRECT_REFRESHED_FULL_PROOF")
	}
}

func TestDesktopLocalVaultUnlockHeldDispatchCancelClosesCandidate(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_CANCEL_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session

	if !f.app.openLocalVaultFileUnlock(localVaultUnlockRef(aPath, aManifest)) {
		t.Fatal("LOCAL_UNLOCK_CANCEL_OPEN_REFUSED")
	}
	state := &f.app.localVaultUnlock
	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_CANCEL_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	op := state.op
	if op == nil || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_CANCEL_CANDIDATE_NOT_STAGED")
	}
	candidate := localVaultSessionStagedCandidate(t, op)
	oldDispatch := q.dispatches[0]
	q.dispatches = nil

	f.app.cancelLocalVaultFileUnlock()
	if state.open || state.busy || state.op != nil || state.password != "" || state.secret != "" {
		t.Fatal("LOCAL_UNLOCK_CANCEL_RETAINED_STATE")
	}
	if op.finiteOutcome() != localVaultFileSessionOutcomeCancelled {
		t.Fatal("LOCAL_UNLOCK_CANCEL_NOT_FINITE")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_CANCEL_DID_NOT_QUEUE_PRODUCT_CLOSE")
	}
	q.runLaunch(t)
	waitLocalVaultSessionSettlement(t, op)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_UNLOCK_CANCEL_CANDIDATE_READABLE")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_UNLOCK_CANCEL_LOCKED_PARENT")
	}
	// The held old dispatch is deliberately never executed and the candidate
	// was closed only by the product cleanup launch.
	_ = oldDispatch
}

func TestDesktopLocalVaultUnlockLateCompletionLeavesNewDialog(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	cPath, cManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_LATE_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session

	if !f.app.openLocalVaultFileUnlock(localVaultUnlockRef(aPath, aManifest)) {
		t.Fatal("LOCAL_UNLOCK_LATE_FIRST_OPEN_REFUSED")
	}
	state := &f.app.localVaultUnlock
	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	q.runLaunch(t)
	oldOp := state.op
	if oldOp == nil || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_LATE_FIRST_NOT_STAGED")
	}
	oldCandidate := localVaultSessionStagedCandidate(t, oldOp)
	oldDispatch := q.dispatches[0]
	q.dispatches = nil

	cRef := localVaultUnlockRef(cPath, cManifest)
	f.app.localVaultFiles.selected = cPath
	if !f.app.openLocalVaultFileUnlock(cRef) {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_OPEN_REFUSED")
	}
	if state.target.scope != f.scope(cPath, cManifest) {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_TARGET_NOT_FROZEN")
	}
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_LATE_OLD_CLEANUP_NOT_QUEUED")
	}
	q.runLaunch(t)
	waitLocalVaultSessionSettlement(t, oldOp)
	if _, err := oldCandidate.Summary(); err == nil {
		t.Fatal("LOCAL_UNLOCK_LATE_OLD_CANDIDATE_READABLE")
	}

	state.password, state.secret = f.password, f.secret
	f.app.submitLocalVaultFileUnlock()
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_WORKER_NOT_QUEUED")
	}
	q.runLaunch(t)
	newOp := state.op
	if newOp == nil || newOp == oldOp || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_NOT_STAGED")
	}
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	newDispatch := q.dispatches[0]
	q.dispatches = nil

	oldDispatch()
	if !state.open || !state.busy || state.op != newOp ||
		state.target.scope != f.scope(cPath, cManifest) {
		t.Fatal("LOCAL_UNLOCK_LATE_OLD_COMPLETION_CLEARED_NEW_DIALOG")
	}
	if len(q.launches) != 0 {
		t.Fatal("LOCAL_UNLOCK_LATE_OLD_COMPLETION_QUEUED_WORK")
	}
	if _, err := newCandidate.Summary(); err != nil {
		t.Fatal("LOCAL_UNLOCK_LATE_OLD_COMPLETION_CLOSED_NEW_CANDIDATE")
	}

	newDispatch()
	q.drain(t)
	if state.open || state.busy || state.op != nil || state.status != localVaultFileUnlockStatusOpened {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_NOT_COMPLETED")
	}
	cSlot := f.app.localVaultFiles.sessionSlots[f.scope(cPath, cManifest)]
	if cSlot == nil || cSlot.session != newCandidate || cSlot.operation != nil {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_CHILD_NOT_ADOPTED")
	}
	if _, err := newCandidate.Summary(); err != nil {
		t.Fatal("LOCAL_UNLOCK_LATE_NEW_CHILD_LOST")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
}

func TestDesktopLocalVaultUnlockAlreadyOpenRefuses(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	aScope := f.scope(aPath, aManifest)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session

	aRef := localVaultUnlockRef(aPath, aManifest)
	if !f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_DIALOG_NOT_OPEN")
	}
	f.openVault(t, q, aScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_ADOPT_SETUP_FAILED")
	}
	aSession := aSlot.session
	if !f.app.localVaultUnlock.open {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_DIALOG_LOST")
	}

	state := &f.app.localVaultUnlock
	state.password, state.secret = f.password, f.secret
	launches := len(q.launches)
	f.app.submitLocalVaultFileUnlock()
	if len(q.launches) != launches {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_SUBMIT_QUEUED_WORK")
	}
	if state.open || state.busy || state.op != nil || state.password != "" ||
		state.secret != "" || state.status != localVaultFileUnlockStatusAlreadyOpen {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_SUBMIT_STATE_INVALID")
	}
	if aSlot.session != aSession {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_SUBMIT_REPLACED_CHILD")
	}
	summary, err := aSession.Summary()
	if err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_SUBMIT_CLOSED_CHILD")
	}

	if f.app.openLocalVaultFileUnlock(aRef) {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_REOPENED_ADOPTED")
	}
	if state.open || state.status != localVaultFileUnlockStatusAlreadyOpen {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_STATE_INVALID")
	}
	if aSlot.session != aSession {
		t.Fatal("LOCAL_UNLOCK_OPEN_REFUSAL_REPLACED_ADOPTED_CHILD")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
}

func TestDesktopLocalVaultUnlockCompletionWaitsForUIResult(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest, bPath, bManifest := localVaultUnlockPair(t, f)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_UNLOCK_WAIT_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session

	if !f.app.openLocalVaultFileUnlock(localVaultUnlockRef(aPath, aManifest)) {
		t.Fatal("LOCAL_UNLOCK_WAIT_OPEN_REFUSED")
	}
	state := &f.app.localVaultUnlock
	state.password, state.secret = f.password, "not-a-valid-secret"
	f.app.submitLocalVaultFileUnlock()
	q.runLaunch(t)
	op := state.op
	if op == nil {
		t.Fatal("LOCAL_UNLOCK_WAIT_OP_MISSING")
	}
	result := localVaultSessionStagedResult(t, op)
	if result.outcome != localVaultFileSessionOutcomeFailed || result.candidate != nil {
		t.Fatal("LOCAL_UNLOCK_WAIT_PARSE_NOT_FAILED")
	}
	select {
	case <-op.settledSignal():
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_UNLOCK_WAIT_NOT_SETTLED")
	}
	if !op.isSettled() {
		t.Fatal("LOCAL_UNLOCK_WAIT_SETTLEMENT_INCONSISTENT")
	}
	if !state.open || !state.busy || state.op != op ||
		state.status != localVaultFileUnlockStatusBusy {
		t.Fatal("LOCAL_UNLOCK_WAIT_COMPLETION_FIRED_EARLY")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_UNLOCK_WAIT_UI_RESULT_NOT_HELD")
	}
	q.runDispatch(t)
	if !state.open || state.busy || state.op != nil ||
		state.status != localVaultFileUnlockStatusFailed {
		t.Fatal("LOCAL_UNLOCK_WAIT_UI_RESULT_NOT_OBSERVED")
	}
	assertLocalVaultUnlockBUnchanged(t, f.app, bScope, bSlot, bSession, bManifest.VaultID)
}
