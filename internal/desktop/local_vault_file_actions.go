package desktop

import (
	"path/filepath"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
)

const (
	localVaultFileLockStatusLocking     = "正在锁定本地文件库"
	localVaultFileLockStatusLocked      = "本地文件库已锁定"
	localVaultFileLockStatusFailed      = "锁定未完成，请核查本地状态"
	localVaultFileLockStatusUnavailable = "本地文件库暂不可用，请稍后重试"
)

// localVaultFileSelectedSnapshotRef returns the exact current snapshot ref for
// the selected path. It never reconstructs an identity from the selected path
// or a display label.
func (a *App) localVaultFileSelectedSnapshotRef() (localVaultFileRef, string, bool) {
	selected := a.localVaultFiles.selected
	if selected == "" {
		return localVaultFileRef{}, "", false
	}
	for _, entry := range a.localVaultFileDisplayLabelSnapshot() {
		if entry.ref.path == selected {
			return entry.ref, entry.label, true
		}
	}
	return localVaultFileRef{}, "", false
}

// localVaultFileSelectedStoredSlot resolves the exact existing stored slot and
// current parent for the selected snapshot ref. It does not use the Active-only
// scope helper, VaultPath or any caller-supplied journal authority, so an owned
// Busy/Revoked slot remains available to the lock revocation action.
func (a *App) localVaultFileSelectedStoredSlot() (*localVaultFileSessionSlot, bool) {
	ref, _, ok := a.localVaultFileSelectedSnapshotRef()
	if !ok || a.session == nil {
		return nil, false
	}
	var found *localVaultFileSessionSlot
	for scope, slot := range a.localVaultFiles.sessionSlots {
		if slot == nil || slot.scope != scope || slot.parent != a.session ||
			slot.appGeneration != a.generation {
			continue
		}
		if scope.configPath != ref.path || scope.vaultID != ref.vaultID ||
			scope.journalPath != ref.journalPath {
			continue
		}
		if found != nil && found != slot {
			return nil, false
		}
		found = slot
	}
	return found, found != nil
}

func (a *App) localVaultFileSelectedStoredScope() (localVaultFileSessionScope, bool) {
	slot, ok := a.localVaultFileSelectedStoredSlot()
	if !ok {
		return localVaultFileSessionScope{}, false
	}
	return slot.scope, true
}

func (a *App) localVaultFileSelectedScopeMatches(scope localVaultFileSessionScope) bool {
	ref, _, ok := a.localVaultFileSelectedSnapshotRef()
	return ok && ref.path == scope.configPath && ref.vaultID == scope.vaultID &&
		ref.journalPath == scope.journalPath
}

// setLocalVaultFileProjectionOrigin atomically binds the accepted projection
// data to the exact current view. It is called only on the UI goroutine after
// the view sequence has advanced and the exact slot is still current.
func (a *App) setLocalVaultFileProjectionOrigin(scope localVaultFileSessionScope, slot *localVaultFileSessionSlot) bool {
	state := &a.localVaultFiles
	if slot == nil || a.session == nil || slot.scope != scope ||
		slot.parent != a.session || slot.appGeneration != a.generation ||
		state.sessionSlots[scope] != slot {
		return false
	}
	state.projectionOrigin = &localVaultFileProjectionOrigin{
		scope:        scope,
		parent:       a.session,
		generation:   a.generation,
		slot:         slot,
		slotSequence: slot.sequence,
		viewSequence: state.viewSequence,
	}
	state.unopenedNotice = nil
	return true
}

// invalidateLocalVaultFileProjectionView cancels only this view's pending
// projection delivery, advances the view sequence, and clears the accepted
// projection binding and data. It never closes or mutates an adopted wrapper.
func (a *App) invalidateLocalVaultFileProjectionView(status string) {
	state := &a.localVaultFiles
	a.cancelLocalVaultFileRefreshViewReads(state.selected, state.viewSequence)
	state.viewSequence++
	state.items = nil
	state.projectionOrigin = nil
	state.unopenedNotice = nil
	state.viewVerification = localVaultFileViewUnverified
	state.status = status
}

func localVaultFileRefByPath(refs []localVaultFileRef, path string) (localVaultFileRef, bool) {
	for _, ref := range refs {
		if ref.path == path {
			return ref, true
		}
	}
	return localVaultFileRef{}, false
}

// applyLocalVaultFileRefs is the one production list-callback acceptance
// helper. It compares the new selected full tuple against the accepted origin,
// or the old selected full tuple when no origin exists. Only name and display
// prefix changes are display metadata; any path/VaultID/journal/backend-root
// drift or disappearance invalidates the old view without closing children.
func (a *App) applyLocalVaultFileRefs(refs []localVaultFileRef, backendRoot string, listErr error) {
	state := &a.localVaultFiles
	if listErr != nil {
		a.invalidateLocalVaultFileProjectionView(localVaultFileStatusReview)
		state.refs = nil
		state.refsBackendRoot = ""
		state.status = "本地文件库目录待核查"
		return
	}
	if origin := state.projectionOrigin; origin != nil {
		state.unopenedNotice = nil
		ref, ok := localVaultFileRefByPath(refs, origin.scope.configPath)
		if ok && ref.vaultID == origin.scope.vaultID &&
			ref.journalPath == origin.scope.journalPath &&
			backendRoot == origin.scope.backendRoot {
			state.refs = refs
			state.refsBackendRoot = backendRoot
			return
		}
		a.invalidateLocalVaultFileProjectionView(localVaultFileStatusUnavailable)
		state.refs = refs
		state.refsBackendRoot = backendRoot
		return
	}
	if notice := state.unopenedNotice; notice != nil {
		valid := notice.parent == a.session && notice.generation == a.generation &&
			notice.viewSequence == state.viewSequence &&
			state.selected == notice.scope.configPath
		if valid {
			ref, ok := localVaultFileRefByPath(refs, notice.scope.configPath)
			if ok && ref.vaultID == notice.scope.vaultID &&
				ref.journalPath == notice.scope.journalPath &&
				backendRoot == notice.scope.backendRoot {
				state.refs = refs
				state.refsBackendRoot = backendRoot
				state.unopenedNotice = nil
				return
			}
		}
		// A present notice that fails exact validation must not fall through
		// to ordinary old/new refs equality, which could otherwise keep the
		// failed notice's finite created status.
		a.invalidateLocalVaultFileProjectionView(localVaultFileStatusUnavailable)
		state.refs = refs
		state.refsBackendRoot = backendRoot
		return
	}
	if state.selected != "" {
		oldRef, oldOK := localVaultFileRefByPath(state.refs, state.selected)
		newRef, newOK := localVaultFileRefByPath(refs, state.selected)
		if !oldOK || !newOK || oldRef.vaultID != newRef.vaultID ||
			oldRef.journalPath != newRef.journalPath ||
			state.refsBackendRoot != backendRoot {
			a.invalidateLocalVaultFileProjectionView(localVaultFileStatusUnavailable)
		}
	}
	state.refs = refs
	state.refsBackendRoot = backendRoot
}

// localVaultFileCurrentScopeGate is the common display-only read gate. It
// starts from the accepted projection origin, so a different same-configPath
// tuple can never authorize global items or provenance. If the reviewed ref is
// present it must match the origin full tuple; if it has not arrived yet, the
// origin itself proves the already-presented creation target. The current
// parent/generation/map/slot pointer/sequence/view sequence and nonblocking
// workspace root are revalidated at the delivery boundary.
func (a *App) localVaultFileCurrentScopeGate() (localVaultFileSessionScope, *localVaultFileSessionSlot, bool) {
	state := &a.localVaultFiles
	origin := state.projectionOrigin
	if origin == nil || a.session == nil || origin.parent != a.session ||
		origin.generation != a.generation || state.selected != origin.scope.configPath ||
		state.viewSequence != origin.viewSequence || origin.slot == nil ||
		origin.slot.scope != origin.scope || origin.slot.parent != a.session ||
		origin.slot.appGeneration != a.generation ||
		origin.slot.sequence != origin.slotSequence ||
		state.sessionSlots[origin.scope] != origin.slot || origin.slot.retiring {
		return localVaultFileSessionScope{}, nil, false
	}
	if ref, _, ok := a.localVaultFileSelectedSnapshotRef(); ok {
		if ref.path != origin.scope.configPath || ref.vaultID != origin.scope.vaultID ||
			ref.journalPath != origin.scope.journalPath {
			return localVaultFileSessionScope{}, nil, false
		}
	}
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		return localVaultFileSessionScope{}, nil, false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != origin.scope.backendRoot {
		return localVaultFileSessionScope{}, nil, false
	}
	if state.projectionOrigin != origin || state.selected != origin.scope.configPath ||
		state.viewSequence != origin.viewSequence ||
		state.sessionSlots[origin.scope] != origin.slot ||
		origin.slot.parent != a.session ||
		origin.slot.appGeneration != a.generation ||
		origin.slot.sequence != origin.slotSequence || origin.slot.retiring {
		return localVaultFileSessionScope{}, nil, false
	}
	personalPath, cache = a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		return localVaultFileSessionScope{}, nil, false
	}
	_, currentRoot = localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != origin.scope.backendRoot ||
		state.sessionSlots[origin.scope] != origin.slot || origin.slot.parent != a.session ||
		origin.slot.appGeneration != a.generation ||
		origin.slot.sequence != origin.slotSequence || origin.slot.retiring {
		return localVaultFileSessionScope{}, nil, false
	}
	return origin.scope, origin.slot, true
}

func (a *App) localVaultFileCurrentLiveScopeGate() (localVaultFileSessionScope, *localVaultFileSessionSlot, bool) {
	scope, slot, ok := a.localVaultFileCurrentScopeGate()
	if !ok || slot.session == nil || slot.summary.VaultID == "" ||
		slot.summary.VaultID != scope.vaultID {
		return localVaultFileSessionScope{}, nil, false
	}
	return scope, slot, true
}

// localVaultFileCurrentItems is the only view projection path for cached items.
// It requires the common scope/workspace gate plus a live nonretiring session
// and matching retained summary, so detached, Busy or changed-workspace views
// cannot render old items while a sibling wrapper remains preserved.
func (a *App) localVaultFileCurrentItems() []personal.VaultFileBaselineItem {
	if _, _, ok := a.localVaultFileCurrentLiveScopeGate(); !ok {
		return nil
	}
	return a.localVaultFiles.items
}

func (a *App) localVaultFileDisplayStatus() string {
	if scope, ok := a.localVaultFileSelectedStoredScope(); ok {
		if outcome, done := a.localVaultFileLockResult(scope); done {
			return localVaultFileLockStatus(outcome)
		}
		if a.localVaultFileLockBlocks(scope) {
			return localVaultFileLockStatusLocking
		}
	}
	return a.localVaultFiles.status
}

func localVaultFileLockStatus(outcome localVaultFileLockOutcome) string {
	switch outcome {
	case localVaultFileLockOutcomeSucceeded:
		return localVaultFileLockStatusLocked
	case localVaultFileLockOutcomeFailed:
		return localVaultFileLockStatusFailed
	default:
		return ""
	}
}

func (a *App) localVaultFileSelectedLockUnfinished() bool {
	scope, ok := a.localVaultFileSelectedStoredScope()
	return ok && a.localVaultFileLockBlocks(scope)
}

func (a *App) clickLocalVaultFileUnlockAction() {
	if a.session == nil || a.localCreate.open || a.localVaultUnlock.open {
		return
	}
	ref, _, ok := a.localVaultFileSelectedSnapshotRef()
	if !ok {
		a.localVaultFiles.status = localVaultFileStatusUnavailable
		return
	}
	if a.localVaultFileSelectedLockUnfinished() {
		a.localVaultFiles.status = localVaultFileLockStatusUnavailable
		return
	}
	a.openLocalVaultFileUnlock(ref)
}

func (a *App) clickLocalVaultFileRefreshAction() {
	slot, ok := a.localVaultFileSelectedStoredSlot()
	if !ok {
		a.localVaultFiles.status = localVaultFileStatusUnavailable
		return
	}
	scope := slot.scope
	// A new manual request supersedes this selected view's prior provenance and
	// pending projection before any begin/refusal check. This never closes the
	// borrowed wrapper or touches another scope or sibling.
	a.invalidateLocalVaultFileRefreshFresh(scope)
	a.cancelLocalVaultFileRefreshExact(slot.refresh)
	if a.localVaultFileLockBlocks(scope) {
		a.localVaultFiles.status = localVaultFileLockStatusUnavailable
		return
	}
	if a.beginLocalVaultFileRefresh(scope) == nil {
		a.localVaultFiles.status = localVaultFileStatusUnavailable
		return
	}
	if a.localVaultFiles.status == localVaultFileStatusUnavailable {
		// Clear only the prior finite transient refusal feedback; Fresh remains
		// reserved for the accepted worker's exact Summary callback.
		a.localVaultFiles.status = localVaultFileStatusReady
	}
}

func (a *App) clickLocalVaultFileLockAction() {
	scope, ok := a.localVaultFileSelectedStoredScope()
	if !ok {
		a.localVaultFiles.status = localVaultFileLockStatusUnavailable
		return
	}
	op := a.beginLocalVaultFileLock(scope)
	if op == nil {
		a.localVaultFiles.status = localVaultFileLockStatusUnavailable
		return
	}
	a.localVaultFiles.items = nil
	if _, done := op.finiteOutcome(); done {
		a.finishLocalVaultFileLockUI(op, scope)
		return
	}
	a.localVaultFiles.status = localVaultFileLockStatusLocking
	if !op.claimUIWaiter() {
		return
	}
	done := op.doneSignal()
	dispatcher := a.dispatch
	a.launch(func() {
		<-done
		if dispatcher != nil {
			dispatcher(func() { a.finishLocalVaultFileLockUI(op, scope) })
		}
	})
}

// claimUIWaiter is UI-goroutine-only scheduling. The first click for one
// existing lock marker owns the single notify waiter; later clicks, navigation
// or completion never reset it and never launch another waiter.
func (op *localVaultFileLockOperation) claimUIWaiter() bool {
	if op == nil || op.uiWaiterClaimed {
		return false
	}
	op.uiWaiterClaimed = true
	return true
}

// finishLocalVaultFileLockUI is the one late repaint guard. It never Closes,
// grants authority or infers success from an empty cache. It publishes only the
// controller's finite getter result for the exact still-current parent,
// generation, slot, marker and selected full scope.
func (a *App) finishLocalVaultFileLockUI(op *localVaultFileLockOperation, scope localVaultFileSessionScope) {
	if op == nil {
		return
	}
	if a.session != op.parent || a.generation != op.generation {
		return
	}
	slot := a.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.scope != scope || slot.parent != op.parent ||
		slot.appGeneration != op.generation || slot.lock != op {
		return
	}
	if !a.localVaultFileSelectedScopeMatches(scope) {
		return
	}
	outcome, done := a.localVaultFileLockResult(scope)
	if !done {
		return
	}
	switch outcome {
	case localVaultFileLockOutcomeSucceeded:
		a.localVaultFiles.status = localVaultFileLockStatusLocked
	case localVaultFileLockOutcomeFailed:
		a.localVaultFiles.status = localVaultFileLockStatusFailed
	default:
		return
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *App) localVaultFileUnlockDialogTarget() (string, bool) {
	state := &a.localVaultUnlock
	if !state.open || state.target.parent == nil || a.session != state.target.parent ||
		a.generation != state.target.generation || state.target.parentPath == "" {
		return "", false
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, state.target.parentPath)
	if backendRoot != state.target.scope.backendRoot ||
		filepath.Dir(state.target.scope.configPath) != profileDir {
		return "", false
	}
	for _, entry := range a.localVaultFileDisplayLabelSnapshot() {
		ref := entry.ref
		if ref.path == state.target.scope.configPath && ref.vaultID == state.target.scope.vaultID &&
			ref.journalPath == state.target.scope.journalPath {
			return entry.label, true
		}
	}
	return "", false
}

func (a *App) onevraLocalVaultFileActions(c *ui.Context) {
	_, _, selectedOK := a.localVaultFileSelectedSnapshotRef()
	scope, hasScope := a.localVaultFileSelectedStoredScope()
	slot, _ := a.localVaultFileSelectedStoredSlot()
	hasWrapper := slot != nil && slot.session != nil
	lockUnfinished := hasScope && a.localVaultFileLockBlocks(scope)
	modalConflict := a.localCreate.open || a.localVaultUnlock.open

	unlock := oneui.Button(c, "解锁本地文件库", oneui.ButtonOutline)
	unlock.Disabled(!selectedOK || modalConflict || lockUnfinished || hasWrapper)
	if unlock.Clicked() {
		a.clickLocalVaultFileUnlockAction()
	}
	refresh := oneui.Button(c, "刷新本地文件库", oneui.ButtonOutline)
	refresh.Disabled(!hasScope || slot == nil || slot.retiring || slot.session == nil || lockUnfinished)
	if refresh.Clicked() {
		a.clickLocalVaultFileRefreshAction()
	}
	lock := oneui.Button(c, "锁定本地文件库", oneui.ButtonOutline)
	lock.Disabled(!hasScope)
	if lock.Clicked() {
		a.clickLocalVaultFileLockAction()
	}
}
