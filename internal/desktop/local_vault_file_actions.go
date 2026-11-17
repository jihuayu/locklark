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

// localVaultFileCurrentScopeGate is the common display-only read gate. It
// resolves the unique exact stored slot for the selected reviewed snapshot ref
// and requires the current parent/App generation/map entry, a nonblocking
// Active routing snapshot whose current settings workspace root still matches
// the stored backend root, and the same exact binding at the delivery
// boundary. It grants no read, authority or grant and never calls VaultPath.
func (a *App) localVaultFileCurrentScopeGate() (localVaultFileSessionScope, *localVaultFileSessionSlot, bool) {
	ref, _, ok := a.localVaultFileSelectedSnapshotRef()
	if !ok || a.session == nil {
		return localVaultFileSessionScope{}, nil, false
	}
	slot, ok := a.localVaultFileSelectedStoredSlot()
	if !ok {
		return localVaultFileSessionScope{}, nil, false
	}
	scope := slot.scope
	if scope.configPath != ref.path || scope.vaultID != ref.vaultID ||
		scope.journalPath != ref.journalPath || scope.backendRoot == "" ||
		slot.parent != a.session || slot.appGeneration != a.generation ||
		slot.retiring || a.localVaultFiles.sessionSlots[scope] != slot {
		return localVaultFileSessionScope{}, nil, false
	}
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		return localVaultFileSessionScope{}, nil, false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != scope.backendRoot {
		return localVaultFileSessionScope{}, nil, false
	}
	// Revalidate the exact binding and current workspace root after the
	// nonblocking snapshot, immediately before returning metadata.
	if a.localVaultFiles.sessionSlots[scope] != slot || slot.parent != a.session ||
		slot.appGeneration != a.generation || slot.retiring {
		return localVaultFileSessionScope{}, nil, false
	}
	personalPath, cache = a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		return localVaultFileSessionScope{}, nil, false
	}
	_, currentRoot = localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != scope.backendRoot ||
		a.localVaultFiles.sessionSlots[scope] != slot || slot.parent != a.session ||
		slot.appGeneration != a.generation || slot.retiring {
		return localVaultFileSessionScope{}, nil, false
	}
	return scope, slot, true
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
	scope, ok := a.localVaultFileSelectedStoredScope()
	if !ok {
		a.localVaultFiles.status = localVaultFileStatusUnavailable
		return
	}
	if a.localVaultFileLockBlocks(scope) {
		a.localVaultFiles.status = localVaultFileLockStatusUnavailable
		return
	}
	if a.beginLocalVaultFileRefresh(scope) == nil {
		a.localVaultFiles.status = localVaultFileStatusUnavailable
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
