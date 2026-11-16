package desktop

import (
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

// localVaultFileViewVerification is controller-only provenance for the local
// vault-file projection. Fresh evidence exists only after a real borrowed
// wrapper Summary and its exact UI callback were accepted. Navigation and any
// wrapper boundary discard it; a cached projection remains readable.
type localVaultFileViewVerification uint8

const (
	localVaultFileViewUnverified localVaultFileViewVerification = iota
	localVaultFileViewCached
	localVaultFileViewFresh
	localVaultFileViewFailed
)

const (
	// localVaultFileCachedCaption is the only caption for pure cache or
	// navigation. It never claims a fresh read.
	localVaultFileCachedCaption = "显示上次验证结果"
	// localVaultFileFreshCaption is reserved for the exact successful refresh
	// callback. Initial adoption, a cache getter or a started refresh cannot
	// produce it.
	localVaultFileFreshCaption = "本次刷新已验证"
	// localVaultFileFailedCaption is the finite feedback for an actual Summary
	// failure that still owned the exact current wrapper and view.
	localVaultFileFailedCaption = "本次刷新未完成；请核查本地状态"
)

// localVaultFileRefreshOutcome is the finite result of one projection read.
// The operation never owns the wrapper, so no outcome includes a Close.
type localVaultFileRefreshOutcome uint8

const (
	localVaultFileRefreshOutcomeNone localVaultFileRefreshOutcome = iota
	localVaultFileRefreshOutcomeVerified
	localVaultFileRefreshOutcomeFailed
	localVaultFileRefreshOutcomeCancelled
	localVaultFileRefreshOutcomeWithheld
)

type localVaultFileRefreshResult struct {
	summary vaultfileclient.LocalGenesisBaseline
	outcome localVaultFileRefreshOutcome
}

// localVaultFileRefreshOperation is the small private per-slot projection
// operation. It freezes the exact slot, full scope, parent, App generation,
// borrowed wrapper, read sequence and view sequence at reservation. The single
// mutex guards only the ready/terminal handoff and its summary/outcome; it is
// never held across Summary, dispatch, launch, validation or Close.
type localVaultFileRefreshOperation struct {
	slot         *localVaultFileSessionSlot
	scope        localVaultFileSessionScope
	parent       *personal.Session
	parentPath   string
	generation   uint64
	wrapper      *vaultfileclient.LocalGenesisSession
	viewSelected string
	viewSequence uint64
	readSequence uint64

	mu       sync.Mutex
	ready    bool
	terminal bool
	summary  vaultfileclient.LocalGenesisBaseline
	outcome  localVaultFileRefreshOutcome
}

// stage transfers one result to the operation. It refuses after cancellation,
// leaving ownership of any summary with the caller.
func (op *localVaultFileRefreshOperation) stage(result localVaultFileRefreshResult) bool {
	if op == nil {
		return false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.terminal || op.ready {
		return false
	}
	op.summary = result.summary
	op.outcome = result.outcome
	op.ready = true
	return true
}

// take is the unique UI-side ownership transfer. Cancellation already claimed
// the pending projection returns false, so a late callback is a no-op.
func (op *localVaultFileRefreshOperation) take() (localVaultFileRefreshResult, bool) {
	if op == nil {
		return localVaultFileRefreshResult{}, false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.ready || op.terminal {
		return localVaultFileRefreshResult{}, false
	}
	result := localVaultFileRefreshResult{summary: op.summary, outcome: op.outcome}
	op.summary = vaultfileclient.LocalGenesisBaseline{}
	op.ready = false
	op.terminal = true
	return result, true
}

// takeCancelled makes an unsettled operation terminal and returns any
// undelivered projection to the caller for immediate clearing. It never
// touches the borrowed wrapper.
func (op *localVaultFileRefreshOperation) takeCancelled() (vaultfileclient.LocalGenesisBaseline, bool) {
	if op == nil {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.terminal {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	op.terminal = true
	op.outcome = localVaultFileRefreshOutcomeCancelled
	if !op.ready {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	summary := op.summary
	op.summary = vaultfileclient.LocalGenesisBaseline{}
	op.ready = false
	return summary, true
}

func (op *localVaultFileRefreshOperation) terminalState() bool {
	if op == nil {
		return true
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.terminal
}

// withhold records the finite delivery gate without changing the ready or
// terminal transition. The projection itself was already cleared by the UI.
func (op *localVaultFileRefreshOperation) withhold() {
	if op == nil {
		return
	}
	op.mu.Lock()
	op.outcome = localVaultFileRefreshOutcomeWithheld
	op.mu.Unlock()
}

// finiteOutcome is read by tests and by exact cancellation/finish paths. It
// never mutates the ready or terminal transition.
func (op *localVaultFileRefreshOperation) finiteOutcome() localVaultFileRefreshOutcome {
	if op == nil {
		return localVaultFileRefreshOutcomeNone
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.outcome
}

// beginLocalVaultFileRefresh borrows only the exact adopted wrapper of one
// current slot. It freezes full identity and the current view sequence, then
// launches one worker that calls that wrapper's real Summary. The wrapper is
// never handed to candidate ownership and is never closed here.
func (a *App) beginLocalVaultFileRefresh(scope localVaultFileSessionScope) *localVaultFileRefreshOperation {
	if a.session == nil || scope.configPath == "" ||
		a.localVaultFiles.selected == "" ||
		a.localVaultFiles.selected != scope.configPath {
		return nil
	}
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" {
		return nil
	}
	state := &a.localVaultFiles
	if state.selected != scope.configPath {
		return nil
	}
	slot := state.sessionSlots[scope]
	if slot == nil || slot.retiring || slot.session == nil ||
		slot.scope != scope || slot.parent != a.session ||
		slot.appGeneration != a.generation {
		return nil
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, parentPath)
	if currentRoot != scope.backendRoot {
		return nil
	}
	// A new attempt supersedes any older projection read on this exact slot.
	// Cancel first so its late stage is refused and its undelivered copy is
	// cleared; never Close the wrapper here.
	if slot.refresh != nil {
		a.cancelLocalVaultFileRefreshExact(slot.refresh)
	}
	// Only one projection read may belong to the current view, even if an
	// older alias slot for the same selected path still exists.
	a.cancelLocalVaultFileRefreshViewReads(state.selected, state.viewSequence)
	slot.refreshSequence++
	op := &localVaultFileRefreshOperation{
		slot:         slot,
		scope:        scope,
		parent:       slot.parent,
		parentPath:   parentPath,
		generation:   slot.appGeneration,
		wrapper:      slot.session,
		viewSelected: state.selected,
		viewSequence: state.viewSequence,
		readSequence: slot.refreshSequence,
	}
	slot.refresh = op
	if state.viewVerification == localVaultFileViewFresh {
		// A started attempt cannot leave the previous success masquerading
		// as this attempt's result.
		state.viewVerification = localVaultFileViewCached
	}
	a.launchLocalVaultFileRefresh(op)
	return op
}

// launchLocalVaultFileRefresh captures the readonly wrapper and method plus the
// dispatch/pause seams on the UI path before launch. Only a real wrapper
// Summary participates; the slot cache is never used as a refresh source.
func (a *App) launchLocalVaultFileRefresh(op *localVaultFileRefreshOperation) {
	if op == nil || op.wrapper == nil {
		return
	}
	wrapper := op.wrapper
	dispatch := a.dispatch
	pause := a.localVaultFiles.refreshSummaryPauseForTest
	a.launch(func() {
		if op.terminalState() {
			return
		}
		summary, err := wrapper.Summary()
		if pause != nil {
			pause()
		}
		outcome := localVaultFileRefreshOutcomeVerified
		if err != nil {
			outcome = localVaultFileRefreshOutcomeFailed
			clearLocalVaultFileSessionSummary(&summary)
		}
		result := localVaultFileRefreshResult{summary: summary, outcome: outcome}
		// Stage before dispatch. A refusal means cancellation already owns the
		// pending projection, so this worker clears its own copy and returns.
		if !op.stage(result) {
			clearLocalVaultFileSessionSummary(&result.summary)
			return
		}
		if dispatch != nil {
			// The closure captures the operation, never the projection.
			dispatch(func() { a.takeAndCompleteLocalVaultFileRefresh(op) })
		}
	})
}

// takeAndCompleteLocalVaultFileRefresh is the single UI-side take. A repeated,
// cancelled or already-delivered callback cannot affect a later operation.
func (a *App) takeAndCompleteLocalVaultFileRefresh(op *localVaultFileRefreshOperation) bool {
	result, ok := op.take()
	if !ok {
		return false
	}
	a.completeLocalVaultFileRefresh(op, result)
	return true
}

// completeLocalVaultFileRefresh accepts a successful projection only while the
// full frozen identity, current map slot, current wrapper, read operation/read
// sequence, view selection/sequence and parent cache authority still match.
// Failures clear only the exact current wrapper cache; stale results never
// close a current or replacement child.
func (a *App) completeLocalVaultFileRefresh(op *localVaultFileRefreshOperation, result localVaultFileRefreshResult) {
	if op == nil {
		clearLocalVaultFileSessionSummary(&result.summary)
		return
	}
	state := &a.localVaultFiles
	cache := a.syncLocalVaultFileSessions()
	current := a.localVaultFileRefreshCurrentExact(op)
	viewCurrent := a.localVaultFileRefreshViewCurrent(op)
	switch result.outcome {
	case localVaultFileRefreshOutcomeVerified:
		if cache == personal.VaultFileCacheActive && current && viewCurrent {
			// Recheck the delivery boundary immediately before accepting. The
			// synchronization above may retire a parent/generation/revoked
			// boundary; no projection may cross it.
			if a.syncLocalVaultFileSessions() == personal.VaultFileCacheActive &&
				a.localVaultFileRefreshCurrentExact(op) &&
				a.localVaultFileRefreshViewCurrent(op) &&
				result.summary.VaultID == op.scope.vaultID {
				slot := op.slot
				items := append([]personal.VaultFileBaselineItem(nil), result.summary.Items...)
				slot.summary = localVaultFileSessionSummaryClone(result.summary)
				clearLocalVaultFileSessionSummary(&result.summary)
				state.items = items
				state.viewVerification = localVaultFileViewFresh
				slot.refresh = nil
				return
			}
		}
		// Busy, stale or replaced: withhold the projection, preserve the exact
		// adopted wrapper and every sibling, and never claim fresh success.
		clearLocalVaultFileSessionSummary(&result.summary)
		op.withhold()
		if op.slot != nil && op.slot.refresh == op {
			op.slot.refresh = nil
		}
	case localVaultFileRefreshOutcomeFailed:
		clearLocalVaultFileSessionSummary(&result.summary)
		if current {
			// The client contract already terminally closed this exact wrapper.
			// Only while it is still the current exact wrapper may its cache be
			// cleared and a finite failure recorded.
			op.slot.session = nil
			clearLocalVaultFileSessionSummary(&op.slot.summary)
			op.slot.refresh = nil
			if viewCurrent {
				state.items = nil
				state.viewVerification = localVaultFileViewFailed
			}
		} else if op.slot != nil && op.slot.refresh == op {
			op.slot.refresh = nil
		}
	default:
		clearLocalVaultFileSessionSummary(&result.summary)
		if op.slot != nil && op.slot.refresh == op {
			op.slot.refresh = nil
		}
	}
}

// localVaultFileRefreshCurrentExact checks the map/slot/wrapper identity
// without synchronizing or mutating any boundary. It is used both before and
// after the final delivery sync.
func (a *App) localVaultFileRefreshCurrentExact(op *localVaultFileRefreshOperation) bool {
	if op == nil || op.slot == nil || op.parent == nil || a.session == nil {
		return false
	}
	state := &a.localVaultFiles
	slot := op.slot
	if state.sessionSlots[op.scope] != slot || slot.scope != op.scope ||
		slot.parent != op.parent || slot.appGeneration != op.generation ||
		a.session != op.parent || a.generation != op.generation ||
		slot.refresh != op || slot.refreshSequence != op.readSequence ||
		slot.session != op.wrapper {
		return false
	}
	// Use the personal path frozen at reservation. VaultPath may wait on the
	// parent session mutex, which a Busy delivery must never do.
	_, currentRoot := localVaultFilePaths(a.settingsPath, op.parentPath)
	return currentRoot == op.scope.backendRoot
}

// localVaultFileRefreshViewCurrent checks the delivered view ownership. The
// operation's frozen path, its frozen selected path, and the current selected
// path must all be the same scope at the same sequence, and the slot must still
// own this exact read operation.
func (a *App) localVaultFileRefreshViewCurrent(op *localVaultFileRefreshOperation) bool {
	if op == nil || op.slot == nil || op.slot.refresh != op {
		return false
	}
	state := &a.localVaultFiles
	return op.scope.configPath != "" &&
		op.viewSelected == op.scope.configPath &&
		state.selected == op.viewSelected &&
		state.selected == op.scope.configPath &&
		state.viewSequence == op.viewSequence
}

// cancelLocalVaultFileRefreshExact clears only this operation's undelivered
// projection and releases its exact slot/view bindings. It deliberately never
// closes or otherwise touches the borrowed wrapper.
func (a *App) cancelLocalVaultFileRefreshExact(op *localVaultFileRefreshOperation) {
	if op == nil {
		return
	}
	summary, pending := op.takeCancelled()
	if pending {
		clearLocalVaultFileSessionSummary(&summary)
	}
	if op.slot != nil && op.slot.refresh == op {
		op.slot.refresh = nil
	}
}

// cancelLocalVaultFileRefreshViewReads cancels only operations frozen to the
// exact view identity.
func (a *App) cancelLocalVaultFileRefreshViewReads(selected string, sequence uint64) {
	for _, slot := range a.localVaultFiles.sessionSlots {
		if slot == nil || slot.refresh == nil {
			continue
		}
		op := slot.refresh
		if op.viewSelected == selected && op.viewSequence == sequence {
			a.cancelLocalVaultFileRefreshExact(op)
		}
	}
}

// cancelLocalVaultFileRefreshView is the navigation/closeView boundary. It
// cancels only projection delivery for this view and invalidates fresh
// evidence; adopted children and sibling slots stay alive.
func (a *App) cancelLocalVaultFileRefreshView() {
	state := &a.localVaultFiles
	a.cancelLocalVaultFileRefreshViewReads(state.selected, state.viewSequence)
	state.viewSequence++
	state.viewVerification = localVaultFileViewUnverified
}

// invalidateLocalVaultFileRefreshFresh drops only this scope's fresh view
// evidence when its wrapper is detached or replaced. Cached bytes remain until
// the established slot close clears them.
func (a *App) invalidateLocalVaultFileRefreshFresh(scope localVaultFileSessionScope) {
	state := &a.localVaultFiles
	if state.selected == scope.configPath && state.viewVerification == localVaultFileViewFresh {
		state.viewVerification = localVaultFileViewCached
	}
}

// localVaultFileRefreshCaption is the controller feedback for the view layer.
// Fresh is possible only from an accepted successful Summary callback; a pure
// cache or navigated-back selection reports the cached caption.
func (a *App) localVaultFileRefreshCaption() string {
	if a.syncLocalVaultFileSessions() != personal.VaultFileCacheActive {
		return ""
	}
	state := &a.localVaultFiles
	switch state.viewVerification {
	case localVaultFileViewFresh:
		return localVaultFileFreshCaption
	case localVaultFileViewFailed:
		return localVaultFileFailedCaption
	}
	if a.session == nil || state.selected == "" {
		return ""
	}
	for _, slot := range state.sessionSlots {
		if slot == nil || slot.retiring || slot.session == nil ||
			slot.scope.configPath != state.selected || slot.parent != a.session ||
			slot.appGeneration != a.generation || slot.summary.VaultID == "" ||
			slot.summary.VaultID != slot.scope.vaultID {
			continue
		}
		return localVaultFileCachedCaption
	}
	return ""
}
