package desktop

import (
	"context"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

// A local vault-file session slot is the App-internal lifecycle owner for one
// exact local ref. Its identity is the slot pointer plus the current operation
// pointer and sequence; a counter that restarts at one is never enough to bind
// a late result to a rebuilt slot.
//
// Slots retain only the opaque client wrapper. They never retain a password,
// Secret Key, recovery kit, parent material, VUK, ScopedUnlock handle, identity
// or database. The wrapper's public Summary and Close methods are the only
// child operations used here.
type localVaultFileSessionScope struct {
	configPath  string
	vaultID     string
	backendRoot string
}

type localVaultFileSessionOperation struct {
	slot       *localVaultFileSessionSlot
	parent     *personal.Session
	generation uint64
	sequence   uint64
	scope      localVaultFileSessionScope
	ctx        context.Context
	cancel     context.CancelFunc
	// canceled is mutated only on the App dispatch path. The launched worker
	// never reads it; adopt rechecks it after being dispatched.
	canceled bool
}

type localVaultFileSessionSlot struct {
	scope         localVaultFileSessionScope
	parent        *personal.Session
	appGeneration uint64
	sequence      uint64
	operation     *localVaultFileSessionOperation
	session       *vaultfileclient.LocalGenesisSession
	summary       vaultfileclient.LocalGenesisBaseline
}

// localVaultFileSessionScopeFor resolves the exact navigation ref and the
// current workspace without reading a manifest or touching a wrapper.
func (a *App) localVaultFileSessionScopeFor(ref localVaultFileRef) (localVaultFileSessionScope, bool) {
	if a.session == nil || !a.session.Unlocked() || ref.path == "" || ref.vaultID == "" {
		return localVaultFileSessionScope{}, false
	}
	_, backendRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if backendRoot == "" {
		return localVaultFileSessionScope{}, false
	}
	return localVaultFileSessionScope{configPath: ref.path, vaultID: ref.vaultID, backendRoot: backendRoot}, true
}

// syncLocalVaultFileSessions is the lazy generation/parent boundary. It keeps
// the registry from surviving an App generation or parent change even when the
// caller is not App.Lock; App.Lock also calls clearLocalVaultFileSessions
// explicitly at its own established boundary.
func (a *App) syncLocalVaultFileSessions() {
	state := &a.localVaultFiles
	if state.sessionParent == a.session && state.sessionGeneration == a.generation {
		return
	}
	a.clearLocalVaultFileSessions()
	state.sessionParent = a.session
	state.sessionGeneration = a.generation
}

// clearLocalVaultFileSessions cancels every pending operation, detaches every
// adopted wrapper, clears every retained summary, and starts each real Close
// through the existing launch path. It takes no parent lock and never touches
// a sibling wrapper or a single-vault navigation decision.
func (a *App) clearLocalVaultFileSessions() {
	state := &a.localVaultFiles
	for _, slot := range state.sessionSlots {
		a.retireLocalVaultFileSessionSlot(slot)
	}
	state.sessionSlots = nil
	state.sessionParent = nil
	state.sessionGeneration = 0
}

// beginLocalVaultFileSession starts one real candidate open for the exact slot.
// The pending operation stores only the ref scope, captured parent, App
// generation and cancel information. Explicit short-lived factors are cloned
// into the launched worker and cleared there; they are not stored in the slot
// or the operation.
func (a *App) beginLocalVaultFileSession(scope localVaultFileSessionScope, password, key []byte) *localVaultFileSessionOperation {
	if a.session == nil || !a.session.Unlocked() || scope.configPath == "" ||
		scope.vaultID == "" || scope.backendRoot == "" {
		return nil
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if currentRoot != scope.backendRoot {
		return nil
	}
	a.syncLocalVaultFileSessions()
	state := &a.localVaultFiles
	slot := state.sessionSlots[scope]
	if slot != nil && (slot.parent != a.session || slot.appGeneration != a.generation) {
		a.retireLocalVaultFileSessionSlot(slot)
		slot = nil
	}
	if slot == nil {
		slot = &localVaultFileSessionSlot{scope: scope, parent: a.session, appGeneration: a.generation}
		if state.sessionSlots == nil {
			state.sessionSlots = make(map[localVaultFileSessionScope]*localVaultFileSessionSlot)
		}
		state.sessionSlots[scope] = slot
	} else {
		a.cancelLocalVaultFileSessionOperation(slot)
		if old := slot.session; old != nil {
			slot.session = nil
			clearLocalVaultFileSessionSummary(&slot.summary)
			a.launch(func() { _ = old.Close() })
		}
	}
	slot.sequence++
	ctx, cancel := context.WithCancel(context.Background())
	op := &localVaultFileSessionOperation{
		slot:       slot,
		parent:     slot.parent,
		generation: slot.appGeneration,
		sequence:   slot.sequence,
		scope:      scope,
		ctx:        ctx,
		cancel:     cancel,
	}
	slot.operation = op
	ownedPassword := append([]byte(nil), password...)
	ownedKey := append([]byte(nil), key...)
	a.launch(func() {
		defer clear(ownedPassword)
		defer clear(ownedKey)
		if op.ctx.Err() != nil {
			return
		}
		candidate, summary, err := a.openLocalVaultFileSessionCandidate(op, ownedPassword, ownedKey)
		if err != nil {
			a.dispatch(func() { a.adoptLocalVaultFileSessionCandidate(op, nil, vaultfileclient.LocalGenesisBaseline{}) })
			return
		}
		if hook := a.localVaultFiles.sessionCandidateForTest; hook != nil {
			hook(op, candidate)
		}
		a.dispatch(func() { a.adoptLocalVaultFileSessionCandidate(op, candidate, summary) })
	})
	return op
}

// openLocalVaultFileSessionCandidate is the production factory. It calls the
// frozen client with the operation's captured parent, never with mutable
// a.session state.
func (a *App) openLocalVaultFileSessionCandidate(op *localVaultFileSessionOperation, password, key []byte) (*vaultfileclient.LocalGenesisSession, vaultfileclient.LocalGenesisBaseline, error) {
	if op == nil || op.parent == nil {
		return nil, vaultfileclient.LocalGenesisBaseline{}, vaultfileclient.ErrLocalReview
	}
	return vaultfileclient.OpenLocalGenesisSession(op.parent, op.scope.configPath, op.scope.backendRoot, op.scope.vaultID, password, key)
}

// adoptLocalVaultFileSessionCandidate accepts a candidate only when the exact
// slot, operation, sequence, parent, App generation, workspace, ref path and
// VaultID still match. Every stale, failed or replaced candidate is closed and
// its summary dropped; it can never remove or revive a later generation.
func (a *App) adoptLocalVaultFileSessionCandidate(op *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession, summary vaultfileclient.LocalGenesisBaseline) {
	a.syncLocalVaultFileSessions()
	valid := candidate != nil && op != nil && !op.canceled && op.slot != nil &&
		op.slot.operation == op && op.slot.sequence == op.sequence &&
		op.slot.scope == op.scope && op.slot.parent == op.parent &&
		op.slot.appGeneration == op.generation &&
		a.session == op.parent && a.generation == op.generation &&
		a.localVaultFiles.sessionSlots[op.scope] == op.slot &&
		summary.VaultID == op.scope.vaultID
	if valid {
		_, currentRoot := localVaultFilePaths(a.settingsPath, op.parent.VaultPath())
		valid = currentRoot == op.scope.backendRoot
	}
	if !valid {
		clearLocalVaultFileSessionSummary(&summary)
		if candidate != nil {
			a.launch(func() { _ = candidate.Close() })
		}
		return
	}
	slot := op.slot
	if old := slot.session; old != nil && old != candidate {
		a.launch(func() { _ = old.Close() })
	}
	slot.session = candidate
	slot.summary = localVaultFileSessionSummaryClone(summary)
	if op.cancel != nil {
		op.cancel()
		op.cancel = nil
	}
}

// cancelLocalVaultFileSessionOperation cancels only this slot's pending
// operation. An already adopted wrapper is left for an explicit close or
// replacement so a pending failure cannot close a valid child.
func (a *App) cancelLocalVaultFileSessionOperation(slot *localVaultFileSessionSlot) {
	if slot == nil || slot.operation == nil {
		return
	}
	op := slot.operation
	op.canceled = true
	if op.cancel != nil {
		op.cancel()
		op.cancel = nil
	}
	slot.operation = nil
}

// cancelLocalVaultFileSession is the narrow cancel entry for one exact ref.
func (a *App) cancelLocalVaultFileSession(scope localVaultFileSessionScope) {
	a.syncLocalVaultFileSessions()
	a.cancelLocalVaultFileSessionOperation(a.localVaultFiles.sessionSlots[scope])
}

// closeLocalVaultFileSession removes one exact slot, cancels its pending
// operation, detaches and clears its summary, and starts only that wrapper's
// real Close. Parent and sibling wrappers are not locked or closed.
func (a *App) closeLocalVaultFileSession(scope localVaultFileSessionScope) {
	a.syncLocalVaultFileSessions()
	a.retireLocalVaultFileSessionSlot(a.localVaultFiles.sessionSlots[scope])
}

func (a *App) retireLocalVaultFileSessionSlot(slot *localVaultFileSessionSlot) {
	if slot == nil {
		return
	}
	state := &a.localVaultFiles
	if state.sessionSlots[slot.scope] == slot {
		delete(state.sessionSlots, slot.scope)
	}
	a.cancelLocalVaultFileSessionOperation(slot)
	session := slot.session
	slot.session = nil
	clearLocalVaultFileSessionSummary(&slot.summary)
	slot.parent = nil
	if session != nil {
		a.launch(func() { _ = session.Close() })
	}
}

// readLocalVaultFileSession returns only the bounded summary retained for the
// current slot. It does not hand out a token, handle, identity or database.
func (a *App) readLocalVaultFileSession(scope localVaultFileSessionScope) (vaultfileclient.LocalGenesisBaseline, bool) {
	a.syncLocalVaultFileSessions()
	slot := a.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil || slot.parent != a.session ||
		slot.appGeneration != a.generation {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if currentRoot != scope.backendRoot {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	return localVaultFileSessionSummaryClone(slot.summary), true
}

func localVaultFileSessionSummaryClone(summary vaultfileclient.LocalGenesisBaseline) vaultfileclient.LocalGenesisBaseline {
	out := summary
	if len(summary.Items) != 0 {
		out.Items = append([]personal.VaultFileBaselineItem(nil), summary.Items...)
	}
	return out
}

func clearLocalVaultFileSessionSummary(summary *vaultfileclient.LocalGenesisBaseline) {
	if summary == nil {
		return
	}
	for i := range summary.Items {
		summary.Items[i] = personal.VaultFileBaselineItem{}
	}
	summary.Items = nil
	summary.VaultID = ""
}
