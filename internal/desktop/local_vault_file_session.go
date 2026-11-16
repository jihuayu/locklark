package desktop

import (
	"context"
	"sync"

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

type localVaultFileSessionOutcome uint8

const (
	localVaultFileSessionOutcomeNone localVaultFileSessionOutcome = iota
	localVaultFileSessionOutcomeOpened
	localVaultFileSessionOutcomeFailed
	localVaultFileSessionOutcomeCancelled
)

// localVaultFileSessionResult is the single result handed from the launched
// worker to the serial dispatch path. Ownership transfers on stage and then to
// the one successful take (or to cancellation).
type localVaultFileSessionResult struct {
	candidate *vaultfileclient.LocalGenesisSession
	summary   vaultfileclient.LocalGenesisBaseline
	outcome   localVaultFileSessionOutcome
}

type localVaultFileSessionOperation struct {
	slot       *localVaultFileSessionSlot
	parent     *personal.Session
	generation uint64
	sequence   uint64
	scope      localVaultFileSessionScope
	ctx        context.Context
	cancel     context.CancelFunc

	// handoffMu guards the one result slot plus its ready/terminal transition.
	// It is never held across dispatch, launch, validation, Close or IO.
	handoffMu       sync.Mutex
	handoffReady    bool
	handoffResult   localVaultFileSessionResult
	handoffTerminal bool
	outcome         localVaultFileSessionOutcome

	// processingFinished is set exactly once by the producer after its last
	// cryptographic/material use and, when the factory succeeded, after the
	// exact candidate has been staged. candidateOutstanding stays true while a
	// real candidate is owned by the handoff or the serial dispatch path and
	// has not been legally adopted or actually Closed. settled is closed once
	// both conditions hold; taking the handoff, cancelling the context, a
	// finite outcome, a worker return or a queued Close request never closes it
	// by itself.
	processingFinished   bool
	candidateOutstanding bool
	settled              bool
	settledCh            chan struct{}
}

// markProcessingFinished records the producer's terminal state and settles only
// when no real candidate remains outstanding. A successfully created candidate
// must already have been staged, so there is no premature no-candidate window.
func (op *localVaultFileSessionOperation) markProcessingFinished() {
	if op == nil {
		return
	}
	op.handoffMu.Lock()
	op.processingFinished = true
	op.trySettleLocked()
	op.handoffMu.Unlock()
}

// markCandidateResolved releases the one real candidate after it was legally
// adopted by the slot or after its actual Close returned. It must be called
// outside the lock that guards any Close or IO.
func (op *localVaultFileSessionOperation) markCandidateResolved() {
	if op == nil {
		return
	}
	op.handoffMu.Lock()
	op.candidateOutstanding = false
	op.trySettleLocked()
	op.handoffMu.Unlock()
}

func (op *localVaultFileSessionOperation) trySettleLocked() {
	if op.settled || !op.processingFinished || op.candidateOutstanding {
		return
	}
	op.settled = true
	close(op.settledCh)
}

// settledSignal returns the one-shot settlement channel. It is immutable after
// reservation, so callers may wait without holding handoffMu.
func (op *localVaultFileSessionOperation) settledSignal() <-chan struct{} {
	if op == nil {
		return nil
	}
	return op.settledCh
}

func (op *localVaultFileSessionOperation) isSettled() bool {
	if op == nil {
		return false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	return op.settled
}

func (op *localVaultFileSessionOperation) processingDone() bool {
	if op == nil {
		return false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	return op.processingFinished
}

// stage transfers ownership of result to the operation. It refuses after
// cancellation/terminal, in which case the caller still owns and closes any
// returned candidate.
func (op *localVaultFileSessionOperation) stage(result localVaultFileSessionResult) bool {
	if op == nil {
		return false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	if op.handoffTerminal || op.handoffReady {
		return false
	}
	op.handoffResult = result
	op.handoffReady = true
	if result.candidate != nil {
		op.candidateOutstanding = true
	}
	return true
}

// take is the unique dispatch-side ownership transfer. It becomes terminal
// exactly once and returns no result after cancellation already took it.
func (op *localVaultFileSessionOperation) take() (localVaultFileSessionResult, bool) {
	if op == nil {
		return localVaultFileSessionResult{}, false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	if !op.handoffReady {
		return localVaultFileSessionResult{}, false
	}
	result := op.handoffResult
	op.handoffResult = localVaultFileSessionResult{}
	op.handoffReady = false
	op.handoffTerminal = true
	return result, true
}

// takeCancelled makes the operation terminal and returns any undelivered
// result to the caller for exact cleanup.
func (op *localVaultFileSessionOperation) takeCancelled() (localVaultFileSessionResult, bool) {
	if op == nil {
		return localVaultFileSessionResult{}, false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	op.handoffTerminal = true
	op.outcome = localVaultFileSessionOutcomeCancelled
	if !op.handoffReady {
		return localVaultFileSessionResult{}, false
	}
	result := op.handoffResult
	op.handoffResult = localVaultFileSessionResult{}
	op.handoffReady = false
	return result, true
}

func (op *localVaultFileSessionOperation) finish(outcome localVaultFileSessionOutcome) {
	if op == nil {
		return
	}
	op.handoffMu.Lock()
	op.outcome = outcome
	op.handoffTerminal = true
	op.handoffMu.Unlock()
}

func (op *localVaultFileSessionOperation) finiteOutcome() localVaultFileSessionOutcome {
	if op == nil {
		return localVaultFileSessionOutcomeNone
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	return op.outcome
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
	if a.syncLocalVaultFileSessions() != personal.VaultFileCacheActive ||
		ref.path == "" || ref.vaultID == "" {
		return localVaultFileSessionScope{}, false
	}
	_, backendRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if backendRoot == "" {
		return localVaultFileSessionScope{}, false
	}
	return localVaultFileSessionScope{configPath: ref.path, vaultID: ref.vaultID, backendRoot: backendRoot}, true
}

// syncLocalVaultFileSessions is the lazy generation/parent boundary. A parent
// pointer or App generation change clears the prior slots as before. The same
// current parent in Busy preserves slots, summaries and pending operations; it
// withholds delivery and authorization until Active. Revoked clears and is
// never rebound as a valid sessionParent. App.Lock also calls
// clearLocalVaultFileSessions explicitly at its own established boundary.
func (a *App) syncLocalVaultFileSessions() personal.VaultFileCacheState {
	state := &a.localVaultFiles
	parent := a.session
	if parent == nil {
		a.clearLocalVaultFileSessions()
		return personal.VaultFileCacheRevoked
	}
	cache := parent.VaultFileCacheState()
	if state.sessionParent != parent || state.sessionGeneration != a.generation {
		a.clearLocalVaultFileSessions()
	}
	if cache == personal.VaultFileCacheRevoked {
		a.clearLocalVaultFileSessions()
		return cache
	}
	// A new parent may bind while Busy, but begin/adopt/read still require
	// Active before any open, adoption or cache delivery.
	state.sessionParent = parent
	state.sessionGeneration = a.generation
	return cache
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

// beginLocalVaultFileSession reserves one operation and immediately starts the
// generic candidate-open worker. The pending operation stores only the ref
// scope, captured parent, App generation and cancel information. Explicit
// short-lived factors are cloned into the launched worker and cleared there;
// they are not stored in the slot or the operation.
//
// Creation completion uses the reserve/submit split below so it can own its
// exact handoff before the single Complete/Verify worker launches. Calling this
// generic entry from that worker would start a second factor-open launch.
func (a *App) beginLocalVaultFileSession(scope localVaultFileSessionScope, password, key []byte) *localVaultFileSessionOperation {
	op := a.reserveLocalVaultFileSessionOperation(scope)
	if op == nil {
		return nil
	}
	a.launchLocalVaultFileSessionOperation(op, password, key)
	return op
}

// reserveLocalVaultFileSessionOperation binds the exact slot, parent, App
// generation, sequence and scope. It performs no factor work and captures no
// password, Secret Key or recovery kit. It runs on the UI path so creation
// completion can reserve before its worker launches.
func (a *App) reserveLocalVaultFileSessionOperation(scope localVaultFileSessionScope) *localVaultFileSessionOperation {
	if a.syncLocalVaultFileSessions() != personal.VaultFileCacheActive ||
		scope.configPath == "" || scope.vaultID == "" || scope.backendRoot == "" {
		return nil
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if currentRoot != scope.backendRoot {
		return nil
	}
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
		settledCh:  make(chan struct{}),
	}
	slot.operation = op
	return op
}

// launchLocalVaultFileSessionOperation starts the generic candidate-open worker
// for an already reserved operation. The dispatcher and test hook are captured
// on the UI path, so the worker never reads mutable App state.
func (a *App) launchLocalVaultFileSessionOperation(op *localVaultFileSessionOperation, password, key []byte) {
	if op == nil {
		return
	}
	ownedPassword := append([]byte(nil), password...)
	ownedKey := append([]byte(nil), key...)
	dispatch := a.dispatch
	hook := a.localVaultFiles.sessionCandidateForTest
	openPause := a.localVaultFiles.sessionCandidateOpenPauseForTest
	closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
	a.launch(func() {
		defer clear(ownedPassword)
		defer clear(ownedKey)
		if op.ctx.Err() != nil {
			// No factory ran, so no candidate can exist. Clear both
			// worker-owned factor copies before the settlement mark; the
			// deferred clears remain as safety.
			clear(ownedPassword)
			clear(ownedKey)
			op.markProcessingFinished()
			return
		}
		if openPause != nil {
			openPause()
		}
		candidate, summary, err := a.openLocalVaultFileSessionCandidate(op, ownedPassword, ownedKey)
		outcome := localVaultFileSessionOutcomeOpened
		if err != nil {
			outcome = localVaultFileSessionOutcomeFailed
		}
		result := localVaultFileSessionResult{candidate: candidate, summary: summary, outcome: outcome}
		// The worker's factor copies are dead once the real factory returns.
		// Clear them before staging, marking or dispatch so a blocked UI path
		// cannot delay erasure; the deferred clears remain as safety.
		clear(ownedPassword)
		clear(ownedKey)
		a.stageAndDispatchLocalVaultFileSessionResult(op, result, dispatch, hook, closePause)
	})
}

// stageLocalVaultFileSessionResult stages one result on the operation and calls
// the optional hook. It never dispatches; the caller's single dispatch closure
// owns the take/adopt and any UI transition. On refusal the operation already
// became terminal, so this call still owns and closes the returned candidate
// before the producer is allowed to report processing finished.
func (a *App) stageLocalVaultFileSessionResult(op *localVaultFileSessionOperation, result localVaultFileSessionResult, hook func(*localVaultFileSessionOperation), closePause func()) bool {
	if op == nil || !op.stage(result) {
		clearLocalVaultFileSessionSummary(&result.summary)
		closeLocalVaultFileSessionCandidate(op, result.candidate, closePause)
		return false
	}
	if hook != nil {
		hook(op)
	}
	return true
}

// stageAndDispatchLocalVaultFileSessionResult is the generic worker's single
// ownership handoff. Dispatcher, hook and pause seams were captured before
// launch. Processing is marked after a successful candidate was staged and
// before the dispatcher is invoked, so a blocked or dropped dispatch can never
// prevent cancellation settlement.
func (a *App) stageAndDispatchLocalVaultFileSessionResult(op *localVaultFileSessionOperation, result localVaultFileSessionResult, dispatch func(func()), hook func(*localVaultFileSessionOperation), closePause func()) bool {
	staged := a.stageLocalVaultFileSessionResult(op, result, hook, closePause)
	op.markProcessingFinished()
	if !staged {
		return false
	}
	if dispatch != nil {
		dispatch(func() { a.takeAndCompleteLocalVaultFileSessionResult(op) })
	}
	return true
}

// closeLocalVaultFileSessionCandidate is the one real cleanup Close for a
// candidate that never became an adopted slot. The optional pause is a
// parameterless private test seam invoked immediately before Close. Settlement
// is released only after the real Close returns; no operation lock is held
// across the seam or the Close.
func closeLocalVaultFileSessionCandidate(op *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession, pause func()) {
	if candidate == nil {
		return
	}
	if pause != nil {
		pause()
	}
	_ = candidate.Close()
	op.markCandidateResolved()
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

// takeAndCompleteLocalVaultFileSessionResult is the serial dispatch owner of
// the single staged result. take is terminal, so a late or repeated callback
// cannot affect a later operation or child.
func (a *App) takeAndCompleteLocalVaultFileSessionResult(op *localVaultFileSessionOperation) bool {
	result, ok := op.take()
	if !ok {
		return false
	}
	a.completeLocalVaultFileSessionResult(op, result)
	return true
}

// completeLocalVaultFileSessionResult accepts a candidate only when the exact
// slot, operation, sequence, parent, App generation, workspace, ref path,
// VaultID and finite opened outcome still match. Every stale, failed, Busy or
// replaced candidate is closed exactly and its summary dropped; the current
// operation is then ended with a finite outcome.
func (a *App) completeLocalVaultFileSessionResult(op *localVaultFileSessionOperation, result localVaultFileSessionResult) {
	cache := a.syncLocalVaultFileSessions()
	valid := result.outcome == localVaultFileSessionOutcomeOpened &&
		cache == personal.VaultFileCacheActive && result.candidate != nil && op != nil &&
		op.slot != nil && op.slot.operation == op && op.slot.sequence == op.sequence &&
		op.slot.scope == op.scope && op.slot.parent == op.parent &&
		op.slot.appGeneration == op.generation &&
		a.session == op.parent && a.generation == op.generation &&
		a.localVaultFiles.sessionSlots[op.scope] == op.slot &&
		result.summary.VaultID == op.scope.vaultID
	if valid {
		_, currentRoot := localVaultFilePaths(a.settingsPath, op.parent.VaultPath())
		valid = currentRoot == op.scope.backendRoot
	}
	if valid {
		slot := op.slot
		if old := slot.session; old != nil && old != result.candidate {
			a.launch(func() { _ = old.Close() })
		}
		slot.session = result.candidate
		slot.summary = localVaultFileSessionSummaryClone(result.summary)
		// The slot now owns the capability. The operation settles only after
		// this legal transfer; a later slot close is the slot's responsibility.
		op.markCandidateResolved()
		a.finishLocalVaultFileSessionOperation(op, localVaultFileSessionOutcomeOpened)
		return
	}
	clearLocalVaultFileSessionSummary(&result.summary)
	if result.candidate != nil {
		closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
		a.launch(func() { closeLocalVaultFileSessionCandidate(op, result.candidate, closePause) })
	} else {
		op.markCandidateResolved()
	}
	outcome := result.outcome
	if outcome != localVaultFileSessionOutcomeFailed {
		outcome = localVaultFileSessionOutcomeFailed
	}
	a.finishLocalVaultFileSessionOperation(op, outcome)
}

// finishLocalVaultFileSessionOperation records the finite outcome and ends the
// pending operation only if it is still the exact current operation.
func (a *App) finishLocalVaultFileSessionOperation(op *localVaultFileSessionOperation, outcome localVaultFileSessionOutcome) {
	op.finish(outcome)
	if op.slot != nil && op.slot.operation == op {
		if op.cancel != nil {
			op.cancel()
			op.cancel = nil
		}
		op.slot.operation = nil
	}
}

// cancelLocalVaultFileSessionOperation cancels only this slot's pending
// operation. An already adopted wrapper is left for an explicit close or
// replacement so a pending failure cannot close a valid child.
func (a *App) cancelLocalVaultFileSessionOperation(slot *localVaultFileSessionSlot) {
	if slot == nil {
		return
	}
	a.cancelLocalVaultFileSessionOperationExact(slot.operation)
}

// cancelLocalVaultFileSessionOperationExact cancels this exact operation, never
// whatever operation the slot may hold later. It closes only an undelivered
// staged candidate; an already adopted wrapper is left for explicit close or
// replacement so a stale callback cannot close a valid current child.
func (a *App) cancelLocalVaultFileSessionOperationExact(op *localVaultFileSessionOperation) {
	if op == nil {
		return
	}
	result, pending := op.takeCancelled()
	a.finishLocalVaultFileSessionOperation(op, localVaultFileSessionOutcomeCancelled)
	if !pending {
		return
	}
	clearLocalVaultFileSessionSummary(&result.summary)
	if result.candidate != nil {
		closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
		a.launch(func() { closeLocalVaultFileSessionCandidate(op, result.candidate, closePause) })
	} else {
		op.markCandidateResolved()
	}
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
// current slot. It is a cache getter: it does not re-read the frozen manifest
// or key material and does not call the opaque wrapper's Summary. Fresh
// verification remains wrapper.Summary. It does not hand out a token, handle,
// identity or database. Busy withholds delivery and drops only the local clone,
// preserving the slot and retained summary; Revoked lets sync clear the
// corresponding parent state. Caller-held copies already returned cannot be
// recalled.
func (a *App) readLocalVaultFileSession(scope localVaultFileSessionScope) (vaultfileclient.LocalGenesisBaseline, bool) {
	if a.syncLocalVaultFileSessions() != personal.VaultFileCacheActive {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	slot := a.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.session == nil || slot.parent != a.session ||
		slot.appGeneration != a.generation {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, a.session.VaultPath())
	if currentRoot != scope.backendRoot {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	summary := localVaultFileSessionSummaryClone(slot.summary)
	if a.syncLocalVaultFileSessions() != personal.VaultFileCacheActive ||
		a.localVaultFiles.sessionSlots[scope] != slot || slot.session == nil {
		clearLocalVaultFileSessionSummary(&summary)
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	return summary, true
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
