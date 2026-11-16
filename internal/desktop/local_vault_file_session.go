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
	// journalPath is the scheduling hint captured from the strict manifest
	// read. It is part of the exact slot key but is not routing authority or a
	// grant; the client constructor compares it to its own captured manifest.
	journalPath string
}

type localVaultFileSessionOutcome uint8

const (
	localVaultFileSessionOutcomeNone localVaultFileSessionOutcome = iota
	localVaultFileSessionOutcomeOpened
	localVaultFileSessionOutcomeFailed
	localVaultFileSessionOutcomeCancelled
	// localVaultFileSessionOutcomeWithheld is a private finite outcome for an
	// otherwise exact opened candidate whose delivery was blocked only by a
	// transient VaultFileCacheBusy parent. It is not a factor failure and never
	// adopts the candidate.
	localVaultFileSessionOutcomeWithheld
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
	// parentPath is the immutable nonblocking routing hint frozen at reserve
	// from the same snapshot that authorized the begin. It is never auth,
	// proof, a factor or a grant; workers still perform their real checks.
	parentPath string
	ctx        context.Context
	cancel     context.CancelFunc
	// waitFor is the immutable set of older operations with the same parent
	// instance and exact journalPath that must settle before this producer may
	// enter its real factory or protocol. It is captured by reserve before any
	// predecessor is cancelled or replaced.
	waitFor []*localVaultFileSessionOperation

	// handoffMu guards the one result slot plus its ready/terminal transition.
	// It is never held across dispatch, launch, validation, Close or IO.
	handoffMu       sync.Mutex
	handoffReady    bool
	handoffResult   localVaultFileSessionResult
	handoffTerminal bool
	outcome         localVaultFileSessionOutcome

	// onComplete is an immutable-once UI observer installed before the worker
	// launches. It is invoked at most once, after this operation has a real
	// finite outcome and its exact slot binding has ended. Settlement alone,
	// a held dispatch or a queued cleanup Close never invokes it. The observer
	// is taken out under handoffMu and called outside the mutex so a reentrant
	// callback cannot observe a half-cleared observer.
	onComplete     func(localVaultFileSessionOutcome)
	completionSent bool

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

// takeCancelled makes a non-UI-completed operation terminal and returns any
// undelivered result to the caller for exact cleanup. A UI-completed finite
// outcome is protected at the start: handoffTerminal with a non-None outcome
// means the UI already consumed and observed the result (Opened, Failed, or a
// prior Cancelled). A late cancellation returns without rewriting that outcome,
// closing a child, or notifying a second observer. take() alone sets terminal
// while the outcome is still None; that is material handoff, not a completed
// finite UI outcome, and must not block cancellation.
//
// For every other state cancellation records Cancelled, terminalizes the
// handoff, and returns any ready undelivered result for the existing outside-mu
// cleanup. Settlement is not the protection boundary: a no-candidate failure can
// settle before its UI take, and that pending projection must be consumed so a
// stale callback cannot later finish Failed. A defensive candidate in an
// already settled state still follows the same cleanup caller contract.
func (op *localVaultFileSessionOperation) takeCancelled() (localVaultFileSessionResult, bool, bool) {
	if op == nil {
		return localVaultFileSessionResult{}, false, false
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	if op.handoffTerminal && op.outcome != localVaultFileSessionOutcomeNone {
		return localVaultFileSessionResult{}, false, false
	}
	active := !op.settled
	op.handoffTerminal = true
	op.outcome = localVaultFileSessionOutcomeCancelled
	if !op.handoffReady {
		return localVaultFileSessionResult{}, false, active
	}
	result := op.handoffResult
	op.handoffResult = localVaultFileSessionResult{}
	op.handoffReady = false
	return result, true, active
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

// setCompletionObserver installs the one UI completion observer before the
// worker launches. Callers that do not need an observer leave it nil.
func (op *localVaultFileSessionOperation) setCompletionObserver(fn func(localVaultFileSessionOutcome)) {
	if op == nil {
		return
	}
	op.handoffMu.Lock()
	op.onComplete = fn
	op.handoffMu.Unlock()
}

// takeCompletionObserver returns a finite outcome and its one-shot observer.
// A missing or not-yet-finite outcome does not consume the observer. The
// caller must invoke the returned function outside handoffMu.
func (op *localVaultFileSessionOperation) takeCompletionObserver() (localVaultFileSessionOutcome, func(localVaultFileSessionOutcome)) {
	if op == nil {
		return localVaultFileSessionOutcomeNone, nil
	}
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	if op.completionSent || op.outcome == localVaultFileSessionOutcomeNone {
		return op.outcome, nil
	}
	op.completionSent = true
	fn := op.onComplete
	op.onComplete = nil
	return op.outcome, fn
}

// notifyLocalVaultFileSessionCompletion observes the finite outcome only after
// the operation's exact slot binding has ended. It never polls settlement.
func (a *App) notifyLocalVaultFileSessionCompletion(op *localVaultFileSessionOperation) {
	outcome, fn := op.takeCompletionObserver()
	if fn != nil {
		fn(outcome)
	}
}

// collectLocalVaultFileSessionPredecessors gathers every unsettled operation
// already owned by a slot with the same parent instance and exact journalPath.
// The full UI identity remains separate; this is only the scheduling key.
// Retiring tails are included, and exact operation pointers are deduplicated.
// It must run before the caller cancels or replaces any of them.
func (a *App) collectLocalVaultFileSessionPredecessors(scope localVaultFileSessionScope) []*localVaultFileSessionOperation {
	state := &a.localVaultFiles
	seen := make(map[*localVaultFileSessionOperation]struct{})
	var out []*localVaultFileSessionOperation
	add := func(op *localVaultFileSessionOperation) {
		if op == nil || op.isSettled() {
			return
		}
		if _, ok := seen[op]; ok {
			return
		}
		seen[op] = struct{}{}
		out = append(out, op)
	}
	addWithWait := func(op *localVaultFileSessionOperation) {
		add(op)
		if op == nil {
			return
		}
		for _, pred := range op.waitFor {
			add(pred)
		}
	}
	for _, slot := range state.sessionSlots {
		if slot == nil || slot.parent != a.session || slot.scope.journalPath != scope.journalPath {
			continue
		}
		addWithWait(slot.operation)
		for _, op := range slot.tail {
			addWithWait(op)
		}
	}
	return out
}

// waitLocalVaultFileSessionPredecessors blocks the producer until every
// captured predecessor settles. Either the passed outer context or the
// operation's own context may cancel while waiting; the first cancellation runs
// onCancel promptly and at most once (to clear worker-owned material), but the
// wait still completes. Generic callers pass the same context twice. Settlement
// is not signalled here; callers mark processing finished only after this
// returns.
func waitLocalVaultFileSessionPredecessors(op *localVaultFileSessionOperation, ctx context.Context, onCancel func()) {
	if op == nil || len(op.waitFor) == 0 {
		return
	}
	cleared := false
	clearOnCancel := func() {
		if cleared {
			return
		}
		cleared = true
		if onCancel != nil {
			onCancel()
		}
	}
	var outerDone, ownDone <-chan struct{}
	if ctx != nil {
		outerDone = ctx.Done()
	}
	if op.ctx != nil {
		ownDone = op.ctx.Done()
	}
	if (ctx != nil && ctx.Err() != nil) || (op.ctx != nil && op.ctx.Err() != nil) {
		clearOnCancel()
	}
	done := make(chan struct{})
	go func() {
		for _, pred := range op.waitFor {
			<-pred.settledSignal()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-outerDone:
		clearOnCancel()
		<-done
	case <-ownDone:
		clearOnCancel()
		<-done
	}
	if !cleared && ((ctx != nil && ctx.Err() != nil) || (op.ctx != nil && op.ctx.Err() != nil)) {
		clearOnCancel()
	}
}

type localVaultFileSessionSlot struct {
	scope         localVaultFileSessionScope
	parent        *personal.Session
	appGeneration uint64
	sequence      uint64
	operation     *localVaultFileSessionOperation
	session       *vaultfileclient.LocalGenesisSession
	summary       vaultfileclient.LocalGenesisBaseline
	// refresh is the narrow projection-only operation borrowing session. It
	// never owns or closes that wrapper and is cancelled on every detach,
	// replace, retire and parent-clear boundary. refreshSequence is the
	// delivery read identity for the exact current operation.
	refresh         *localVaultFileRefreshOperation
	refreshSequence uint64
	// retiring marks a slot retained as an ordering tail after its cache,
	// wrapper and current operation were detached. It is never cache-readable
	// and is purged only after all tail operations settle.
	retiring bool
	tail     []*localVaultFileSessionOperation
	// purgeReady is closed by the tail-readiness goroutine. The map is purged
	// only on the UI path.
	purgeReady chan struct{}
	// closeTail is the latest tracked physical Close for a detached adopted
	// wrapper owned by this slot. It is installed before the real Close worker
	// launches and is inherited across same-parent scope replacement. It never
	// retains the wrapper, a factor, key, kit, token, handle or App pointer.
	closeTail *localVaultFileCloseTail
}

// localVaultFileCloseResult is the finite cumulative outcome of a tracked
// adopted-wrapper Close chain. No raw error string or object is retained.
type localVaultFileCloseResult uint8

const (
	localVaultFileCloseResultUnknown localVaultFileCloseResult = iota
	localVaultFileCloseResultSucceeded
	localVaultFileCloseResultFailed
)

// localVaultFileCloseTail is the immutable completion record for one adopted
// wrapper's real Close. The previous close is held only by the launched worker
// closure while it waits for that close's actual done and folds its finite
// result; the worker then releases it. This node retains only the done channel
// and finite enum: no prior pointer, wrapper, factor, key, kit, token, handle,
// App or slot pointer.
type localVaultFileCloseTail struct {
	done   chan struct{}
	result localVaultFileCloseResult
}

// localVaultFileCloseTailFinished reports whether this tail and therefore every
// prior tail in its chain have published their finite result.
func localVaultFileCloseTailFinished(tail *localVaultFileCloseTail) bool {
	if tail == nil {
		return true
	}
	select {
	case <-tail.done:
		return true
	default:
		return false
	}
}

// detachLocalVaultFileSessionWrapper is the one UI-side adopted-wrapper detach
// helper. It cancels only this slot's borrowed projection delivery, invalidates
// its fresh evidence, removes the exact wrapper from the slot, clears the
// visible summary, and installs the new close tail before launching the worker
// that performs the real Close. The worker receives only the opaque wrapper and
// the prior tail; it never reads or mutates App or slot state and never holds a
// lock across Close, launch or dispatch. Calling it again after the wrapper is
// detached is a no-op for the physical Close.
func (a *App) detachLocalVaultFileSessionWrapper(slot *localVaultFileSessionSlot) *localVaultFileCloseTail {
	if slot == nil {
		return nil
	}
	a.cancelLocalVaultFileRefreshExact(slot.refresh)
	a.invalidateLocalVaultFileRefreshFresh(slot.scope)
	wrapper := slot.session
	if wrapper == nil {
		return slot.closeTail
	}
	slot.session = nil
	clearLocalVaultFileSessionSummary(&slot.summary)
	// prior is captured only by this worker closure. The published tail node
	// does not retain it, so a completed chain cannot keep every previous node
	// alive through the active slot's latest closeTail.
	prior := slot.closeTail
	tail := &localVaultFileCloseTail{done: make(chan struct{})}
	slot.closeTail = tail
	pause := a.localVaultFiles.sessionAdoptedClosePauseForTest
	a.launch(func() {
		if pause != nil {
			pause()
		}
		closeErr := wrapper.Close()
		result := localVaultFileCloseResultSucceeded
		if closeErr != nil {
			result = localVaultFileCloseResultFailed
		}
		if prior != nil {
			<-prior.done
			if prior.result != localVaultFileCloseResultSucceeded {
				result = localVaultFileCloseResultFailed
			}
		}
		tail.result = result
		close(tail.done)
	})
	return tail
}

// localVaultFileSessionScopeFor resolves the exact navigation ref and the
// current workspace without reading a manifest or touching a wrapper.
func (a *App) localVaultFileSessionScopeFor(ref localVaultFileRef) (localVaultFileSessionScope, bool) {
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" ||
		ref.path == "" || ref.vaultID == "" {
		return localVaultFileSessionScope{}, false
	}
	_, backendRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if backendRoot == "" {
		return localVaultFileSessionScope{}, false
	}
	return localVaultFileSessionScope{configPath: ref.path, vaultID: ref.vaultID, backendRoot: backendRoot, journalPath: ref.journalPath}, true
}

// syncLocalVaultFileSessions is the lazy generation/parent boundary. A parent
// pointer change drops the old parent's slots and tails; the old workers still
// close their own candidates. A same-parent App generation change detaches the
// current cache/operation/wrapper state but preserves retiring ordering tails.
// A read-only Revoked cache state is treated the same way: it detaches current
// cache state but is not proof that the parent was actually locked. App.Lock is
// the established all-tail drop boundary.
func (a *App) syncLocalVaultFileSessions() personal.VaultFileCacheState {
	state := &a.localVaultFiles
	parent := a.session
	if parent == nil {
		a.clearLocalVaultFileSessions()
		state.sessionPath = ""
		return personal.VaultFileCacheRevoked
	}
	a.purgeSettledLocalVaultFileSessionTails()
	cache, personalPath := parent.VaultFileCacheSnapshot()
	if state.sessionParent != parent {
		a.clearLocalVaultFileSessions()
	} else if state.sessionGeneration != a.generation {
		a.detachLocalVaultFileSessionsForBoundary()
	}
	if cache == personal.VaultFileCacheRevoked {
		a.detachLocalVaultFileSessionsForBoundary()
		state.sessionParent = parent
		state.sessionGeneration = a.generation
		state.sessionPath = ""
		return cache
	}
	// A new parent may bind while Busy, but begin/adopt/read still require
	// Active before any open, adoption or cache delivery. The routing path is
	// bound only when this same snapshot is Active; Busy and Revoked keep it
	// empty with no stale fallback.
	state.sessionParent = parent
	state.sessionGeneration = a.generation
	if cache == personal.VaultFileCacheActive {
		state.sessionPath = personalPath
	} else {
		state.sessionPath = ""
	}
	return cache
}

// detachLocalVaultFileSessionsForBoundary cancels and detaches every current
// slot while retaining retiring ordering tails. It never waits.
func (a *App) detachLocalVaultFileSessionsForBoundary() {
	state := &a.localVaultFiles
	for _, slot := range state.sessionSlots {
		if slot == nil || slot.retiring {
			continue
		}
		a.retireLocalVaultFileSessionSlot(slot)
	}
}

// clearLocalVaultFileSessions is the established all-tail drop boundary used by
// App.Lock and actual parent replacement. It cancels every pending operation,
// detaches every adopted wrapper, clears every retained summary, and starts each
// real Close through the existing launch path. Retiring metadata is dropped;
// old workers still settle and close their own candidates. It takes no parent
// lock and never touches a sibling wrapper or a single-vault navigation
// decision.
func (a *App) clearLocalVaultFileSessions() {
	state := &a.localVaultFiles
	for _, slot := range state.sessionSlots {
		if slot == nil {
			continue
		}
		if slot.operation != nil {
			a.cancelLocalVaultFileSessionOperationExact(slot.operation)
		}
		// The helper also cancels this exact projection delivery and invalidates
		// fresh evidence even when there is no adopted wrapper, then installs
		// the tracked close tail before the real Close launches.
		a.detachLocalVaultFileSessionWrapper(slot)
		slot.operation = nil
		slot.retiring = true
		slot.tail = nil
		slot.parent = nil
	}
	state.sessionSlots = nil
	state.sessionParent = nil
	state.sessionGeneration = 0
	if state.viewVerification == localVaultFileViewFresh {
		state.viewVerification = localVaultFileViewCached
	}
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
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" ||
		scope.configPath == "" || scope.vaultID == "" || scope.backendRoot == "" ||
		scope.journalPath == "" {
		return nil
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != scope.backendRoot {
		return nil
	}
	state := &a.localVaultFiles
	// Capture every unsettled same-parent/same-journal predecessor before any
	// cancellation or replacement. Full scope equality is deliberately not the
	// ordering key: read-aliased config paths can share one journal.
	predecessors := a.collectLocalVaultFileSessionPredecessors(scope)
	slot := state.sessionSlots[scope]
	// A retiring or expired entry remains discoverable while its physical
	// close is unfinished. Capture that exact tail before the map entry is
	// replaced; the new current slot inherits it so a later retire or parent
	// clear joins the already-launched Close.
	var inheritTail *localVaultFileCloseTail
	if slot != nil && slot.retiring {
		// The retiring entry keeps its tail and ordering operations for
		// collection; the new current slot is a distinct pointer so its async
		// purge cannot delete it.
		inheritTail = slot.closeTail
		slot = nil
	}
	if slot != nil && (slot.parent != a.session || slot.appGeneration != a.generation) {
		a.retireLocalVaultFileSessionSlot(slot)
		inheritTail = slot.closeTail
		slot = nil
	}
	// Conflicting pending predecessors are cancelled exactly. A held old
	// dispatch is bypassed by reclaiming its pending handoff here rather than
	// making the successor depend on that dispatch.
	for _, pred := range predecessors {
		a.cancelLocalVaultFileSessionOperationExact(pred)
	}
	if slot == nil {
		if inheritTail == nil {
			if existing := state.sessionSlots[scope]; existing != nil {
				inheritTail = existing.closeTail
			}
		}
		slot = &localVaultFileSessionSlot{
			scope: scope, parent: a.session, appGeneration: a.generation,
			closeTail: inheritTail,
		}
		if state.sessionSlots == nil {
			state.sessionSlots = make(map[localVaultFileSessionScope]*localVaultFileSessionSlot)
		}
		state.sessionSlots[scope] = slot
	} else {
		// Reusing a live slot replaces its wrapper through the one tracked
		// detach helper, which cancels this exact projection delivery before
		// installing the new close tail and launching the real Close.
		a.detachLocalVaultFileSessionWrapper(slot)
		slot.tail = nil
	}
	slot.sequence++
	ctx, cancel := context.WithCancel(context.Background())
	op := &localVaultFileSessionOperation{
		slot:       slot,
		parent:     slot.parent,
		generation: slot.appGeneration,
		sequence:   slot.sequence,
		scope:      scope,
		parentPath: personalPath,
		ctx:        ctx,
		cancel:     cancel,
		waitFor:    predecessors,
		settledCh:  make(chan struct{}),
	}
	slot.operation = op
	return op
}

// launchLocalVaultFileSessionOperation starts the generic candidate-open worker
// for an already reserved operation with an already parsed key. The dispatcher
// and test hook are captured on the UI path, so the worker never reads mutable
// App state.
func (a *App) launchLocalVaultFileSessionOperation(op *localVaultFileSessionOperation, password, key []byte) {
	a.launchLocalVaultFileSessionOperationWithFactors(op, password, key, nil)
}

// launchLocalVaultFileSessionUnlockOperation starts the same candidate-open
// worker for the explicit local-vault unlock dialog. The Secret Key arrives as
// short-lived text; it is parsed inside this one worker, after predecessor
// ordering and cancellation checks, so no decoded key or factor is stored in
// the operation, slot or dialog state.
func (a *App) launchLocalVaultFileSessionUnlockOperation(op *localVaultFileSessionOperation, password, secret []byte) {
	a.launchLocalVaultFileSessionOperationWithFactors(op, password, nil, secret)
}

func (a *App) launchLocalVaultFileSessionOperationWithFactors(op *localVaultFileSessionOperation, password, key, secret []byte) {
	if op == nil {
		return
	}
	ownedPassword := append([]byte(nil), password...)
	ownedKey := append([]byte(nil), key...)
	ownedSecret := append([]byte(nil), secret...)
	dispatch := a.dispatch
	hook := a.localVaultFiles.sessionCandidateForTest
	openPause := a.localVaultFiles.sessionCandidateOpenPauseForTest
	closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
	predecessorWait := a.localVaultFiles.sessionPredecessorWaitForTest
	postBarrierCancelPause := a.localVaultFiles.sessionPostBarrierCancelPauseForTest
	a.launch(func() {
		defer clear(ownedPassword)
		defer clear(ownedKey)
		defer clear(ownedSecret)
		clearFactors := func() {
			clear(ownedPassword)
			clear(ownedKey)
			clear(ownedSecret)
		}
		if len(op.waitFor) != 0 {
			if predecessorWait != nil {
				predecessorWait()
			}
			waitLocalVaultFileSessionPredecessors(op, op.ctx, clearFactors)
		}
		if op.ctx.Err() != nil {
			// No factory ran, so no candidate can exist. The barrier is already
			// resolved; clear every worker-owned factor copy and only then
			// report processing finished.
			clearFactors()
			if len(op.waitFor) != 0 && postBarrierCancelPause != nil {
				postBarrierCancelPause()
			}
			op.markProcessingFinished()
			return
		}
		if openPause != nil {
			openPause()
		}
		if ownedSecret != nil {
			parsed, err := personal.ParseSecret(string(ownedSecret))
			clear(ownedSecret)
			if err != nil {
				// A malformed Secret Key is a fixed no-candidate failure. It
				// never reaches the factory and no key is retained.
				clearFactors()
				a.stageAndDispatchLocalVaultFileSessionResult(op,
					localVaultFileSessionResult{outcome: localVaultFileSessionOutcomeFailed},
					dispatch, hook, closePause)
				return
			}
			clear(ownedKey)
			ownedKey = parsed
		}
		candidate, summary, err := a.openLocalVaultFileSessionCandidate(op, ownedPassword, ownedKey)
		outcome := localVaultFileSessionOutcomeOpened
		if err != nil {
			outcome = localVaultFileSessionOutcomeFailed
		}
		result := localVaultFileSessionResult{candidate: candidate, summary: summary, outcome: outcome}
		// Every worker-owned factor copy, including a parsed key, is dead once
		// the real factory returns. Clear before staging, marking or dispatch
		// so a blocked UI path cannot delay erasure; the deferred clears remain
		// as safety.
		clearFactors()
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
	return vaultfileclient.OpenLocalGenesisSessionForJournal(op.parent, op.scope.configPath, op.scope.backendRoot, op.scope.vaultID, op.scope.journalPath, password, key)
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

// localVaultFileSessionResultIdentityValid checks the exact result, slot,
// operation, scope, sequence, parent, App generation and workspace binding of
// an otherwise valid opened candidate without requiring the cache to be Active.
// Workspace identity uses only the operation's frozen parentPath and the
// current settings path metadata; it reads no new authority and never blocks on
// the parent.
func (a *App) localVaultFileSessionResultIdentityValid(op *localVaultFileSessionOperation, result localVaultFileSessionResult) bool {
	if op == nil || result.outcome != localVaultFileSessionOutcomeOpened ||
		result.candidate == nil || op.slot == nil ||
		op.slot.operation != op || op.slot.sequence != op.sequence ||
		op.slot.scope != op.scope || op.slot.parent != op.parent ||
		op.slot.appGeneration != op.generation ||
		a.session != op.parent || a.generation != op.generation ||
		a.localVaultFiles.sessionSlots[op.scope] != op.slot ||
		result.summary.VaultID != op.scope.vaultID || op.parentPath == "" {
		return false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, op.parentPath)
	return currentRoot == op.scope.backendRoot
}

// completeLocalVaultFileSessionResult accepts a candidate only when the exact
// slot, operation, sequence, parent, App generation, workspace, ref path and
// VaultID still match. A valid opened candidate blocked only by a transient
// Busy parent becomes the private finite Withheld outcome and is still closed
// through the normal pre-adoption cleanup. Invalid, stale, failed and revoked
// results keep the existing finite failure mapping. Every candidate is closed
// exactly once and its summary dropped; the operation then ends with a finite
// outcome.
func (a *App) completeLocalVaultFileSessionResult(op *localVaultFileSessionOperation, result localVaultFileSessionResult) {
	cache := a.syncLocalVaultFileSessions()
	identityValid := a.localVaultFileSessionResultIdentityValid(op, result)
	withheld := identityValid && cache == personal.VaultFileCacheBusy
	if identityValid && cache == personal.VaultFileCacheActive {
		personalPath, finalCache := a.localVaultFileRoutingPath()
		if finalCache == personal.VaultFileCacheActive && personalPath != "" &&
			personalPath == op.parentPath {
			slot := op.slot
			// Adoption replaces the slot's exact wrapper; any borrowed
			// projection read for the prior wrapper ends with that wrapper.
			a.cancelLocalVaultFileRefreshExact(slot.refresh)
			a.invalidateLocalVaultFileRefreshFresh(slot.scope)
			if old := slot.session; old != nil && old != result.candidate {
				a.detachLocalVaultFileSessionWrapper(slot)
			}
			slot.session = result.candidate
			slot.summary = localVaultFileSessionSummaryClone(result.summary)
			// The slot now owns the capability. The operation settles only
			// after this legal transfer; a later slot close is the slot's
			// responsibility.
			op.markCandidateResolved()
			a.finishLocalVaultFileSessionOperation(op, localVaultFileSessionOutcomeOpened)
			return
		}
		withheld = finalCache == personal.VaultFileCacheBusy
	}
	clearLocalVaultFileSessionSummary(&result.summary)
	if result.candidate != nil {
		closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
		a.launch(func() { closeLocalVaultFileSessionCandidate(op, result.candidate, closePause) })
	} else {
		op.markCandidateResolved()
	}
	outcome := result.outcome
	if withheld {
		outcome = localVaultFileSessionOutcomeWithheld
	} else if outcome != localVaultFileSessionOutcomeFailed {
		outcome = localVaultFileSessionOutcomeFailed
	}
	a.finishLocalVaultFileSessionOperation(op, outcome)
}

// finishLocalVaultFileSessionOperation records the finite outcome and ends the
// pending operation only if it is still the exact current operation.
func (a *App) finishLocalVaultFileSessionOperation(op *localVaultFileSessionOperation, outcome localVaultFileSessionOutcome) {
	op.finish(outcome)
	if op.slot != nil && op.slot.operation == op {
		if !op.isSettled() {
			// A failure whose candidate cleanup is still running remains a
			// discoverable predecessor through the existing slot tail.
			op.slot.tail = appendLocalVaultFileSessionOperation(op.slot.tail, op)
		}
		if op.cancel != nil {
			op.cancel()
			op.cancel = nil
		}
		op.slot.operation = nil
	}
	// The finite outcome is now recorded and the exact slot binding has ended.
	// This is the only point that may report UI completion; it is never tied
	// to an earlier settlement or to a queued cleanup Close.
	a.notifyLocalVaultFileSessionCompletion(op)
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
// replacement so a stale callback cannot close a valid current child. A
// UI-completed finite operation is left untouched by takeCancelled. For a
// non-UI-completed operation, any ready result is returned for this existing
// outside-mu cleanup: a no-candidate projection is cleared here and an
// impossible inconsistent candidate still follows the same exact cleanup
// launch instead of being retained.
func (a *App) cancelLocalVaultFileSessionOperationExact(op *localVaultFileSessionOperation) {
	if op == nil {
		return
	}
	result, pending, active := op.takeCancelled()
	if active && op.slot != nil {
		// Keep an unsettled cancelled operation discoverable through the
		// existing slot tail even when this is a narrow cancel rather than a
		// close/retire. A later producer with the same parent and journal must
		// still join it; settled tails are skipped by collection.
		op.slot.tail = appendLocalVaultFileSessionOperation(op.slot.tail, op)
	}
	// Always release an exact stale slot binding. A settled opened outcome is
	// never changed by takeCancelled.
	a.endLocalVaultFileSessionOperation(op)
	// Cancellation is a real finite outcome once takeCancelled recorded it and
	// the exact binding ended. The pending candidate cleanup below is product
	// work and is not awaited by the UI observer.
	a.notifyLocalVaultFileSessionCompletion(op)
	if !pending {
		return
	}
	clearLocalVaultFileSessionSummary(&result.summary)
	if result.candidate != nil {
		closePause := a.localVaultFiles.sessionCandidateClosePauseForTest
		a.launch(func() { closeLocalVaultFileSessionCandidate(op, result.candidate, closePause) })
		return
	}
	if active {
		op.markCandidateResolved()
	}
}

// endLocalVaultFileSessionOperation releases the exact current slot binding for
// an operation that already recorded its outcome. It never changes the finite
// outcome, so a late cancellation cannot overwrite an operation that settled
// concurrently.
func (a *App) endLocalVaultFileSessionOperation(op *localVaultFileSessionOperation) {
	if op == nil {
		return
	}
	if op.slot != nil && op.slot.operation == op {
		if op.cancel != nil {
			op.cancel()
			op.cancel = nil
		}
		op.slot.operation = nil
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
	// Every retire/detach boundary cancels a borrowed projection read, even
	// when the slot has no generic candidate operation.
	a.cancelLocalVaultFileRefreshExact(slot.refresh)
	a.invalidateLocalVaultFileRefreshFresh(slot.scope)
	if slot.retiring {
		return
	}
	state := &a.localVaultFiles
	if op := slot.operation; op != nil {
		slot.tail = appendLocalVaultFileSessionOperation(slot.tail, op)
		a.cancelLocalVaultFileSessionOperationExact(op)
		slot.operation = nil
	}
	// Detach the exact adopted wrapper through the tracked-close helper before
	// marking the entry retired. The new tail is installed before the real
	// Close launches, and the helper clears the visible summary immediately.
	a.detachLocalVaultFileSessionWrapper(slot)
	// Keep parent, scope, closeTail and appGeneration so a same-parent/new-slot
	// reopen can inherit this ordering and physical-close tail. The entry is
	// never cache-readable.
	slot.retiring = true
	if state.sessionSlots[slot.scope] != slot {
		return
	}
	a.scheduleLocalVaultFileSessionTailPurge(slot)
}

func appendLocalVaultFileSessionOperation(list []*localVaultFileSessionOperation, op *localVaultFileSessionOperation) []*localVaultFileSessionOperation {
	if op == nil {
		return list
	}
	for _, existing := range list {
		if existing == op {
			return list
		}
	}
	return append(list, op)
}

// scheduleLocalVaultFileSessionTailPurge marks a retiring entry ready only
// after every tail operation settles and the latest tracked adopted-wrapper
// Close chain publishes its finite result. The readiness goroutine never
// touches the App map; the next UI sync rechecks the exact current map entry,
// its latest closeTail and its operations before deleting. This keeps a
// no-cache tombstone available for inheritance across close/reopen and App
// generation changes without a second registry or an off-UI map mutation.
func (a *App) scheduleLocalVaultFileSessionTailPurge(slot *localVaultFileSessionSlot) {
	if slot == nil {
		return
	}
	if slot.purgeReady == nil {
		slot.purgeReady = make(chan struct{})
	}
	tail := append([]*localVaultFileSessionOperation(nil), slot.tail...)
	closeTail := slot.closeTail
	allSettled := localVaultFileCloseTailFinished(closeTail)
	if allSettled {
		for _, op := range tail {
			if !op.isSettled() {
				allSettled = false
				break
			}
		}
	}
	if allSettled {
		close(slot.purgeReady)
		return
	}
	ready := slot.purgeReady
	go func() {
		for _, op := range tail {
			<-op.settledSignal()
		}
		if closeTail != nil {
			<-closeTail.done
		}
		close(ready)
	}()
}

// purgeSettledLocalVaultFileSessionTails runs on the UI path. It deletes only
// the exact retiring slot pointer currently in the map with a ready, fully
// settled operation tail and a finished latest closeTail. The latest tail is
// rechecked here rather than trusting an older readiness snapshot, and a later
// slot that inherited the scope is never deleted.
func (a *App) purgeSettledLocalVaultFileSessionTails() {
	state := &a.localVaultFiles
	for scope, slot := range state.sessionSlots {
		if slot == nil || !slot.retiring || slot.purgeReady == nil {
			continue
		}
		select {
		case <-slot.purgeReady:
		default:
			continue
		}
		if state.sessionSlots[scope] != slot {
			continue
		}
		allSettled := true
		for _, op := range slot.tail {
			if !op.isSettled() {
				allSettled = false
				break
			}
		}
		if allSettled && localVaultFileCloseTailFinished(slot.closeTail) {
			delete(state.sessionSlots, scope)
		}
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
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	routingPath := personalPath
	slot := a.localVaultFiles.sessionSlots[scope]
	if slot == nil || slot.retiring || slot.session == nil || slot.parent != a.session ||
		slot.appGeneration != a.generation {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if currentRoot != scope.backendRoot {
		return vaultfileclient.LocalGenesisBaseline{}, false
	}
	summary := localVaultFileSessionSummaryClone(slot.summary)
	personalPath, cache = a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" ||
		personalPath != routingPath ||
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
