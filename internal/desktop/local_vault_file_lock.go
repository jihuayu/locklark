package desktop

import (
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
)

// localVaultFileLockOutcome is the finite result of one explicit lock
// operation. Unknown is never published: only the worker that observed all
// captured producer settlements and tracked Close completions may record
// Succeeded or Failed.
type localVaultFileLockOutcome uint8

const (
	localVaultFileLockOutcomeUnknown localVaultFileLockOutcome = iota
	localVaultFileLockOutcomeSucceeded
	localVaultFileLockOutcomeFailed
)

// localVaultFileLockOperation is the existing-slot explicit-lock marker and
// finite completion record. It freezes the parent, journal scheduling key,
// request scope, anchor, App generation and sequence. The worker holds only
// local snapshots of producers and close tails; this operation never retains a
// wrapper, factor, key, kit, identity, token, database or raw error.
type localVaultFileLockOperation struct {
	parent      *personal.Session
	generation  uint64
	sequence    uint64
	scope       localVaultFileSessionScope
	journalPath string
	anchor      *localVaultFileSessionSlot
	prepared    bool

	mu      sync.Mutex
	done    bool
	outcome localVaultFileLockOutcome
	doneCh  chan struct{}
}

func (op *localVaultFileLockOperation) finish(outcome localVaultFileLockOutcome) {
	if op == nil {
		return
	}
	if outcome == localVaultFileLockOutcomeUnknown {
		outcome = localVaultFileLockOutcomeFailed
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.done {
		return
	}
	op.done = true
	op.outcome = outcome
	close(op.doneCh)
}

func (op *localVaultFileLockOperation) finiteOutcome() (localVaultFileLockOutcome, bool) {
	if op == nil {
		return localVaultFileLockOutcomeUnknown, false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.done {
		return localVaultFileLockOutcomeUnknown, false
	}
	return op.outcome, true
}

func (op *localVaultFileLockOperation) isDone() bool {
	_, done := op.finiteOutcome()
	return done
}

func (op *localVaultFileLockOperation) doneSignal() <-chan struct{} {
	if op == nil {
		return nil
	}
	return op.doneCh
}

func (a *App) localVaultFileLockMatchingSlots(parent *personal.Session, journalPath string) []*localVaultFileSessionSlot {
	if parent == nil || journalPath == "" {
		return nil
	}
	var slots []*localVaultFileSessionSlot
	for _, slot := range a.localVaultFiles.sessionSlots {
		if slot != nil && slot.parent == parent && slot.scope.journalPath == journalPath {
			slots = append(slots, slot)
		}
	}
	return slots
}

func (a *App) localVaultFileLockExisting(scope localVaultFileSessionScope) *localVaultFileLockOperation {
	var completed *localVaultFileLockOperation
	for _, slot := range a.localVaultFileLockMatchingSlots(a.session, scope.journalPath) {
		op := slot.lock
		if op == nil {
			continue
		}
		if !op.isDone() {
			return op
		}
		if completed == nil && op.parent == a.session && op.generation == a.generation {
			completed = op
		}
	}
	return completed
}

// localVaultFileLockBlocks is the shared reserve barrier. It checks every
// same-parent/exact-journal slot, including aliases and retiring anchors, and
// blocks only while the marker's physical work is unfinished.
func (a *App) localVaultFileLockBlocks(scope localVaultFileSessionScope) bool {
	for _, slot := range a.localVaultFileLockMatchingSlots(a.session, scope.journalPath) {
		if slot.lock != nil && !slot.lock.isDone() {
			return true
		}
	}
	return false
}

// clearCompletedLocalVaultFileLocks consumes completed markers at the next
// real open boundary. Unfinished markers are never cleared here.
func (a *App) clearCompletedLocalVaultFileLocks(scope localVaultFileSessionScope) {
	for _, slot := range a.localVaultFileLockMatchingSlots(a.session, scope.journalPath) {
		if slot.lock != nil && slot.lock.isDone() {
			slot.lock = nil
		}
	}
}

// localVaultFileLockResult is the finite getter for the existing UI binding.
// It performs no wait. A completed marker is durable for the current anchor
// until the next open boundary; an unfinished marker reports false.
func (a *App) localVaultFileLockResult(scope localVaultFileSessionScope) (localVaultFileLockOutcome, bool) {
	a.syncLocalVaultFileSessions()
	if a.session == nil {
		return localVaultFileLockOutcomeUnknown, false
	}
	if slot := a.localVaultFiles.sessionSlots[scope]; slot != nil {
		if slot.parent == a.session && slot.appGeneration == a.generation &&
			slot.scope == scope && slot.lock != nil &&
			slot.lock.parent == a.session && slot.lock.generation == a.generation &&
			slot.lock.sequence != 0 && slot.lock.journalPath == scope.journalPath {
			return slot.lock.finiteOutcome()
		}
		return localVaultFileLockOutcomeUnknown, false
	}
	for _, slot := range a.localVaultFileLockMatchingSlots(a.session, scope.journalPath) {
		if slot.appGeneration == a.generation && slot.scope.backendRoot == scope.backendRoot &&
			slot.lock != nil && slot.lock.parent == a.session &&
			slot.lock.generation == a.generation && slot.lock.sequence != 0 {
			return slot.lock.finiteOutcome()
		}
	}
	return localVaultFileLockOutcomeUnknown, false
}

// beginLocalVaultFileLock freezes one explicit lock operation on the existing
// slot registry, marks every matching same-parent/exact-journal slot before any
// cancellation or detach, cancels each exact matching producer, detaches each
// adopted wrapper through the tracked helper, and launches one worker that owns
// only local producer/tail snapshots. It performs no VaultPath, parent-mutex,
// IO, dispatch or synchronous wait on the UI path.
func (a *App) beginLocalVaultFileLock(scope localVaultFileSessionScope) *localVaultFileLockOperation {
	if a.session == nil || !a.session.Unlocked() ||
		scope.configPath == "" || scope.vaultID == "" ||
		scope.backendRoot == "" || scope.journalPath == "" {
		return nil
	}
	a.syncLocalVaultFileSessions()
	if a.session == nil || !a.session.Unlocked() {
		return nil
	}
	state := &a.localVaultFiles
	op := a.localVaultFileLockExisting(scope)
	if op == nil {
		state.lockSequence++
		op = &localVaultFileLockOperation{
			parent:      a.session,
			generation:  a.generation,
			sequence:    state.lockSequence,
			scope:       scope,
			journalPath: scope.journalPath,
			doneCh:      make(chan struct{}),
		}
	}

	// The request scope is always the retained no-cache anchor. Existing
	// matching aliases are marked with the same pointer before any cancellation
	// or wrapper detach.
	anchor := state.sessionSlots[scope]
	if anchor == nil {
		anchor = &localVaultFileSessionSlot{
			scope: scope, parent: a.session, appGeneration: a.generation,
			retiring: true,
		}
		if state.sessionSlots == nil {
			state.sessionSlots = make(map[localVaultFileSessionScope]*localVaultFileSessionSlot)
		}
		state.sessionSlots[scope] = anchor
		a.scheduleLocalVaultFileSessionTailPurge(anchor)
	}
	if op.anchor == nil {
		op.anchor = anchor
	}
	slots := a.localVaultFileLockMatchingSlots(a.session, scope.journalPath)
	anchorFound := false
	for _, slot := range slots {
		if slot == anchor {
			anchorFound = true
			break
		}
	}
	if !anchorFound {
		slots = append(slots, anchor)
	}
	for _, slot := range slots {
		slot.lock = op
	}
	if op.prepared {
		return op
	}
	op.prepared = true

	// Collect exact producers before cancellation. Settlement already includes
	// any pre-adoption candidate actual Close, so the worker never closes or
	// counts those candidates again.
	producers := a.collectLocalVaultFileSessionPredecessors(scope)
	for _, producer := range producers {
		a.cancelLocalVaultFileSessionOperationExact(producer)
	}

	selected := a.localVaultFiles.selected
	for _, slot := range slots {
		wasRetiring := slot.retiring
		a.detachLocalVaultFileSessionWrapper(slot)
		if selected != "" && slot.scope.configPath == selected {
			a.localVaultFiles.items = nil
		}
		slot.retiring = true
		if !wasRetiring || slot.purgeReady == nil {
			a.scheduleLocalVaultFileSessionTailPurge(slot)
		}
	}
	if selected != "" {
		if selected == scope.configPath {
			a.localVaultFiles.items = nil
		} else {
			for _, ref := range a.localVaultFiles.refs {
				if ref.path == selected && ref.journalPath == scope.journalPath {
					a.localVaultFiles.items = nil
					break
				}
			}
		}
	}

	// Capture only the latest tail per matching slot. A latest tail already
	// joins its previous actual Close completion, so no long chain is retained.
	tails := make([]*localVaultFileCloseTail, 0, len(slots))
	seenTails := make(map[*localVaultFileCloseTail]struct{})
	for _, slot := range slots {
		if slot.closeTail == nil {
			continue
		}
		if _, ok := seenTails[slot.closeTail]; ok {
			continue
		}
		seenTails[slot.closeTail] = struct{}{}
		tails = append(tails, slot.closeTail)
	}

	producersLocal := append([]*localVaultFileSessionOperation(nil), producers...)
	tailsLocal := append([]*localVaultFileCloseTail(nil), tails...)
	a.launch(func() {
		for _, producer := range producersLocal {
			<-producer.settledSignal()
		}
		outcome := localVaultFileLockOutcomeSucceeded
		for _, tail := range tailsLocal {
			<-tail.done
			if tail.result != localVaultFileCloseResultSucceeded {
				outcome = localVaultFileLockOutcomeFailed
			}
		}
		op.finish(outcome)
	})
	return op
}
