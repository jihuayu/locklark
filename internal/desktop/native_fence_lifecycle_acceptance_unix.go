//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errNativeInitialUnlockFence = errors.New("native initial account unlock fence aborted")

const nativeInitialUnlockFenceObserverLifetime = nativeFenceProductionWait + nativeFenceProductionTerm

type nativeInitialAdoptedSignal struct {
	attemptID  uint64
	childCount int
}

// nativeInitialUnlockFenceLifecycle is the private owner-side handoff to the
// UI adoption action. It carries only a finite attempt id/count and a buffered
// one-shot signal; it never carries a batch, session, wrapper or App.
type nativeInitialUnlockFenceLifecycle struct {
	mu sync.Mutex

	adopted    chan nativeInitialAdoptedSignal
	attemptID  uint64
	childCount int
}

func (l *nativeInitialUnlockFenceLifecycle) installAdopted(attemptID uint64, childCount int) <-chan nativeInitialAdoptedSignal {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.adopted == nil {
		l.adopted = make(chan nativeInitialAdoptedSignal, 1)
	}
	l.attemptID = attemptID
	l.childCount = childCount
	return l.adopted
}

// signalAdopted is called only after the original generation/path/settings/
// slot/cache gates pass and the real parent/session/slots are installed. It is
// a nonblocking finite notification, never protocol I/O or SDK cleanup.
func (l *nativeInitialUnlockFenceLifecycle) signalAdopted() {
	l.mu.Lock()
	adopted := l.adopted
	attemptID := l.attemptID
	childCount := l.childCount
	l.mu.Unlock()
	if adopted == nil {
		return
	}
	select {
	case adopted <- nativeInitialAdoptedSignal{attemptID: attemptID, childCount: childCount}:
	default:
	}
}

func nativeInitialUnlockFenceAttemptID(attempt accountUnlockAttempt) uint64 {
	id := attempt.generation
	id ^= attempt.operation + 0x9e3779b97f4a7c15 + (id << 6) + (id >> 2)
	id ^= attempt.sequence + 0x9e3779b97f4a7c15 + (id << 6) + (id >> 2)
	if id == 0 {
		return 1
	}
	return id
}

// nativeInitialUnlockFenceAfterWork runs in the worker after work(ctx) returns
// and before the original generic cancel/UI dispatch. Only a valid typed real
// initial-account outcome with an owned batch is eligible.
func nativeInitialUnlockFenceAfterWork(ctx context.Context, accountUnlock bool, attempt accountUnlockAttempt, r *outcome) {
	if !accountUnlock || r == nil || r.err != nil || r.initialAccount == nil ||
		r.initialAccount.batch == nil || r.apply == nil {
		return
	}
	initial := r.initialAccount
	metadata := initial.finiteMetadata()
	if !metadata.valid || metadata.uniqueChildren < 0 || metadata.uniqueChildren > nativeFenceMaxChildren {
		return
	}
	transport := nativeInitialUnlockFenceForBuild()
	if transport == nil {
		return
	}
	attemptID := nativeInitialUnlockFenceAttemptID(attempt)
	claim := transport.claim(attemptID, metadata.uniqueChildren)
	switch claim.state {
	case nativeFenceClaimBound:
	case nativeFenceClaimAlreadyBound, nativeFenceClaimDisabled:
		return
	default:
		transport.close()
		nativeInitialUnlockFenceAbortOwned(initial.batch, r)
		return
	}
	nativeInitialUnlockFenceOwn(ctx, transport, attemptID, initial, r, nativeInitialUnlockFenceObserverLifetime)
}

// nativeInitialUnlockFenceOwn is the private owner phase. It may receive the
// batch through initial, but it hands the observer only finite channels,
// transport, finite attempt/count and a bounded lifetime.
func nativeInitialUnlockFenceOwn(ctx context.Context, transport *nativeFenceTransport, attemptID uint64,
	initial *initialAccountUnlockOutcome, r *outcome, lifetime time.Duration) {
	if transport == nil || initial == nil || initial.batch == nil || !initial.metadata.valid ||
		initial.metadata.uniqueChildren < 0 || initial.metadata.uniqueChildren > nativeFenceMaxChildren {
		if transport != nil {
			transport.close()
		}
		if initial != nil && initial.batch != nil {
			nativeInitialUnlockFenceAbortOwned(initial.batch, r)
		} else {
			nativeInitialUnlockFenceDiscard(r)
		}
		return
	}
	batch := initial.batch
	childCount := initial.metadata.uniqueChildren
	notice, ok := batch.drainNotice()
	if !ok {
		transport.close()
		nativeInitialUnlockFenceAbortOwned(batch, r)
		return
	}
	adopted := initial.fence.installAdopted(attemptID, childCount)
	held := transport.hold(ctx)
	if held.verdict == nativeFenceVerdictReleased {
		go nativeInitialUnlockFenceObserve(transport, attemptID, childCount, notice, adopted, lifetime)
		return
	}
	batch.drop(nil)
	nativeInitialUnlockFenceDiscard(r)
	go nativeInitialUnlockFenceObserve(transport, attemptID, childCount, notice, nil, lifetime)
}

func nativeInitialUnlockFenceAbortOwned(batch *localVaultFileInitialBatch, r *outcome) {
	if batch != nil {
		batch.drop(nil)
	}
	nativeInitialUnlockFenceDiscard(r)
}

func nativeInitialUnlockFenceDiscard(r *outcome) {
	if r == nil {
		return
	}
	r.apply = nil
	r.drop = nil
	r.initialAccount = nil
	r.err = errNativeInitialUnlockFence
}

// nativeInitialUnlockFenceObserve is a free observer. It receives no owner,
// App, session, wrapper, token, rows, identity, outcome or resource closure.
func nativeInitialUnlockFenceObserve(transport *nativeFenceTransport, attemptID uint64, childCount int,
	drain <-chan localVaultFileInitialDrainSummary, adopted <-chan nativeInitialAdoptedSignal, lifetime time.Duration) {
	if transport == nil {
		return
	}
	defer transport.close()
	if lifetime <= 0 {
		lifetime = nativeInitialUnlockFenceObserverLifetime
	}
	timer := time.NewTimer(lifetime)
	defer timer.Stop()
	for {
		select {
		case summary, ok := <-drain:
			if !ok {
				drain = nil
				if adopted == nil {
					return
				}
				continue
			}
			if summary.state != localVaultFileInitialDrainComplete ||
				summary.closedWrappers != childCount ||
				!summary.parentLocked || !summary.refsCleared || !summary.rowsCleared {
				return
			}
			result := transport.publishDrained(attemptID, summary.closedWrappers, summary.parentLocked)
			if result.status != nativeFenceNotifyDone && result.status != nativeFenceNotifyTransportFailed {
				return
			}
			return
		case signal, ok := <-adopted:
			if !ok {
				adopted = nil
				if drain == nil {
					return
				}
				continue
			}
			if signal.attemptID != attemptID || signal.childCount != childCount {
				continue
			}
			result := transport.publishAdopted(attemptID, signal.childCount)
			if result.status != nativeFenceNotifyDone && result.status != nativeFenceNotifyTransportFailed {
				return
			}
			return
		case <-timer.C:
			return
		}
	}
}
