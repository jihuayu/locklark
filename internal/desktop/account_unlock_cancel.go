package desktop

// accountUnlockAttempt is finite identity only: no factor, material, parent,
// wrapper, token or capability. The sequence distinguishes retries that share
// an App generation and operation counter.
type accountUnlockAttempt struct {
	generation uint64
	operation  uint64
	sequence   uint64
}

func (a *App) beginAccountUnlock(generation, operation uint64) accountUnlockAttempt {
	a.accountUnlockSequence++
	attempt := accountUnlockAttempt{
		generation: generation,
		operation:  operation,
		sequence:   a.accountUnlockSequence,
	}
	a.accountUnlock = &attempt
	return attempt
}

func (a *App) retireAccountUnlock(attempt accountUnlockAttempt) {
	if a.accountUnlock != nil && *a.accountUnlock == attempt {
		a.accountUnlock = nil
	}
}

// accountUnlockCancelToken returns an immutable token only for the exact
// current explicit account unlock. A stale rendered button cannot cancel a
// later attempt, a completed session, or an unrelated operation.
func (a *App) accountUnlockCancelToken() (accountUnlockAttempt, bool) {
	if a.accountUnlock == nil || a.session != nil || !a.busy {
		return accountUnlockAttempt{}, false
	}
	attempt := *a.accountUnlock
	if a.generation != attempt.generation || a.operationSequence != attempt.operation {
		return accountUnlockAttempt{}, false
	}
	return attempt, true
}

// cancelAccountUnlock invokes the established Lock cancellation/revocation
// path on the UI thread. The captured token must match the current attempt.
func (a *App) cancelAccountUnlock(attempt accountUnlockAttempt) {
	if a.accountUnlock == nil || *a.accountUnlock != attempt ||
		a.session != nil || !a.busy ||
		a.generation != attempt.generation ||
		a.operationSequence != attempt.operation {
		return
	}
	a.Lock()
}
