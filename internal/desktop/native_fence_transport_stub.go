//go:build !locklark_native_acceptance

package desktop

import "context"

// nativeFenceTransport is intentionally inert in ordinary builds. It inspects
// no descriptor, opens no endpoint, starts no goroutine and changes no timing.
type nativeFenceTransport struct{}

func newNativeFenceTransport(controlInFD, eventOutFD int) *nativeFenceTransport {
	return &nativeFenceTransport{}
}

func (t *nativeFenceTransport) claim(attemptID uint64, childCount int) nativeFenceClaimResult {
	return nativeFenceClaimResult{
		state:  nativeFenceClaimDisabled,
		reason: nativeFenceReasonDisabled,
	}
}

func (t *nativeFenceTransport) hold(ctx context.Context) nativeFenceHoldResult {
	return nativeFenceHoldResult{
		verdict: nativeFenceVerdictDisabled,
		reason:  nativeFenceReasonDisabled,
	}
}

func (t *nativeFenceTransport) publishDrained(attemptID uint64, closedCount int, parentLocked bool) nativeFenceNotifyResult {
	return nativeFenceNotifyResult{
		status: nativeFenceNotifyRejected,
		reason: nativeFenceReasonDisabled,
	}
}

func (t *nativeFenceTransport) publishAdopted(attemptID uint64, childCount int) nativeFenceNotifyResult {
	return nativeFenceNotifyResult{
		status: nativeFenceNotifyRejected,
		reason: nativeFenceReasonDisabled,
	}
}

func (t *nativeFenceTransport) close() {}
