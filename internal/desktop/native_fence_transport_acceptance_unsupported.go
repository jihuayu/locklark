//go:build locklark_native_acceptance && !darwin && !linux

package desktop

import "context"

// nativeFenceTransport on unsupported tagged platforms is safely unavailable.
// It parses no environment, inspects no descriptor and starts no goroutine.
type nativeFenceTransport struct{}

func newNativeFenceTransport(controlInFD, eventOutFD int) *nativeFenceTransport {
	return &nativeFenceTransport{}
}

func (t *nativeFenceTransport) claim(attemptID uint64, childCount int) nativeFenceClaimResult {
	return nativeFenceClaimResult{
		state:  nativeFenceClaimInvalid,
		reason: nativeFenceReasonUnavailable,
	}
}

func (t *nativeFenceTransport) hold(ctx context.Context) nativeFenceHoldResult {
	return nativeFenceHoldResult{
		verdict: nativeFenceVerdictInvalid,
		reason:  nativeFenceReasonUnavailable,
	}
}

func (t *nativeFenceTransport) publishDrained(attemptID uint64, closedCount int, parentLocked bool) nativeFenceNotifyResult {
	return nativeFenceNotifyResult{
		status: nativeFenceNotifyRejected,
		reason: nativeFenceReasonUnavailable,
	}
}

func (t *nativeFenceTransport) publishAdopted(attemptID uint64, childCount int) nativeFenceNotifyResult {
	return nativeFenceNotifyResult{
		status: nativeFenceNotifyRejected,
		reason: nativeFenceReasonUnavailable,
	}
}

func (t *nativeFenceTransport) close() {}
