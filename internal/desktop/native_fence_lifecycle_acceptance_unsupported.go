//go:build locklark_native_acceptance && !darwin && !linux

package desktop

import "context"

// nativeInitialUnlockFenceLifecycle is unavailable on unsupported tagged
// platforms. The hook is a safe no-op and the adoption signal does nothing.
type nativeInitialUnlockFenceLifecycle struct{}

func (l *nativeInitialUnlockFenceLifecycle) signalAdopted() {}

func nativeInitialUnlockFenceAfterWork(ctx context.Context, accountUnlock bool, attempt accountUnlockAttempt, r *outcome) {
}
