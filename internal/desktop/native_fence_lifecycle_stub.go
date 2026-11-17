//go:build !locklark_native_acceptance

package desktop

import "context"

// nativeInitialUnlockFenceLifecycle is empty in ordinary builds. The actual
// adoption signal is a no-op and the worker hook performs no environment,
// descriptor, I/O, channel, goroutine or wait work.
type nativeInitialUnlockFenceLifecycle struct{}

func (l *nativeInitialUnlockFenceLifecycle) signalAdopted() {}

func nativeInitialUnlockFenceAfterWork(ctx context.Context, accountUnlock bool, attempt accountUnlockAttempt, r *outcome) {
}
