//go:build !locklark_native_acceptance

package desktop

import (
	"context"
	"testing"
)

func TestNativeInitialUnlockFenceDefaultNoOp(t *testing.T) {
	t.Setenv("LOCKLARK_NATIVE_FENCE_CONTROL_FD", "not-a-descriptor")
	t.Setenv("LOCKLARK_NATIVE_FENCE_EVENT_FD", "also-not-a-descriptor")

	initial := &initialAccountUnlockOutcome{
		metadata: initialAccountUnlockMetadata{valid: true, uniqueChildren: 2},
	}
	apply := func() {}
	drop := func() {}
	r := outcome{apply: apply, drop: drop, initialAccount: initial}

	nativeInitialUnlockFenceAfterWork(context.Background(),
		true, accountUnlockAttempt{generation: 1, operation: 2, sequence: 3}, &r)
	if r.apply == nil || r.drop == nil || r.err != nil || r.initialAccount != initial {
		t.Fatal("NATIVE_INITIAL_FENCE_DEFAULT_HOOK_MUTATED")
	}
	if transport := nativeInitialUnlockFenceForBuild(); transport != nil {
		t.Fatal("NATIVE_INITIAL_FENCE_DEFAULT_FACTORY_READ_ENV")
	}
}
