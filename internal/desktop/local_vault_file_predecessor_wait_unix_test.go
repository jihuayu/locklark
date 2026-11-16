//go:build darwin || linux

package desktop

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalVaultSessionPredecessorWaitObservesEitherContext(t *testing.T) {
	cases := []struct {
		name        string
		cancelOuter bool
	}{
		{name: "OWN_CONTEXT"},
		{name: "OUTER_CONTEXT", cancelOuter: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer, outerCancel := context.WithCancel(context.Background())
			defer outerCancel()
			own, ownCancel := context.WithCancel(context.Background())
			defer ownCancel()

			pred := &localVaultFileSessionOperation{settledCh: make(chan struct{})}
			op := &localVaultFileSessionOperation{
				ctx:     own,
				waitFor: []*localVaultFileSessionOperation{pred},
			}
			var clears atomic.Int32
			cleared := make(chan struct{}, 1)
			done := make(chan struct{})
			go func() {
				waitLocalVaultFileSessionPredecessors(op, outer, func() {
					clears.Add(1)
					select {
					case cleared <- struct{}{}:
					default:
					}
				})
				close(done)
			}()

			if tc.cancelOuter {
				outerCancel()
			} else {
				ownCancel()
			}
			select {
			case <-cleared:
			case <-time.After(5 * time.Second):
				t.Fatal("LOCAL_WAIT_CANCEL_CALLBACK_MISSING")
			}
			// The callback fires before predecessor completion, but the waiter
			// must not return or settle early.
			select {
			case <-done:
				t.Fatal("LOCAL_WAIT_RETURNED_BEFORE_PREDECESSOR")
			default:
			}

			close(pred.settledCh)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("LOCAL_WAIT_STUCK_AFTER_PREDECESSOR")
			}
			if got := clears.Load(); got != 1 {
				t.Fatalf("LOCAL_WAIT_CANCEL_CALLBACK_COUNT=%d", got)
			}
			if tc.cancelOuter {
				if own.Err() != nil {
					t.Fatal("LOCAL_WAIT_WRONG_CONTEXT_CANCELLED")
				}
			} else if outer.Err() != nil {
				t.Fatal("LOCAL_WAIT_WRONG_CONTEXT_CANCELLED")
			}
		})
	}
}
