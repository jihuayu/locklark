//go:build windows

package browserhost

import (
	"context"
	"testing"
	"time"
)

// The real named pipe end-to-end path is covered through the desktop broker
// tests. This unit regression pins the two properties they do not state:
// the Windows ordering constant is the read-before-auth mode, and the least
// privileged dial budget keeps a 300ms cap while inheriting shorter and
// canceled caller contexts.
func TestWindowsBrokerHandshakeOrderingAndDialBudget(t *testing.T) {
	if !peerBeforeHello {
		t.Fatal("peerBeforeHello must select Windows read-before-auth mode")
	}

	start := time.Now()
	ctx, cancel := dialBudget(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Sub(start) > 300*time.Millisecond {
		t.Fatalf("default dial budget: %v", deadline)
	}

	shorter := time.Now().Add(20 * time.Millisecond)
	caller, cancelCaller := context.WithDeadline(context.Background(), shorter)
	defer cancelCaller()
	inherited, cancelInherited := dialBudget(caller)
	defer cancelInherited()
	if got, ok := inherited.Deadline(); !ok || !got.Equal(shorter) {
		t.Fatalf("inherited dial deadline: %v, want %v", got, shorter)
	}

	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	budgeted, cancelBudgeted := dialBudget(canceled)
	defer cancelBudgeted()
	if budgeted.Err() == nil {
		t.Fatal("dial budget ignored a canceled caller context")
	}

	if _, e := dialLocal(context.Background(), `\\.\pipe\Locklark-Browser-missing-test-pipe`); e != ErrBrokerUnavailable {
		t.Fatalf("missing pipe: %v", e)
	}
}
