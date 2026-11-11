//go:build windows

package browserhost

import (
	"context"
	"testing"
	"time"
)

// The real named pipe end-to-end path is covered through the desktop broker
// tests. This unit regression pins the two properties they do not state:
// the Windows ordering constant selects read-before-auth, and the least
// privileged dial budget keeps a 300ms cap while inheriting shorter and
// canceled caller contexts.
func TestWindowsBrokerHandshakeOrderingAndDialBudget(t *testing.T) {
	if !peerAfterHello {
		t.Fatal("peerAfterHello must select Windows read-before-auth mode")
	}

	// dialBudget adds its 300ms inside the call, so bound the deadline by the
	// call interval instead of a single start timestamp.
	before := time.Now()
	ctx, cancel := dialBudget(context.Background())
	after := time.Now()
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(before.Add(300*time.Millisecond)) || deadline.After(after.Add(300*time.Millisecond)) {
		t.Fatalf("default dial budget: %v, want within [%v, %v]", deadline, before.Add(300*time.Millisecond), after.Add(300*time.Millisecond))
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
