package nativeclipboard

import (
	"context"
	"testing"
	"time"
)

// The contextual writer receives the exact offer deadline and a non-blocking
// liveness check; the Manager still owns the cancellation/write decision.
func TestManagerWithWriterPassesClearDeadlineAndLiveValidation(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	var gotClear time.Time
	var gotValid bool
	m := NewManagerWithWriter(queue.dispatch, func(value []byte, clearUntil time.Time, valid func() bool) (*Lease, error) {
		gotClear = clearUntil
		gotValid = valid()
		return owner.write(value)
	}, owner.clear)
	defer m.Close()
	clearUntil := time.Now().Add(5 * time.Second)
	ticket, err := m.Prepare([]byte("contextual secret"), time.Now().Add(10*time.Second), clearUntil, func() bool { return true })
	if err != nil || len(ticket) != 64 {
		t.Fatalf("prepare = %q, %v", ticket, err)
	}
	done := m.Commit(context.Background(), ticket)
	if !queue.step() {
		t.Fatal("commit did not dispatch its native work")
	}
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("outcome = %v, want Confirmed", outcome)
	}
	if gotClear != clearUntil {
		t.Fatalf("contextual clear deadline = %v, want %v", gotClear, clearUntil)
	}
	if !gotValid {
		t.Fatal("live validation was false during an authorized write")
	}
	if writes, _, _, value := owner.state(); writes != 1 || string(value) != "contextual secret" {
		t.Fatalf("owner writes = %d, value = %q", writes, value)
	}
}

// Cancellation must be observable through the contextual valid callback while a
// write is borrowing the buffer, and the callback must not wait for that write.
func TestManagerWithWriterValidationIsNonblockingDuringCancellation(t *testing.T) {
	queue := &fakeQueue{}
	entered := make(chan struct{})
	release := make(chan struct{})
	validCh := make(chan bool, 1)
	owner := &fakeOwner{}
	m := NewManagerWithWriter(queue.dispatch, func(value []byte, _ time.Time, valid func() bool) (*Lease, error) {
		close(entered)
		<-release
		start := time.Now()
		live := valid()
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("valid callback blocked for %v", elapsed)
		}
		validCh <- live
		return owner.write(value)
	}, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("inflight secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	stepped := make(chan struct{})
	go func() {
		if !queue.step() {
			t.Error("commit did not dispatch its native work")
		}
		close(stepped)
	}()
	<-entered
	m.CancelOffer(ticket)
	close(release)
	<-stepped
	if live := <-validCh; live {
		t.Fatal("live validation remained true after cancellation")
	}
	if outcome := waitOutcome(t, done); outcome != Unknown {
		t.Fatalf("outcome = %v, want Unknown", outcome)
	}
}

func TestManagerWithWriterRequiresLivePrepare(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManagerWithWriter(queue.dispatch, func(value []byte, _ time.Time, _ func() bool) (*Lease, error) {
		return owner.write(value)
	}, owner.clear)
	defer m.Close()
	if _, err := m.Prepare([]byte("secret"), time.Now().Add(time.Second), time.Time{}, func() bool { return false }); err != ErrUnavailable {
		t.Fatalf("prepare error = %v, want ErrUnavailable", err)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("writes = %d, want 0", writes)
	}
}
