package nativeclipboard

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeQueue is a serial UI queue: dispatch only enqueues; tests drain it.
type fakeQueue struct {
	mu sync.Mutex
	q  []func()
}

func (f *fakeQueue) dispatch(fn func()) bool {
	f.mu.Lock()
	f.q = append(f.q, fn)
	f.mu.Unlock()
	return true
}

func (f *fakeQueue) drain() int {
	ran := 0
	for {
		f.mu.Lock()
		if len(f.q) == 0 {
			f.mu.Unlock()
			return ran
		}
		fn := f.q[0]
		f.q = f.q[1:]
		f.mu.Unlock()
		fn()
		ran++
	}
}

// fakeOwner models native ownership: only the current owner lease can clear.
type fakeOwner struct {
	mu      sync.Mutex
	writes  int
	values  [][]byte
	owner   *Lease
	cleared []*Lease
	err     error
	hook    func(call int, value []byte) (*Lease, error)
}

func (o *fakeOwner) write(value []byte) (*Lease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.writes++
	o.values = append(o.values, append([]byte(nil), value...))
	if o.hook != nil {
		lease, err := o.hook(o.writes, value)
		if lease != nil {
			o.owner = lease
		}
		return lease, err
	}
	if o.err != nil {
		return &Lease{native: []byte("partial")}, o.err
	}
	o.owner = &Lease{native: []byte("native")}
	return o.owner, nil
}

func (o *fakeOwner) clear(lease *Lease) Result {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cleared = append(o.cleared, lease)
	if lease != o.owner {
		return Superseded
	}
	o.owner = nil
	return Cleared
}

func (o *fakeOwner) state() (writes int, owner *Lease, cleared int, value []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.values) > 0 {
		value = o.values[len(o.values)-1]
	}
	return o.writes, o.owner, len(o.cleared), value
}

func (o *fakeOwner) takeover(lease *Lease) {
	o.mu.Lock()
	o.owner = lease
	o.mu.Unlock()
}

func (f *fakeQueue) step() bool {
	f.mu.Lock()
	if len(f.q) == 0 {
		f.mu.Unlock()
		return false
	}
	fn := f.q[0]
	f.q = f.q[1:]
	f.mu.Unlock()
	fn()
	return true
}

func waitOutcome(t *testing.T, ch <-chan Outcome) Outcome {
	t.Helper()
	select {
	case outcome := <-ch:
		return outcome
	case <-time.After(2 * time.Second):
		t.Fatal("no outcome was delivered")
		return Unknown
	}
}

func TestManagerPrepareCopiesThenCommitsExactlyOnce(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	value := []byte("prepared secret canary")
	ticket, err := m.Prepare(value, time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil || len(ticket) != 64 {
		t.Fatalf("prepare = %q, %v", ticket, err)
	}
	value[0] = 'X'
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatal("prepare performed a native write")
	}
	done := m.Commit(context.Background(), ticket)
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatal("commit wrote before the UI callback ran")
	}
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("outcome = %v, want Confirmed", outcome)
	}
	writes, lease, _, written := owner.state()
	if writes != 1 || lease == nil {
		t.Fatalf("writes = %d lease = %v", writes, lease)
	}
	if string(written) != "prepared secret canary" {
		t.Fatalf("write saw a mutated or aliased value: %q", written)
	}
	if outcome := waitOutcome(t, m.Commit(context.Background(), ticket)); outcome != Refused {
		t.Fatalf("duplicate commit = %v, want Refused", outcome)
	}
	if writes, _, _, _ := owner.state(); writes != 1 {
		t.Fatalf("duplicate commit wrote again: %d", writes)
	}
}

func TestManagerCancelOfferBeforeQueuedUIRefusesWithoutWrite(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("cancelled canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	buffer := m.offer.value
	m.mu.Unlock()
	done := m.Commit(context.Background(), ticket)
	m.CancelOffer(ticket)
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("cancel before UI = %v, want Refused", outcome)
	}
	if ran := queue.drain(); ran != 1 {
		t.Fatalf("queued callbacks drained = %d, want 1", ran)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("cancelled queued commit wrote %d times", writes)
	}
	if _, err := m.Prepare([]byte("after cancel"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("slot stayed busy after the drained callback: %v", err)
	}
	for i, b := range buffer {
		if b != 0 {
			t.Fatalf("cancelled offer buffer byte %d was not cleared", i)
		}
	}
}

func TestManagerPartialWriteReportsUnknownWithCleanupOnly(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{err: ErrWrite}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	ticket, err := m.Prepare([]byte("partial canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Unknown {
		t.Fatalf("partial write = %v, want Unknown", outcome)
	}
	writes, current, cleared, _ := owner.state()
	if writes != 1 {
		t.Fatalf("write was retried: %d writes", writes)
	}
	if current != nil {
		t.Fatal("partial write adopted native ownership")
	}
	if cleared != 1 {
		t.Fatalf("cleanup attempts = %d, want 1", cleared)
	}
	if m.CleanupPending() {
		t.Fatal("resolved cleanup still reports pending")
	}
	queue.drain()
	if writes, _, cleared, _ := owner.state(); writes != 1 || cleared != 1 {
		t.Fatalf("post-cleanup writes = %d cleared = %d", writes, cleared)
	}
}

func TestManagerForeignOwnerSurvivesStaleLeaseAndDeadline(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	first, err := m.Prepare([]byte("same bytes"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	staleSequence := m.sequence
	m.mu.Unlock()
	firstDone := m.Commit(context.Background(), first)
	queue.drain()
	if outcome := waitOutcome(t, firstDone); outcome != Confirmed {
		t.Fatalf("first commit = %v", outcome)
	}
	_, oldLease, _, _ := owner.state()
	second, err := m.Prepare([]byte("same bytes"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondDone := m.Commit(context.Background(), second)
	queue.drain()
	if outcome := waitOutcome(t, secondDone); outcome != Confirmed {
		t.Fatalf("second commit = %v", outcome)
	}
	_, newLease, cleared, _ := owner.state()
	if oldLease == nil || newLease == nil || oldLease == newLease {
		t.Fatal("identical bytes did not produce a distinct lease")
	}
	if cleared != 0 {
		t.Fatalf("superseded acquisition issued %d cleanups", cleared)
	}
	m.expire(oldLease, staleSequence)
	queue.drain()
	if _, current, clearedAfter, _ := owner.state(); clearedAfter != cleared || current != newLease {
		t.Fatal("stale deadline cleared the newer owner")
	}
	m.cleanup(oldLease)
	queue.drain()
	if _, current, _, _ := owner.state(); current != newLease || m.CleanupPending() {
		t.Fatal("old lease cleanup disturbed the newer owner")
	}
}

func TestManagerStaleAuthorityAndExpiryRefuseWithoutWrite(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	live := true
	ticket, err := m.Prepare([]byte("stale canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return live })
	if err != nil {
		t.Fatal(err)
	}
	live = false
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("stale authority = %v, want Refused", outcome)
	}
	expiring, err := m.Prepare([]byte("expiring canary"), time.Now().Add(50*time.Millisecond), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Millisecond)
	if outcome := waitOutcome(t, m.Commit(context.Background(), expiring)); outcome != Refused {
		t.Fatalf("expired offer = %v, want Refused", outcome)
	}
	queue.drain()
	if writes, _, cleared, _ := owner.state(); writes != 0 || cleared != 0 {
		t.Fatalf("refusals wrote %d times and cleared %d leases", writes, cleared)
	}
}

func TestManagerDispatcherRejectReturnsWithoutHanging(t *testing.T) {
	owner := &fakeOwner{}
	m := NewManager(func(func()) bool { return false }, owner.write, owner.clear)
	ticket, err := m.Prepare([]byte("rejected canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("rejected dispatch = %v, want Refused", outcome)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("rejected dispatch wrote %d times", writes)
	}
	m.Close()
	m.Close()
}

func TestManagerCloseIsIdempotentAndRedacted(t *testing.T) {
	const canary = "manager-json-canary"
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	ticket, err := m.Prepare([]byte(canary), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("commit = %v", outcome)
	}
	raw, marshalErr := json.Marshal(m)
	if marshalErr == nil || strings.Contains(string(raw)+marshalErr.Error(), canary) {
		t.Fatalf("manager marshaling leaked or succeeded: %q %v", raw, marshalErr)
	}
	m.Close()
	m.Close()
	queue.drain()
	if m.CleanupPending() {
		t.Fatal("cleanup still pending after Close drained")
	}
	if _, err := m.Prepare([]byte(canary), time.Now().Add(time.Second), time.Time{}, func() bool { return true }); err == nil {
		t.Fatal("Prepare succeeded after Close")
	}
	if writes, _, _, _ := owner.state(); writes != 1 {
		t.Fatalf("writes = %d, want 1", writes)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagerCleanupPendingTracksOpaqueAvailability(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	ticket, err := m.Prepare([]byte("pending canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("commit = %v", outcome)
	}
	m.Clear()
	if !m.CleanupPending() {
		t.Fatal("queued cleanup must report pending availability")
	}
	if _, current, _, _ := owner.state(); current == nil {
		t.Fatal("cleanup ran before the UI callback drained")
	}
	queue.drain()
	if m.CleanupPending() {
		t.Fatal("confirmed cleanup still pending")
	}
	if _, current, cleared, _ := owner.state(); current != nil || cleared != 1 {
		t.Fatalf("owner = %v cleared = %d", current, cleared)
	}
}

func TestManagerCancelDuringBlockedWriteIsUnknownOnce(t *testing.T) {
	queue := &fakeQueue{}
	borrowedCh := make(chan []byte, 1)
	release := make(chan struct{})
	lease := &Lease{native: []byte("blocked owner")}
	var mu sync.Mutex
	writes, cleared := 0, 0
	var clearedLease *Lease
	m := NewManager(queue.dispatch, func(value []byte) (*Lease, error) {
		borrowedCh <- value
		<-release
		mu.Lock()
		writes++
		mu.Unlock()
		return lease, nil
	}, func(l *Lease) Result {
		mu.Lock()
		defer mu.Unlock()
		cleared++
		clearedLease = l
		return Cleared
	})
	ticket, err := m.Prepare([]byte("blocked canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	go queue.drain()
	var borrowed []byte
	select {
	case borrowed = <-borrowedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("native write never started")
	}
	m.CancelOffer(ticket)
	close(release)
	if outcome := waitOutcome(t, done); outcome != Unknown {
		t.Fatalf("cancel during write = %v, want Unknown", outcome)
	}
	for i, b := range borrowed {
		if b != 0 {
			t.Fatalf("borrowed buffer byte %d not cleared after write", i)
		}
	}
	waitFor(t, "conditional cleanup", func() bool { mu.Lock(); defer mu.Unlock(); return writes == 1 && cleared == 1 })
	if clearedLease != lease {
		t.Fatal("cleanup did not receive the partial lease")
	}
	select {
	case extra := <-done:
		t.Fatalf("duplicate outcome %v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestManagerQueuedContextCancelRefusesWithoutWrite(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ticket, err := m.Prepare([]byte("context canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(ctx, ticket)
	cancel()
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("queued context cancel = %v, want Refused", outcome)
	}
	if _, err := m.Prepare([]byte("second canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("cancelled queued job kept the slot: %v", err)
	}
	if ran := queue.drain(); ran != 1 {
		t.Fatalf("drained callbacks = %d, want 1", ran)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("cancelled commit wrote %d times", writes)
	}
	if _, err := m.Prepare([]byte("second canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("slot did not free after drain: %v", err)
	}
}

func TestManagerClearDeadlineRevokesOnlyItsOwnLease(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("deadline canary"), time.Now().Add(10*time.Second), time.Now().Add(50*time.Millisecond), func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("commit = %v", outcome)
	}
	if _, current, _, _ := owner.state(); current == nil {
		t.Fatal("confirmed acquisition lost its lease")
	}
	waitFor(t, "deadline revocation", func() bool { queue.drain(); _, _, cleared, _ := owner.state(); return cleared == 1 })
	if _, current, cleared, _ := owner.state(); current != nil || cleared != 1 {
		t.Fatalf("owner = %v cleared = %d", current, cleared)
	}
	if writes, _, _, _ := owner.state(); writes != 1 {
		t.Fatalf("deadline wrote again: %d", writes)
	}
}

// Negative control: a partial second acquisition must not be shielded by the
// previously confirmed lease sitting in m.lease, and the old clearUntil timer
// must never turn into a cleanup of the new (partial) acquisition.
func TestManagerPartialWriteAfterConfirmedLeaseKeepsCleanupAuthority(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	partial := &Lease{native: []byte("partial new copy")}
	owner.hook = func(call int, value []byte) (*Lease, error) {
		if call == 1 {
			return &Lease{native: []byte("confirmed old copy")}, nil
		}
		return partial, ErrWrite
	}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	first, err := m.Prepare([]byte("old secret"), time.Now().Add(10*time.Second), time.Now().Add(120*time.Millisecond), func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	firstDone := m.Commit(context.Background(), first)
	queue.drain()
	if outcome := waitOutcome(t, firstDone); outcome != Confirmed {
		t.Fatalf("first commit = %v", outcome)
	}
	_, oldLease, _, _ := owner.state()
	second, err := m.Prepare([]byte("new secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondDone := m.Commit(context.Background(), second)
	queue.drain()
	if outcome := waitOutcome(t, secondDone); outcome != Unknown {
		t.Fatalf("partial second write = %v, want Unknown", outcome)
	}
	time.Sleep(150 * time.Millisecond)
	queue.drain()
	writes, current, cleared, _ := owner.state()
	if writes != 2 {
		t.Fatalf("writes = %d, want 2 (no retry)", writes)
	}
	if cleared != 1 || len(owner.cleared) != 1 || owner.cleared[0] != partial {
		t.Fatalf("cleanup attempts = %d, want exactly the new partial lease", cleared)
	}
	if current != nil {
		t.Fatalf("partial acquisition was left owned (secret retained): %v", oldLease)
	}
	if oldLease == nil || owner.cleared[0] == oldLease {
		t.Fatal("old confirmed lease was the cleanup target")
	}
}

func TestManagerPartialWriteNeverBlanksForeignOwner(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	partial := &Lease{native: []byte("partial copy")}
	foreign := &Lease{native: []byte("foreign owner")}
	owner.hook = func(call int, value []byte) (*Lease, error) {
		if call == 1 {
			return &Lease{native: []byte("old copy")}, nil
		}
		return partial, ErrWrite
	}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	first, err := m.Prepare([]byte("old secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	firstDone := m.Commit(context.Background(), first)
	queue.drain()
	if outcome := waitOutcome(t, firstDone); outcome != Confirmed {
		t.Fatalf("first commit = %v", outcome)
	}
	second, err := m.Prepare([]byte("new secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondDone := m.Commit(context.Background(), second)
	if !queue.step() {
		t.Fatal("queued write callback was missing")
	}
	if outcome := waitOutcome(t, secondDone); outcome != Unknown {
		t.Fatalf("partial second write = %v, want Unknown", outcome)
	}
	owner.takeover(foreign)
	queue.drain()
	writes, current, cleared, _ := owner.state()
	if writes != 2 || cleared != 1 || len(owner.cleared) != 1 || owner.cleared[0] != partial {
		t.Fatalf("writes = %d cleared = %d, want cleanup of only the partial lease", writes, cleared)
	}
	if current != foreign {
		t.Fatalf("foreign owner was blanked: %v", current)
	}
	waitFor(t, "pending cleanup resolution", func() bool { return !m.CleanupPending() })
}

func TestManagerClearDuringBlockedPartialWriteCleansNewLease(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	partial := &Lease{native: []byte("blocked partial copy")}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	owner.hook = func(call int, value []byte) (*Lease, error) {
		if call == 1 {
			return &Lease{native: []byte("old copy")}, nil
		}
		entered <- struct{}{}
		<-release
		return partial, ErrWrite
	}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	first, err := m.Prepare([]byte("old secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	firstDone := m.Commit(context.Background(), first)
	queue.drain()
	if outcome := waitOutcome(t, firstDone); outcome != Confirmed {
		t.Fatalf("first commit = %v", outcome)
	}
	second, err := m.Prepare([]byte("new secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondDone := m.Commit(context.Background(), second)
	go queue.drain()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("partial write never started")
	}
	m.Clear()
	close(release)
	if outcome := waitOutcome(t, secondDone); outcome != Unknown {
		t.Fatalf("cleared partial write = %v, want Unknown", outcome)
	}
	waitFor(t, "partial cleanup", func() bool { _, _, cleared, _ := owner.state(); return cleared == 1 })
	writes, current, cleared, _ := owner.state()
	if writes != 2 || cleared != 1 || owner.cleared[0] != partial || current != nil {
		t.Fatalf("writes = %d cleared = %d current = %v", writes, cleared, current)
	}
}

// A nonzero clearUntil earlier than until is the hard boundary for a pending
// offer: its plaintext buffer must be zeroed at that boundary, not at until,
// and a commit attempted afterwards must refuse without writing.
func TestManagerPendingOfferDeadlineUsesEarlierClearUntil(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	until := time.Now().Add(10 * time.Second)
	clearUntil := time.Now().Add(150 * time.Millisecond)
	ticket, err := m.Prepare([]byte("early offer canary"), until, clearUntil, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	if m.offer == nil {
		m.mu.Unlock()
		t.Fatal("prepare published no offer")
	}
	buffer, boundary := m.offer.value, m.offer.deadline()
	m.mu.Unlock()
	if !boundary.Equal(clearUntil) {
		t.Fatalf("offer boundary = %v, want earlier clearUntil %v", boundary, clearUntil)
	}
	waitFor(t, "offer expiry at the earlier clearUntil", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.offer == nil
	})
	for i, b := range buffer {
		if b != 0 {
			t.Fatalf("pending offer byte %d survived the earlier deadline", i)
		}
	}
	if writes, _, cleared, _ := owner.state(); writes != 0 || cleared != 0 {
		t.Fatalf("offer expiry wrote %d times and cleared %d leases", writes, cleared)
	}
	if outcome := waitOutcome(t, m.Commit(context.Background(), ticket)); outcome != Refused {
		t.Fatalf("commit after the earlier deadline = %v, want Refused", outcome)
	}
	queue.drain()
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("refused late commit wrote %d times", writes)
	}
}

// A queued job must be cancelled and its borrowed plaintext zeroed at the
// earlier clearUntil, before the fake UI queue is drained.
func TestManagerQueuedJobDeadlineUsesEarlierClearUntil(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("queued canary"), time.Now().Add(10*time.Second), time.Now().Add(150*time.Millisecond), func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	// The job borrows the offer buffer, whose header cancel() guards with
	// valueMu; take the header while it is still the pending offer and rely on
	// the outcome channel to order the zero checks after the clear.
	m.mu.Lock()
	buffer := m.offer.value
	m.mu.Unlock()
	done := m.Commit(context.Background(), ticket)
	m.mu.Lock()
	queued := m.job != nil
	m.mu.Unlock()
	if !queued {
		t.Fatal("commit queued no job")
	}
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("queued job at the earlier deadline = %v, want Refused", outcome)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("cancelled queued job wrote %d times before drain", writes)
	}
	for i, b := range buffer {
		if b != 0 {
			t.Fatalf("queued job buffer byte %d survived the earlier deadline", i)
		}
	}
	if ran := queue.drain(); ran != 1 {
		t.Fatalf("drained callbacks = %d, want 1", ran)
	}
	if writes, _, cleared, _ := owner.state(); writes != 0 || cleared != 0 {
		t.Fatalf("stale callback wrote %d times and cleared %d leases", writes, cleared)
	}
	select {
	case extra := <-done:
		t.Fatalf("duplicate outcome %v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

// The offer timer is stopped here so only Commit's own boundary recheck can
// refuse: a commit after the earlier clearUntil must write nothing and must not
// retain the pending plaintext.
func TestManagerCommitAfterEarlierClearUntilRefusesWithoutWrite(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	clearUntil := time.Now().Add(120 * time.Millisecond)
	ticket, err := m.Prepare([]byte("late commit canary"), time.Now().Add(10*time.Second), clearUntil, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.offer.timer.Stop()
	buffer := m.offer.value
	m.mu.Unlock()
	waitFor(t, "earlier clearUntil to pass", func() bool { return !time.Now().Before(clearUntil) })
	if outcome := waitOutcome(t, m.Commit(context.Background(), ticket)); outcome != Refused {
		t.Fatalf("late commit = %v, want Refused", outcome)
	}
	queue.drain()
	if writes, _, cleared, _ := owner.state(); writes != 0 || cleared != 0 {
		t.Fatalf("late commit wrote %d times and cleared %d leases", writes, cleared)
	}
	for i, b := range buffer {
		if b != 0 {
			t.Fatalf("refused commit left byte %d of the offer buffer", i)
		}
	}
	m.mu.Lock()
	offer := m.offer
	m.mu.Unlock()
	if offer != nil {
		t.Fatal("refused late commit kept the offer slot")
	}
}

// A zero clearUntil keeps native clearing off: no lease timer is armed and the
// confirmed lease survives until an explicit Clear.
func TestManagerZeroClearUntilArmsNoNativeClear(t *testing.T) {
	queue, owner := &fakeQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("zero canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	queue.drain()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("commit = %v, want Confirmed", outcome)
	}
	m.mu.Lock()
	armed := m.leaseTimer
	m.mu.Unlock()
	if armed != nil {
		t.Fatal("zero clearUntil armed a native clear timer")
	}
	if _, current, _, _ := owner.state(); current == nil {
		t.Fatal("confirmed lease disappeared without a native clear deadline")
	}
	m.Clear()
	queue.drain()
	if _, current, cleared, _ := owner.state(); current != nil || cleared != 1 {
		t.Fatalf("explicit clear left owner = %v cleared = %d", current, cleared)
	}
}

// stalledQueue accepts dispatch work but never runs it until the test takes a
// specific callback, modelling a UI queue that can stall indefinitely.
type stalledQueue struct {
	mu sync.Mutex
	q  []func()
}

func (s *stalledQueue) dispatch(fn func()) bool {
	s.mu.Lock()
	s.q = append(s.q, fn)
	s.mu.Unlock()
	return true
}

func (s *stalledQueue) take(index int) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.q) {
		return nil
	}
	fn := s.q[index]
	s.q = append(s.q[:index:index], s.q[index+1:]...)
	return fn
}

func (s *stalledQueue) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.q)
}

// A queued commit whose deadline wins must report Refused, wipe the buffer and
// free the slot even though the stalled UI callback never ran.
func TestManagerQueuedDeadlineReleasesSlotWithoutDrain(t *testing.T) {
	queue, owner := &stalledQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("deadline canary"), time.Now().Add(120*time.Millisecond), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	buffer := m.offer.value
	m.mu.Unlock()
	done := m.Commit(context.Background(), ticket)
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("queued deadline = %v, want Refused", outcome)
	}
	for i, b := range buffer {
		if b != 0 {
			t.Fatalf("deadline buffer byte %d was not cleared", i)
		}
	}
	m.mu.Lock()
	leaked := m.job
	m.mu.Unlock()
	if leaked != nil {
		t.Fatal("queued job stayed occupied after its deadline")
	}
	if queue.size() != 1 {
		t.Fatalf("stalled callbacks = %d, want 1", queue.size())
	}
	if _, err := m.Prepare([]byte("next canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("prepare refused after queued deadline: %v", err)
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("deadline wrote %d times", writes)
	}
}

// A cancelled job leaves one payload-free UI runner. Later explicit commits
// reuse that runner, so a stalled UI cannot accumulate one callback per cancel.
func TestManagerQueuedRunnerCoalescesAfterCancellation(t *testing.T) {
	queue, owner := &stalledQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	for i := 0; i < 100; i++ {
		ticket, err := m.Prepare([]byte("cancelled secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
		if err != nil {
			t.Fatalf("prepare %d: %v", i, err)
		}
		done := m.Commit(context.Background(), ticket)
		m.CancelOffer(ticket)
		if outcome := waitOutcome(t, done); outcome != Refused {
			t.Fatalf("cancel %d: %v", i, outcome)
		}
		if queue.size() != 1 {
			t.Fatalf("cancel %d queued %d runners", i, queue.size())
		}
	}
	ticket, err := m.Prepare([]byte("new secret"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	if queue.size() != 1 {
		t.Fatalf("new commit queued %d runners", queue.size())
	}
	runner := queue.take(0)
	if runner == nil {
		t.Fatal("runner missing")
	}
	runner()
	if outcome := waitOutcome(t, done); outcome != Confirmed {
		t.Fatalf("new commit: %v", outcome)
	}
	writes, lease, _, written := owner.state()
	if writes != 1 || lease == nil || string(written) != "new secret" {
		t.Fatal("runner wrote a cancelled payload or lost the new commit")
	}
	if _, err := m.Prepare([]byte("third canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("slot stayed busy: %v", err)
	}
}

// An explicit CancelOffer for a queued (never drained) commit must free the slot
// immediately and keep the abandoned callback from writing.
func TestManagerCancelOfferQueuedReleasesSlot(t *testing.T) {
	queue, owner := &stalledQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("cancel canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	done := m.Commit(context.Background(), ticket)
	m.CancelOffer(ticket)
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("cancel offer = %v, want Refused", outcome)
	}
	m.mu.Lock()
	busy := m.job
	m.mu.Unlock()
	if busy != nil {
		t.Fatal("cancel offer left the queued job occupied")
	}
	if _, err := m.Prepare([]byte("after cancel offer"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("prepare refused after cancel offer: %v", err)
	}
	if late := queue.take(0); late != nil {
		late()
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("cancelled queued commit wrote %d times", writes)
	}
}

// Cancelling the commit context while the work is still queued releases the
// slot without waiting for the stalled UI callback.
func TestManagerQueuedContextCancelReleasesSlot(t *testing.T) {
	queue, owner := &stalledQueue{}, &fakeOwner{}
	m := NewManager(queue.dispatch, owner.write, owner.clear)
	defer m.Close()
	ticket, err := m.Prepare([]byte("context canary"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := m.Commit(ctx, ticket)
	cancel()
	if outcome := waitOutcome(t, done); outcome != Refused {
		t.Fatalf("context cancel = %v, want Refused", outcome)
	}
	m.mu.Lock()
	busy := m.job
	m.mu.Unlock()
	if busy != nil {
		t.Fatal("context cancel left the queued job occupied")
	}
	if _, err := m.Prepare([]byte("after context cancel"), time.Now().Add(10*time.Second), time.Time{}, func() bool { return true }); err != nil {
		t.Fatalf("prepare refused after context cancel: %v", err)
	}
	if late := queue.take(0); late != nil {
		late()
	}
	if writes, _, _, _ := owner.state(); writes != 0 {
		t.Fatalf("context-cancelled commit wrote %d times", writes)
	}
}
