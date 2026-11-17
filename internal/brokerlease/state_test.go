package brokerlease

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func brokerLeaseBinding() Binding {
	var b Binding
	b.Vault[0] = 1
	b.SnapshotEpoch = 2
	b.Session[0] = 2
	b.SessionGeneration = 2
	b.DesktopEpoch = 2
	b.Item[0] = 3
	b.Revision[0] = 4
	b.Field = FieldPassword
	b.Profile[0] = 5
	b.Caller[0] = 6
	b.Terminal[0] = 7
	b.Execution[0] = 8
	return b
}

func brokerLeaseNow() time.Time {
	return time.Unix(1_700_000_000, 0)
}

func mustNewLease(t *testing.T, b Binding, deadline, now time.Time) *Lease {
	t.Helper()
	l, err := New(b, deadline, now)
	if err != nil {
		t.Fatal("new lease rejected valid input")
	}
	return l
}

func mustActiveLease(t *testing.T, now time.Time) *Lease {
	t.Helper()
	l := mustNewLease(t, brokerLeaseBinding(), now.Add(time.Minute), now)
	if err := l.Activate(brokerLeaseBinding(), now.Add(time.Minute), now); err != nil {
		t.Fatal("valid activation rejected")
	}
	return l
}

func mustNoError(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected failure class", label)
	}
}

func mustFailure(t *testing.T, err, want error, label string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: wrong failure class", label)
	}
}

func mustState(t *testing.T, l *Lease, want State, label string) {
	t.Helper()
	if l.State() != want {
		t.Fatalf("%s: wrong lifecycle state", label)
	}
}

func TestBrokerLeaseBindingScope(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()
	deadline := now.Add(time.Minute)

	invalid := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"vault", func(x *Binding) { x.Vault = VaultID{} }},
		{"snapshot", func(x *Binding) { x.SnapshotEpoch = 0 }},
		{"session", func(x *Binding) { x.Session = SessionID{} }},
		{"item", func(x *Binding) { x.Item = ItemID{} }},
		{"revision", func(x *Binding) { x.Revision = RevisionID{} }},
		{"field_zero", func(x *Binding) { x.Field = FieldUnknown }},
		{"field_unknown", func(x *Binding) { x.Field = Field(99) }},
		{"profile", func(x *Binding) { x.Profile = ProfileID{} }},
		{"caller", func(x *Binding) { x.Caller = CallerID{} }},
		{"terminal", func(x *Binding) { x.Terminal = TerminalID{} }},
		{"execution", func(x *Binding) { x.Execution = ExecutionScopeID{} }},
	}
	for _, tc := range invalid {
		x := b
		tc.mutate(&x)
		_, err := New(x, deadline, now)
		mustFailure(t, err, ErrBinding, tc.name)
	}

	mismatch := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"vault", func(x *Binding) { x.Vault[0]++ }},
		{"snapshot", func(x *Binding) { x.SnapshotEpoch++ }},
		{"session", func(x *Binding) { x.Session[0]++ }},
		{"session_generation", func(x *Binding) { x.SessionGeneration++ }},
		{"desktop_epoch", func(x *Binding) { x.DesktopEpoch++ }},
		{"item", func(x *Binding) { x.Item[0]++ }},
		{"revision", func(x *Binding) { x.Revision[0]++ }},
		{"field", func(x *Binding) { x.Field = FieldUsername }},
		{"profile", func(x *Binding) { x.Profile[0]++ }},
		{"caller", func(x *Binding) { x.Caller[0]++ }},
		{"terminal", func(x *Binding) { x.Terminal[0]++ }},
		{"execution", func(x *Binding) { x.Execution[0]++ }},
	}
	for _, tc := range mismatch {
		x := b
		tc.mutate(&x)
		if b.Equal(x) {
			t.Fatalf("%s: equality missed a field", tc.name)
		}
	}

	l := mustNewLease(t, b, deadline, now)
	held := b
	b.Vault[0]++
	if !l.Binding().Equal(held) {
		t.Fatal("new lease did not retain a value copy")
	}
	if l.Binding().Equal(b) {
		t.Fatal("new lease followed caller mutation")
	}
}

func TestBrokerLeaseActivationAndDeadline(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()
	deadline := now.Add(time.Minute)

	pending := mustNewLease(t, b, deadline, now)
	mustState(t, pending, StatePending, "new")
	_, err := pending.Use(Nonce{1}, b, now)
	mustFailure(t, err, ErrState, "use_before_activation")

	wrongDeadline := mustNewLease(t, b, deadline, now)
	err = wrongDeadline.Activate(b, deadline.Add(time.Second), now)
	mustFailure(t, err, ErrDeadline, "extended_deadline")
	mustState(t, wrongDeadline, StateRevoked, "extended_deadline")
	err = wrongDeadline.Activate(b, deadline, now)
	mustFailure(t, err, ErrState, "revoked_after_deadline_mismatch")

	wrongBinding := mustNewLease(t, b, deadline, now)
	changed := b
	changed.Item[0]++
	err = wrongBinding.Activate(changed, deadline, now)
	mustFailure(t, err, ErrBinding, "stale_binding")
	mustState(t, wrongBinding, StateRevoked, "stale_binding")

	active := mustNewLease(t, b, deadline, now)
	mustNoError(t, active.Activate(b, deadline, now), "activate")
	mustState(t, active, StateActive, "activate")

	permit, err := active.Use(Nonce{2}, b, now.Add(10*time.Second))
	mustNoError(t, err, "first_use")
	if !permit.Deadline().Equal(deadline) {
		t.Fatal("permit deadline changed")
	}
	permit, err = active.Use(Nonce{3}, b, now.Add(11*time.Second))
	mustNoError(t, err, "second_use")
	if !permit.Deadline().Equal(deadline) {
		t.Fatal("activity extended the deadline")
	}
	if !active.Deadline().Equal(deadline) {
		t.Fatal("lease deadline changed")
	}

	_, err = active.Use(Nonce{4}, b, deadline)
	mustFailure(t, err, ErrExpired, "expired")
	mustState(t, active, StateRevoked, "expired")
	err = active.Activate(b, deadline, deadline)
	mustFailure(t, err, ErrState, "expired_reactivation")

	_, err = New(b, now, now)
	mustFailure(t, err, ErrDeadline, "deadline_equal_now")
	_, err = New(b, now.Add(MaxLeaseLifetime+time.Second), now)
	mustFailure(t, err, ErrDeadline, "deadline_too_far")
	_, err = New(b, time.Time{}, now)
	mustFailure(t, err, ErrDeadline, "deadline_zero")
	_, err = New(b, deadline, time.Time{})
	mustFailure(t, err, ErrClock, "now_zero")

	regressed := mustActiveLease(t, now)
	_, err = regressed.Use(Nonce{5}, b, now.Add(5*time.Second))
	mustNoError(t, err, "before_regression")
	_, err = regressed.Use(Nonce{6}, b, now.Add(4*time.Second))
	mustFailure(t, err, ErrClock, "clock_regression")
	mustState(t, regressed, StateRevoked, "clock_regression")
	_, err = regressed.Use(Nonce{7}, b, now.Add(6*time.Second))
	mustFailure(t, err, ErrState, "clock_regression_revival")
}

func TestBrokerLeaseNonceSingleWinnerAndCapacity(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()

	serial := mustActiveLease(t, now)
	_, err := serial.Use(Nonce{}, b, now.Add(time.Second))
	mustFailure(t, err, ErrNonce, "zero_nonce")
	_, err = serial.Use(Nonce{1}, b, now.Add(time.Second))
	mustNoError(t, err, "serial_first")
	_, err = serial.Use(Nonce{1}, b, now.Add(2*time.Second))
	mustFailure(t, err, ErrNonceReplay, "serial_replay")

	concurrent := mustActiveLease(t, now)
	const workers = 64
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := concurrent.Use(Nonce{9}, b, now.Add(time.Second))
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	winners, replays := 0, 0
	for e := range results {
		switch {
		case e == nil:
			winners++
		case errors.Is(e, ErrNonceReplay):
			replays++
		default:
			t.Fatal("concurrent use returned an unexpected failure class")
		}
	}
	if winners != 1 || replays != workers-1 {
		t.Fatal("concurrent nonce did not have exactly one winner")
	}

	capacity := mustActiveLease(t, now)
	var first Nonce
	for i := 0; i < MaxAdmissionsPerLease; i++ {
		var n Nonce
		n[0] = byte(i + 1)
		n[1] = byte((i + 1) >> 8)
		n[2] = 9
		if i == 0 {
			first = n
		}
		_, err = capacity.Use(n, b, now.Add(time.Second))
		mustNoError(t, err, "capacity_fill")
	}
	_, err = capacity.Use(Nonce{255, 255, 255, 1}, b, now.Add(time.Second))
	mustFailure(t, err, ErrNonceCapacity, "capacity_exhausted")
	_, err = capacity.Use(first, b, now.Add(time.Second))
	mustFailure(t, err, ErrNonceReplay, "capacity_did_not_evict")
	mustState(t, capacity, StateActive, "capacity")

	var cache nonceCache
	mustNoError(t, cache.consume(first), "cache_consume")
	mustFailure(t, cache.consume(first), ErrNonceReplay, "cache_consumed_failure_not_returned")
}

func TestBrokerLeaseRefresh(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()
	oldDeadline := now.Add(time.Minute)
	newDeadline := now.Add(2 * time.Minute)

	old := mustActiveLease(t, now)
	r1 := b
	r1.SnapshotEpoch++
	r1.SessionGeneration++
	r1.DesktopEpoch++
	r1.Revision[0]++
	next, err := old.Refresh(r1, newDeadline, now.Add(10*time.Second))
	mustNoError(t, err, "refresh")
	mustState(t, old, StateRevoked, "old_after_refresh")
	mustState(t, next, StatePending, "new_pending")

	_, err = old.Use(Nonce{1}, b, now.Add(11*time.Second))
	mustFailure(t, err, ErrState, "old_use_after_refresh")
	err = old.Activate(b, oldDeadline, now.Add(11*time.Second))
	mustFailure(t, err, ErrState, "old_activation_after_refresh")

	_, err = next.Use(Nonce{2}, r1, now.Add(11*time.Second))
	mustFailure(t, err, ErrState, "refresh_is_not_approval")
	mustNoError(t, next.Activate(r1, newDeadline, now.Add(11*time.Second)), "activate_refresh")
	mustState(t, next, StateActive, "refresh_active")
	_, err = next.Use(Nonce{3}, r1, now.Add(12*time.Second))
	mustNoError(t, err, "refresh_use")

	old2 := mustActiveLease(t, now)
	cancelled, err := old2.Refresh(r1, newDeadline, now.Add(10*time.Second))
	mustNoError(t, err, "refresh_for_cancel")
	mustNoError(t, cancelled.Revoke(now.Add(11*time.Second)), "cancel_new")
	mustNoError(t, cancelled.BeginClose(now.Add(11*time.Second)), "close_new")
	mustNoError(t, cancelled.Close(now.Add(11*time.Second)), "closed_new")
	err = cancelled.Activate(r1, newDeadline, now.Add(12*time.Second))
	mustFailure(t, err, ErrState, "cancelled_refresh_not_revived")
	mustState(t, old2, StateRevoked, "old_after_cancel")
	err = old2.Activate(b, oldDeadline, now.Add(12*time.Second))
	mustFailure(t, err, ErrState, "old_not_revived_by_cancel")

	scope := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"vault", func(x *Binding) { x.Vault[0]++ }},
		{"item", func(x *Binding) { x.Item[0]++ }},
		{"field", func(x *Binding) { x.Field = FieldUsername }},
		{"profile", func(x *Binding) { x.Profile[0]++ }},
		{"caller", func(x *Binding) { x.Caller[0]++ }},
		{"terminal", func(x *Binding) { x.Terminal[0]++ }},
		{"execution", func(x *Binding) { x.Execution[0]++ }},
	}
	for _, tc := range scope {
		l := mustActiveLease(t, now)
		x := b
		tc.mutate(&x)
		_, err = l.Refresh(x, newDeadline, now.Add(10*time.Second))
		mustFailure(t, err, ErrRefreshScope, tc.name)
		mustState(t, l, StateRevoked, tc.name)
	}

	versions := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"snapshot", func(x *Binding) { x.SnapshotEpoch-- }},
		{"desktop_epoch", func(x *Binding) { x.DesktopEpoch-- }},
		{"session_generation", func(x *Binding) { x.SessionGeneration-- }},
	}
	for _, tc := range versions {
		l := mustActiveLease(t, now)
		x := b
		tc.mutate(&x)
		_, err = l.Refresh(x, newDeadline, now.Add(10*time.Second))
		mustFailure(t, err, ErrRefreshVersion, tc.name)
		mustState(t, l, StateRevoked, tc.name)
	}

	badDeadline := mustActiveLease(t, now)
	_, err = badDeadline.Refresh(r1, now, now.Add(10*time.Second))
	mustFailure(t, err, ErrDeadline, "refresh_deadline_past")
	mustState(t, badDeadline, StateRevoked, "refresh_deadline_past")
	badDeadline = mustActiveLease(t, now)
	_, err = badDeadline.Refresh(r1, now.Add(MaxLeaseLifetime+time.Minute), now.Add(10*time.Second))
	mustFailure(t, err, ErrDeadline, "refresh_deadline_too_far")
	mustState(t, badDeadline, StateRevoked, "refresh_deadline_too_far")

	invalid := mustActiveLease(t, now)
	bad := b
	bad.Caller = CallerID{}
	_, err = invalid.Refresh(bad, newDeadline, now.Add(10*time.Second))
	mustFailure(t, err, ErrBinding, "refresh_invalid_binding")
	mustState(t, invalid, StateRevoked, "refresh_invalid_binding")

	unknown := mustActiveLease(t, now)
	mustNoError(t, unknown.MarkUnknown(now.Add(time.Second)), "mark_unknown_before_refresh")
	_, err = unknown.Refresh(r1, newDeadline, now.Add(2*time.Second))
	mustFailure(t, err, ErrUnknown, "refresh_unknown")
	mustState(t, unknown, StateRevoked, "refresh_unknown")
}

func TestBrokerLeaseLifecycleAndUnknown(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()

	l := mustActiveLease(t, now)
	err := l.BeginClose(now.Add(time.Second))
	mustFailure(t, err, ErrState, "close_without_revoke")
	mustNoError(t, l.Revoke(now.Add(time.Second)), "revoke")
	mustState(t, l, StateRevoked, "revoke")
	mustNoError(t, l.Revoke(now.Add(2*time.Second)), "revoke_idempotent")
	_, err = l.Use(Nonce{1}, b, now.Add(2*time.Second))
	mustFailure(t, err, ErrState, "use_revoked")
	err = l.Activate(b, now.Add(time.Minute), now.Add(2*time.Second))
	mustFailure(t, err, ErrState, "activate_revoked")

	mustNoError(t, l.BeginClose(now.Add(3*time.Second)), "begin_close")
	mustState(t, l, StateClosing, "begin_close")
	mustNoError(t, l.BeginClose(now.Add(4*time.Second)), "begin_close_idempotent")
	mustNoError(t, l.Close(now.Add(4*time.Second)), "close")
	mustState(t, l, StateClosed, "close")
	mustNoError(t, l.Close(now.Add(5*time.Second)), "close_idempotent")
	mustNoError(t, l.BeginClose(now.Add(5*time.Second)), "begin_close_closed")
	mustNoError(t, l.Revoke(now.Add(5*time.Second)), "revoke_closed")
	mustState(t, l, StateClosed, "closed_monotonic")

	u := mustActiveLease(t, now)
	mustNoError(t, u.MarkUnknown(now.Add(time.Second)), "mark_unknown")
	if !u.Unknown() {
		t.Fatal("unknown was not recorded")
	}
	mustState(t, u, StateRevoked, "unknown_revoked")
	_, err = u.Use(Nonce{2}, b, now.Add(2*time.Second))
	mustFailure(t, err, ErrUnknown, "use_unknown")
	_, err = u.Refresh(b, now.Add(2*time.Minute), now.Add(2*time.Second))
	mustFailure(t, err, ErrUnknown, "refresh_unknown")
	mustNoError(t, u.Revoke(now.Add(2*time.Second)), "unknown_revoke")
	if !u.Unknown() {
		t.Fatal("revoke erased unknown")
	}
	mustNoError(t, u.BeginClose(now.Add(3*time.Second)), "unknown_begin_close")
	mustNoError(t, u.Close(now.Add(3*time.Second)), "unknown_close")
	if !u.Unknown() {
		t.Fatal("close erased unknown")
	}
	mustState(t, u, StateClosed, "unknown_closed")
	_, err = u.Use(Nonce{3}, b, now.Add(4*time.Second))
	mustFailure(t, err, ErrUnknown, "closed_unknown_use")

	closed := mustActiveLease(t, now)
	mustNoError(t, closed.Revoke(now.Add(time.Second)), "closed_revoke")
	mustNoError(t, closed.BeginClose(now.Add(time.Second)), "closed_begin")
	mustNoError(t, closed.Close(now.Add(time.Second)), "closed_close")
	mustNoError(t, closed.MarkUnknown(now.Add(2*time.Second)), "unknown_after_close")
	if !closed.Unknown() {
		t.Fatal("post-close unknown was not recorded")
	}
	mustState(t, closed, StateClosed, "unknown_after_close_state")
}

func TestBrokerLeaseClockFailClosed(t *testing.T) {
	b := brokerLeaseBinding()
	now := brokerLeaseNow()

	zeroClock := mustActiveLease(t, now)
	err := zeroClock.MarkUnknown(time.Time{})
	mustFailure(t, err, ErrClock, "zero_clock")
	mustState(t, zeroClock, StateRevoked, "zero_clock")
	if zeroClock.Unknown() {
		t.Fatal("invalid clock was recorded as an operation outcome")
	}
	_, err = zeroClock.Use(Nonce{1}, b, now.Add(time.Second))
	mustFailure(t, err, ErrState, "zero_clock_no_revival")

	regressed := mustActiveLease(t, now)
	mustNoError(t, regressed.Revoke(now.Add(2*time.Second)), "revoke_before_regression")
	err = regressed.BeginClose(now.Add(time.Second))
	mustFailure(t, err, ErrClock, "regression_on_close")
	mustState(t, regressed, StateRevoked, "regression_monotonic")
	mustNoError(t, regressed.BeginClose(now.Add(3*time.Second)), "close_after_valid_clock")
	mustState(t, regressed, StateClosing, "close_after_valid_clock")
}
