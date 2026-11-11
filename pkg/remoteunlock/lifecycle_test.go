package remoteunlock

import (
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Synthetic base time used by every lifecycle test. All times are explicit
// caller-supplied Unix milliseconds; the lifecycle never reads a clock.
const lifecycleNowMS int64 = 1700000000000

// lifecycleContext returns the synthetic vector context with a deadline that is
// far past every short phase deadline used below.
func lifecycleContext() ChannelBindingContext {
	c := vectorContext()
	c.DeadlineUnixMS = lifecycleNowMS + 600_000
	return c
}

func mustLifecycle(t *testing.T, ctx ChannelBindingContext, now int64) *RequestLifecycle {
	t.Helper()
	l, err := NewRequestLifecycle(ctx, now)
	if err != nil {
		t.Fatalf("NewRequestLifecycle: %v", err)
	}
	return l
}

func mustStatus(t *testing.T, l *RequestLifecycle, now int64, want string) {
	t.Helper()
	got, err := l.StatusAt(now)
	if err != nil {
		t.Fatalf("StatusAt(%d): %v", now, err)
	}
	if got != want {
		t.Fatalf("StatusAt(%d) = %q, want %q", now, got, want)
	}
}

func TestLifecycleStatusConstants(t *testing.T) {
	want := map[string]string{
		"requested": StatusRequested,
		"confirmed": StatusConfirmed,
		"received":  StatusReceived,
		"unknown":   StatusUnknown,
		"cancelled": StatusCancelled,
		"expired":   StatusExpired,
	}
	for k, v := range want {
		if k != v {
			t.Fatalf("status constant %q = %q; statuses are frozen", k, v)
		}
	}
	if DefaultRequestTTLMS != 120_000 {
		t.Fatalf("DefaultRequestTTLMS = %d, want 120000", DefaultRequestTTLMS)
	}
	if MaxActivePhaseMS != 30_000 {
		t.Fatalf("MaxActivePhaseMS = %d, want 30000", MaxActivePhaseMS)
	}
}

func TestLifecycleValidTransitionOrder(t *testing.T) {
	ctx := lifecycleContext()
	l := mustLifecycle(t, ctx, lifecycleNowMS)
	mustStatus(t, l, lifecycleNowMS, StatusRequested)

	if l.Context() != ctx {
		t.Fatalf("Context() changed the supplied context\n got: %+v\nwant: %+v", l.Context(), ctx)
	}

	if err := l.Confirm(lifecycleNowMS + 1_000); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	mustStatus(t, l, lifecycleNowMS+1_000, StatusConfirmed)

	if err := l.Receive(lifecycleNowMS + 2_000); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	mustStatus(t, l, lifecycleNowMS+2_000, StatusReceived)
}

func TestLifecycleInvalidTransitions(t *testing.T) {
	t.Run("receive before confirm", func(t *testing.T) {
		l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
		if err := l.Receive(lifecycleNowMS); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("Receive = %v, want ErrLifecycleTransition", err)
		}
		mustStatus(t, l, lifecycleNowMS, StatusRequested)
	})

	t.Run("confirm twice", func(t *testing.T) {
		l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
		if err := l.Confirm(lifecycleNowMS); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if err := l.Confirm(lifecycleNowMS + 1); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("second Confirm = %v, want ErrLifecycleTransition", err)
		}
		mustStatus(t, l, lifecycleNowMS+1, StatusConfirmed)
	})

	t.Run("confirm beyond phase", func(t *testing.T) {
		l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
		if err := l.Confirm(lifecycleNowMS + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("Confirm at phase deadline = %v, want ErrLifecycleTransition", err)
		}
	})

	t.Run("non-positive times", func(t *testing.T) {
		l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
		for _, now := range []int64{0, -1, math.MinInt64} {
			if err := l.Confirm(now); !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("Confirm(%d) = %v, want ErrLifecycleInvalidTime", now, err)
			}
			if err := l.Receive(now); !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("Receive(%d) = %v, want ErrLifecycleInvalidTime", now, err)
			}
			if err := l.MarkUnknown(now); !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("MarkUnknown(%d) = %v, want ErrLifecycleInvalidTime", now, err)
			}
			if err := l.Cancel(now); !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("Cancel(%d) = %v, want ErrLifecycleInvalidTime", now, err)
			}
			if got, err := l.StatusAt(now); got != StatusUnknown || !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("StatusAt(%d) = %q, %v; want unknown, ErrLifecycleInvalidTime", now, got, err)
			}
		}
		mustStatus(t, l, lifecycleNowMS, StatusRequested)
	})
}

func TestLifecycleReceiveIsOneShot(t *testing.T) {
	l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
	if err := l.Confirm(lifecycleNowMS); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := l.Receive(lifecycleNowMS + 1); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Receive(lifecycleNowMS + int64(2+i)); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("repeated Receive #%d = %v, want ErrLifecycleTransition", i, err)
		}
	}
	mustStatus(t, l, lifecycleNowMS+10, StatusReceived)
}

func TestLifecycleReceiveConcurrentlyOnce(t *testing.T) {
	const goroutines = 32
	l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
	if err := l.Confirm(lifecycleNowMS); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok, rejected int
	var wrong []error
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := l.Receive(lifecycleNowMS + int64(i%5) + 1)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrLifecycleTransition):
				rejected++
			default:
				wrong = append(wrong, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if len(wrong) != 0 {
		t.Fatalf("unexpected Receive errors: %v", wrong)
	}
	if ok != 1 {
		t.Fatalf("successful Receive calls = %d, want exactly 1", ok)
	}
	if rejected != goroutines-1 {
		t.Fatalf("rejected Receive calls = %d, want %d", rejected, goroutines-1)
	}
	mustStatus(t, l, lifecycleNowMS+10, StatusReceived)
}

func TestLifecycleUnknownIsTerminal(t *testing.T) {
	for _, phase := range []string{"requested", "confirmed"} {
		t.Run(phase, func(t *testing.T) {
			l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
			if phase == "confirmed" {
				if err := l.Confirm(lifecycleNowMS); err != nil {
					t.Fatalf("Confirm: %v", err)
				}
			}
			if err := l.MarkUnknown(lifecycleNowMS + 5); err != nil {
				t.Fatalf("MarkUnknown: %v", err)
			}
			mustStatus(t, l, lifecycleNowMS+5, StatusUnknown)
			mustStatus(t, l, lifecycleNowMS+10, StatusUnknown)

			if err := l.Confirm(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Confirm after unknown = %v, want ErrLifecycleTransition", err)
			}
			if err := l.Receive(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Receive after unknown = %v, want ErrLifecycleTransition", err)
			}
			if err := l.Cancel(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Cancel after unknown = %v, want ErrLifecycleTransition", err)
			}
			if err := l.MarkUnknown(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("MarkUnknown after unknown = %v, want ErrLifecycleTransition", err)
			}
			// Unknown never becomes expired later.
			mustStatus(t, l, lifecycleNowMS+10_000_000, StatusUnknown)
		})
	}
}

func TestLifecycleCancelIsTerminal(t *testing.T) {
	for _, phase := range []string{"requested", "confirmed"} {
		t.Run(phase, func(t *testing.T) {
			l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
			if phase == "confirmed" {
				if err := l.Confirm(lifecycleNowMS); err != nil {
					t.Fatalf("Confirm: %v", err)
				}
			}
			if err := l.Cancel(lifecycleNowMS + 5); err != nil {
				t.Fatalf("Cancel: %v", err)
			}
			mustStatus(t, l, lifecycleNowMS+5, StatusCancelled)
			mustStatus(t, l, lifecycleNowMS+10, StatusCancelled)

			if err := l.Confirm(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Confirm after cancel = %v, want ErrLifecycleTransition", err)
			}
			if err := l.Receive(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Receive after cancel = %v, want ErrLifecycleTransition", err)
			}
			if err := l.MarkUnknown(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("MarkUnknown after cancel = %v, want ErrLifecycleTransition", err)
			}
			if err := l.Cancel(lifecycleNowMS + 10); !errors.Is(err, ErrLifecycleTransition) {
				t.Fatalf("Cancel after cancel = %v, want ErrLifecycleTransition", err)
			}
		})
	}

	t.Run("received cannot be cancelled retroactively", func(t *testing.T) {
		l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
		if err := l.Confirm(lifecycleNowMS); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if err := l.Receive(lifecycleNowMS + 1); err != nil {
			t.Fatalf("Receive: %v", err)
		}
		if err := l.Cancel(lifecycleNowMS + 2); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("Cancel after receive = %v, want ErrLifecycleTransition", err)
		}
		if err := l.MarkUnknown(lifecycleNowMS + 2); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("MarkUnknown after receive = %v, want ErrLifecycleTransition", err)
		}
		mustStatus(t, l, lifecycleNowMS+2, StatusReceived)
	})
}

func TestLifecycleRequestedPhaseDeadlineBoundary(t *testing.T) {
	// The context deadline is far away, so the 30 s request phase cap applies.
	l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
	mustStatus(t, l, lifecycleNowMS+MaxActivePhaseMS-1, StatusRequested)

	// Expiry is now >= phaseDeadline, so the exact boundary is expired.
	mustStatus(t, l, lifecycleNowMS+MaxActivePhaseMS, StatusExpired)
	if err := l.Confirm(lifecycleNowMS + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("Confirm at phase boundary = %v, want ErrLifecycleTransition", err)
	}
	if err := l.Receive(lifecycleNowMS + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("Receive at phase boundary = %v, want ErrLifecycleTransition", err)
	}
	mustStatus(t, l, lifecycleNowMS+MaxActivePhaseMS+1, StatusExpired)
}

func TestLifecycleConfirmedPhaseIsRecomputed(t *testing.T) {
	ctx := lifecycleContext()
	confirmAt := lifecycleNowMS + 20_000
	l := mustLifecycle(t, ctx, lifecycleNowMS)
	if err := l.Confirm(confirmAt); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	// The confirmed phase runs 30 s from the transition, not from construction.
	mustStatus(t, l, confirmAt+1, StatusConfirmed)
	mustStatus(t, l, confirmAt+MaxActivePhaseMS-1, StatusConfirmed)
	mustStatus(t, l, confirmAt+MaxActivePhaseMS, StatusExpired)

	if err := l.Confirm(confirmAt + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("Confirm after expiry = %v, want ErrLifecycleTransition", err)
	}
	if err := l.Receive(confirmAt + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("Receive after expiry = %v, want ErrLifecycleTransition", err)
	}
	if err := l.MarkUnknown(confirmAt + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("MarkUnknown after expiry = %v, want ErrLifecycleTransition", err)
	}
	if err := l.Cancel(confirmAt + MaxActivePhaseMS); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("Cancel after expiry = %v, want ErrLifecycleTransition", err)
	}
}

func TestLifecycleConfirmedPhaseBeforeExpiryReceives(t *testing.T) {
	l := mustLifecycle(t, lifecycleContext(), lifecycleNowMS)
	confirmAt := lifecycleNowMS + 20_000
	if err := l.Confirm(confirmAt); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := l.Receive(confirmAt + MaxActivePhaseMS - 1); err != nil {
		t.Fatalf("Receive just before confirmed deadline: %v", err)
	}
	mustStatus(t, l, confirmAt+MaxActivePhaseMS-1, StatusReceived)
}

func TestLifecycleShorterRequestDeadline(t *testing.T) {
	t.Run("context deadline bounds requested phase", func(t *testing.T) {
		ctx := lifecycleContext()
		ctx.DeadlineUnixMS = lifecycleNowMS + 5_000
		l := mustLifecycle(t, ctx, lifecycleNowMS)
		if l.Context().DeadlineUnixMS != ctx.DeadlineUnixMS {
			t.Fatalf("context deadline rewritten to %d, want %d", l.Context().DeadlineUnixMS, ctx.DeadlineUnixMS)
		}
		mustStatus(t, l, lifecycleNowMS+4_999, StatusRequested)
		mustStatus(t, l, lifecycleNowMS+5_000, StatusExpired)
	})

	t.Run("context deadline bounds confirmed phase", func(t *testing.T) {
		ctx := lifecycleContext()
		ctx.DeadlineUnixMS = lifecycleNowMS + 40_000
		l := mustLifecycle(t, ctx, lifecycleNowMS)
		confirmAt := lifecycleNowMS + 19_000
		if err := l.Confirm(confirmAt); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		// min(confirmAt+30000, now+40000) = now+40000.
		mustStatus(t, l, lifecycleNowMS+39_999, StatusConfirmed)
		if err := l.Receive(lifecycleNowMS + 40_000); !errors.Is(err, ErrLifecycleTransition) {
			t.Fatalf("Receive at absolute deadline = %v, want ErrLifecycleTransition", err)
		}
		mustStatus(t, l, lifecycleNowMS+40_000, StatusExpired)
	})

	t.Run("deadline not after now is rejected", func(t *testing.T) {
		for _, deadline := range []int64{lifecycleNowMS, lifecycleNowMS - 1, 1} {
			ctx := lifecycleContext()
			ctx.DeadlineUnixMS = deadline
			if _, err := NewRequestLifecycle(ctx, lifecycleNowMS); !errors.Is(err, ErrLifecycleInvalidContext) {
				t.Fatalf("deadline %d: NewRequestLifecycle = %v, want ErrLifecycleInvalidContext", deadline, err)
			}
		}
	})
}

func TestDefaultRequestDeadlineUnixMS(t *testing.T) {
	def, err := DefaultRequestDeadlineUnixMS(lifecycleNowMS)
	if err != nil {
		t.Fatalf("DefaultRequestDeadlineUnixMS: %v", err)
	}
	if def != lifecycleNowMS+120_000 {
		t.Fatalf("DefaultRequestDeadlineUnixMS(%d) = %d, want %d", lifecycleNowMS, def, lifecycleNowMS+120_000)
	}
	if got, err := DefaultRequestDeadlineUnixMS(1); err != nil || got != 120_001 {
		t.Fatalf("DefaultRequestDeadlineUnixMS(1) = %d, %v; want 120001, nil", got, err)
	}
	maxNow := int64(math.MaxInt64) - DefaultRequestTTLMS
	if got, err := DefaultRequestDeadlineUnixMS(maxNow); err != nil || got != math.MaxInt64 {
		t.Fatalf("DefaultRequestDeadlineUnixMS(max-ttl) = %d, %v; want MaxInt64, nil", got, err)
	}

	for _, now := range []int64{0, -1, math.MinInt64} {
		if _, err := DefaultRequestDeadlineUnixMS(now); !errors.Is(err, ErrLifecycleInvalidTime) {
			t.Fatalf("DefaultRequestDeadlineUnixMS(%d) = %v, want ErrLifecycleInvalidTime", now, err)
		}
	}
	for _, now := range []int64{maxNow + 1, math.MaxInt64} {
		if _, err := DefaultRequestDeadlineUnixMS(now); !errors.Is(err, ErrLifecycleInvalidTime) {
			t.Fatalf("DefaultRequestDeadlineUnixMS(%d) = %v, want overflow error", now, err)
		}
	}

	// A context carrying the default deadline is accepted at its origin and
	// stops being a lifecycle request exactly when the TTL elapses.
	ctx := lifecycleContext()
	ctx.DeadlineUnixMS = def
	l, err := NewRequestLifecycle(ctx, 1)
	if err != nil {
		t.Fatalf("NewRequestLifecycle with default deadline: %v", err)
	}
	// The 30 s requested phase cap first expires the lifecycle; the two-minute
	// deadline only matters while a phase stays active.
	if got, err := l.StatusAt(MaxActivePhaseMS - 1); got != StatusRequested || err != nil {
		t.Fatalf("StatusAt(29999) = %q, %v; want requested, nil", got, err)
	}
	if got, err := l.StatusAt(119_999); got != StatusExpired || err != nil {
		t.Fatalf("StatusAt(119999) = %q, %v; want expired, nil", got, err)
	}
	if got, err := l.StatusAt(120_000); got != StatusExpired || err != nil {
		t.Fatalf("StatusAt(120000) = %q, %v; want expired, nil", got, err)
	}
	// ctx.DeadlineUnixMS == DefaultRequestTTLMS+1; that exact instant is not
	// strictly after the supplied now.
	if _, err := NewRequestLifecycle(ctx, def); !errors.Is(err, ErrLifecycleInvalidContext) {
		t.Fatalf("NewRequestLifecycle at deadline = %v, want ErrLifecycleInvalidContext", err)
	}
}

func TestNewRequestLifecycleRejectsInvalidInput(t *testing.T) {
	t.Run("invalid contexts", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*ChannelBindingContext)
		}{
			{"zero context", func(c *ChannelBindingContext) { *c = ChannelBindingContext{} }},
			{"empty request id", func(c *ChannelBindingContext) { c.RequestID = "" }},
			{"uppercase vault id", func(c *ChannelBindingContext) { c.VaultID = "VAULT" }},
			{"overlong member id", func(c *ChannelBindingContext) { c.MemberID = strings.Repeat("m", MaxIdentifierLen+1) }},
			{"zero key epoch", func(c *ChannelBindingContext) { c.KeyEpoch = 0 }},
			{"zero deadline", func(c *ChannelBindingContext) { c.DeadlineUnixMS = 0 }},
			{"negative deadline", func(c *ChannelBindingContext) { c.DeadlineUnixMS = -1 }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := lifecycleContext()
				tt.mutate(&ctx)
				if _, err := NewRequestLifecycle(ctx, lifecycleNowMS); !errors.Is(err, ErrLifecycleInvalidContext) {
					t.Fatalf("NewRequestLifecycle = %v, want ErrLifecycleInvalidContext", err)
				}
			})
		}
	})

	t.Run("non-positive now", func(t *testing.T) {
		for _, now := range []int64{0, -1} {
			if _, err := NewRequestLifecycle(lifecycleContext(), now); !errors.Is(err, ErrLifecycleInvalidTime) {
				t.Fatalf("now %d: NewRequestLifecycle = %v, want ErrLifecycleInvalidTime", now, err)
			}
		}
	})

	t.Run("phase overflow", func(t *testing.T) {
		// now+30 s would overflow int64 before the context deadline is applied.
		ctx := logicContextWithDeadline(math.MaxInt64)
		if _, err := NewRequestLifecycle(ctx, math.MaxInt64-MaxActivePhaseMS+1); !errors.Is(err, ErrLifecycleInvalidTime) {
			t.Fatalf("NewRequestLifecycle = %v, want ErrLifecycleInvalidTime", err)
		}
	})

	t.Run("context preserved", func(t *testing.T) {
		ctx := lifecycleContext()
		l, err := NewRequestLifecycle(ctx, lifecycleNowMS)
		if err != nil {
			t.Fatalf("NewRequestLifecycle: %v", err)
		}
		// Mutating the caller copy cannot alter the stored context.
		ctx.DeadlineUnixMS = 1
		if l.Context().DeadlineUnixMS != lifecycleNowMS+600_000 {
			t.Fatalf("stored deadline changed to %d", l.Context().DeadlineUnixMS)
		}
	})
}

func logicContextWithDeadline(deadline int64) ChannelBindingContext {
	c := vectorContext()
	c.DeadlineUnixMS = deadline
	return c
}

func TestLifecycleStringsDoNotLeakContextValues(t *testing.T) {
	c := vectorContext()
	c.DeadlineUnixMS = lifecycleNowMS + 600_000
	secrets := []string{
		c.RequestID,
		c.PairID,
		c.MemberID,
		c.SourceDeviceID,
		c.TargetDeviceID,
		c.VaultID,
		base64.RawURLEncoding.EncodeToString(c.RequestDigest[:]),
		base64.RawURLEncoding.EncodeToString(c.PolicyDigest[:]),
		strconv.FormatInt(c.DeadlineUnixMS, 10),
	}
	// Also probe with distinctive values so a substring match is unlikely to
	// collide with static wording.
	probe := vectorContext()
	probe.RequestID = "leakprobe-request"
	probe.PairID = "leakprobe-pair"
	probe.MemberID = "leakprobe-member"
	probe.SourceDeviceID = "leakprobe-source"
	probe.TargetDeviceID = "leakprobe-target"
	probe.VaultID = "leakprobe-vault"
	probe.RequestDigest[0] = 0xee
	probe.PolicyDigest[0] = 0xff
	probe.DeadlineUnixMS = lifecycleNowMS + 777_777
	secrets = append(secrets, "leakprobe",
		base64.RawURLEncoding.EncodeToString(probe.RequestDigest[:]),
		base64.RawURLEncoding.EncodeToString(probe.PolicyDigest[:]),
		strconv.FormatInt(probe.DeadlineUnixMS, 10))

	var messages []string
	for _, ctx := range []ChannelBindingContext{c, probe} {
		l := mustLifecycle(t, ctx, lifecycleNowMS)
		check := func(err error) {
			if err != nil {
				messages = append(messages, err.Error())
			}
		}
		for _, now := range []int64{0, -1} {
			check(l.Receive(now))
			check(l.Confirm(now))
			check(l.MarkUnknown(now))
			check(l.Cancel(now))
			if _, err := l.StatusAt(now); err != nil {
				messages = append(messages, err.Error())
			}
		}
		check(l.Receive(lifecycleNowMS))
		if err := l.Confirm(lifecycleNowMS); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		check(l.Confirm(lifecycleNowMS))
		if err := l.Receive(lifecycleNowMS + 1); err != nil {
			t.Fatalf("Receive: %v", err)
		}
		check(l.Receive(lifecycleNowMS + 1))
		check(l.Cancel(lifecycleNowMS + 1))
	}

	// Constructor rejections also carry static messages.
	bad := probe
	bad.VaultID = "LEAKPROBEUPPER"
	_, err := NewRequestLifecycle(bad, lifecycleNowMS)
	if err == nil {
		t.Fatal("expected constructor error for invalid identifier")
	}
	messages = append(messages, err.Error())
	_, err = NewRequestLifecycle(probe, probe.DeadlineUnixMS)
	if err == nil {
		t.Fatal("expected constructor error for elapsed deadline")
	}
	messages = append(messages, err.Error())

	if len(messages) < 10 {
		t.Fatalf("collected only %d error messages", len(messages))
	}
	for _, msg := range messages {
		for _, s := range secrets {
			if strings.Contains(msg, s) {
				t.Fatalf("message %q leaked context value %q", msg, s)
			}
		}
	}

	statuses := []string{StatusRequested, StatusConfirmed, StatusReceived, StatusUnknown, StatusCancelled, StatusExpired}
	for _, st := range statuses {
		for _, s := range secrets {
			if strings.Contains(st, s) {
				t.Fatalf("status %q leaked context value %q", st, s)
			}
		}
	}
}

// TestLifecycleFreshInstanceDoesNotRecognizePriorState documents the scope
// boundary: a new instance starts in requested and does not know that a prior
// instance consumed the request. Replay rejection is the caller's job through
// fresh request state and the real TLS exporter binding.
func TestLifecycleFreshInstanceDoesNotRecognizePriorState(t *testing.T) {
	ctx := lifecycleContext()
	first := mustLifecycle(t, ctx, lifecycleNowMS)
	if err := first.Confirm(lifecycleNowMS); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := first.Receive(lifecycleNowMS + 1); err != nil {
		t.Fatalf("Receive: %v", err)
	}

	second := mustLifecycle(t, ctx, lifecycleNowMS+2)
	mustStatus(t, second, lifecycleNowMS+2, StatusRequested)
	if err := second.Confirm(lifecycleNowMS + 3); err != nil {
		t.Fatalf("Confirm on fresh instance: %v", err)
	}
}
