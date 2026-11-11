package osunlock

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCapabilityCacheRechecksAfterTTL pins the macOS edge case in #102: a
// capability decision must expire instead of living for the whole process, so
// opening the lid or attaching a biometric keyboard is observed without a
// restart, while repeated renders inside the window reuse one probe.
func TestCapabilityCacheRechecksAfterTTL(t *testing.T) {
	var cache capabilityCache
	var probes atomic.Int32
	probe := func() string {
		if probes.Add(1) == 1 {
			return "不可用"
		}
		return "Touch ID"
	}
	clockAt := func(t time.Time) func() time.Time { return func() time.Time { return t } }
	start := time.Unix(1000, 0)
	if got := cache.get(clockAt(start), time.Second, probe); got != "不可用" {
		t.Fatalf("first probe = %q", got)
	}
	if got := cache.get(clockAt(start.Add(900*time.Millisecond)), time.Second, probe); got != "不可用" || probes.Load() != 1 {
		t.Fatalf("within-window probe = %q probes=%d", got, probes.Load())
	}
	if got := cache.get(clockAt(start.Add(time.Second)), time.Second, probe); got != "Touch ID" || probes.Load() != 2 {
		t.Fatalf("expired-window probe = %q probes=%d", got, probes.Load())
	}
	// A clock that moved backwards must not pin a stale answer.
	if got := cache.get(clockAt(start), time.Second, probe); got != "Touch ID" || probes.Load() != 3 {
		t.Fatalf("backwards-clock probe = %q probes=%d", got, probes.Load())
	}
}

func TestCapabilityCacheConcurrent(t *testing.T) {
	var cache capabilityCache
	var probes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.get(time.Now, time.Minute, func() string { probes.Add(1); return "Touch ID" })
		}()
	}
	wg.Wait()
	if probes.Load() != 1 {
		t.Fatalf("concurrent callers probed %d times", probes.Load())
	}
	if got := cache.get(time.Now, time.Minute, func() string { return "other" }); got != "Touch ID" {
		t.Fatalf("within-window probe = %q", got)
	}
}

// TestCapabilityCacheSamplesClockUnderLock pins the timestamp race: callers
// that sample their time before the mutex can acquire it out of order, so a
// later sample commits first and an earlier one then appears to travel
// backwards and forces a redundant probe. The clock is therefore read while the
// mutex is held; the clock callback proves it by finding the lock unavailable.
func TestCapabilityCacheSamplesClockUnderLock(t *testing.T) {
	var cache capabilityCache
	now := time.Unix(2000, 0)
	clock := func() time.Time {
		if cache.mu.TryLock() {
			cache.mu.Unlock()
			t.Fatal("clock called outside the cache lock")
		}
		return now
	}
	if got := cache.get(clock, time.Minute, func() string { return "Touch ID" }); got != "Touch ID" {
		t.Fatalf("first probe = %q", got)
	}
	if got := cache.get(clock, time.Minute, func() string { return "other" }); got != "Touch ID" {
		t.Fatalf("within-window probe = %q", got)
	}
}

// TestDeleteBothAttemptsSecretAfterCredentialFailure pins the Windows edge case
// in #102: a failed native credential deletion must not skip removing the
// wrapped secret, and every failure still collapses to the fixed error.
func TestDeleteBothAttemptsSecretAfterCredentialFailure(t *testing.T) {
	failure := errors.New("native failure")
	for _, tc := range []struct {
		name                 string
		credential, secret   error
		wantSecretDeleteCall bool
		want                 error
	}{
		{"credential-fails", failure, nil, true, ErrUnavailable},
		{"secret-fails", nil, failure, true, ErrUnavailable},
		{"both-fail", failure, failure, true, ErrUnavailable},
		{"both-succeed", nil, nil, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secretDeleted := false
			got := deleteBoth(func() error { return tc.credential }, func() error {
				secretDeleted = true
				return tc.secret
			})
			if !errors.Is(got, tc.want) {
				t.Fatalf("deleteBoth = %v, want %v", got, tc.want)
			}
			if secretDeleted != tc.wantSecretDeleteCall {
				t.Fatalf("secret delete called = %v", secretDeleted)
			}
		})
	}
}
