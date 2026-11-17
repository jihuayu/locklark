package desktop

import (
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

// revealPendingFixture enables the preference and selects a login item with a
// queued dispatcher, so the tests control when asynchronous results land.
func revealPendingFixture(t *testing.T) (*App, string, string, *[]func()) {
	t.Helper()
	a, revision := revealRuntimeFixture(t, vault.Item{Kind: "login", Category: vault.CategoryLogin, Title: "pending target", Password: "secret-value"})
	id := a.v2.rows[0].ID
	if err := a.SetRevealPasswords(true); err != nil {
		t.Fatal(err)
	}
	pending := new([]func())
	a.dispatch = func(fn func()) { *pending = append(*pending, fn) }
	drain := func() {
		for len(*pending) > 0 {
			next := (*pending)[0]
			*pending = (*pending)[1:]
			next()
		}
	}
	a.selectItem(id, revision)
	drain()
	return a, id, revision, pending
}

func TestRevealPasswordsBusyKeepsScheduleForRetry(t *testing.T) {
	a, id, revision, pending := revealPendingFixture(t)
	if newOnevraTestTester(a).HasText("secret-value") {
		t.Fatal("precondition: password revealed before the deferred read")
	}
	// Another operation holds the single worker slot. The tick must not
	// consume the schedule, and the untaken request must not arm pending, so
	// a later tick retries.
	a.busy = true
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if a.narrowRevealPending || a.defaultRevealAt.IsZero() || len(*pending) != 0 {
		t.Fatal("a busy worker slot consumed the default reveal schedule or armed pending")
	}
	a.busy = false
	// Let the busy selection read finish, as the real dispatcher would.
	for len(*pending) > 0 {
		next := (*pending)[0]
		*pending = (*pending)[1:]
		next()
	}
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if !a.narrowRevealPending || !a.defaultRevealAt.IsZero() || len(*pending) == 0 {
		t.Fatal("retry after busy did not start the narrow read")
	}
	a.dispatch = func(fn func()) { fn() }
	for len(*pending) > 0 {
		next := (*pending)[0]
		*pending = (*pending)[1:]
		next()
	}
	if a.narrowRevealPending || !a.defaultRevealAt.IsZero() || !a.v2.narrowPassword.current(id, revision, time.Now()) {
		t.Fatal("retried read did not disclose the password and clear pending")
	}
}

func TestRevealPasswordsPrepareErrorClearsPending(t *testing.T) {
	a, _, revision, pending := revealPendingFixture(t)
	// A stale revision makes PrepareField return a plain error (no delivered
	// field, no drop callback), exactly the path runContext does not clean up.
	stale := []byte(revision)
	if stale[len(stale)-1] == '0' {
		stale[len(stale)-1] = '1'
	} else {
		stale[len(stale)-1] = '0'
	}
	a.v2.detail.Revision = string(stale)
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if !a.narrowRevealPending || len(*pending) == 0 {
		t.Fatal("precondition: disclosure read did not start")
	}
	for len(*pending) > 0 {
		next := (*pending)[0]
		*pending = (*pending)[1:]
		next()
	}
	if a.narrowRevealPending {
		t.Fatal("failed PrepareField left narrowRevealPending set forever")
	}
	if a.v2.narrowPassword.value != nil {
		t.Fatal("failed PrepareField disclosed a value")
	}
}

func TestRevealPasswordsLockReleasesPending(t *testing.T) {
	a, _, _, pending := revealPendingFixture(t)
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if !a.narrowRevealPending || len(*pending) == 0 {
		t.Fatal("precondition: disclosure read did not start")
	}
	a.Lock()
	for len(*pending) > 0 {
		next := (*pending)[0]
		*pending = (*pending)[1:]
		next()
	}
	if a.narrowRevealPending {
		t.Fatal("lock left a superseded disclosure read pending")
	}
}

func TestRevealPasswordsStaleCallbackKeepsNewerPending(t *testing.T) {
	a, _, _, pending := revealPendingFixture(t)
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if !a.narrowRevealPending || len(*pending) == 0 {
		t.Fatal("precondition: first read did not start")
	}
	// While the first read is still queued, a newer request takes ownership of
	// pending. Its stale callback must leave the newer request alone.
	a.narrowRevealSeq++
	a.narrowRevealPending = true
	for len(*pending) > 0 {
		next := (*pending)[0]
		*pending = (*pending)[1:]
		next()
	}
	if !a.narrowRevealPending {
		t.Fatal("stale callback cleared a newer request's pending flag")
	}
}
