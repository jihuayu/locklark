package personal

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file owns the revocation lifecycle of session-native run bundle grants.
// It only exercises private state from inside the package: the captured byte
// slices are never printed, marshalled or turned into strings, they exist to
// prove that a revocation path zeroes the very backing array that was handed to
// the native caller.

// runBundleGrantBacking captures the live credential backing arrays of one
// grant without copying them. Capture happens while the grant is unused, so the
// slices are stable until a revocation path zeroes them in place.
func runBundleGrantBacking(t *testing.T, g *NativeRunBundleGrant) [][]byte {
	t.Helper()
	if g == nil || g.state == nil {
		t.Fatal("lifecycle fixture has no grant state")
	}
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	backing := make([][]byte, 0, len(g.state.values))
	for _, value := range g.state.values {
		if len(value) == 0 {
			t.Fatal("lifecycle fixture prepared an empty slot")
		}
		backing = append(backing, value)
	}
	if len(backing) == 0 {
		t.Fatal("lifecycle fixture prepared no slots")
	}
	return backing
}

// runBundleGrantNeedZeroed asserts that every captured backing byte was zeroed
// in place, which is the only revocation evidence a caller can never observe.
func runBundleGrantNeedZeroed(t *testing.T, backing [][]byte, where string) {
	t.Helper()
	if len(backing) == 0 {
		t.Fatalf("%s: no captured backing arrays", where)
	}
	for i, value := range backing {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("%s: slot %d backing array still holds bytes", where, i)
			}
		}
	}
}

// runBundleGrantNeedLive asserts that a captured backing array is untouched,
// which is how a foreign or stale revocation path proves it did nothing.
func runBundleGrantNeedLive(t *testing.T, backing [][]byte, where string) {
	t.Helper()
	for _, value := range backing {
		for _, b := range value {
			if b != 0 {
				return
			}
		}
	}
	t.Fatalf("%s: captured grant had already been zeroed", where)
}

// runBundleGrantRegistered reports whether the owning session still tracks the
// grant as resident state.
func runBundleGrantRegistered(s *Session, g *NativeRunBundleGrant) bool {
	if g == nil || g.state == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runBundleGrants[g.state]
}

// runBundleGrantRegistrySize reports how many grants the session still owns.
func runBundleGrantRegistrySize(s *Session) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runBundleGrants)
}

// runBundleGrantTimerOf reports the armed deadline timer of a grant.
func runBundleGrantTimerOf(g *NativeRunBundleGrant) *time.Timer {
	if g == nil || g.state == nil {
		return nil
	}
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	return g.state.timer
}

func runBundleGrantGenOf(g *NativeRunBundleGrant) uint64 {
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	return g.state.gen
}

// TestRunBundleGrantLockZeroesUndeliveredGrant is the regression this lifecycle
// exists for: a prepared grant that is never consumed must not survive Lock.
// The assertions run immediately after Lock returns, with no Consume and no
// grace period, so a TTL timestamp alone can never satisfy them.
func TestRunBundleGrantLockZeroesUndeliveredGrant(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	backing := runBundleGrantBacking(t, grant)
	if !runBundleGrantRegistered(s, grant) {
		t.Fatal("a validated prepare did not register its grant with the session")
	}
	if runBundleGrantTimerOf(grant) == nil {
		t.Fatal("a registered grant has no owned deadline timer")
	}
	if got := runBundleGrantRegistrySize(s); got != 1 {
		t.Fatalf("session owns %d grants, want 1", got)
	}

	s.Lock()
	runBundleGrantNeedZeroed(t, backing, "lock without consume")
	if runBundleGrantRegistered(s, grant) {
		t.Fatal("Lock left an undelivered grant in the session registry")
	}
	if runBundleGrantTimerOf(grant) != nil {
		t.Fatal("Lock left the grant deadline timer armed")
	}
	if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
		t.Fatal("Lock left grant state resident")
	}
	if got := runBundleGrantRegistrySize(s); got != 0 {
		t.Fatalf("Lock returned with %d owned grants", got)
	}
	called := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrSessionLocked || called != 0 {
		t.Fatalf("a locked session delivered a grant: %v (called %d)", err, called)
	}
	// Repeated Lock stays harmless and still leaves no owned state behind.
	s.Lock()
	if got := runBundleGrantRegistrySize(s); got != 0 {
		t.Fatalf("second Lock left %d owned grants", got)
	}
}

// TestRunBundleGrantDeadlineZeroesUnconsumedGrant drives the owned deadline
// callback through the private lifetime seam, so the real callback runs without
// waiting for the production 30 second ceiling.
func TestRunBundleGrantDeadlineZeroesUnconsumedGrant(t *testing.T) {
	previous := runBundleGrantTTL
	runBundleGrantTTL = func() time.Duration { return 25 * time.Millisecond }
	t.Cleanup(func() { runBundleGrantTTL = previous })

	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	backing := runBundleGrantBacking(t, grant)
	if remaining := grant.state.until.Sub(time.Now()); remaining <= 0 || remaining > 25*time.Millisecond {
		t.Fatalf("prepared deadline %v did not use the private test lifetime", remaining)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for runBundleGrantRegistered(s, grant) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runBundleGrantRegistered(s, grant) {
		t.Fatal("the owned deadline callback did not unregister the grant within 100ms")
	}
	runBundleGrantNeedZeroed(t, backing, "deadline without consume")
	if runBundleGrantTimerOf(grant) != nil {
		t.Fatal("the deadline callback left its timer armed")
	}
	if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
		t.Fatal("an expired grant kept its slot entries")
	}
	if got := runBundleGrantRegistrySize(s); got != 0 {
		t.Fatalf("an expired grant left %d registry entries", got)
	}
	called := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("an expired grant was delivered: %v (called %d)", err, called)
	}
}

// TestRunBundleGrantRegistryCapacityRefusesAndClearFreesIt proves the registry
// is bounded, that a full registry refuses before any intent exists, and that
// Clear frees capacity for the very next Prepare without Consume or Lock.
func TestRunBundleGrantRegistryCapacityRefusesAndClearFreesIt(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	grants := make([]*NativeRunBundleGrant, 0, maxRunBundleGrants)
	backing := make([][][]byte, 0, maxRunBundleGrants)
	for i := 0; i < maxRunBundleGrants; i++ {
		grant := runBundleGrantPrepare(t, s, targets, request)
		grants = append(grants, grant)
		backing = append(backing, runBundleGrantBacking(t, grant))
	}
	if got := runBundleGrantRegistrySize(s); got != maxRunBundleGrants {
		t.Fatalf("session owns %d grants, want %d", got, maxRunBundleGrants)
	}

	beforeEvents := runBundleGrantAudit(t, f)
	beforeIntents := runBundleGrantIntentCount(beforeEvents)
	beforeIntent := runBundleGrantLastIntent(t, beforeEvents)
	refused, err := s.PrepareRunBundleGrant(context.Background(), targets, request, filepath.Join(t.TempDir(), "client-root"))
	if err != ErrRunBundleGrant || refused != nil {
		t.Fatalf("a full registry accepted another prepare: %v", err)
	}
	// The audit read itself journals exactly one audit.list disclosure event, so
	// the refusal proof is: one new event, that event is the read, every earlier
	// event kept its hash, and no run bundle intent was appended.
	afterEvents := runBundleGrantAudit(t, f)
	if len(afterEvents) != len(beforeEvents)+1 || afterEvents[len(beforeEvents)].Action != "audit.list" {
		t.Fatalf("a capacity refusal appended a journal event other than the audit read: %d -> %d", len(beforeEvents), len(afterEvents))
	}
	for i := range beforeEvents {
		if afterEvents[i].hash() != beforeEvents[i].hash() {
			t.Fatal("a capacity refusal changed an existing journal event")
		}
	}
	if got := runBundleGrantIntentCount(afterEvents); got != beforeIntents {
		t.Fatalf("a capacity refusal committed %d run bundle intents", got-beforeIntents)
	}
	if last := runBundleGrantLastIntent(t, afterEvents); last.hash() != beforeIntent.hash() {
		t.Fatal("a capacity refusal replaced the last committed run bundle intent")
	}
	if got := runBundleGrantRegistrySize(s); got != maxRunBundleGrants {
		t.Fatalf("a capacity refusal consumed a registry slot: %d", got)
	}
	for i := range backing {
		runBundleGrantNeedLive(t, backing[i], fmt.Sprintf("capacity refusal %d", i))
	}

	for i, grant := range grants {
		grant.Clear()
		runBundleGrantNeedZeroed(t, backing[i], fmt.Sprintf("clear %d", i))
		if runBundleGrantTimerOf(grant) != nil {
			t.Fatalf("Clear left grant %d's timer armed", i)
		}
	}
	// Clear is a grant-local operation: the bounded registry entry may stay until
	// the next Prepare prunes it.
	if got := runBundleGrantRegistrySize(s); got > maxRunBundleGrants {
		t.Fatalf("revoked grants exceeded the registry bound: %d", got)
	}
	reused := runBundleGrantPrepare(t, s, targets, request)
	if !runBundleGrantRegistered(s, reused) {
		t.Fatal("the replacement grant is not registered")
	}
	if got := runBundleGrantRegistrySize(s); got != 1 {
		t.Fatalf("Prepare did not prune revoked grants: %d entries remain", got)
	}
}

// TestRunBundleGrantForeignSessionLockCannotCancelGrant keeps the foreign
// guarantee on the new registry: another session's Lock, even one that is
// locked, cannot unregister, stop or zero the owner's grant.
func TestRunBundleGrantForeignSessionLockCannotCancelGrant(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	backing := runBundleGrantBacking(t, grant)
	other := runBundleGrantUnlock(t, f, time.Minute)
	called := 0
	if err := other.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("foreign session consumed a grant: %v (called %d)", err, called)
	}
	other.Lock()
	if !runBundleGrantRegistered(s, grant) {
		t.Fatal("a foreign Lock unregistered the owner's grant")
	}
	if runBundleGrantTimerOf(grant) == nil {
		t.Fatal("a foreign Lock stopped the owner's deadline timer")
	}
	runBundleGrantNeedLive(t, backing, "foreign lock")
	delivered := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
		delivered++
		if !bytes.Equal(values["password"], []byte(bundleTestPassword)) || !bytes.Equal(values["username"], []byte(bundleTestUsername)) {
			t.Error("owner delivery changed after a foreign Lock")
		}
		return nil
	}); err != nil || delivered != 1 {
		t.Fatalf("owner delivery after a foreign Lock: %v (called %d)", err, delivered)
	}
	runBundleGrantNeedZeroed(t, backing, "owner delivery after foreign lock")
}

// TestRunBundleGrantStaleDeadlineCannotClearReplacement proves the generation
// and registry identity checks: a callback that belongs to a revoked
// registration must never unregister or zero a later grant.
func TestRunBundleGrantStaleDeadlineCannotClearReplacement(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	revoked := runBundleGrantPrepare(t, s, targets, request)
	gen := runBundleGrantGenOf(revoked)
	revokedBacking := runBundleGrantBacking(t, revoked)
	revoked.Clear()
	runBundleGrantNeedZeroed(t, revokedBacking, "revoked grant")

	replacement := runBundleGrantPrepare(t, s, targets, request)
	replacementBacking := runBundleGrantBacking(t, replacement)
	if runBundleGrantRegistered(s, revoked) {
		t.Fatal("the revoked grant stayed in the registry after the next prepare")
	}
	// A queued callback from the revoked registration is stale: it carries the
	// revoked state pointer, and the registry is keyed by exact state identity.
	s.expireRunBundleGrant(revoked.state, gen)
	if !runBundleGrantRegistered(s, replacement) {
		t.Fatal("a stale deadline unregistered the replacement grant")
	}
	if runBundleGrantRegistered(s, revoked) {
		t.Fatal("a stale deadline re-registered the revoked grant")
	}
	// A mismatched generation for the live state is equally harmless: the guard is
	// per registration, so an older timer of the same state cannot clear a newer
	// one, and it leaves the state and its timer untouched.
	s.expireRunBundleGrant(replacement.state, runBundleGrantGenOf(replacement)+1)
	if !runBundleGrantRegistered(s, replacement) {
		t.Fatal("a mismatched generation unregistered the replacement grant")
	}
	if runBundleGrantTimerOf(replacement) == nil {
		t.Fatal("a stale deadline stopped the replacement grant's timer")
	}
	runBundleGrantNeedLive(t, replacementBacking, "stale deadline")
	if runBundleGrantValuesOf(replacement) == nil {
		t.Fatal("a stale deadline zeroed the replacement grant")
	}
	delivered := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), replacement, func(map[string][]byte, RunBundleGrantReceipt) error {
		delivered++
		return nil
	}); err != nil || delivered != 1 {
		t.Fatalf("replacement delivery after a stale deadline: %v (called %d)", err, delivered)
	}
	runBundleGrantNeedZeroed(t, replacementBacking, "replacement delivery")
}

// TestRunBundleGrantLockClearConsumeRace runs the three revocation paths at
// once. It asserts a single callback, no deadlock from a reentrant Clear inside
// that callback, no mid-callback zeroization of borrowed bytes, and no resident
// grant state once Lock has returned.
func TestRunBundleGrantLockClearConsumeRace(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	for round := 0; round < 4; round++ {
		session := s
		if round > 0 {
			session = runBundleGrantUnlock(t, f, time.Minute)
		}
		grant := runBundleGrantPrepare(t, session, targets, request)
		backing := runBundleGrantBacking(t, grant)
		var callbacks atomic.Int32
		start := make(chan struct{})
		var workers sync.WaitGroup

		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_ = session.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
				callbacks.Add(1)
				// Clear and Discard from inside the callback take only the grant
				// mutex, so they must not deadlock and must not zero borrowed bytes.
				grant.Clear()
				grant.Discard()
				if !bytes.Equal(values["password"], []byte(bundleTestPassword)) || !bytes.Equal(values["username"], []byte(bundleTestUsername)) {
					t.Error("a reentrant Clear disturbed borrowed bytes during delivery")
				}
				return nil
			})
		}()
		for i := 0; i < 2; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				grant.Clear()
				grant.Discard()
			}()
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			session.Lock()
		}()

		close(start)
		finished := make(chan struct{})
		go func() {
			workers.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: Lock, Clear and Consume deadlocked", round)
		}
		if got := callbacks.Load(); got > 1 {
			t.Fatalf("round %d: %d callbacks ran for one grant", round, got)
		}
		runBundleGrantNeedZeroed(t, backing, fmt.Sprintf("round %d", round))
		if got := runBundleGrantRegistrySize(session); got != 0 {
			t.Fatalf("round %d: Lock returned with %d resident grants", round, got)
		}
		if runBundleGrantTimerOf(grant) != nil {
			t.Fatalf("round %d: a deadline timer survived Lock", round)
		}
		called := 0
		if err := session.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
			called++
			return nil
		}); err != nil && err != ErrRunBundleGrant && err != ErrSessionLocked || called != 0 {
			t.Fatalf("round %d: late second delivery: %v (called %d)", round, err, called)
		}
	}
}
