package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
)

// maxRunBundleGrantLifetime bounds how long a prepared bundle may wait for its
// native caller. Every grant is capped again by the session idle deadline.
const maxRunBundleGrantLifetime = 30 * time.Second

// maxRunBundleGrants bounds how many prepared, undelivered grants one session
// may keep resident. The registry is an owner list, not a disclosure cache, so
// exceeding it refuses before any intent is journaled.
const maxRunBundleGrants = 8

// runBundleGrantTTL is the private deadline seam used when Prepare arms the
// owned expiry callback. No caller can choose a lifetime: the seam is
// unexported, only this package's tests narrow it, and every grant is still
// capped by the session idle window.
var runBundleGrantTTL = func() time.Duration { return maxRunBundleGrantLifetime }

// ErrRunBundleGrant reports a grant that is unknown, expired, already consumed
// or bound to another session. Delivery state is unknown and never inferred.
var ErrRunBundleGrant = errors.New("run bundle grant refused, expired or already consumed")

// runBundleBeforeClaim is an unexported test seam placed after the session
// activity check and before the claim gate. Production leaves it as a no-op;
// tests use it to pause inside the exact window a concurrent lock must win.
var runBundleBeforeClaim = func() {}

// RunBundleGrantReceipt is the non-secret binding of one prepared bundle. It
// records authorization only and never claims that a process ran.
type RunBundleGrantReceipt struct {
	Session      string
	Intent       string
	TargetDigest string
}

// runBundleGrantState owns every mutable and private part of one grant. The
// public grant only points at it, so formatting or copying the public value can
// never copy a mutex or reach a credential byte.
//
// mu serializes ownership changes between Consume, Clear, Discard and the owned
// deadline callback. Every Consume attempt is additionally serialized by the
// owning Session mutex. mu is never held across the caller callback, so Clear
// and Discard can never deadlock against a delivery in progress.
//
// Lock order is always Session.mu then state.mu. Clear and Discard deliberately
// take only state.mu, because they may be called reentrantly from a Consume
// callback that already owns Session.mu.
type runBundleGrantState struct {
	mu      sync.Mutex
	values  map[string][]byte
	receipt RunBundleGrantReceipt
	until   time.Time
	owner   *Session
	used    bool
	// timer is the owned deadline callback and gen identifies the registration
	// that armed it. A callback whose generation no longer matches, or whose
	// state left the registry, stops itself without touching bytes.
	timer *time.Timer
	gen   uint64
}

// NativeRunBundleGrant is a one-use, session-bound bundle disclosure. Values
// are private bytes borrowed by the consume callback; this type never renders
// them to a filesystem, log, map marshaller or string.
type NativeRunBundleGrant struct {
	state *runBundleGrantState
}

func (NativeRunBundleGrant) MarshalJSON() ([]byte, error) { return nil, ErrRunBundleGrant }
func (NativeRunBundleGrant) String() string               { return "[native run bundle grant]" }
func (NativeRunBundleGrant) GoString() string             { return "[native run bundle grant]" }

// Clear zeroes every disclosed byte and drops the slot entries. It is safe to
// call repeatedly, from any goroutine, and after consumption; a grant whose
// values are currently borrowed by a consume callback is left untouched because
// that callback owns them and Consume zeros them on return.
//
// Clear takes only the grant mutex, so it also works reentrantly from inside a
// Consume callback, which already owns the session mutex. A revoked grant stays
// in the bounded session registry until the next Prepare prunes it or Lock
// clears it; both happen before any capacity decision, so revocation frees a
// slot immediately.
func (g *NativeRunBundleGrant) Clear() {
	if g == nil || g.state == nil {
		return
	}
	g.state.revoke()
}

// Discard is an explicit discard of an unused grant. It behaves exactly like
// Clear and never returns credential material.
func (g *NativeRunBundleGrant) Discard() { g.Clear() }

// revoke zeroes an unused grant and stops its owned timer. Bytes already
// borrowed by a delivery are untouched: used is set before the callback runs,
// so the callback keeps exclusive ownership until Consume retires the state.
func (g *runBundleGrantState) revoke() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used {
		return
	}
	g.stopTimerLocked()
	g.discardLocked()
}

func (g *runBundleGrantState) stopTimerLocked() {
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
}

// discardLocked zeroes the disclosed bytes and drops every binding except the
// owner. The owner stays so a later Consume can still tell "this session's own
// revoked grant" (a lock or expiry) from "another session's grant" (foreign).
func (g *runBundleGrantState) discardLocked() {
	clearBundleValues(g.values)
	g.values = nil
	g.receipt = RunBundleGrantReceipt{}
	g.until = time.Time{}
	g.used = true
}

// dead reports whether this grant can never be delivered again: it was already
// consumed, explicitly cleared or revoked, or its deadline passed.
func (g *runBundleGrantState) dead(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.used || !now.Before(g.until)
}

// expire is the deadline transition. It only zeroes the grant when the
// registration generation still matches and the grant was not consumed or
// revoked first, so a stale timer can never clear a replacement state.
func (g *runBundleGrantState) expire(gen uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen != gen || g.used {
		return false
	}
	g.stopTimerLocked()
	g.discardLocked()
	return true
}

// retire drops the timer and zeroes every retained byte. It is idempotent and
// always runs under the owning Session mutex, so no Lock can return while an
// undelivered grant still holds bytes.
func (g *runBundleGrantState) retire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopTimerLocked()
	g.discardLocked()
}

// registerRunBundleGrantLocked arms the owned deadline and records ownership.
// It must only run after the signed intent committed and the returned slots were
// validated, so no timer or registry slot can exist for a refused prepare.
func (s *Session) registerRunBundleGrantLocked(state *runBundleGrantState, lifetime time.Duration) bool {
	if len(s.runBundleGrants) >= maxRunBundleGrants {
		return false
	}
	if s.runBundleGrants == nil {
		s.runBundleGrants = make(map[*runBundleGrantState]bool, maxRunBundleGrants)
	}
	s.runBundleGrants[state] = true
	state.mu.Lock()
	state.gen++
	gen := state.gen
	state.timer = time.AfterFunc(lifetime, func() { s.expireRunBundleGrant(state, gen) })
	state.mu.Unlock()
	return true
}

// pruneRunBundleGrantsLocked releases grants that can never be delivered again:
// consumed, cleared or revoked states and expired deadlines. It runs before a
// new intent exists, so a full registry refuses without journaling anything and
// a cleared state cannot hold capacity past the next Prepare.
func (s *Session) pruneRunBundleGrantsLocked() {
	now := time.Now()
	for state := range s.runBundleGrants {
		if !state.dead(now) {
			continue
		}
		state.retire()
		delete(s.runBundleGrants, state)
	}
}

// clearRunBundleGrantsLocked is the Lock transition: stop every owned timer,
// zero every undelivered grant and drop the registry. The caller holds Session
// mutex, so Lock cannot return while a grant byte is still resident.
func (s *Session) clearRunBundleGrantsLocked() {
	for state := range s.runBundleGrants {
		state.retire()
		delete(s.runBundleGrants, state)
	}
}

// retireRunBundleGrantLocked removes one state from the registry and zeroes it.
// It is only used on this session's own entries, always under Session mutex.
func (s *Session) retireRunBundleGrantLocked(state *runBundleGrantState) {
	state.retire()
	delete(s.runBundleGrants, state)
}

// expireRunBundleGrant is the owned deadline callback. It acquires the session
// mutex first and the grant mutex second, exactly like every other lifecycle
// change, so it can never zero bytes that a Consume callback is borrowing:
// Consume marks the grant used before invoking fn and holds the session mutex
// until fn returns. The registry identity and generation checks make a stale
// timer harmless; it stops itself and never clears a replacement state.
func (s *Session) expireRunBundleGrant(state *runBundleGrantState, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runBundleGrants[state] {
		return
	}
	if !state.expire(gen) {
		return
	}
	delete(s.runBundleGrants, state)
}

// trustedRunBundleSpec pins a caller-supplied policy to one built-in profile.
// An unknown profile ID, or a spec whose slots, environment, files, argument
// policy, directories or limits differ from the registry entry, is refused
// before any intent can exist. Both sides are canonical clones, so a caller
// cannot hand over memory that changes during comparison.
func trustedRunBundleSpec(candidate cliprofile.Spec) (cliprofile.Spec, bool) {
	want, err := json.Marshal(cliprofile.CloneSpec(candidate))
	if err != nil {
		return cliprofile.Spec{}, false
	}
	defer clear(want)
	for _, profile := range cliprofile.List() {
		trusted := profile.Spec()
		if trusted.ID != candidate.ID {
			continue
		}
		got, err := json.Marshal(cliprofile.CloneSpec(trusted))
		if err != nil {
			return cliprofile.Spec{}, false
		}
		equal := bytes.Equal(want, got)
		clear(got)
		if !equal {
			return cliprofile.Spec{}, false
		}
		return trusted, true
	}
	return cliprofile.Spec{}, false
}

// PrepareRunBundleGrant commits the authenticated all-target intent through the
// existing item.run.bundle store action and only then returns an opaque one-use
// grant. It never starts a program, renders a value onto the filesystem, or
// returns a partial set: any stale, missing, trashed or malformed target yields
// no values at all. The caller-supplied root is a client-private temporary path
// that is only validated and bound into the intent, never created here.
func (s *Session) PrepareRunBundleGrant(ctx context.Context, targets []BundleTarget, request RunBundleRequest, root string) (*NativeRunBundleGrant, error) {
	if s == nil || ctx == nil {
		return nil, ErrRunTarget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ErrRunCancelled
	}
	spec, ok := trustedRunBundleSpec(request.Spec)
	if !ok {
		return nil, ErrRunTarget
	}
	// Own every caller slice and map, and pin the trusted policy, before the
	// signed intent so nothing can change between authorization and delivery.
	targets = cloneRunBundleTargets(targets)
	request = cloneRunBundleRequest(request)
	request.Spec = spec
	storeRequest := &runBundleStoreRequest{targets: targets, request: request, root: root}
	if storeRequest.validate() != nil {
		return nil, ErrRunTarget
	}
	// Capacity is decided before the intent exists: pruning released or expired
	// own grants here means a refusal leaves no audit trace and no values.
	s.pruneRunBundleGrantsLocked()
	if len(s.runBundleGrants) >= maxRunBundleGrants {
		return nil, ErrRunBundleGrant
	}
	r, e := s.executeActive(runBundleAction, vault.Item{}, nil, commandOption{runBundle: storeRequest}, true)
	if e != nil {
		clearBundleValues(r.values)
		return nil, e
	}
	// A lock or cancellation that wins after the intent committed must yield no
	// values at all, because the caller cannot know how far delivery got.
	if e := s.active(false); e != nil {
		clearBundleValues(r.values)
		return nil, e
	}
	if ctx.Err() != nil {
		clearBundleValues(r.values)
		return nil, ErrRunCancelled
	}
	if len(r.values) != len(targets) || !idOK(r.session) || !digestOK(r.intent) || !digestOK(r.destinationDigest) {
		clearBundleValues(r.values)
		return nil, ErrRunCredential
	}
	now := time.Now()
	until := now.Add(runBundleGrantTTL())
	if idle := s.last.Add(s.idle); idle.Before(until) {
		until = idle
	}
	if !now.Before(until) {
		clearBundleValues(r.values)
		return nil, ErrRunBundleGrant
	}
	state := &runBundleGrantState{
		values:  r.values,
		receipt: RunBundleGrantReceipt{Session: r.session, Intent: r.intent, TargetDigest: r.destinationDigest},
		until:   until,
		owner:   s,
	}
	// Registration is the only way credential bytes become session state, and it
	// happens after the committed prepare output was validated above.
	if !s.registerRunBundleGrantLocked(state, until.Sub(now)) {
		state.retire()
		return nil, ErrRunBundleGrant
	}
	return &NativeRunBundleGrant{state: state}, nil
}

// RunBundleDeliveryRevoked reports, with one atomic load and no Session mutex,
// whether a lock has been requested for this session. It is the cheap final
// revocation read a broker makes immediately before building a disclosure
// frame and again immediately before writing it. It is deliberately not
// Unlocked: that uses TryLock and would report a false "still unlocked" while
// another goroutine is inside a transaction. A nil session is revoked.
func (s *Session) RunBundleDeliveryRevoked() bool {
	if s == nil {
		return true
	}
	return s.lockRequested.Load()
}

// ConsumeRunBundleGrant runs fn under the session mutex exactly once for a grant
// this session prepared. Ownership is verified before anything else, so a
// foreign session, even a locked one, is refused without touching the owner's
// grant. The callback receives a shallow copy of the slot map: it may delete or
// replace entries freely, while the original private map and its byte slices
// stay retained for zeroization. Every retained byte is zeroed and the private
// entries dropped once fn returns, including on error or panic, before the
// session mutex is released. The callback must not reenter the Session; Clear
// and Discard stay safe because they take only the grant mutex.
//
// The final claim and RequestLock share saveMu as a short linearization gate.
// The lock order is Session.mu, then saveMu, then the grant mutex, and saveMu is
// released before fn runs, so the callback never holds it. A lock that wins the
// gate before the claim refuses with no callback at all; a claim that wins
// marks the grant used and defines the disclosure boundary, because bytes that
// the callback already borrowed cannot be revoked. The server still re-reads
// RunBundleDeliveryRevoked immediately before building and writing its frame.
func (s *Session) ConsumeRunBundleGrant(ctx context.Context, g *NativeRunBundleGrant, fn func(map[string][]byte, RunBundleGrantReceipt) error) error {
	if s == nil || ctx == nil || g == nil || g.state == nil || fn == nil {
		return ErrRunBundleGrant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := g.state
	// Ownership is claimed first: a foreign session, even a locked one, is
	// refused here without touching the owner's grant, registry entry or bytes.
	if !state.ownedBy(s) {
		return ErrRunBundleGrant
	}
	if !state.claimable(s) {
		// This session's own grant is already delivered, cleared or revoked. Report
		// the lock when that is the reason, otherwise the historical refusal.
		if e := s.active(false); e != nil {
			return e
		}
		return ErrRunBundleGrant
	}
	if e := s.active(false); e != nil {
		// Only this session's own unused grant may be discarded here.
		state.discardIfUnused(s)
		s.retireRunBundleGrantLocked(state)
		return e
	}
	if ctx.Err() != nil {
		return ErrRunCancelled
	}
	// The session was active a moment ago, but RequestLock may win here. The
	// seam pauses exactly in that window for deterministic tests.
	runBundleBeforeClaim()
	s.saveMu.Lock()
	if s.lockRequested.Load() {
		s.saveMu.Unlock()
		state.discardIfUnused(s)
		s.retireRunBundleGrantLocked(state)
		return ErrSessionLocked
	}
	// Claim under the same gate RequestLock uses for its lockRequested store.
	// saveMu is released before the callback: once used is set the bytes are
	// borrowed and a later lock cannot revoke them, so the callback must never
	// hold saveMu.
	values, receipt, ok := state.consume(s)
	s.saveMu.Unlock()
	if !ok {
		// Used, revoked or expired: release this session's own registry entry so a
		// cleared grant never holds capacity or a timer handle.
		s.retireRunBundleGrantLocked(state)
		return ErrRunBundleGrant
	}
	// The bytes are borrowed for the whole callback. Lock is blocked on the
	// session mutex and a public Clear sees used=true, so neither may zero them;
	// this defer is what zeroes them as soon as fn returns.
	defer s.retireRunBundleGrantLocked(state)
	return fn(values, receipt)
}

// ownedBy reports, without mutating anything, whether this grant was prepared
// by owner. It never reveals a byte and never touches another session's grant.
func (g *runBundleGrantState) ownedBy(owner *Session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.owner == owner
}

// claimable reports, without mutating anything, whether this grant still
// belongs to owner and has never been delivered.
func (g *runBundleGrantState) claimable(owner *Session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.owner == owner && !g.used
}

// discardIfUnused zeroes the grant only while it still belongs to owner, so a
// lock or expiry in one session can never clear another session's grant.
func (g *runBundleGrantState) discardIfUnused(owner *Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owner == owner && !g.used {
		g.stopTimerLocked()
		g.discardLocked()
	}
}

// consume marks the grant used and returns a shallow copy of the slot map that
// shares the disclosed byte slices. The private map stays retained, so a
// callback that deletes or replaces entries cannot make the original secret
// backing arrays unreachable to retire(). The deadline timer is stopped here:
// delivery has begun, and from now on the callback owns those bytes.
func (g *runBundleGrantState) consume(owner *Session) (map[string][]byte, RunBundleGrantReceipt, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owner != owner || g.used {
		return nil, RunBundleGrantReceipt{}, false
	}
	if !time.Now().Before(g.until) {
		g.stopTimerLocked()
		g.discardLocked()
		return nil, RunBundleGrantReceipt{}, false
	}
	g.used = true
	g.stopTimerLocked()
	public := make(map[string][]byte, len(g.values))
	for name, value := range g.values {
		public[name] = value
	}
	return public, g.receipt, true
}
