// Package brokerlease contains a pure, secret-free lease state machine.
//
// It binds owner-observed identity, session, revision, field, profile, caller,
// terminal, execution scope, and an immutable deadline. It does not perform
// transport, approval, child execution, SDK calls, vault IO, or platform
// authentication. A digest in Binding is an owner observation, not proof that
// an external process or kernel identity was authenticated.
//
// This package is deliberately not wired into production ingress. Any owner
// adapter must still supply a fresh authenticated observation, revalidate the
// real Session and revision gates, and linearize final delivery itself.
//
// Production callers pass time.Now(), which carries a monotonic reading. Tests
// pass their deterministic clock through the same public methods. The package
// never substitutes a different clock or disables clock-regression checks.
package brokerlease

import (
	"errors"
	"sync"
	"time"
)

// MaxLeaseLifetime is the hard upper bound applied to a new pending or
// refreshed deadline. The owner may impose a shorter bound.
const MaxLeaseLifetime = 24 * time.Hour

// State is the monotonic lifecycle state of one lease instance.
type State uint8

const (
	StatePending State = iota + 1
	StateActive
	StateRevoked
	StateClosing
	StateClosed
)

// Errors are fixed sentinels. They never carry a binding, nonce, handle, or
// owner path, so callers may classify failures without echoing sensitive data.
var (
	ErrBinding        = errors.New("brokerlease: binding rejected")
	ErrDeadline       = errors.New("brokerlease: deadline rejected")
	ErrExpired        = errors.New("brokerlease: lease expired")
	ErrState          = errors.New("brokerlease: state rejected")
	ErrClock          = errors.New("brokerlease: clock rejected")
	ErrNonce          = errors.New("brokerlease: nonce rejected")
	ErrNonceReplay    = errors.New("brokerlease: nonce already consumed")
	ErrNonceCapacity  = errors.New("brokerlease: nonce capacity exhausted")
	ErrUnknown        = errors.New("brokerlease: outcome unknown")
	ErrRefreshScope   = errors.New("brokerlease: refresh identity scope changed")
	ErrRefreshVersion = errors.New("brokerlease: refresh version regressed")
)

// Lease is one bounded pending or approved authority record. It holds only
// pure state protected by a mutex. No callback, IO, or external operation is
// invoked while that mutex is held.
type Lease struct {
	mu       sync.Mutex
	state    State
	binding  Binding
	deadline time.Time
	created  time.Time
	last     time.Time
	unknown  bool
	nonces   nonceCache
}

// Permit is a nonsecret admission observation. It does not authorize delivery
// by itself: the owner adapter must revalidate current session, revision, and
// deadline gates immediately before actual use. It contains no nonce or
// credential material.
type Permit struct {
	binding  Binding
	deadline time.Time
}

// Binding returns the exact binding admitted by this permit.
func (p Permit) Binding() Binding { return p.binding }

// Deadline returns the fixed deadline in force when the permit was admitted.
func (p Permit) Deadline() time.Time { return p.deadline }

// New creates a Pending lease from a complete owner observation. It performs
// no approval. The deadline is fixed here and must be after now and no farther
// than MaxLeaseLifetime.
func New(binding Binding, deadline, now time.Time) (*Lease, error) {
	if !binding.Valid() {
		return nil, ErrBinding
	}
	if now.IsZero() {
		return nil, ErrClock
	}
	if deadline.IsZero() || !deadline.After(now) || deadline.Sub(now) > MaxLeaseLifetime {
		return nil, ErrDeadline
	}
	return &Lease{
		state:    StatePending,
		binding:  binding,
		deadline: deadline,
		created:  now,
		last:     now,
	}, nil
}

// Binding returns a value copy of the exact scope captured at New.
func (l *Lease) Binding() Binding {
	if l == nil {
		return Binding{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.binding
}

// State returns the lifecycle state.
func (l *Lease) State() State {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// Deadline returns the immutable deadline for this instance.
func (l *Lease) Deadline() time.Time {
	if l == nil {
		return time.Time{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deadline
}

// Unknown reports whether an operation outcome was marked uncertain. The value
// is sticky across revocation and close.
func (l *Lease) Unknown() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.unknown
}

// Activate makes a Pending lease Active only when the supplied current
// observation and approved deadline exactly match the original pending record.
// A mismatch permanently revokes the pending authority. Activate is the
// explicit approval boundary; nothing becomes Active automatically.
func (l *Lease) Activate(current Binding, approvedDeadline, now time.Time) error {
	if l == nil {
		return ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return err
	}
	if l.unknown {
		l.revokeLocked()
		return ErrUnknown
	}
	if l.state != StatePending {
		return ErrState
	}
	if err := l.expireIfNeeded(now); err != nil {
		return err
	}
	if !approvedDeadline.Equal(l.deadline) {
		l.revokeLocked()
		return ErrDeadline
	}
	if !current.Equal(l.binding) {
		l.revokeLocked()
		return ErrBinding
	}
	l.state = StateActive
	return nil
}

// Use consumes a fresh per-use nonce and returns a nonsecret admission permit.
// The nonce is consumed only after state, deadline, unknown-outcome, and exact
// binding checks pass. A consumed nonce is never returned by a later failure,
// cancellation, revocation, or close. Revocation blocks subsequent admissions;
// an already-issued permit remains only an observation for the owner to
// revalidate.
func (l *Lease) Use(nonce Nonce, current Binding, now time.Time) (Permit, error) {
	if l == nil {
		return Permit{}, ErrState
	}
	if nonce == (Nonce{}) {
		return Permit{}, ErrNonce
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return Permit{}, err
	}
	if l.unknown {
		l.revokeLocked()
		return Permit{}, ErrUnknown
	}
	if l.state != StateActive {
		return Permit{}, ErrState
	}
	if err := l.expireIfNeeded(now); err != nil {
		return Permit{}, err
	}
	if !current.Equal(l.binding) {
		l.revokeLocked()
		return Permit{}, ErrBinding
	}
	if err := l.nonces.consume(nonce); err != nil {
		return Permit{}, err
	}
	return Permit{binding: l.binding, deadline: l.deadline}, nil
}

// Refresh permanently revokes the receiver before returning a NEW Pending
// decision for an updated observation. The old handle can never become Active
// again. The refreshed observation may advance revision, snapshot, session, and
// desktop counters, but it may not silently change vault, item, field, profile,
// caller, terminal, or execution identity scope. A changed scope requires a new
// explicit grant. Refresh performs no approval; the returned lease must be
// Activated explicitly. A fresh deadline is accepted only as a new pending
// deadline and remains subject to owner approval and real Session authority.
func (l *Lease) Refresh(updated Binding, deadline, now time.Time) (*Lease, error) {
	if l == nil {
		return nil, ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return nil, err
	}
	if l.unknown {
		l.revokeLocked()
		return nil, ErrUnknown
	}
	if l.state != StateActive {
		return nil, ErrState
	}
	if err := l.expireIfNeeded(now); err != nil {
		return nil, err
	}
	// Old authority dies before any new pending decision is produced, even if
	// the refreshed observation or deadline is rejected below.
	l.revokeLocked()
	if !updated.Valid() {
		return nil, ErrBinding
	}
	if updated.Vault != l.binding.Vault ||
		updated.Item != l.binding.Item ||
		updated.Field != l.binding.Field ||
		updated.Profile != l.binding.Profile ||
		updated.Caller != l.binding.Caller ||
		updated.Terminal != l.binding.Terminal ||
		updated.Execution != l.binding.Execution {
		return nil, ErrRefreshScope
	}
	if updated.SnapshotEpoch < l.binding.SnapshotEpoch ||
		updated.DesktopEpoch < l.binding.DesktopEpoch ||
		(updated.Session == l.binding.Session && updated.SessionGeneration < l.binding.SessionGeneration) {
		return nil, ErrRefreshVersion
	}
	next, err := New(updated, deadline, now)
	if err != nil {
		return nil, err
	}
	return next, nil
}

// Revoke applies logical revocation immediately. It does not perform cleanup
// and does not clear an uncertain outcome. Closing and Closed never move back
// to Active.
func (l *Lease) Revoke(now time.Time) error {
	if l == nil {
		return ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return err
	}
	l.revokeLocked()
	return nil
}

// BeginClose moves a logically revoked lease to Closing. The owner may call it
// only after it has started real cleanup; this package performs none.
func (l *Lease) BeginClose(now time.Time) error {
	if l == nil {
		return ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return err
	}
	switch l.state {
	case StateRevoked:
		l.state = StateClosing
		return nil
	case StateClosing, StateClosed:
		return nil
	default:
		return ErrState
	}
}

// Close records the trusted owner's acknowledgement that cleanup completed. It
// is not proof that any SDK, pipe, or process actually closed. It never clears
// Unknown.
func (l *Lease) Close(now time.Time) error {
	if l == nil {
		return ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return err
	}
	switch l.state {
	case StateClosing:
		l.state = StateClosed
		return nil
	case StateClosed:
		return nil
	default:
		return ErrState
	}
}

// MarkUnknown permanently records an uncertain operation outcome. It blocks
// use and refresh on this instance, revokes pending or active admission, and
// remains true after revocation or close. It performs no reconciliation and
// creates no durable record.
func (l *Lease) MarkUnknown(now time.Time) error {
	if l == nil {
		return ErrState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.observe(now); err != nil {
		return err
	}
	l.unknown = true
	l.revokeLocked()
	return nil
}

// observe enforces a nil/zero clock and monotonic non-regression. A regression
// fails closed by revoking pending or active authority. Closing and Closed stay
// monotonic.
func (l *Lease) observe(now time.Time) error {
	if now.IsZero() {
		l.revokeLocked()
		return ErrClock
	}
	if !l.last.IsZero() && now.Before(l.last) {
		l.revokeLocked()
		return ErrClock
	}
	if now.After(l.last) {
		l.last = now
	}
	return nil
}

// expireIfNeeded revokes pending or active authority at the fixed deadline.
func (l *Lease) expireIfNeeded(now time.Time) error {
	if now.Before(l.deadline) {
		return nil
	}
	l.revokeLocked()
	return ErrExpired
}

// revokeLocked preserves the monotonic order Pending/Active -> Revoked ->
// Closing -> Closed. It does not touch unknown or perform cleanup.
func (l *Lease) revokeLocked() {
	switch l.state {
	case StatePending, StateActive:
		l.state = StateRevoked
	}
}
