package personal

import (
	"context"
	"time"
)

// LegacyPartitionPublishPhase is one single-use boundary of a staged
// legacy-partition publish. Phases are claimed monotonically so a resumed
// route may start at publish, acknowledgement or delivery, but no phase may be
// entered twice or out of order.
type LegacyPartitionPublishPhase uint8

const (
	LegacyPartitionPhasePrepare LegacyPartitionPublishPhase = iota + 1
	LegacyPartitionPhasePublish
	LegacyPartitionPhaseAck
	LegacyPartitionPhaseDeliver
)

func (p LegacyPartitionPublishPhase) String() string {
	switch p {
	case LegacyPartitionPhasePrepare:
		return "prepare"
	case LegacyPartitionPhasePublish:
		return "publish"
	case LegacyPartitionPhaseAck:
		return "ack"
	case LegacyPartitionPhaseDeliver:
		return "deliver"
	default:
		return "unknown"
	}
}

// LegacyPartitionPublishClaim is the short-lived operation claim that
// arbitrates one legacy-partition prepare/publish/ack/deliver sequence with
// RequestLock. It reuses the ordinary registered MutationGate and saveMu
// linearization; the caller performs all slow validation before each Claim and
// starts the irreversible step immediately after it returns.
type LegacyPartitionPublishClaim struct {
	gate  *MutationGate
	phase LegacyPartitionPublishPhase
}

// legacyPartitionClaimTestHook is nil in production. Tests use the fixed stage
// names to signal arbitration and to sample one deterministic instant after any
// registered gate wait. It never receives material, a capability or data.
var legacyPartitionClaimTestHook func(stage string) time.Time

func legacyPartitionClaimBeforeArbitration() {
	if legacyPartitionClaimTestHook != nil {
		_ = legacyPartitionClaimTestHook("before-save-mu")
	}
}

func legacyPartitionClaimSample() time.Time {
	if legacyPartitionClaimTestHook != nil {
		return legacyPartitionClaimTestHook("sample-time")
	}
	return time.Now()
}

// BeginLegacyPartitionPublishClaim registers one claim for the current full
// factor scope. Registration shares saveMu with RequestLock; it never holds a
// Session lock across later I/O.
func (s *Session) BeginLegacyPartitionPublishClaim() (*LegacyPartitionPublishClaim, error) {
	if s == nil {
		return nil, ErrMutationCancelled
	}
	gate := NewMutationGate(time.Now().Add(passkeyTransferFullFactorWindow))
	if err := s.RegisterMutation(gate); err != nil {
		return nil, ErrMutationCancelled
	}
	return &LegacyPartitionPublishClaim{gate: gate}, nil
}

// Claim consumes exactly the next monotonic phase under saveMu. It verifies
// cancellation, the current full-factor/active scope and this exact registered
// token at the same sampled instant, then releases every Session lock before
// the caller starts the irreversible operation. A lock, cancellation or
// deadline that has already won makes the phase fail closed with unchanged
// phase.
func (c *LegacyPartitionPublishClaim) Claim(ctx context.Context, s *Session, phase LegacyPartitionPublishPhase) error {
	if c == nil || c.gate == nil || s == nil || ctx == nil || phase > LegacyPartitionPhaseDeliver {
		return ErrMutationCancelled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(false); err != nil {
		c.gate.Cancel()
		return err
	}
	legacyPartitionClaimBeforeArbitration()
	s.saveMu.Lock()
	registered := s.saveGate == c.gate
	if registered {
		registered = c.gate.Pending()
	}
	now := legacyPartitionClaimSample()
	valid := registered && c.phase < phase && !s.lockRequested.Load() &&
		len(s.material) != 0 && ctx.Err() == nil &&
		s.freshFullFactorAt(now) == nil && !s.idleExpired(now)
	if valid {
		c.phase = phase
	} else {
		c.gate.Cancel()
	}
	s.saveMu.Unlock()
	if valid {
		return nil
	}
	return c.failure(ctx, s, now)
}

// Ready is a non-consuming early observation used only to avoid slow work
// after a lock, cancellation or deadline has already won. It never advances the
// phase and never replaces the final Claim immediately before the irreversible
// step.
func (c *LegacyPartitionPublishClaim) Ready(ctx context.Context, s *Session) error {
	if c == nil || c.gate == nil || s == nil || ctx == nil {
		return ErrMutationCancelled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(false); err != nil {
		c.gate.Cancel()
		return err
	}
	legacyPartitionClaimBeforeArbitration()
	s.saveMu.Lock()
	registered := s.saveGate == c.gate
	if registered {
		registered = c.gate.Pending()
	}
	now := legacyPartitionClaimSample()
	valid := registered && !s.lockRequested.Load() && len(s.material) != 0 &&
		ctx.Err() == nil && s.freshFullFactorAt(now) == nil && !s.idleExpired(now)
	if !valid {
		c.gate.Cancel()
	}
	s.saveMu.Unlock()
	if valid {
		return nil
	}
	return c.failure(ctx, s, now)
}

// failure runs after saveMu is released. It computes every expired or revoked
// authority at the exact arbitration sample and performs the ordinary Session
// lock cleanup independently of the typed error it returns. Context errors stay
// discoverable; factor-only keeps material until a lock condition occurs.
func (c *LegacyPartitionPublishClaim) failure(ctx context.Context, s *Session, now time.Time) error {
	idle := s.idleExpired(now)
	revoked := s.lockRequested.Load()
	unavailable := len(s.material) == 0
	if idle || revoked || unavailable {
		s.lock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.freshFullFactorAt(now) != nil {
		return ErrFullFactorRequired
	}
	if idle || revoked || unavailable {
		return ErrSessionLocked
	}
	return ErrMutationCancelled
}

// Release drops this claim. It is safe after a failed phase, a lock or success.
func (c *LegacyPartitionPublishClaim) Release(s *Session) {
	if c == nil || c.gate == nil || s == nil {
		return
	}
	s.ReleaseMutation(c.gate)
	c.gate = nil
}
