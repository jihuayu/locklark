package personal

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// VaultFileReadDeliveryClaim is a single-use, opaque read-delivery authority
// derived from one exact active owned vault-file child. It copies only that
// child's original fixed full-factor and idle deadlines. It never starts a new
// timer, reads Session.fullUnlock, reserves saveGate, grants mutation rights or
// authorizes a generic, foreign or replaced child. The zero value is invalid.
type VaultFileReadDeliveryClaim struct {
	state *vaultFileReadDeliveryClaimState
}

type vaultFileReadDeliveryClaimState struct {
	mu sync.Mutex

	session *Session
	path    string
	token   VaultFileChildToken

	fullFactorDeadline time.Time
	idleDeadline       time.Time

	armed    bool
	closing  bool
	sealed   bool
	consumed bool
	invalid  bool
	closeErr error

	// custody is non-nil only when this exact claim was bound to one custody
	// seal state. Ordinary Consume refuses such a claim; only the bound seal's
	// Take may perform the final arbitration and detach the outputs.
	custody *vaultFileBackupCustodySealState
}

// String, GoString, MarshalJSON and Format are fixed redactions. The value
// receivers also cover a dereferenced copy; only the unexported shared state
// pointer is copied, so consumption remains single-use across copies.
func (VaultFileReadDeliveryClaim) String() string   { return "[vault-file read delivery claim]" }
func (VaultFileReadDeliveryClaim) GoString() string { return "[vault-file read delivery claim]" }
func (VaultFileReadDeliveryClaim) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (VaultFileReadDeliveryClaim) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[vault-file read delivery claim]"))
}

// vaultFileReadDeliveryClaimTestHook is nil in production. Tests use the fixed
// stage name to inject one deterministic final sample time. It receives no
// capability, factor, key, child or data.
var vaultFileReadDeliveryClaimTestHook func(stage string) time.Time

func vaultFileReadDeliveryClaimSample() time.Time {
	if vaultFileReadDeliveryClaimTestHook != nil {
		return vaultFileReadDeliveryClaimTestHook("sample-time")
	}
	return time.Now()
}

// BeginVaultFileReadDeliveryClaim verifies the exact current ownership of the
// token's active owned child and copies that child's immutable post-verification
// deadlines. It takes only short locks and performs no IO while holding them.
// A missing, generic, foreign, replaced, expired or retired child is refused.
func (s *Session) BeginVaultFileReadDeliveryClaim(token VaultFileChildToken) (*VaultFileReadDeliveryClaim, error) {
	if s == nil || token.generation == 0 || token.path == "" ||
		token.owner == nil || s.vaultFileOwner == nil || token.owner != s.vaultFileOwner {
		return nil, ErrVaultFileScopedChild
	}
	// The caller must hold a current exact owned child. This is the existing
	// target-only ownership proof, not a point read or a caller deadline.
	if err := s.RevalidateVaultFileChildOwnership(token); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.lockRequested.Load() || s.vaultFileRevoked.Load() ||
		len(s.material) == 0 || s.idleExpired(time.Now()) {
		s.mu.Unlock()
		return nil, ErrSessionLocked
	}
	s.saveMu.Lock()
	s.vaultFileMu.Lock()
	child := s.vaultFileChildren[token.path]
	valid := child != nil && child.token == token && child.owned != nil
	var fullFactorDeadline, idleDeadline time.Time
	if valid {
		child.mu.Lock()
		valid = !child.closed && !child.fullFactorDeadline.IsZero()
		fullFactorDeadline = child.fullFactorDeadline
		idleDeadline = child.idleDeadline
		child.mu.Unlock()
	}
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.mu.Unlock()
	if !valid {
		return nil, ErrVaultFileScopedChild
	}
	return &VaultFileReadDeliveryClaim{state: &vaultFileReadDeliveryClaimState{
		session:            s,
		path:               token.path,
		token:              token,
		fullFactorDeadline: fullFactorDeadline,
		idleDeadline:       idleDeadline,
		armed:              true,
	}}, nil
}

// CloseChild retires exactly the claimed child and waits for the real handle
// close completion. It never removes a replacement child and never closes a
// sibling. The actual close error is returned, not swallowed. The claim is
// sealed only after a successful close, so a failed or already-retired child
// cannot be reauthorized.
func (c *VaultFileReadDeliveryClaim) CloseChild(s *Session) error {
	if c == nil || c.state == nil || s == nil {
		return ErrVaultFileScopedChild
	}
	state := c.state
	state.mu.Lock()
	if state.session != s || !state.armed || state.closing || state.sealed || state.consumed || state.invalid {
		state.mu.Unlock()
		return ErrVaultFileScopedChild
	}
	state.closing = true
	state.mu.Unlock()

	s.saveMu.Lock()
	s.vaultFileMu.Lock()
	child := s.vaultFileChildren[state.path]
	valid := child != nil && child.token == state.token && child.owned != nil
	if valid {
		delete(s.vaultFileChildren, state.path)
	}
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	if !valid {
		state.mu.Lock()
		state.closing = false
		state.invalid = true
		state.mu.Unlock()
		return ErrVaultFileScopedChild
	}

	err := s.retireVaultFileChildWithError(child)
	state.mu.Lock()
	state.closing = false
	state.armed = false
	if err != nil {
		state.invalid = true
		state.closeErr = err
	} else {
		state.sealed = true
	}
	state.mu.Unlock()
	return err
}

type vaultFileReadDeliveryDecision struct {
	valid         bool
	parentInvalid bool
	childExpired  bool
	ctxErr        error
}

// arbitrateLocked is the single shared final sample. The caller holds
// claim.state.mu, Session.mu and saveMu in that order. It marks the claim
// consumed or invalid exactly once and freezes parent failures under the same
// arbiter RequestLock uses.
func vaultFileReadDeliveryArbitrateLocked(state *vaultFileReadDeliveryClaimState,
	s *Session, ctx context.Context, now time.Time) vaultFileReadDeliveryDecision {
	revoked := s.lockRequested.Load() || s.vaultFileRevoked.Load()
	unavailable := len(s.material) == 0
	parentIdle := s.idleExpired(now)
	childExpired := !now.Before(state.fullFactorDeadline) ||
		(!state.idleDeadline.IsZero() && !now.Before(state.idleDeadline))
	ctxErr := ctx.Err()
	parentInvalid := revoked || unavailable || parentIdle
	decision := vaultFileReadDeliveryDecision{
		valid:         !parentInvalid && !childExpired && ctxErr == nil,
		parentInvalid: parentInvalid, childExpired: childExpired, ctxErr: ctxErr,
	}
	if decision.valid {
		state.consumed = true
	} else {
		state.invalid = true
		if parentInvalid {
			s.lockRequested.Store(true)
			s.vaultFileRevoked.Store(true)
		}
	}
	return decision
}

// finishDecision applies the existing post-arbitration cleanup protocol after
// claim.state.mu, Session.mu and saveMu have all been released.
func finishVaultFileReadDeliveryDecision(s *Session, decision vaultFileReadDeliveryDecision) error {
	if decision.valid {
		return nil
	}
	if decision.parentInvalid {
		s.lockVaultFileParent()
		if decision.ctxErr != nil {
			return decision.ctxErr
		}
		return ErrSessionLocked
	}
	if decision.ctxErr != nil {
		return decision.ctxErr
	}
	return ErrVaultFileScopedChild
}

// validateCustodyBinding checks the exact armed claim before and during a
// custody bind without changing it. The caller holds state.mu.
func validateVaultFileReadDeliveryCustodyBinding(state *vaultFileReadDeliveryClaimState,
	s *Session, token VaultFileChildToken) error {
	if state == nil || s == nil || state.session != s || state.token != token ||
		!state.armed || state.closing || state.sealed || state.consumed ||
		state.invalid || state.closeErr != nil || state.custody != nil {
		return ErrVaultFileScopedChild
	}
	return nil
}

// bindCustody atomically attaches one custody seal to this exact armed claim.
// A second bind, a foreign Session/token or any already-closed/invalid claim is
// refused.
func (c *VaultFileReadDeliveryClaim) bindCustody(s *Session, token VaultFileChildToken,
	seal *vaultFileBackupCustodySealState) error {
	if c == nil || c.state == nil || seal == nil || s == nil {
		return ErrVaultFileScopedChild
	}
	state := c.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := validateVaultFileReadDeliveryCustodyBinding(state, s, token); err != nil {
		return err
	}
	state.custody = seal
	seal.claim = state
	return nil
}

// Consume is the final short arbitration with RequestLock for ordinary read
// delivery. A custody-bound claim is refused here; its exact seal's Take owns
// the one final arbitration and output detach. It samples time while owning
// saveMu, checks the current parent idle/active/revocation state with the exact
// captured child deadlines and context, and consumes once. An observed parent
// failure is frozen under saveMu, then drained with the existing parent-lock
// cleanup only after saveMu and the claim lock are released. Child-only expiry
// and cancellation leave the parent and siblings authorized. A refusal leaves
// the claim invalid.
func (c *VaultFileReadDeliveryClaim) Consume(ctx context.Context, s *Session) error {
	if c == nil || c.state == nil || s == nil || ctx == nil {
		return ErrVaultFileScopedChild
	}
	state := c.state
	state.mu.Lock()
	if state.session != s || state.custody != nil || !state.sealed ||
		state.consumed || state.invalid || state.closeErr != nil {
		state.mu.Unlock()
		return ErrVaultFileScopedChild
	}

	s.mu.Lock()
	s.saveMu.Lock()
	decision := vaultFileReadDeliveryArbitrateLocked(state, s, ctx, vaultFileReadDeliveryClaimSample())
	s.saveMu.Unlock()
	s.mu.Unlock()
	state.mu.Unlock()
	return finishVaultFileReadDeliveryDecision(s, decision)
}
