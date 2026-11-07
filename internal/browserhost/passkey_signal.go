package browserhost

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// SignalView is the native-only owner review surface for one WebAuthn signal
// hint. It carries only public selectors and the requested names; the page gets
// nothing but the fixed acceptance acknowledgement.
type SignalView struct {
	ID, Origin, RPID, Kind string
	Changes                []personal.PasskeySignalChange
	Working                bool
	Until                  time.Time
}

// pendingSignal is the single bounded signal hint a connection may hold. The
// async review owns no MutationGate: the gate is created only when the owner
// explicitly confirms.
//
// gate is published through an atomic pointer because it is read by three
// independent paths: the native approval worker, the connection-wide lock
// invalidation (which only holds authMu) and the expiry/reject paths. Every
// reader uses Load and every writer uses Store/CompareAndSwap so cancellation
// can never race a plain field access.
type pendingSignal struct {
	request   personal.PasskeySignalRequest
	wire      Request
	session   *personal.Session
	gate      atomic.Pointer[personal.MutationGate]
	proposal  []personal.PasskeySignalChange
	until     time.Time
	epoch     uint64
	cancelled atomic.Bool
	working   bool
	timer     *time.Timer
}

// cancelGate cancels a published gate, if any. It is safe to call from any
// goroutine at any time.
func (p *pendingSignal) cancelGate() {
	if p == nil {
		return
	}
	if gate := p.gate.Load(); gate != nil {
		gate.Cancel()
	}
}

// handlePasskeySignal acknowledges a strict signal dictionary before any
// credential lookup. The acknowledgement is the exact fixed frame and never
// reports counts, presence or outcome. A pending native operation keeps
// priority: the hint is acknowledged and ignored without disturbing it.
func (c *Connection) handlePasskeySignal(r Request) error {
	request, err := personal.ParsePasskeySignal(r.Origin, []byte(r.Options))
	if err != nil {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil || !c.valid(r.Capability) {
		return c.refuse(r.ID)
	}
	// ACK strictly before the authenticated read; the page learns nothing about
	// local credentials from it.
	if err := c.response(Response{ID: r.ID, Type: "passkey-signal-accepted"}); err != nil {
		return err
	}
	if c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil || c.signal != nil || c.stagedBusy || c.upload != nil {
		return nil
	}
	until := minTime(c.until, c.now().Add(2*time.Minute))
	p := &pendingSignal{request: request, wire: r, session: s, until: until, epoch: c.epoch, working: true}
	c.signal = p
	c.signalStatus = "正在核对网站 Passkey 信号"
	c.authMu.Lock()
	c.signalAuth = p
	c.authMu.Unlock()
	p.timer = time.AfterFunc(time.Until(until), func() {
		p.cancelled.Store(true)
		p.cancelGate()
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.signal != p {
			return
		}
		if p.working {
			// The worker keeps the registered gate until it returns; it observes
			// the cancelled gate before winning the commit.
			return
		}
		c.clearSignal(p)
		c.signalStatus = "网站 Passkey 信号已过期"
	})
	go func() {
		proposal, reviewErr := s.ReviewPasskeySignal(p.request)
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.signal != p {
			return
		}
		p.working = false
		if reviewErr != nil || !c.signalLive(p) || len(proposal.Changes) == 0 {
			c.clearSignal(p)
			if reviewErr != nil {
				c.signalStatus = "网站 Passkey 信号无法核对"
			} else {
				c.signalStatus = "没有需要更新的 Passkey 账号"
			}
			return
		}
		p.proposal = proposal.Changes
		c.signalStatus = "网站请求更新 Passkey 账号；请核对后确认"
	}()
	return nil
}

func (c *Connection) signalLive(p *pendingSignal) bool {
	if p == nil || p.session == nil || c.session.Load() != p.session || p.cancelled.Load() {
		return false
	}
	return p.epoch == c.generation.Load() && c.valid(p.wire.Capability) && c.now().Before(p.until)
}

// clearSignal releases the signal surface. A working owner confirmation keeps
// ownership of its registered gate until it returns.
func (c *Connection) clearSignal(p *pendingSignal) {
	if p == nil {
		return
	}
	p.cancelled.Store(true)
	p.cancelGate()
	if p.timer != nil {
		p.timer.Stop()
	}
	if !p.working {
		if gate := p.gate.Swap(nil); gate != nil && p.session != nil {
			p.session.ReleaseMutation(gate)
		}
	}
	if c.signal == p {
		c.signal = nil
	}
	c.authMu.Lock()
	if c.signalAuth == p {
		c.signalAuth = nil
	}
	c.authMu.Unlock()
}

func (c *Connection) signalSnapshot() (*SignalView, string) {
	p := c.signal
	if p == nil {
		return nil, c.signalStatus
	}
	return &SignalView{
		ID:      p.wire.ID,
		Origin:  p.wire.Origin,
		RPID:    p.request.RPID,
		Kind:    p.request.Kind,
		Changes: append([]personal.PasskeySignalChange(nil), p.proposal...),
		Working: p.working,
		Until:   p.until,
	}, c.signalStatus
}

// signalResult maps the durable outcome of one owner confirmation to a native
// owner status. A committed update whose authority was revoked before the
// status was published is UNKNOWN, never success. Any error after the commit
// decision is also unknown; a pre-commit cancellation or refusal is a known
// failure. Nothing here is ever sent to the page.
func signalResult(err error, gate *personal.MutationGate, live bool) (status string, ok bool) {
	won := gate != nil && gate.CommitWon()
	switch {
	case err == nil && live:
		return "已按网站信号更新 Passkey 账号", true
	case err == nil && won:
		return "Passkey 信号更新结果未确认；请核实金库", false
	case err == nil:
		return "Passkey 信号未应用；账号可能已变化", false
	case errors.Is(err, personal.ErrMutationUnknown) || won:
		return "Passkey 信号更新结果未确认；请核实金库", false
	default:
		return "Passkey 信号未应用；账号可能已变化", false
	}
}

// ApprovePasskeySignal is called only by the native owner UI after an explicit
// confirmation. It reserves the single Session mutation slot only now, then
// hands the exact reviewed proposal to the atomic, fully revalidated
// transaction. A reject/lock/expiry that races the database wait cancels the
// published gate, so the transaction can never win after cancellation. No frame
// follows an approval, denial, expiry or empty review.
func (c *Connection) ApprovePasskeySignal(id string) error {
	c.mu.Lock()
	p := c.signal
	if p == nil || p.wire.ID != id || p.working || len(p.proposal) == 0 || !c.signalLive(p) {
		c.mu.Unlock()
		return ErrProtocol
	}
	gate := personal.NewMutationGate(p.until)
	// Publish the gate before unlocking so a concurrent reject, lock or expiry
	// can cancel it even while the database write is in flight.
	p.gate.Store(gate)
	p.working = true
	session, request := p.session, p.request
	changes := append([]personal.PasskeySignalChange(nil), p.proposal...)
	c.mu.Unlock()
	c.changed()
	err := func() error {
		// Cancellation before registration must never reserve the slot.
		if p.cancelled.Load() || !gate.Pending() {
			gate.Cancel()
			return ErrProtocol
		}
		if registerErr := session.RegisterMutation(gate); registerErr != nil {
			gate.Cancel()
			return registerErr
		}
		// A reject/lock/expiry that landed between the pre-check and the
		// reservation must not proceed to the transaction.
		if p.cancelled.Load() || !gate.Pending() {
			gate.Cancel()
			session.ReleaseMutation(gate)
			return personal.ErrMutationCancelled
		}
		_, applyErr := session.ApplyPasskeySignal(request, changes, gate)
		return applyErr
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	p.working = false
	// ApplyPasskeySignal (or the explicit release above) owns the gate; drop our
	// reference so clearSignal never releases it a second time.
	p.gate.CompareAndSwap(gate, nil)
	result := ErrProtocol
	// A lock/reject that raced the transaction may already have cleared the
	// surface. The durable-outcome status is still published (UNKNOWN after a
	// won commit, a known refusal before it) unless a newer signal owns it.
	if c.signal == p || c.signal == nil {
		status, ok := signalResult(err, gate, c.signalLive(p))
		c.signalStatus = status
		if ok {
			result = nil
		}
	}
	if c.signal == p {
		c.clearSignal(p)
	}
	return result
}

// RejectPasskeySignal is called only by the native owner UI. It cancels a live
// approval gate immediately, including while the owner confirmation is waiting
// on the database, so no later commit can win.
func (c *Connection) RejectPasskeySignal(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	p := c.signal
	if p == nil || p.wire.ID != id {
		return ErrProtocol
	}
	p.cancelled.Store(true)
	p.cancelGate()
	if p.working {
		return nil
	}
	c.clearSignal(p)
	c.signalStatus = "已忽略网站 Passkey 信号"
	return nil
}
