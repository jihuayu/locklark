package personal

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

const desktopOTPShowAction = "item.desktop.show.otp-code"
const desktopOTPCopyAction = "item.desktop.copy.otp-code"

func otpAction(a string) bool {
	return a == otpDisclosureAction || a == referenceOTPAction || a == desktopOTPShowAction || a == desktopOTPCopyAction || a == browserOTPAction
}

type NativeOTPTarget struct{ ID, Revision string }
type OTPBounds struct {
	From, Until          int64
	WallSample, Deadline time.Time
}

func (b OTPBounds) Valid(now time.Time) bool {
	return !now.Round(0).Before(b.WallSample) && now.Unix() >= b.From && now.Unix() < b.Until && now.Before(b.Deadline)
}
func (b *OTPBounds) Check(now time.Time) bool {
	if !b.Valid(now) {
		return false
	}
	b.WallSample = now.Round(0)
	return true
}
func otpBounds(now time.Time, from, until int64, ttl time.Duration) OTPBounds {
	remaining := time.Unix(until, 0).Sub(now.Round(0))
	if remaining < ttl {
		ttl = remaining
	}
	return OTPBounds{from, until, now.Round(0), now.Add(ttl)}
}

type otpCap struct {
	cancelled atomic.Bool
	mu        sync.Mutex
	code      []byte
	target    NativeOTPTarget
	purpose   string
	bounds    OTPBounds
	used      bool
	timer     *time.Timer
}

func (c *otpCap) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.code)
	c.code = nil
	c.used = true
	if c.timer != nil {
		c.timer.Stop()
	}
}

// Cancellation never waits for a worker or UI callback owning the buffer.
func (c *otpCap) cancel() {
	c.cancelled.Store(true)
	if c.mu.TryLock() {
		clear(c.code)
		c.code = nil
		c.used = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
	}
}
func (s *Session) registerOTPCap(c *otpCap) bool {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.lockRequested.Load() || !s.otpCapacity() {
		c.cancel()
		return false
	}
	s.otpCaps.Store(c, true)
	return true
}

type NativeOTP struct{ cap *otpCap }
type NativeOTPDelivery struct{ cap *otpCap }

func (NativeOTP) String() string                       { return "[native OTP preparation]" }
func (NativeOTP) GoString() string                     { return "[native OTP preparation]" }
func (NativeOTP) MarshalJSON() ([]byte, error)         { return nil, ErrDesktopDelivery }
func (NativeOTPDelivery) String() string               { return "[native OTP delivery]" }
func (NativeOTPDelivery) GoString() string             { return "[native OTP delivery]" }
func (NativeOTPDelivery) MarshalJSON() ([]byte, error) { return nil, ErrDesktopDelivery }
func (s *Session) otpNowTime() time.Time {
	if s.otpNow != nil {
		return s.otpNow()
	}
	return time.Now()
}
func (s *Session) otpCapacity() bool {
	count := 0
	s.otpCaps.Range(func(_, _ any) bool { count++; return count < 8 })
	return count < 8
}
func (s *Session) PrepareOTP(target NativeOTPTarget, purpose string, g *MutationGate) (*NativeOTP, error) {
	action := desktopOTPShowAction
	if purpose == "copy" {
		action = desktopOTPCopyAction
	} else if purpose != "show" {
		g.Cancel()
		s.ReleaseMutation(g)
		return nil, ErrDesktopDelivery
	}
	if !ValidEditTarget(target.ID, target.Revision, "otp") {
		g.Cancel()
		s.ReleaseMutation(g)
		return nil, ErrDesktopDelivery
	}
	started := s.otpNowTime().Round(0)
	s.mu.Lock()
	capacity := s.otpCapacity()
	s.mu.Unlock()
	if !capacity {
		g.Cancel()
		s.ReleaseMutation(g)
		return nil, ErrDesktopDelivery
	}
	r, e := s.nativeMutation(action, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision}, commandOption{}, g)
	if r.otp != nil {
		defer r.otp.Clear()
	}
	if e != nil {
		return nil, e
	}
	if r.otp == nil {
		return nil, ErrDesktopDelivery
	}
	sample := s.otpNowTime()
	if sample.Round(0).Before(started) {
		return nil, ErrOTPTime
	}
	code, e := r.otp.At(sample.Unix())
	r.otp.Clear() // No parsed seed remains while registering or dispatching the code.
	if e != nil {
		return nil, e
	}
	window := code.Window()
	p := &NativeOTP{cap: &otpCap{code: []byte(code.Value()), target: target, purpose: purpose, bounds: otpBounds(sample, window.From, window.Until, 10*time.Second)}}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil || !s.otpCapacity() || !p.cap.bounds.Check(s.otpNowTime()) {
		p.cap.clear()
		return nil, ErrOTPTime
	}
	if s.otpPrepared == nil {
		s.otpPrepared = make(map[*NativeOTP]bool)
	}
	if !s.registerOTPCap(p.cap) {
		p.cap.clear()
		return nil, ErrSessionLocked
	}
	s.otpPrepared[p] = true
	p.cap.mu.Lock()
	p.cap.timer = time.AfterFunc(time.Until(p.cap.bounds.Deadline), func() { p.cap.clear(); s.otpCaps.Delete(p.cap); s.mu.Lock(); delete(s.otpPrepared, p); s.mu.Unlock() })
	p.cap.mu.Unlock()
	return p, nil
}
func (s *Session) AuthorizeOTP(p *NativeOTP) (*NativeOTPDelivery, error) {
	return s.authorizeOTPWith(p, func(target NativeOTPTarget) error {
		return s.readNativeTarget(target.ID, target.Revision, func(vault.Item) error { return nil })
	})
}
func (s *Session) authorizeOTPWith(p *NativeOTP, verify func(NativeOTPTarget) error) (*NativeOTPDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil || !s.otpPrepared[p] {
		return nil, ErrDesktopDelivery
	}
	delete(s.otpPrepared, p)
	defer func() { p.cap.clear(); s.otpCaps.Delete(p.cap) }()
	p.cap.mu.Lock()
	if p.cap.cancelled.Load() || p.cap.used || !p.cap.bounds.Check(s.otpNowTime()) {
		p.cap.mu.Unlock()
		return nil, ErrOTPTime
	}
	target, purpose := p.cap.target, p.cap.purpose
	p.cap.mu.Unlock()
	if e := s.active(false); e != nil {
		return nil, e
	}
	// Verification uses metadata only. Keep the code in its cancellable holder
	// throughout disk I/O, so lock/expiry can clear it without waiting for I/O.
	if e := verify(target); e != nil {
		return nil, e
	}
	if e := s.active(false); e != nil {
		return nil, e
	}
	p.cap.mu.Lock()
	defer p.cap.mu.Unlock()
	now := s.otpNowTime()
	if p.cap.cancelled.Load() || p.cap.used || len(p.cap.code) == 0 || !p.cap.bounds.Check(now) {
		return nil, ErrOTPTime
	}
	bounds := p.cap.bounds
	deliveryBounds := otpBounds(now, bounds.From, bounds.Until, 2*time.Second)
	if bounds.Deadline.Before(deliveryBounds.Deadline) {
		deliveryBounds.Deadline = bounds.Deadline
	}
	// Atomically exchange registered holders with RequestLock. There is no
	// unregistered local buffer and no disk or UI work under this short lock.
	s.saveMu.Lock()
	if s.lockRequested.Load() || p.cap.cancelled.Load() {
		s.saveMu.Unlock()
		return nil, ErrSessionLocked
	}
	d := &NativeOTPDelivery{cap: &otpCap{code: p.cap.code, target: target, purpose: purpose, bounds: deliveryBounds}}
	s.otpCaps.Store(d.cap, true)
	p.cap.code = nil
	p.cap.used = true
	if p.cap.timer != nil {
		p.cap.timer.Stop()
	}
	s.otpCaps.Delete(p.cap)
	s.saveMu.Unlock()
	if s.otpDeliveries == nil {
		s.otpDeliveries = make(map[*NativeOTPDelivery]bool)
	}
	s.otpDeliveries[d] = true
	d.cap.mu.Lock()
	d.cap.timer = time.AfterFunc(time.Until(deliveryBounds.Deadline), func() {
		d.cap.clear()
		s.otpCaps.Delete(d.cap)
		s.mu.Lock()
		delete(s.otpDeliveries, d)
		s.mu.Unlock()
	})
	d.cap.mu.Unlock()
	if s.lockRequested.Load() {
		d.cap.clear()
		s.otpCaps.Delete(d.cap)
		delete(s.otpDeliveries, d)
		return nil, ErrSessionLocked
	}
	return d, nil
}

// DeliverOTP does no I/O; run it only on the UI thread. The synchronous callback
// must not reenter Session. The last authenticated observation was in AuthorizeOTP.
func (s *Session) DeliverOTP(d *NativeOTPDelivery, selected NativeOTPTarget, deliver func([]byte, OTPBounds) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d == nil || !s.otpDeliveries[d] {
		return ErrDesktopDelivery
	}
	delete(s.otpDeliveries, d)
	defer func() { d.cap.clear(); s.otpCaps.Delete(d.cap) }()
	if e := s.active(false); e != nil {
		return e
	}
	return func() error {
		d.cap.mu.Lock()
		defer d.cap.mu.Unlock()
		if d.cap.cancelled.Load() || d.cap.used || d.cap.target != selected || deliver == nil || !d.cap.bounds.Check(s.otpNowTime()) {
			return ErrOTPTime
		}
		if d.cap.timer != nil {
			d.cap.timer.Stop()
		}
		now := s.otpNowTime()
		if !d.cap.bounds.Check(now) {
			return ErrOTPTime
		}
		// This short grant is the delivery linearization point shared with
		// RequestLock. A lock after grant cannot retract the synchronous callback.
		s.saveMu.Lock()
		if s.lockRequested.Load() || d.cap.cancelled.Load() || len(s.material) == 0 || s.idleExpired(time.Now()) {
			s.saveMu.Unlock()
			return ErrSessionLocked
		}
		d.cap.used = true
		s.saveMu.Unlock()
		ttl := 15 * time.Second
		if d.cap.purpose == "copy" {
			ttl = 30 * time.Second
		}
		bounds := otpBounds(now, d.cap.bounds.From, d.cap.bounds.Until, ttl)
		if e := deliver(d.cap.code, bounds); e != nil {
			return ErrDesktopDelivery
		}
		return nil
	}()
}

func (s *Session) DiscardOTP(p *NativeOTP) {
	if p == nil {
		return
	}
	p.cap.clear()
	s.otpCaps.Delete(p.cap)
	s.mu.Lock()
	delete(s.otpPrepared, p)
	s.mu.Unlock()
}
func (s *Session) DiscardOTPDelivery(d *NativeOTPDelivery) {
	if d == nil {
		return
	}
	d.cap.clear()
	s.otpCaps.Delete(d.cap)
	s.mu.Lock()
	delete(s.otpDeliveries, d)
	s.mu.Unlock()
}
