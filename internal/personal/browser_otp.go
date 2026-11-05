package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
)

const browserOTPAction = "item.browser.fill.otp-code"
const BrowserOTPBudget = 1500 * time.Millisecond
const browserOTPMargin = 100 * time.Millisecond

var ErrBrowserOTP = errors.New("browser OTP refused")
var ErrBrowserOTPUnknown = errors.New("browser OTP output outcome unknown")

type BrowserOTPContext struct {
	BrowserContext
	WindowID int64 `json:"window_id"`
}

func (c BrowserOTPContext) Valid() bool {
	return c.BrowserContext.Valid() && c.WindowID > 0 && c.WindowID <= 9007199254740991
}

type BrowserOTPTarget struct {
	Context        BrowserOTPContext
	ID, Revision   string
	ProfileVersion int
}

func (t BrowserOTPTarget) valid() bool {
	return t.Context.Valid() && idOK(t.ID) && digestOK(t.Revision) && t.ProfileVersion == 1
}
func (t BrowserOTPTarget) binding(key []byte) (string, error) {
	derived, err := hkdf.Key(sha256.New, key, nil, "locklark/personal/browser-otp/key/v1", 32)
	if err != nil {
		return "", ErrBrowserOTP
	}
	defer clear(derived)
	raw, err := json.Marshal(t)
	if err != nil {
		return "", ErrBrowserOTP
	}
	defer clear(raw)
	m := hmac.New(sha256.New, derived)
	m.Write([]byte("locklark/browser-otp/v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// The public handle is copy-safe and redacted; all arbitration belongs to its
// single private state. It exists before any configuration or code is read.
type BrowserOTPControl struct{ inner *browserOTPState }
type browserOTPState struct {
	mu     sync.Mutex
	status atomic.Uint32 // pending, output-granted, cancelled
	until  time.Time
	done   chan struct{}
	timer  *time.Timer
	owner  *Session
	gate   *MutationGate
	holder *otpCap
}

func NewBrowserOTPControl(until time.Time) *BrowserOTPControl {
	c := &BrowserOTPControl{inner: &browserOTPState{until: until, done: make(chan struct{})}}
	c.inner.mu.Lock()
	c.inner.timer = time.AfterFunc(time.Until(until), func() { c.Cancel() })
	c.inner.mu.Unlock()
	return c
}
func (BrowserOTPControl) String() string               { return "[browser OTP control]" }
func (BrowserOTPControl) GoString() string             { return "[browser OTP control]" }
func (BrowserOTPControl) MarshalJSON() ([]byte, error) { return nil, ErrBrowserOTP }
func (c *BrowserOTPControl) Granted() bool {
	return c != nil && c.inner != nil && c.inner.status.Load() == 1
}
func (c *BrowserOTPControl) Pending() bool {
	if c == nil || c.inner == nil || c.inner.status.Load() != 0 {
		return false
	}
	c.inner.mu.Lock()
	valid := time.Now().Before(c.inner.until) && c.inner.status.Load() == 0
	c.inner.mu.Unlock()
	if !valid {
		c.Cancel()
	}
	return valid
}
func (c *BrowserOTPControl) Deadline() time.Time {
	if c == nil || c.inner == nil {
		return time.Time{}
	}
	c.inner.mu.Lock()
	defer c.inner.mu.Unlock()
	return c.inner.until
}
func (c *BrowserOTPControl) Done() <-chan struct{} {
	if c == nil || c.inner == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return c.inner.done
}
func (c *BrowserOTPControl) Shorten(until time.Time) {
	if c == nil || c.inner == nil {
		return
	}
	c.inner.mu.Lock()
	defer c.inner.mu.Unlock()
	if until.Before(c.inner.until) && c.inner.status.Load() == 0 {
		c.inner.until = until
		c.inner.timer.Reset(time.Until(until))
	}
}
func (c *BrowserOTPControl) Cancel() bool {
	return c.cancelBefore(time.Time{}, false)
}

// CancelBefore claims cancellation only before the current shortened deadline.
// Expired controls are still revoked, but expiry is not a win for this caller.
func (c *BrowserOTPControl) CancelBefore(now time.Time) bool { return c.cancelBefore(now, true) }
func (c *BrowserOTPControl) cancelBefore(now time.Time, enforceDeadline bool) bool {
	if c == nil || c.inner == nil {
		return false
	}
	x := c.inner
	x.mu.Lock()
	claimed := !enforceDeadline || now.Before(x.until)
	if !x.status.CompareAndSwap(0, 2) {
		x.mu.Unlock()
		return false
	}
	close(x.done)
	if x.timer != nil {
		x.timer.Stop()
	}
	if x.gate != nil {
		x.gate.Cancel()
	}
	if x.holder != nil {
		x.holder.cancel()
	}
	owner := x.owner
	x.mu.Unlock()
	// Waiting for I/O or a holder's short ownership lock is never part of
	// Cancel/RequestLock. The registered holder remains cancellable until zeroed.
	if owner != nil {
		go owner.discardBrowserControl(x)
	}
	return claimed
}

type BrowserOTP struct {
	cap     *otpCap
	target  BrowserOTPTarget
	control *BrowserOTPControl
}
type BrowserOTPDelivery struct {
	cap     *otpCap
	target  BrowserOTPTarget
	control *BrowserOTPControl
}
type BrowserOTPOutput struct{ inner *browserOTPOutput }
type browserOTPOutput struct {
	used   atomic.Bool
	code   []byte
	bounds OTPBounds
}

func (o *BrowserOTPOutput) Deadline() time.Time {
	if o == nil || o.inner == nil {
		return time.Time{}
	}
	return o.inner.bounds.Deadline
}

func (BrowserOTP) String() string                       { return "[browser OTP preparation]" }
func (BrowserOTP) GoString() string                     { return "[browser OTP preparation]" }
func (BrowserOTP) MarshalJSON() ([]byte, error)         { return nil, ErrBrowserOTP }
func (BrowserOTPDelivery) String() string               { return "[browser OTP delivery]" }
func (BrowserOTPDelivery) GoString() string             { return "[browser OTP delivery]" }
func (BrowserOTPDelivery) MarshalJSON() ([]byte, error) { return nil, ErrBrowserOTP }
func (BrowserOTPOutput) String() string                 { return "[browser OTP output]" }
func (BrowserOTPOutput) GoString() string               { return "[browser OTP output]" }
func (BrowserOTPOutput) MarshalJSON() ([]byte, error)   { return nil, ErrBrowserOTP }

func (s *Session) registerBrowserControl(c *BrowserOTPControl, g *MutationGate, target BrowserOTPTarget) (*otpCap, error) {
	if c == nil || c.inner == nil || !target.valid() {
		return nil, ErrBrowserOTP
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	x := c.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if s.lockRequested.Load() || x.owner != nil || x.status.Load() != 0 || !time.Now().Before(x.until) || s.saveGate != g || !g.Pending() || !s.otpCapacity() {
		return nil, ErrBrowserOTP
	}
	p := &otpCap{target: NativeOTPTarget{target.ID, target.Revision}, purpose: "browser"}
	x.owner, x.gate, x.holder = s, g, p
	s.browserOTPControls.Store(x, true)
	s.otpCaps.Store(p, true)
	return p, nil
}
func (s *Session) discardBrowserControl(x *browserOTPState) {
	x.mu.Lock()
	holder := x.holder
	x.mu.Unlock()
	if holder != nil {
		holder.clear()
		s.otpCaps.Delete(holder)
	}
	s.browserOTPControls.Delete(x)
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.browserOTPPrepared {
		if p.control.inner == x {
			delete(s.browserOTPPrepared, p)
		}
	}
	for d := range s.browserOTPDeliveries {
		if d.control.inner == x {
			delete(s.browserOTPDeliveries, d)
		}
	}
}

func (s *Session) PrepareBrowserOTP(target BrowserOTPTarget, g *MutationGate, c *BrowserOTPControl) (_ *BrowserOTP, err error) {
	return s.prepareBrowserOTPWith(target, g, c, nil)
}
func (s *Session) prepareBrowserOTPWith(target BrowserOTPTarget, g *MutationGate, c *BrowserOTPControl, run func(commandOption) (result, error)) (_ *BrowserOTP, err error) {
	ok := false
	defer func() {
		if !ok {
			if c != nil {
				c.Cancel()
			}
			if g != nil {
				g.Cancel()
				s.ReleaseMutation(g)
			}
		}
	}()
	cap, err := s.registerBrowserControl(c, g, target)
	if err != nil {
		return nil, err
	}
	started := s.otpNowTime().Round(0)
	r, err := s.nativeMutationWithTouch(browserOTPAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision}, commandOption{browserOTP: &target}, g, run, false)
	if r.otp != nil {
		defer r.otp.Clear()
	}
	if err != nil {
		return nil, err
	}
	if r.otp == nil || !c.Pending() {
		return nil, ErrBrowserOTP
	}
	sample := s.otpNowTime()
	if sample.Round(0).Before(started) {
		return nil, ErrOTPTime
	}
	code, err := r.otp.At(sample.Unix())
	r.otp.Clear()
	if err != nil {
		return nil, err
	}
	window := code.Window()
	if time.Unix(window.Until, 0).Sub(sample.Round(0)) < BrowserOTPBudget+browserOTPMargin {
		return nil, ErrOTPTime
	}
	cap.mu.Lock()
	if cap.cancelled.Load() || cap.used || !c.Pending() {
		cap.mu.Unlock()
		return nil, ErrBrowserOTP
	}
	cap.bounds = otpBounds(sample, window.From, window.Until, BrowserOTPBudget)
	if until := c.Deadline(); until.Before(cap.bounds.Deadline) {
		cap.bounds.Deadline = until
	}
	// The core enforces its own code lifetime even if a caller supplied a
	// longer metadata/control deadline. Keep the original cancellation identity.
	c.Shorten(cap.bounds.Deadline)
	if !c.Pending() {
		cap.mu.Unlock()
		return nil, ErrOTPTime
	}
	cap.code = []byte(code.Value())
	cap.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil || !c.Pending() {
		return nil, ErrBrowserOTP
	}
	p := &BrowserOTP{cap: cap, target: target, control: c}
	if s.browserOTPPrepared == nil {
		s.browserOTPPrepared = map[*BrowserOTP]bool{}
	}
	s.browserOTPPrepared[p] = true
	ok = true
	return p, nil
}
func (s *Session) AuthorizeBrowserOTP(p *BrowserOTP) (*BrowserOTPDelivery, error) {
	return s.authorizeBrowserOTPWith(p, func(target BrowserOTPTarget) error {
		return s.readNativeTargetWithPurpose(target.ID, target.Revision, "browser.otp.verify", func(item vault.Item) error {
			site, err := origin.Website(item.URL)
			if item.State != "" || err != nil || site != target.Context.Origin {
				return ErrBrowserOTP
			}
			return nil
		})
	})
}
func (s *Session) authorizeBrowserOTPWith(p *BrowserOTP, verify func(BrowserOTPTarget) error) (_ *BrowserOTPDelivery, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil || !s.browserOTPPrepared[p] {
		return nil, ErrBrowserOTP
	}
	delete(s.browserOTPPrepared, p)
	ok := false
	defer func() {
		p.cap.clear()
		s.otpCaps.Delete(p.cap)
		if !ok {
			p.control.Cancel()
		}
	}()
	if s.active(false) != nil || !p.control.Pending() {
		return nil, ErrBrowserOTP
	}
	if err = verify(p.target); err != nil {
		return nil, err
	}
	p.cap.mu.Lock()
	defer p.cap.mu.Unlock()
	if p.cap.purpose != "browser" || p.cap.target != (NativeOTPTarget{p.target.ID, p.target.Revision}) {
		return nil, ErrBrowserOTP
	}
	if p.cap.cancelled.Load() || p.cap.used || len(p.cap.code) == 0 || !p.cap.bounds.Check(s.otpNowTime()) {
		return nil, ErrOTPTime
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	x := p.control.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.owner != s || x.holder != p.cap || x.status.Load() != 0 || !time.Now().Before(x.until) || s.lockRequested.Load() {
		return nil, ErrBrowserOTP
	}
	d := &BrowserOTPDelivery{cap: &otpCap{code: p.cap.code, target: p.cap.target, purpose: "browser", bounds: p.cap.bounds}, target: p.target, control: p.control}
	s.otpCaps.Store(d.cap, true)
	p.cap.code = nil
	p.cap.used = true
	x.holder = d.cap
	s.otpCaps.Delete(p.cap)
	if s.browserOTPDeliveries == nil {
		s.browserOTPDeliveries = map[*BrowserOTPDelivery]bool{}
	}
	s.browserOTPDeliveries[d] = true
	ok = true
	return d, nil
}

// GrantBrowserOTP never waits for disk or invokes a callback. Only after a
// writer slot is owned may the transport move this single buffer out of its
// cancellable registry. RequestLock and Cancel arbitrate on the same short locks.
func (s *Session) GrantBrowserOTP(d *BrowserOTPDelivery) (*BrowserOTPOutput, error) {
	if !s.mu.TryLock() {
		return nil, ErrBrowserOTP
	}
	defer s.mu.Unlock()
	if d == nil || !s.browserOTPDeliveries[d] {
		return nil, ErrBrowserOTP
	}
	delete(s.browserOTPDeliveries, d)
	defer func() { d.cap.clear(); s.otpCaps.Delete(d.cap) }()
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	if d.control == nil || d.control.inner == nil {
		return nil, ErrBrowserOTP
	}
	now := s.otpNowTime()
	d.cap.mu.Lock()
	defer d.cap.mu.Unlock()
	if d.cap.purpose != "browser" || d.cap.target != (NativeOTPTarget{d.target.ID, d.target.Revision}) {
		return nil, ErrBrowserOTP
	}
	if d.cap.cancelled.Load() || d.cap.used || !d.cap.bounds.Check(now) || !validBrowserOTPCode(d.cap.code) {
		return nil, ErrBrowserOTP
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	x := d.control.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.owner != s || x.holder != d.cap || s.lockRequested.Load() || x.status.Load() != 0 || !time.Now().Before(x.until) || d.cap.cancelled.Load() || d.cap.used || !time.Now().Before(d.cap.bounds.Deadline) {
		return nil, ErrBrowserOTP
	}
	if !x.status.CompareAndSwap(0, 1) {
		return nil, ErrBrowserOTP
	}
	if x.timer != nil {
		x.timer.Stop()
	}
	output := &BrowserOTPOutput{inner: &browserOTPOutput{code: d.cap.code, bounds: d.cap.bounds}}
	d.cap.code = nil
	d.cap.used = true
	x.holder = nil
	s.browserOTPControls.Delete(x)
	return output, nil
}
func validBrowserOTPCode(code []byte) bool {
	if len(code) != 6 && len(code) != 8 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (o *BrowserOTPOutput) Consume(deliver func([]byte, OTPBounds) error) error {
	if o == nil || o.inner == nil || !o.inner.used.CompareAndSwap(false, true) {
		return ErrBrowserOTPUnknown
	}
	defer func() { clear(o.inner.code); o.inner.code = nil }()
	if deliver == nil || !o.inner.bounds.Check(time.Now()) {
		return ErrBrowserOTPUnknown
	}
	if deliver(o.inner.code, o.inner.bounds) != nil {
		return ErrBrowserOTPUnknown
	}
	return nil
}
func (o *BrowserOTPOutput) Clear() {
	if o != nil && o.inner != nil && o.inner.used.CompareAndSwap(false, true) {
		clear(o.inner.code)
		o.inner.code = nil
	}
}
func (s *Session) DiscardBrowserOTP(p *BrowserOTP) {
	if p != nil {
		p.control.Cancel()
	}
}
func (s *Session) DiscardBrowserOTPDelivery(d *BrowserOTPDelivery) {
	if d != nil {
		d.control.Cancel()
	}
}
