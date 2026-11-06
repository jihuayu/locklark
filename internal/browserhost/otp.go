package browserhost

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

type OTPView struct {
	ID, Origin, ItemID, Revision, Title, Stage string
	Until                                      time.Time
}
type otpRetired uint8

const (
	otpNatural otpRetired = iota + 1
	otpCancelled
	otpGranted
)

type otpCancellation struct {
	mu  sync.Mutex
	won bool
}

type pendingOTP struct {
	cancellation                *otpCancellation
	request                     Request
	target                      personal.BrowserOTPTarget
	session                     *personal.Session
	gate                        *personal.MutationGate
	control                     *personal.BrowserOTPControl
	title                       string
	until                       time.Time
	epoch                       uint64
	nonce                       [32]byte
	originalClaimed, ackClaimed bool
	ackID                       string
	timer                       *time.Timer
}

// Cancellation ingress and retirement agree on who actually won the control
// CAS. This short lock is released before auth bookkeeping or any I/O.
func (p *pendingOTP) requestCancel(now time.Time) bool {
	p.cancellation.mu.Lock()
	defer p.cancellation.mu.Unlock()
	if p.control.CancelBefore(now) {
		p.cancellation.won = true
	}
	return p.cancellation.won
}
func (p *pendingOTP) retirement(state otpRetired) otpRetired {
	p.cancellation.mu.Lock()
	defer p.cancellation.mu.Unlock()
	if p.control.Granted() {
		return otpGranted
	}
	if p.cancellation.won {
		state = otpCancelled
	}
	p.control.Cancel()
	return state
}

func (pendingOTP) String() string               { return "[browser OTP pending]" }
func (pendingOTP) GoString() string             { return "[browser OTP pending]" }
func (pendingOTP) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }

func otpError(id string) Response { return Response{ID: id, Type: "error", Error: "refused"} }
func (c *Connection) sendOTPResponses(responses []Response) error {
	for _, r := range responses {
		if err := c.response(r); err != nil {
			return err
		}
	}
	return nil
}

// Caller holds only Connection.mu. Terminal response ownership is claimed
// here; all actual writer acquisition and pipe I/O takes place after unlock.
func (c *Connection) retireOTP(p *pendingOTP, state otpRetired) []Response {
	if c.otp != p {
		return nil
	}
	state = p.retirement(state)
	var responses []Response
	if state != otpGranted {
		if p.ackID != "" && !p.ackClaimed {
			p.ackClaimed = true
			responses = append(responses, otpError(p.ackID))
		} else if !p.originalClaimed {
			p.originalClaimed = true
			responses = append(responses, otpError(p.request.ID))
		}
	}
	if c.otpRetired == nil {
		c.otpRetired = map[string]otpRetired{}
	}
	c.otpRetired[p.request.ID] = state // bounded by the 128-message connection budget
	if p.timer != nil {
		p.timer.Stop()
	}
	clear(p.nonce[:])
	p.session.ReleaseMutation(p.gate)
	c.otp = nil
	c.rows = nil
	c.context = personal.BrowserContext{}
	c.authMu.Lock()
	if c.otpAuth == p {
		c.otpAuth = nil
	}
	c.authMu.Unlock()
	return responses
}
func (c *Connection) invalidateOTP() {
	if p := c.otp; p != nil {
		if p.control.Granted() {
			c.otpUnknown.Store(true)
			c.otpStatus = "验证码交付结果未确认；不会自动重试"
		} else {
			c.otpStatus = "本次验证码未交付"
		}
		responses := c.retireOTP(p, otpCancelled)
		if len(responses) != 0 {
			go c.sendOTPResponses(responses)
		}
	}
}
func (c *Connection) expireOTP(p *pendingOTP) {
	p.control.Cancel()
	c.mu.Lock()
	if c.otp != p {
		c.mu.Unlock()
		return
	}
	if p.control.Granted() {
		c.otpUnknown.Store(true)
		c.otpStatus = "验证码交付结果未确认；不会自动重试"
	} else {
		c.otpStatus = "验证码请求已失效；本次未交付"
	}
	responses := c.retireOTP(p, otpNatural)
	c.mu.Unlock()
	c.changed()
	_ = c.sendOTPResponses(responses)
}
func (c *Connection) handleOTP(r Request, allowed bool) error {
	if !allowed {
		return c.refuse(r.ID)
	}
	c.mu.Lock()
	c.syncEpoch()
	c.expire()
	var responses []Response
	if p := c.otp; p != nil && !c.now().Before(p.until) {
		responses = append(responses, c.retireOTP(p, otpNatural)...)
	}
	if !c.valid(r.Capability) {
		responses = append(responses, otpError(r.ID))
		c.mu.Unlock()
		c.changed()
		return c.sendOTPResponses(responses)
	}
	switch r.Type {
	case "otp":
		if c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil || c.context.Origin != r.Origin || c.context.TabID != r.TabID || c.context.DocumentID != r.DocumentID {
			responses = append(responses, otpError(r.ID))
			break
		}
		title, found := "", false
		for _, row := range c.rows {
			if row.ID == r.ItemID && row.Revision == r.Revision {
				title, found = row.Title, true
				break
			}
		}
		if !found {
			responses = append(responses, otpError(r.ID))
			break
		}
		s := c.session.Load()
		until := minTime(c.now().Add(30*time.Second), c.until)
		gate := personal.NewMutationGate(until)
		if s == nil || s.RegisterMutation(gate) != nil {
			responses = append(responses, otpError(r.ID))
			break
		}
		control := personal.NewBrowserOTPControl(until)
		if !c.valid(r.Capability) {
			control.Cancel()
			s.ReleaseMutation(gate)
			responses = append(responses, otpError(r.ID))
			break
		}
		p := &pendingOTP{cancellation: &otpCancellation{}, request: r, target: personal.BrowserOTPTarget{Context: r.OTPContext(), ID: r.ItemID, Revision: r.Revision, ProfileVersion: 1}, session: s, gate: gate, control: control, title: title, until: until, epoch: c.epoch}
		c.otp = p
		c.otpRequestID = r.ID
		c.otpStatus = "等待原生批准验证码填充"
		c.authMu.Lock()
		c.otpAuth = p
		c.authMu.Unlock()
		p.timer = time.AfterFunc(time.Until(until), func() { c.expireOTP(p) })
		if c.quickFill {
			go func() { _ = c.ApproveOTP(r.ID) }()
		}
	case "otp-ack":
		p := c.otp
		if p == nil || p.request.ID != r.RequestID || !p.originalClaimed || p.ackID != "" || !p.control.Pending() {
			responses = append(responses, otpError(r.ID))
			break
		}
		nonce, err := hex.DecodeString(r.Nonce)
		matched := err == nil && subtle.ConstantTimeCompare(nonce, p.nonce[:]) == 1
		clear(nonce)
		if !matched {
			responses = append(responses, otpError(r.ID))
			break
		}
		clear(p.nonce[:])
		p.ackID = r.ID
		p.until = minTime(p.until, c.now().Add(personal.BrowserOTPBudget))
		p.control.Shorten(p.until)
		if p.timer != nil {
			p.timer.Stop()
		}
		p.timer = time.AfterFunc(time.Until(p.until), func() { c.expireOTP(p) })
		c.otpStatus = "正在准备本次验证码"
		go c.performOTP(p)
	case "cancel-otp":
		p := c.otp
		if p == nil || p.request.ID != r.RequestID {
			switch c.otpRetired[r.RequestID] {
			case otpGranted:
				responses = append(responses, Response{ID: r.ID, Type: "unknown"})
			case otpCancelled:
				responses = append(responses, Response{ID: r.ID, Type: "cancelled"})
			default:
				responses = append(responses, otpError(r.ID))
			}
			break
		}
		won := p.requestCancel(c.now())
		if p.control.Granted() {
			c.otpUnknown.Store(true)
			c.otpStatus = "验证码交付结果未确认；不会自动重试"
			responses = append(responses, Response{ID: r.ID, Type: "unknown"})
		} else if won {
			c.otpStatus = "本次验证码未交付"
			responses = append(responses, c.retireOTP(p, otpCancelled)...)
			responses = append(responses, Response{ID: r.ID, Type: "cancelled"})
		} else {
			responses = append(responses, c.retireOTP(p, otpNatural)...)
			responses = append(responses, otpError(r.ID))
		}
	}
	c.mu.Unlock()
	c.changed()
	return c.sendOTPResponses(responses)
}

func (c *Connection) ApproveOTP(id string) error {
	c.mu.Lock()
	c.syncEpoch()
	c.expire()
	p := c.otp
	if p == nil || p.request.ID != id || p.originalClaimed || !p.control.Pending() || !c.valid(p.request.Capability) {
		c.mu.Unlock()
		return ErrProtocol
	}
	c.mu.Unlock()
	if err := p.session.TouchBrowserSave(p.gate); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrProtocol
	}
	defer clear(nonce[:])
	c.mu.Lock()
	if c.otp != p || p.originalClaimed || p.epoch != c.generation.Load() || !p.control.Pending() || !c.valid(p.request.Capability) {
		c.mu.Unlock()
		return ErrProtocol
	}
	p.nonce = nonce
	p.originalClaimed = true // claim the O response, not proof of pipe completion
	p.until = minTime(p.until, c.now().Add(3*time.Second))
	p.control.Shorten(p.until)
	p.gate.Shorten(p.until)
	if p.timer != nil {
		p.timer.Stop()
	}
	p.timer = time.AfterFunc(time.Until(p.until), func() { c.expireOTP(p) })
	c.otpStatus = "已批准，正在核对当前页面"
	response := Response{ID: id, Type: "otp-ready", Nonce: hex.EncodeToString(p.nonce[:])}
	c.mu.Unlock()
	c.changed()
	return c.response(response)
}
func (c *Connection) RejectOTP(id string) error {
	c.mu.Lock()
	p := c.otp
	if p == nil || p.request.ID != id {
		c.mu.Unlock()
		return ErrProtocol
	}
	won := p.requestCancel(c.now())
	if p.control.Granted() {
		c.otpUnknown.Store(true)
		c.otpStatus = "验证码交付结果未确认；不会自动重试"
		c.mu.Unlock()
		c.changed()
		return nil
	}
	c.otpStatus = "本次验证码未交付"
	state := otpNatural
	if won {
		state = otpCancelled
	}
	responses := c.retireOTP(p, state)
	c.mu.Unlock()
	c.changed()
	return c.sendOTPResponses(responses)
}

func (c *Connection) performOTP(p *pendingOTP) {
	prepared, err := p.session.PrepareBrowserOTP(p.target, p.gate, p.control)
	if err != nil {
		c.finishOTP(p, err)
		return
	}
	defer p.session.DiscardBrowserOTP(prepared)
	delivery, err := p.session.AuthorizeBrowserOTP(prepared)
	if err != nil {
		c.finishOTP(p, err)
		return
	}
	defer p.session.DiscardBrowserOTPDelivery(delivery)
	err = c.writer.WriteOTP(p.ackID, p.control, func() (*personal.BrowserOTPOutput, error) {
		return c.grantOTP(p, delivery)
	})
	c.finishOTP(p, err)
}
func (c *Connection) grantOTP(p *pendingOTP, delivery *personal.BrowserOTPDelivery) (*personal.BrowserOTPOutput, error) {
	if !c.mu.TryLock() {
		return nil, ErrProtocol
	}
	defer c.mu.Unlock()
	if c.otp != p || p.ackClaimed || p.epoch != c.generation.Load() || c.closed.Load() || !c.now().Before(c.until) || !c.now().Before(p.until) {
		return nil, ErrProtocol
	}
	output, err := p.session.GrantBrowserOTP(delivery)
	if output != nil {
		p.ackClaimed = true
	}
	return output, err
}

func (c *Connection) finishOTP(p *pendingOTP, err error) {
	c.mu.Lock()
	if c.otp != p {
		c.mu.Unlock()
		return
	}
	if p.control.Granted() {
		if err != nil {
			c.otpUnknown.Store(true)
			c.otpStatus = "验证码交付结果未确认；不会自动重试"
		} else {
			c.otpStatus = "已尝试交付本次验证码；网站是否接受未确认"
		}
	} else {
		c.otpStatus = "本次验证码未交付"
	}
	responses := c.retireOTP(p, otpNatural)
	c.mu.Unlock()
	c.changed()
	_ = c.sendOTPResponses(responses)
}
func (c *Connection) otpSnapshot() (*OTPView, string) {
	p := c.otp
	if p == nil {
		return nil, c.otpStatus
	}
	stage := "pending"
	if p.originalClaimed {
		stage = "approved"
	}
	if p.ackID != "" {
		stage = "preparing"
	}
	return &OTPView{ID: p.request.ID, Origin: p.request.Origin, ItemID: p.request.ItemID, Revision: p.request.Revision, Title: p.title, Stage: stage, Until: p.until}, c.otpStatus
}
func (c *Connection) OTPUnknown() bool { return c.otpUnknown.Load() }
