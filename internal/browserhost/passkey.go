package browserhost

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

type PasskeyView struct {
	ID, Origin, RPID, Username            string
	Create, VerificationRequired, Working bool
	Choices                               []personal.PasskeyChoice
}
type pendingPasskey struct {
	request   Request
	target    personal.PasskeyTarget
	parsed    *passkey.Request
	session   *personal.Session
	gate      *personal.MutationGate
	until     time.Time
	epoch     uint64
	cancelled atomic.Bool
	working   bool
	choices   []personal.PasskeyChoice
	timer     *time.Timer
}

func (c *Connection) startPasskey(r Request) error {
	if c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil {
		return c.refuse(r.ID)
	}
	parsed, e := passkey.Parse(r.Origin, r.Type == "passkey-create", []byte(r.Options))
	if e != nil {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	until := minTime(c.until, c.now().Add(2*time.Minute))
	if parsed.Options.Timeout > 0 {
		until = minTime(until, c.now().Add(time.Duration(parsed.Options.Timeout)*time.Millisecond))
	}
	gate := personal.NewMutationGate(until)
	if s.RegisterMutation(gate) != nil {
		return c.refuse(r.ID)
	}
	p := &pendingPasskey{request: r, parsed: parsed, session: s, gate: gate, until: until, epoch: c.epoch, target: personal.PasskeyTarget{Context: r.Context(), Create: parsed.Create, Options: []byte(r.Options)}, working: true}
	c.passkey = p
	c.passkeyStatus = "正在读取 Passkey"
	c.authMu.Lock()
	c.passkeyAuth = p
	c.authMu.Unlock()
	p.timer = time.AfterFunc(time.Until(until), func() {
		p.cancelled.Store(true)
		p.gate.Cancel()
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.passkey != p || p.working {
			return
		}
		c.clearPasskey(p)
		c.passkeyStatus = "Passkey 请求已过期"
		_ = c.refuse(p.request.ID)
	})
	go func() {
		choices, err := s.ReviewPasskey(p.target)
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.passkey != p {
			p.session.ReleaseMutation(p.gate)
			return
		}
		p.working = false
		if err != nil || !c.passkeyLive(p) || !parsed.Create && len(choices) == 0 {
			c.clearPasskey(p)
			c.passkeyStatus = "没有可用的 Passkey，或请求已失效"
			_ = c.refuse(r.ID)
			return
		}
		p.choices = choices
		c.passkeyStatus = "请核对网站并确认 Passkey 操作"
	}()
	return nil
}
func (c *Connection) passkeyLive(p *pendingPasskey) bool {
	return !p.cancelled.Load() && p.epoch == c.generation.Load() && c.valid(p.request.Capability) && c.now().Before(p.until)
}
func (c *Connection) clearPasskey(p *pendingPasskey) {
	p.cancelled.Store(true)
	p.gate.Cancel()
	if p.timer != nil {
		p.timer.Stop()
	}
	// A running worker owns its registered gate until its transaction returns.
	if !p.working {
		p.session.ReleaseMutation(p.gate)
	}
	if c.passkey == p {
		c.passkey = nil
	}
	c.authMu.Lock()
	if c.passkeyAuth == p {
		c.passkeyAuth = nil
	}
	c.authMu.Unlock()
}
func (c *Connection) passkeySnapshot() (*PasskeyView, string) {
	p := c.passkey
	if p == nil {
		return nil, c.passkeyStatus
	}
	return &PasskeyView{ID: p.request.ID, Origin: p.request.Origin, RPID: p.parsed.RPID, Username: p.parsed.Options.User.Name, Create: p.parsed.Create, VerificationRequired: p.parsed.RequiresVerification(), Working: p.working, Choices: append([]personal.PasskeyChoice(nil), p.choices...)}, c.passkeyStatus
}

// Called only from the native UI. An empty selection creates a new login. Fresh
// factors are verified here; the browser can never assert user verification.
func (c *Connection) ApprovePasskey(id, itemID string, password, secret []byte) error {
	defer clear(password)
	defer clear(secret)
	c.mu.Lock()
	p := c.passkey
	if p == nil || p.request.ID != id || p.working || !c.passkeyLive(p) {
		c.mu.Unlock()
		return ErrProtocol
	}
	target := p.target
	if itemID != "" {
		for _, choice := range p.choices {
			if choice.ID == itemID {
				target.ID = choice.ID
				target.Revision = choice.Revision
				break
			}
		}
		if target.ID == "" {
			c.mu.Unlock()
			return ErrProtocol
		}
	} else if !target.Create {
		c.mu.Unlock()
		return ErrProtocol
	}
	p.working = true
	c.mu.Unlock()
	c.changed()
	verified := len(password) > 0 || len(secret) > 0
	var e error
	if verified {
		e = p.session.VerifyPasskeyUser(password, secret)
	}
	if p.parsed.RequiresVerification() && !verified {
		e = passkey.ErrRefused
	}
	var credential passkey.Response
	if e == nil {
		credential, e = p.session.PerformPasskey(target, verified, p.gate)
	} else {
		p.session.ReleaseMutation(p.gate)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	p.working = false
	if c.passkey != p {
		return ErrProtocol
	}
	defer c.clearPasskey(p)
	if e != nil || !c.passkeyLive(p) {
		c.passkeyStatus = "Passkey 未完成；若创建已开始，请在金库核实后再重试"
		if p.gate.CommitWon() {
			_ = c.response(Response{ID: id, Type: "unknown"})
		} else {
			_ = c.refuse(id)
		}
		return ErrProtocol
	}
	raw, e := json.Marshal(credential)
	if e != nil {
		return c.refuse(id)
	}
	// Recheck after any queued output. The signature must not escape a revoked
	// origin/document/session even when its audit was already committed.
	e = c.writer.WriteGranted(p.until, nil, func() (Response, error) {
		if !c.passkeyLive(p) {
			return Response{}, ErrProtocol
		}
		return Response{V: 1, ID: id, Type: "passkey-result", Credential: string(raw)}, nil
	})
	clear(raw)
	if e != nil {
		c.passkeyStatus = "Passkey 结果未确认；请核实网站与金库"
		if !c.closed.Load() {
			_ = c.refuse(id)
		}
		return e
	}
	c.passkeyStatus = "Passkey 已交付给请求网站"
	c.rows = nil
	c.context = personal.BrowserContext{}
	return nil
}
func (c *Connection) RejectPasskey(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	p := c.passkey
	if p == nil || p.request.ID != id {
		return ErrProtocol
	}
	p.cancelled.Store(true)
	p.gate.Cancel()
	if p.working {
		return nil
	}
	c.clearPasskey(p)
	c.passkeyStatus = "已取消 Passkey 操作"
	return c.refuse(id)
}
