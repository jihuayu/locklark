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
	request      Request
	target       personal.PasskeyTarget
	parsed       *passkey.Request
	session      *personal.Session
	gate         *personal.MutationGate
	until        time.Time
	epoch        uint64
	passkeyEpoch uint64
	cancelled    atomic.Bool
	working      bool
	choices      []personal.PasskeyChoice
	timer        *time.Timer
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
	// A conditional selection pins one exact login. Protocol validation allows
	// the pair only for passkey-get, so creation can never attach by selector.
	target := personal.PasskeyTarget{Context: r.Context(), Create: parsed.Create, Options: []byte(r.Options)}
	if !parsed.Create && r.ItemID != "" && r.Revision != "" {
		target.ID, target.Revision = r.ItemID, r.Revision
	}
	p := &pendingPasskey{request: r, parsed: parsed, session: s, gate: gate, until: until, epoch: c.epoch, passkeyEpoch: s.PasskeyRevocationEpoch(), target: target, working: true}
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
	if p == nil || p.session == nil || c.session.Load() != p.session {
		return false
	}
	return !p.cancelled.Load() && p.epoch == c.generation.Load() && p.passkeyEpoch == p.session.PasskeyRevocationEpoch() && c.valid(p.request.Capability) && c.now().Before(p.until)
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

// expireConcurrentPasskey revokes an approval surface whose owning Session has
// advanced the passkey revocation epoch (for example a credential removal on
// another shared connection after the mutation slot was released). A running
// worker keeps ownership of its gate; its queued result is refused by
// passkeyLive before delivery.
func (c *Connection) expireConcurrentPasskey() (refuseID string, stale bool) {
	p := c.passkey
	if p == nil || p.session == nil || p.passkeyEpoch == p.session.PasskeyRevocationEpoch() {
		return "", false
	}
	p.cancelled.Store(true)
	p.gate.Cancel()
	c.passkeyStatus = "Passkey 请求已因凭据删除而失效"
	if p.working {
		return "", true
	}
	refuseID = p.request.ID
	c.clearPasskey(p)
	return refuseID, true
}

func (c *Connection) passkeySnapshot() (*PasskeyView, string) {
	if refuseID, stale := c.expireConcurrentPasskey(); stale {
		if refuseID != "" {
			go c.refuse(refuseID)
		}
		return nil, c.passkeyStatus
	}
	p := c.passkey
	if p == nil {
		return nil, c.passkeyStatus
	}
	return &PasskeyView{ID: p.request.ID, Origin: p.request.Origin, RPID: p.parsed.RPID, Username: p.parsed.Options.User.Name, Create: p.parsed.Create, VerificationRequired: p.parsed.RequiresVerification(), Working: p.working, Choices: append([]personal.PasskeyChoice(nil), p.choices...)}, c.passkeyStatus
}

// resolvePasskeyApproval captures the exact pending request and selected
// target under c.mu. A prepopulated (pinned) target is enforced exactly, and an
// empty selection only ever means "create a new login".
func (c *Connection) resolvePasskeyApproval(id, itemID string) (*pendingPasskey, personal.PasskeyTarget, error) {
	p := c.passkey
	if p == nil || p.request.ID != id || p.working || !c.passkeyLive(p) {
		return nil, personal.PasskeyTarget{}, ErrProtocol
	}
	target := p.target
	pinned := p.target.ID
	if itemID != "" {
		// The UI selection must match a reviewed choice exactly. A prepopulated
		// (pinned) target never satisfies the check by itself, so another account
		// cannot be promoted to the signed identity.
		matched := false
		target.ID, target.Revision = "", ""
		for _, choice := range p.choices {
			if choice.ID == itemID {
				target.ID, target.Revision, matched = choice.ID, choice.Revision, true
				break
			}
		}
		if !matched || pinned != "" && (target.ID != pinned || target.Revision != p.target.Revision) {
			return nil, personal.PasskeyTarget{}, ErrProtocol
		}
	} else {
		// An empty selection only ever creates a new login; it is never an
		// implicit choice of a pinned or merely pre-populated target.
		if !target.Create || pinned != "" {
			return nil, personal.PasskeyTarget{}, ErrProtocol
		}
	}
	return p, target, nil
}

// ApprovePasskey is called only from the native UI. Fresh knowledge factors are
// verified here; the browser can never assert user verification. An empty
// selection creates a new login.
func (c *Connection) ApprovePasskey(id, itemID string, password, secret []byte) error {
	defer clear(password)
	defer clear(secret)
	return c.approvePasskey(id, itemID, func(p *pendingPasskey) (bool, error) {
		verified := len(password) > 0 || len(secret) > 0
		if !verified {
			return false, nil
		}
		return true, p.session.VerifyPasskeyUser(password, secret)
	})
}

// ApprovePasskeyWithSystem is called only from the native UI. Every approval
// asks the trusted OS adapter again for fresh user verification; no earlier
// system unlock, cached result or proof can satisfy it. The browser still never
// asserts user verification, and no new private material crosses this API.
// It fails closed when the adapter is absent or the capsule is not enrolled.
func (c *Connection) ApprovePasskeyWithSystem(id, itemID string, store personal.SystemPasskeyVerificationStore) error {
	if store == nil {
		return ErrProtocol
	}
	return c.approvePasskey(id, itemID, func(p *pendingPasskey) (bool, error) {
		if e := p.session.VerifyPasskeyUserWithSystem(store); e != nil {
			return false, e
		}
		return true, nil
	})
}

// approvePasskey is the single approval path for both knowledge factors and
// the native OS user-verification adapter. It preserves the exact selector and
// revision, the registered mutation gate, the pending request pointer, the
// connection generation and passkey revocation epoch, the deadline and the
// queued writer checks. Neither c.mu nor a Session lock is held while the
// verification callback waits on the user.
func (c *Connection) approvePasskey(id, itemID string, verify func(*pendingPasskey) (bool, error)) error {
	c.mu.Lock()
	p, target, e := c.resolvePasskeyApproval(id, itemID)
	if e != nil {
		c.mu.Unlock()
		return e
	}
	p.working = true
	c.mu.Unlock()
	c.changed()
	verified := false
	if verify != nil {
		verified, e = verify(p)
	}
	if e == nil && p.parsed.RequiresVerification() && !verified {
		e = passkey.ErrRefused
	}
	var credential passkey.Response
	if e != nil {
		p.session.ReleaseMutation(p.gate)
	} else {
		// The user may have cancelled, locked, navigated or let the request
		// expire while the factor or OS prompt was open. Revalidate the same
		// pending request under a short c.mu hold before any commit.
		c.mu.Lock()
		live := c.passkey == p && c.passkeyLive(p)
		c.mu.Unlock()
		if live {
			credential, e = p.session.PerformPasskey(target, verified, p.gate)
		} else {
			p.session.ReleaseMutation(p.gate)
			e = passkey.ErrRefused
		}
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
