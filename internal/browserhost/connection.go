package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

type Pending struct {
	ID, Origin, ItemID, Revision, Title string
	Until                               time.Time
}
type View struct {
	Passkey                 *PasskeyView
	PasskeyStatus           string
	QuickFill               bool
	OTP                     *OTPView
	OTPStatus, OTPRequestID string
	Save                    *SaveView
	SaveStatus              string
	SaveRequestID           string
	Pair                    bool
	Paired                  bool
	Closed                  bool
	Pending                 *Pending
	Busy                    bool
}
type Connection struct {
	passkey, passkeyAuth    *pendingPasskey
	passkeyStatus           string
	quickFill               bool // chosen in the native pairing UI, never by a web page
	otp, otpAuth            *pendingOTP
	otpRetired              map[string]otpRetired
	otpStatus, otpRequestID string
	otpUnknown              atomic.Bool
	save                    *pendingSave
	saveAuth                *pendingSave
	saveOutcome             atomic.Uint32
	saveRequestID           string
	generation              atomic.Uint64
	cancelEpoch             atomic.Uint64
	pendingEpoch            uint64
	epoch                   uint64
	mu                      sync.Mutex
	authMu                  sync.Mutex
	authCapability          string
	authEpoch               uint64
	authUntil               time.Time
	closed                  atomic.Bool
	session                 atomic.Pointer[personal.Session]
	writer                  *Writer
	notify                  func()
	seen                    map[string]bool
	received                int
	hello                   string
	pairUntil               time.Time
	capability              string
	until                   time.Time
	context                 personal.BrowserContext
	rows                    []personal.Row
	pending                 *Request
	pendingUntil            time.Time
	now                     func() time.Time
	desktopShared           bool
	broker                  *Broker
	seenOrder               []string
	seenPos                 int
	sessionEpoch            uint64
	staged                  []*stagedSave
	neverOrigins            map[string]bool
	profileContext          personal.BrowserContext
	matchedProfiles         map[string]string
}

func NewConnection(writer *Writer, notify func()) *Connection {
	return &Connection{writer: writer, notify: notify, seen: map[string]bool{}, neverOrigins: map[string]bool{}, matchedProfiles: map[string]string{}, now: time.Now}
}

// NewDesktopConnection creates a connection in shared desktop mode. The
// standalone message budget and manual pairing path remain untouched.
func NewDesktopConnection(writer *Writer, notify func()) *Connection {
	c := NewConnection(writer, notify)
	c.desktopShared = true
	return c
}

// SetBroker attaches the local IPC broker that owns desktop callbacks.
func (c *Connection) SetBroker(b *Broker) { c.broker = b }

// BindDesktopSession shares the desktop session with this extension connection.
// A pending "hello" is answered immediately; otherwise an unsolicited
// "unlocked" event is pushed.
func (c *Connection) BindDesktopSession(s *personal.Session, epoch uint64, quickFill bool) error {
	return c.bindDesktopSession(s, epoch, quickFill, true)
}

func (c *Connection) bindDesktopSession(s *personal.Session, epoch uint64, quickFill, announce bool) error {
	if s == nil || !s.Unlocked() {
		return ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return ErrProtocol
	}
	c.desktopShared = true
	c.sessionEpoch = epoch
	c.session.Store(s)
	c.quickFill = quickFill
	c.until = c.now().Add(15 * time.Minute)
	if c.generation.Load() != c.epoch {
		c.invalidate()
		c.epoch = c.generation.Load()
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ErrProtocol
	}
	c.capability = hex.EncodeToString(b[:])
	c.authMu.Lock()
	c.authCapability = c.capability
	c.authEpoch = c.epoch
	c.authUntil = c.until
	c.authMu.Unlock()
	c.seen = map[string]bool{}
	c.seenOrder = nil
	c.seenPos = 0
	if c.hello != "" {
		id := c.hello
		c.hello = ""
		return c.response(Response{ID: id, Type: "paired", Capability: c.capability, QuickFill: quickFill, Capabilities: SupportedCapabilities()})
	}
	if !announce {
		c.changed()
		return nil
	}
	return c.response(Response{Type: "unlocked", Capability: c.capability, QuickFill: quickFill, DesktopConnected: true, Unlocked: true, SessionEpoch: epoch, Capabilities: SupportedCapabilities()})
}

// InvalidateDesktopLock revokes session authority and pushes "locked" without
// closing the relay pipe.
func (c *Connection) InvalidateDesktopLock() { c.Invalidate() }
func (c *Connection) changed() {
	if c.notify != nil {
		c.notify()
	}
}
func (c *Connection) response(r Response) error {
	r.V = 1
	if e := c.writer.Write(r); e != nil {
		c.closed.Store(true)
		if s := c.session.Load(); s != nil {
			s.RequestLock()
		}
		return e
	}
	return nil
}
func (c *Connection) refuse(id string) error {
	return c.response(Response{ID: id, Type: "error", Error: "refused"})
}
func (c *Connection) invalidate() {
	c.quickFill = false
	c.clearStaged()
	c.profileContext = personal.BrowserContext{}
	c.matchedProfiles = map[string]string{}
	if c.passkey != nil {
		if c.passkey.gate.CommitWon() {
			c.passkeyStatus = "Passkey 结果未确认；请核实网站与金库"
		}
		c.clearPasskey(c.passkey)
	}
	c.invalidateOTP()
	if c.save != nil {
		if !c.save.gate.Cancel() && c.save.gate.CommitWon() {
			c.save.uncertain.Store(true)
			c.saveOutcome.Store(saveUnknown)
		} else {
			c.saveOutcome.Store(saveRefused)
		}
		c.clearSave(c.save)
	}
	c.authMu.Lock()
	c.authCapability = ""
	c.authMu.Unlock()
	c.seen = map[string]bool{}
	c.seenOrder = nil
	c.seenPos = 0
	c.capability = ""
	c.hello = ""
	c.rows = nil
	c.pending = nil
	c.context = personal.BrowserContext{}
}
func (c *Connection) expire() {
	now := c.now()
	if c.capability != "" && !now.Before(c.until) {
		c.invalidate()
		go c.response(Response{Type: "unpaired", Error: "expired"})
	}
	if p := c.otp; p != nil && !now.Before(p.until) {
		p.control.Cancel()
		if p.control.Granted() {
			c.otpUnknown.Store(true)
			c.otpStatus = "验证码交付结果未确认；不会自动重试"
		} else {
			c.otpStatus = "验证码请求已失效；本次未交付"
		}
		responses := c.retireOTP(p, otpNatural)
		if len(responses) != 0 {
			go c.sendOTPResponses(responses)
		}
	}
	if c.hello != "" && !now.Before(c.pairUntil) {
		id := c.hello
		c.hello = ""
		go c.refuse(id)
	}
	if c.pending != nil && !now.Before(c.pendingUntil) {
		id := c.pending.ID
		c.pending = nil
		c.rows = nil
		c.context = personal.BrowserContext{}
		go c.refuse(id)
	}
}
func (c *Connection) syncEpoch() {
	if g := c.generation.Load(); g != c.epoch {
		c.invalidate()
		c.epoch = g
	}
}
func (c *Connection) valid(cap string) bool {
	s := c.session.Load()
	if c.epoch != c.generation.Load() || c.closed.Load() || c.capability == "" || cap != c.capability || !c.now().Before(c.until) || s == nil || !s.Unlocked() {
		return false
	}
	return true
}

// registerRequest uses only a short authentication lock, never the vault/pipe
// mutex. A fresh authenticated cancel therefore revokes before waiting for a
// transaction, while stale capabilities and replayed IDs cannot change its epoch.
func (c *Connection) registerRequest(r Request) (bool, error) {
	if !r.valid() {
		return false, ErrProtocol
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	c.received++
	if c.closed.Load() || (!c.desktopShared && c.received > 128) || c.desktopShared && c.received > 4096 {
		return false, ErrProtocol
	}
	if c.desktopShared && len(c.seenOrder) >= 512 && !c.seen[r.ID] {
		old := c.seenOrder[c.seenPos]
		delete(c.seen, old)
		c.seenOrder[c.seenPos] = r.ID
		c.seenPos = (c.seenPos + 1) % 512
		c.seen[r.ID] = true
	} else if c.seen[r.ID] {
		// Count the frame but ignore it without a second response, dispatch or
		// cancellation. An old replay cannot revoke a newer legitimate request.
		return false, errDuplicateRequest
	}
	c.seen[r.ID] = true
	if c.desktopShared && len(c.seenOrder) < 512 && !containsID(c.seenOrder, r.ID) {
		c.seenOrder = append(c.seenOrder, r.ID)
	}
	if r.Type == "hello" {
		return true, nil
	}
	allowed := c.authCapability != "" && r.Capability == c.authCapability && c.authEpoch == c.generation.Load() && c.now().Before(c.authUntil)
	if allowed && r.Type == "cancel" {
		c.cancelEpoch.Add(1)
		if c.passkeyAuth != nil {
			c.passkeyAuth.cancelled.Store(true)
			c.passkeyAuth.gate.Cancel()
		}
	}
	if allowed && r.Type == "cancel-save" && c.saveAuth != nil && c.saveAuth.request.ID == r.RequestID {
		if !c.saveAuth.gate.Cancel() && c.saveAuth.gate.CommitWon() {
			c.saveAuth.uncertain.Store(true)
		}
	}
	if allowed && r.Type == "cancel-otp" && c.otpAuth != nil && c.otpAuth.request.ID == r.RequestID {
		c.otpAuth.requestCancel(c.now())
	}
	return allowed, nil
}
func (c *Connection) Handle(r Request) error {
	defer r.Clear()
	allowed, err := c.registerRequest(r)
	if err == errDuplicateRequest {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Type == "otp" || r.Type == "otp-ack" || r.Type == "cancel-otp" {
		return c.handleOTP(r, allowed)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	if r.Type == "status" || r.Type == "session-status" {
		return c.handleStatus(r)
	}
	if r.Type == "unlock-request" {
		if c.broker != nil && c.broker.callbacks.RequestUnlockFocus != nil {
			c.broker.callbacks.RequestUnlockFocus()
		}
		return c.response(Response{ID: r.ID, Type: "status", DesktopConnected: c.desktopShared, Unlocked: c.unlocked(), VaultLocked: !c.unlocked(), Capabilities: c.capabilities()})
	}
	if r.Type == "lock" || r.Type == "vault-lock" {
		if r.Capability != "" && r.Capability != c.capability {
			return c.refuse(r.ID)
		}
		if c.broker != nil && c.broker.callbacks.RequestLock != nil {
			c.broker.callbacks.RequestLock()
		}
		if e := c.response(Response{ID: r.ID, Type: "locked"}); e != nil {
			return e
		}
		c.Invalidate()
		return nil
	}
	if !allowed {
		return c.refuse(r.ID)
	}
	if r.Type == "hello" {
		if c.hello != "" || c.capability != "" {
			return c.refuse(r.ID)
		}
		if c.desktopShared {
			if s := c.session.Load(); s != nil && s.Unlocked() {
				return c.bindDesktopSession(s, c.sessionEpoch, c.quickFill, false)
			}
			if c.broker != nil && c.broker.callbacks.RequestUnlockFocus != nil {
				c.broker.callbacks.RequestUnlockFocus()
			}
		}
		c.hello = r.ID
		c.pairUntil = c.now().Add(time.Minute)
		return nil
	}
	if !c.valid(r.Capability) {
		if r.Capability == c.capability {
			c.invalidate()
		}
		return c.refuse(r.ID)
	}
	if r.Type == "cancel" {
		if p := c.passkey; p != nil {
			p.cancelled.Store(true)
			p.gate.Cancel()
			if !p.working {
				c.clearPasskey(p)
				if e := c.refuse(p.request.ID); e != nil {
					return e
				}
			}
			return c.response(Response{ID: r.ID, Type: "cancelled"})
		}
		if c.save != nil || c.otp != nil {
			return c.refuse(r.ID)
		}
		if c.pending != nil {
			if e := c.refuse(c.pending.ID); e != nil {
				return e
			}
		}
		c.rows = nil
		c.pending = nil
		c.context = personal.BrowserContext{}
		return c.response(Response{ID: r.ID, Type: "cancelled"})
	}
	if r.Type == "passkey-create" || r.Type == "passkey-get" {
		return c.startPasskey(r)
	}
	if isV2Operation(r.Type) {
		return c.handleV2(r)
	}
	if handled, e := c.saveMessage(r); handled {
		return e
	}
	if c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil {
		return c.refuse(r.ID)
	}
	if r.Type == "match" {
		c.rows = nil
		c.context = personal.BrowserContext{}
		s := c.session.Load()
		if s == nil {
			return c.refuse(r.ID)
		}
		epoch := c.epoch
		rows, e := s.BrowserMatch(r.Context())
		if e != nil || epoch != c.generation.Load() || !s.Unlocked() {
			if !s.Unlocked() {
				c.invalidate()
			}
			return c.refuse(r.ID)
		}
		c.context = r.Context()
		c.rows = rows
		return c.response(Response{ID: r.ID, Type: "candidates", Candidates: rows})
	}
	if r.Type == "fill" {
		if c.context.Origin != r.Origin || c.context.TabID != r.TabID || c.context.DocumentID != r.DocumentID {
			return c.refuse(r.ID)
		}
		for _, row := range c.rows {
			if row.ID == r.ItemID && row.Revision == r.Revision {
				c.otpStatus = ""
				copy := r
				c.pending = &copy
				c.pendingEpoch = c.cancelEpoch.Load()
				c.pendingUntil = c.now().Add(30 * time.Second)
				if c.quickFill {
					go func() { _ = c.ApproveFill(r.ID) }()
				}
				return nil
			}
		}
	}
	return c.refuse(r.ID)
}
func (c *Connection) ApprovePair(s *personal.Session) error {
	return c.approvePair(s, false)
}

// ApproveQuickPair is called only by the native pairing UI. Browser selection
// becomes the user gesture for this bounded session; locking revokes it.
func (c *Connection) ApproveQuickPair(s *personal.Session) error {
	return c.approvePair(s, true)
}
func (c *Connection) approvePair(s *personal.Session, quick bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	if c.closed.Load() || c.hello == "" || !c.now().Before(c.pairUntil) || s == nil || !s.Unlocked() {
		return ErrProtocol
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ErrProtocol
	}
	if c.epoch != c.generation.Load() || !s.Unlocked() {
		return ErrProtocol
	}
	c.capability = hex.EncodeToString(b[:])
	c.quickFill = quick
	c.until = c.now().Add(15 * time.Minute)
	c.session.Store(s)
	c.authMu.Lock()
	c.authCapability = c.capability
	c.authEpoch = c.epoch
	c.authUntil = c.until
	c.authMu.Unlock()
	if c.epoch != c.generation.Load() {
		c.session.CompareAndSwap(s, nil)
		s.RequestLock()
		c.invalidate()
		return ErrProtocol
	}
	id := c.hello
	c.hello = ""
	return c.response(Response{ID: id, Type: "paired", Capability: c.capability, QuickFill: quick})
}
func (c *Connection) ApproveFill(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	if c.pending == nil || c.pending.ID != id || !c.valid(c.pending.Capability) || !c.now().Before(c.pendingUntil) {
		return ErrProtocol
	}
	r := *c.pending
	c.pending = nil
	c.rows = nil
	c.context = personal.BrowserContext{}
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	epoch := c.epoch
	f, e := s.PrepareBrowserFill(personal.BrowserFillTarget{ID: r.ItemID, Revision: r.Revision, Context: r.Context()})
	if e != nil {
		if writeErr := c.refuse(r.ID); writeErr != nil {
			return writeErr
		}
		return e
	}
	defer s.DiscardBrowserFill(f)
	consumeErr := c.writer.WriteGranted(minTime(c.until, c.pendingUntil), nil, func() (Response, error) {
		var response Response
		err := s.ConsumeBrowserFill(f, func(user, pass []byte) error {
			// Grant only after owning the writer. A lock/cancel that wins while
			// queued cannot disclose credentials. Already granted output is unknown.
			if c.pendingEpoch != c.cancelEpoch.Load() || epoch != c.generation.Load() || c.closed.Load() || !c.now().Before(c.until) || !c.now().Before(c.pendingUntil) {
				return ErrProtocol
			}
			response = Response{V: 1, ID: r.ID, Type: "fill", Username: string(user), Password: string(pass)}
			return nil
		})
		return response, err
	})
	if consumeErr != nil && !c.closed.Load() {
		_ = c.refuse(r.ID)
	}
	return consumeErr
}
func (c *Connection) Reject() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	if c.save != nil || c.otp != nil {
		return ErrProtocol
	}

	if c.pending != nil {
		id := c.pending.ID
		c.pending = nil
		c.rows = nil
		return c.refuse(id)
	}
	if c.hello != "" {
		id := c.hello
		c.invalidate()
		return c.refuse(id)
	}
	return nil
}

// Invalidate is for native lock. RequestLock rejects new secret operations
// immediately even while a bounded pipe write or a transaction is completing.
func (c *Connection) Invalidate() {
	c.generation.Add(1)
	c.authMu.Lock()
	if p := c.passkeyAuth; p != nil {
		p.cancelled.Store(true)
		p.gate.Cancel()
	}
	if p := c.otpAuth; p != nil {
		p.control.Cancel()
	}
	if p := c.saveAuth; p != nil {
		if !p.gate.Cancel() && p.gate.CommitWon() {
			p.uncertain.Store(true)
			c.saveOutcome.Store(saveUnknown)
		}
	}
	c.authMu.Unlock()
	if !c.closed.Load() {
		go c.response(Response{Type: "locked"})
	}
	if s := c.session.Swap(nil); s != nil {
		s.RequestLock()
	}
	if c.mu.TryLock() {
		c.syncEpoch()
		c.expire()
		c.mu.Unlock()
	}
	c.changed()
}
func (c *Connection) Close() {
	c.closed.Store(true)
	if s := c.session.Load(); s != nil {
		s.RequestLock()
	}
	c.writer.Close()
	c.Invalidate()
}
func (c *Connection) Snapshot() View {
	if !c.mu.TryLock() {
		return View{Busy: true, Closed: c.closed.Load()}
	}
	defer c.mu.Unlock()
	c.syncEpoch()
	c.expire()
	v := View{Closed: c.closed.Load(), Pair: c.hello != "" && c.now().Before(c.pairUntil)}
	if c.capability != "" && !c.valid(c.capability) {
		c.invalidate()
	}
	v.Paired = c.capability != ""
	v.QuickFill = c.quickFill
	v.Passkey, v.PasskeyStatus = c.passkeySnapshot()
	v.Save, v.SaveStatus = c.saveSnapshot()
	v.SaveRequestID = c.saveRequestID
	v.OTP, v.OTPStatus = c.otpSnapshot()
	v.OTPRequestID = c.otpRequestID
	if c.pending != nil {
		r := c.pending
		title := ""
		for _, row := range c.rows {
			if row.ID == r.ItemID {
				title = row.Title
			}
		}
		v.Pending = &Pending{ID: r.ID, Origin: r.Origin, ItemID: r.ItemID, Revision: r.Revision, Title: title, Until: c.pendingUntil}
	}

	return v
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func (c *Connection) unlocked() bool {
	s := c.session.Load()
	return s != nil && s.Unlocked()
}

func (c *Connection) capabilities() []string {
	if c.desktopShared {
		return SupportedCapabilities()
	}
	return nil
}

func (c *Connection) handleStatus(r Request) error {
	if r.Capability != "" && r.Capability != c.capability {
		return c.refuse(r.ID)
	}
	unlocked := c.unlocked()
	resp := Response{ID: r.ID, Type: r.Type, DesktopConnected: c.desktopShared, Unlocked: unlocked, VaultLocked: !unlocked, Paired: c.capability != "", SessionEpoch: c.sessionEpoch, Capabilities: c.capabilities()}
	if unlocked && c.capability != "" {
		resp.Capability = c.capability
		resp.QuickFill = c.quickFill
		c.until = c.now().Add(15 * time.Minute)
	}
	if c.broker != nil {
		resp.NeverOrigins = c.broker.neverOrigins()
	}
	return c.response(resp)
}
