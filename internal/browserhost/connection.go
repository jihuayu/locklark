package browserhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

type Pending struct {
	ID, Origin, ItemID, Revision, Title string
	Until                               time.Time
}

// V2ApprovalView is the native review of one non-quick-fill V2 disclosure or
// mutation. It carries only protocol selectors; mutation payloads, passwords
// and field values never enter the view.
type V2ApprovalView struct {
	ID, Type, Origin, ItemID, Revision, Title string
	Deadline                                  time.Time
}

type pendingV2 struct {
	request     Request
	title       string
	deadline    time.Time
	epoch       uint64
	cancelEpoch uint64
}

// ProfileView is the public native review of one sensitive profile fill. It
// carries only selectors and the deadline; no approved field value is ever
// present in a snapshot.
type ProfileView struct {
	ID, Origin, Title, ItemID, Revision, Category string
	Deadline                                      time.Time
	// Checkout marks a checkout-frames-v1 review. Only then are TopOrigin,
	// TopDocumentID, FrameOrigin, FrameDocumentID and FrameID meaningful.
	Checkout        bool
	TopOrigin       string
	TopDocumentID   string
	FrameOrigin     string
	FrameDocumentID string
	FrameID         int64
}
type View struct {
	Passkey                 *PasskeyView
	PasskeyStatus           string
	Signal                  *SignalView
	SignalStatus            string
	QuickFill               bool
	OTP                     *OTPView
	OTPStatus, OTPRequestID string
	Save                    *SaveView
	SaveStatus              string
	SaveRequestID           string
	Profile                 *ProfileView
	V2                      *V2ApprovalView
	Pair                    bool
	Paired                  bool
	Closed                  bool
	Pending                 *Pending
	Busy                    bool
}
type Connection struct {
	passkey, passkeyAuth    *pendingPasskey
	passkeyStatus           string
	signal, signalAuth      *pendingSignal
	signalStatus            string
	quickFill               bool // chosen in the native pairing UI, never by a web page
	otp, otpAuth            *pendingOTP
	otpRetired              map[string]otpRetired
	otpStatus, otpRequestID string
	otpUnknown              atomic.Bool
	save                    *pendingSave
	saveAuth                *pendingSave
	saveOutcome             atomic.Uint32
	saveRequestID           string
	staged                  map[string]*stagedSave
	upload                  *stagedAttachment
	stagedBusy              bool
	neverOrigins            map[string]bool
	desktopShared           bool
	pairAuthorized          bool
	pairQuickFill           bool
	pairing                 bool
	peer                    Peer
	helloInfo               BrokerHello
	broker                  *Broker
	seenOrder               []string
	seenPos                 int
	sessionEpoch            uint64
	profileContext          personal.BrowserContext
	profileCheckout         *BrowserCheckout
	matchedProfiles         map[string]string
	profile                 *pendingProfile
	v2pending               *pendingV2
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
	clipboard               atomic.Pointer[clipboardState]
	clipboardMu             sync.Mutex
	clipboardGrant          *clipboardGrant
	clipboardTicket         string
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

// setBrokerPeer records the OS-authenticated peer and the bounded hello facts.
// Only the native pairing approval may turn this into session authority.
func (c *Connection) setBrokerPeer(peer Peer, hello BrokerHello) {
	c.mu.Lock()
	c.peer, c.helloInfo = peer, hello
	c.mu.Unlock()
}

// PairAuthorized reports whether the native owner explicitly paired this
// brokered connection. It never becomes true through a browser frame.
func (c *Connection) PairAuthorized() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pairAuthorized
}

// SetBroker attaches the local IPC broker that owns desktop callbacks.
func (c *Connection) SetBroker(b *Broker) {
	c.broker = b
	if b != nil && b.callbacks.NewClipboard != nil && nativeclipboard.NativeLeaseSupported() {
		if m, ttl := b.callbacks.NewClipboard(); m != nil {
			c.setClipboardWithDuration(m, ttl, b.callbacks.ClipboardClearDuration)
		}
	}
}

// BindDesktopSession shares the desktop session with this extension connection.
// A pending "hello" is answered immediately; otherwise an unsolicited
// "unlocked" event is pushed.
func (c *Connection) BindDesktopSession(s *personal.Session, epoch uint64, quickFill bool) error {
	return c.bindDesktopSession(s, epoch, quickFill, true)
}

func (c *Connection) bindDesktopSession(s *personal.Session, epoch uint64, quickFill, announce bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bindDesktopSessionLocked(s, epoch, quickFill, announce)
}

func (c *Connection) bindDesktopSessionLocked(s *personal.Session, epoch uint64, quickFill, announce bool) error {
	if s == nil || !s.Unlocked() {
		return ErrProtocol
	}
	if c.closed.Load() {
		return ErrProtocol
	}
	if c.pairAuthorized {
		// The native pairing choice is the only source of quick-fill authority
		// for a brokered connection.
		quickFill = c.pairQuickFill
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
	c.profile = nil
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
		return c.response(Response{ID: id, Type: "paired", Capability: c.capability, QuickFill: quickFill, Capabilities: c.pairedCapabilities()})
	}
	if !announce {
		c.changed()
		return nil
	}
	return c.response(Response{Type: "unlocked", Capability: c.capability, QuickFill: quickFill, DesktopConnected: true, Unlocked: true, SessionEpoch: epoch, Capabilities: c.pairedCapabilities()})
}

// requestBrowserPair performs the explicit native pairing review off the
// connection mutex. It is the only path that can grant a brokered browser a
// capability. The peer is OS-authenticated; Browser/Origin are display-only.
func (c *Connection) requestBrowserPair(s *personal.Session, epoch uint64) {
	if s == nil || !s.Unlocked() {
		return
	}
	c.mu.Lock()
	id := c.hello
	hello := c.helloInfo
	peer := c.peer
	b := c.broker
	if id == "" || c.closed.Load() || c.capability != "" || c.pairing || !c.now().Before(c.pairUntil) {
		c.mu.Unlock()
		return
	}
	c.pairing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.pairing = false
		c.mu.Unlock()
	}()
	if b == nil || b.callbacks.ApproveBrowserPair == nil {
		c.finishBrowserPairRefusal(id)
		return
	}
	decision, err := b.callbacks.ApproveBrowserPair(context.Background(), BrowserPairRequest{Peer: peer, Browser: hello.Browser, Origin: hello.Origin})
	if err != nil || !decision.Approved {
		c.finishBrowserPairRefusal(id)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	if c.hello != id || c.closed.Load() || c.capability != "" || !c.now().Before(c.pairUntil) {
		return
	}
	c.pairAuthorized = true
	c.pairQuickFill = decision.QuickFill
	if err := c.bindDesktopSessionLocked(s, epoch, decision.QuickFill, false); err != nil {
		c.hello = ""
		go c.refuse(id)
	}
}

func (c *Connection) finishBrowserPairRefusal(id string) {
	c.mu.Lock()
	if c.hello == id {
		c.hello = ""
	}
	c.mu.Unlock()
	if id != "" {
		go c.refuse(id)
	}
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
	defer r.Clear()
	if e := c.writer.Write(r); e != nil {
		c.closed.Store(true)
		// A broken pipe belongs to this one capability. A shared desktop
		// connection must never lock the owner's whole vault because a browser
		// window went away.
		if s := c.session.Load(); s != nil && !c.desktopShared {
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
	if c.passkey != nil {
		if c.passkey.gate.CommitWon() {
			c.passkeyStatus = "Passkey 结果未确认；请核实网站与金库"
		}
		c.clearPasskey(c.passkey)
	}
	if c.signal != nil {
		c.clearSignal(c.signal)
	}
	c.invalidateOTP()
	c.clearStaged()
	c.clearUpload()
	c.neverOrigins = nil
	c.profileContext = personal.BrowserContext{}
	c.profileCheckout = nil
	c.matchedProfiles = map[string]string{}
	c.profile = nil
	c.clearV2PendingLocked(c.v2pending)
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
	if c.desktopShared {
		c.received = 0
		c.seen = map[string]bool{}
		c.seenOrder = nil
		c.seenPos = 0
	}
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
	if p := c.signal; p != nil && !now.Before(p.until) {
		p.cancelled.Store(true)
		p.cancelGate()
		if !p.working {
			c.clearSignal(p)
			c.signalStatus = "网站 Passkey 信号已过期"
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
	if p := c.profile; p != nil && !now.Before(p.deadline) {
		id := p.request.ID
		c.clearProfilePendingLocked(p)
		c.profileCheckout = nil
		go c.refuse(id)
	}
	if p := c.v2pending; p != nil && !now.Before(p.deadline) {
		id := p.request.ID
		c.clearV2PendingLocked(p)
		go c.refuse(id)
	}
	c.expireStaged()
	c.expireUpload()
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
	if isClipboardOperation(r.Type) {
		return c.handleClipboard(r, allowed)
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
		// Only an authenticated capability may lock. Handling this before the
		// capability check let any local process that reached the socket lock
		// the unlocked desktop vault without pairing.
		if !allowed {
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
	if p := c.v2pending; p != nil {
		if r.Type == "cancel" {
			id := p.request.ID
			c.clearV2PendingLocked(p)
			if e := c.refuse(id); e != nil {
				return e
			}
			return c.response(Response{ID: r.ID, Type: "cancelled"})
		}
		if r.Type == "attachment-cancel" {
			return c.attachmentCancel(r)
		}
		return c.refuse(r.ID)
	}
	if !c.quickFill && requiresV2NativeApproval(r.Type) {
		if c.profile != nil || c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil || c.signal != nil || c.stagedBusy || c.upload != nil {
			return c.refuse(r.ID)
		}
		if e := c.startV2Approval(r); e != nil {
			return e
		}
		// The pending review owns the private payload from here. Detach the
		// Handle copy so its deferred Clear cannot wipe the stored request.
		r.payload = nil
		return nil
	}
	if r.Type == "hello" {
		if c.desktopShared {
			if c.capability != "" {
				return c.response(Response{ID: r.ID, Type: "paired", Capability: c.capability, QuickFill: c.quickFill, Capabilities: c.pairedCapabilities()})
			}
			if s := c.session.Load(); s != nil && s.Unlocked() {
				if c.broker != nil && !c.pairAuthorized {
					if c.hello != "" || c.pairing {
						return c.refuse(r.ID)
					}
					c.hello = r.ID
					c.pairUntil = c.now().Add(time.Minute)
					go c.requestBrowserPair(s, c.sessionEpoch)
					return nil
				}
				return c.bindDesktopSessionLocked(s, c.sessionEpoch, c.quickFill, false)
			}
			// A brokered connection may only obtain a capability through the
			// explicit native pairing callback. Mark the hello pending and let
			// NotifyUnlocked start or retry that review.
			if c.broker != nil {
				if c.broker.callbacks.CurrentSession != nil {
					if s, epoch, ok := c.broker.callbacks.CurrentSession(); ok && s != nil && s.Unlocked() {
						if c.hello != "" || c.pairing {
							return c.refuse(r.ID)
						}
						c.hello = r.ID
						c.pairUntil = c.now().Add(time.Minute)
						go c.requestBrowserPair(s, epoch)
						return nil
					}
				}
				if c.broker.callbacks.RequestUnlockFocus != nil {
					c.broker.callbacks.RequestUnlockFocus()
				}
			}
		}
		if c.hello != "" || c.capability != "" {
			return c.refuse(r.ID)
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
		c.cancelClipboardPending()
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
		if p := c.profile; p != nil {
			c.clearProfilePendingLocked(p)
			c.profileCheckout = nil
			if e := c.refuse(p.request.ID); e != nil {
				return e
			}
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
	if r.Type == "passkey-list" {
		// Conditional account enumeration is a read-only query. It is answered
		// even while another native operation is pending and never creates an
		// approval surface of its own.
		return c.listPasskeyCandidates(r)
	}
	// A reserved sensitive profile fill is the only live operation until the
	// native owner approves or rejects it. No save, passkey, generator or other
	// vault mutation may run concurrently with that review.
	if c.profile != nil {
		return c.refuse(r.ID)
	}
	if r.Type == "passkey-signal" {
		return c.handlePasskeySignal(r)
	}
	if r.Type == "passkey-create" || r.Type == "passkey-get" {
		return c.startPasskey(r)
	}
	if r.Type == "generate" {
		return c.handleGenerate(r)
	}
	if handled, e := c.saveMessage(r); handled {
		return e
	}
	if handled, e := c.stagedMessage(r); handled {
		return e
	}
	if handled, e := c.attachmentMessage(r); handled {
		return e
	}
	if isV2Operation(r.Type) {
		return c.handleV2(r)
	}
	if c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil || c.stagedBusy {
		return c.refuse(r.ID)
	}
	if r.Type == "watchtower" || r.Type == "watchtower-summary" {
		s := c.session.Load()
		if s == nil {
			return c.refuse(r.ID)
		}
		epoch := c.epoch
		report, e := s.Watchtower(r.Origin, r.IncludeHIBP)
		if e != nil || epoch != c.generation.Load() || !s.Unlocked() {
			if !s.Unlocked() {
				c.invalidate()
			}
			return c.refuse(r.ID)
		}
		// The report is advisory metadata; a successful scan never discards
		// existing match rows or their context.
		return c.response(Response{ID: r.ID, Type: r.Type, Watchtower: &report})
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
		c.profileContext = r.Context()
		c.profileCheckout = nil
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
	return c.response(Response{ID: id, Type: "paired", Capability: c.capability, QuickFill: quick, Capabilities: c.pairedCapabilities()})
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
	if p := c.profile; p != nil {
		c.clearProfilePendingLocked(p)
		return c.refuse(p.request.ID)
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
	c.revokeClipboard(false)
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
	if p := c.signalAuth; p != nil {
		p.cancelled.Store(true)
		p.cancelGate()
	}
	c.authMu.Unlock()
	if !c.closed.Load() {
		go c.response(Response{Type: "locked"})
	}
	if s := c.session.Swap(nil); s != nil && !c.desktopShared {
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
	c.revokeClipboard(true)
	if s := c.session.Load(); s != nil && !c.desktopShared {
		s.RequestLock()
	}
	c.writer.Close()
	c.Invalidate()
}
func requiresV2NativeApproval(kind string) bool {
	switch kind {
	case "item-copy-field", "item-reveal-field", "item-create", "item-edit", "item-save",
		"item-state", "item-restore-history", "passkey-remove",
		"stage-save", "commit-staged-save",
		"attachment-read", "attachment-commit", "attachment-remove":
		return true
	}
	return false
}

// startV2Approval reserves one public review. The caller holds c.mu. The
// request payload stays private in memory and is cleared on rejection, expiry,
// lock or disconnect.
func (c *Connection) startV2Approval(r Request) error {
	title := r.Title
	if title == "" {
		title = r.Origin
	}
	c.v2pending = &pendingV2{request: r, title: title, deadline: c.now().Add(30 * time.Second), epoch: c.epoch, cancelEpoch: c.cancelEpoch.Load()}
	c.changed()
	return nil
}

func (c *Connection) clearV2PendingLocked(p *pendingV2) {
	if p == nil || c.v2pending != p {
		return
	}
	p.request.Clear()
	c.v2pending = nil
}

// ApproveV2 is called only by the native owner's explicit button. It
// revalidates the exact reservation before executing the original request.
func (c *Connection) ApproveV2(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	p := c.v2pending
	if p == nil || p.request.ID != id || p.epoch != c.epoch || p.cancelEpoch != c.cancelEpoch.Load() || !c.valid(p.request.Capability) || !c.now().Before(p.deadline) {
		return ErrProtocol
	}
	r := p.request
	c.v2pending = nil
	return c.executeV2Approved(r)
}

func (c *Connection) executeV2Approved(r Request) error {
	switch r.Type {
	case "stage-save", "commit-staged-save":
		if handled, e := c.stagedMessage(r); handled {
			return e
		}
	case "attachment-commit", "attachment-remove", "attachment-read":
		if handled, e := c.attachmentMessage(r); handled {
			return e
		}
	default:
		if isV2Operation(r.Type) {
			return c.handleV2(r)
		}
	}
	return c.refuse(r.ID)
}

// RejectV2 is the native refusal for one exact pending V2 review. It never
// executes the stored mutation or disclosure.
func (c *Connection) RejectV2(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	p := c.v2pending
	if p == nil || p.request.ID != id {
		return ErrProtocol
	}
	requestID := p.request.ID
	c.clearV2PendingLocked(p)
	return c.refuse(requestID)
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
	v.Signal, v.SignalStatus = c.signalSnapshot()
	v.Save, v.SaveStatus = c.saveSnapshot()
	v.SaveRequestID = c.saveRequestID
	v.OTP, v.OTPStatus = c.otpSnapshot()
	v.OTPRequestID = c.otpRequestID
	if p := c.v2pending; p != nil {
		v.V2 = &V2ApprovalView{ID: p.request.ID, Type: p.request.Type, Origin: p.request.Origin, ItemID: p.request.ItemID, Revision: p.request.Revision, Title: p.title, Deadline: p.deadline}
	}
	if p := c.profile; p != nil {
		review := &ProfileView{ID: p.request.ID, Origin: p.request.Origin, Title: p.title, ItemID: p.request.ItemID, Revision: p.request.Revision, Category: p.category, Deadline: p.deadline}
		if p.checkout != nil {
			// Public selectors only: the owner sees the top document and the
			// target frame side by side before approving.
			review.Checkout = true
			review.TopOrigin = p.checkout.TopOrigin
			review.TopDocumentID = p.checkout.TopDocumentID
			review.FrameOrigin = p.request.Origin
			review.FrameDocumentID = p.request.DocumentID
			review.FrameID = p.checkout.FrameID
		}
		v.Profile = review
	}
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

// pairedCapabilities is the negotiation list advertised with an authority
// grant ("paired"/"unlocked"). Standalone native pairing never set
// desktopShared, so gating this list on capabilities() silently revoked the
// baseline (attachments-v1 and friends) from every manual pairing and disabled
// attachment upload. The baseline is therefore always advertised here, and the
// clipboard lease is appended only when this connection actually owns a
// clipboard manager: no manager, no clipboard claim, and desktopConnected is
// left to the callers.
func (c *Connection) pairedCapabilities() []string {
	out := append([]string(nil), supportedCapabilities...)
	if c.clipboard.Load() != nil && nativeclipboard.NativeLeaseSupported() {
		out = append(out, clipboardCapability)
	}
	return out
}

func (c *Connection) capabilities() []string {
	if !c.desktopShared {
		return nil
	}
	out := append([]string(nil), supportedCapabilities...)
	if c.clipboard.Load() != nil && nativeclipboard.NativeLeaseSupported() {
		out = append(out, clipboardCapability)
	}
	return out
}

func (c *Connection) handleStatus(r Request) error {
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
