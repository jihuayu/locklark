package browserhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

type Pending struct {
	ID, Origin, ItemID, Revision, Title string
	Until                               time.Time
}

// V2ApprovalView is the native review of one non-quick-fill V2 disclosure or
// mutation. It carries only protocol selectors and bounded public names;
// mutation payloads, passwords and field values never enter the view.
//
// Stored* describe the authenticated item the request targets, exactly as read
// when the review was reserved. Requested* describe what the request asks to
// read or write: a mutation's requested identity anchor and the public names of
// the fields it would write. Both are label lists only (builtin member names
// such as "用户名"/"密码" and custom field labels); no value, note text, raw
// item JSON or credential material is ever projected.
type V2ApprovalView struct {
	ID, Type, Origin, ItemID, Revision, Title string
	// Field is the public wire selector (for example "password" or
	// "attachment:<id>"), never a field value. Action and Summary are public
	// descriptions of the requested operation, including state transitions;
	// no payload or new secret value enters the view.
	Field, Action, Summary string
	Deadline               time.Time
	// RevisionPinned reports that an item-get request omitted its revision and
	// the review reserved the exact authenticated revision in Revision. The
	// approval executes the original handleItemGet path, which rechecks that
	// same revision, so a concurrent edit refuses the disclosure.
	RevisionPinned bool
	// StoredTitle / StoredCategory / StoredFields anchor the authenticated
	// item. StoredFields names the public builtin members the item's detail
	// frame shows and its custom section field labels.
	StoredTitle    string
	StoredCategory string
	StoredFields   []string
	// RequestedTitle / RequestedCategory / RequestedFields describe a mutation
	// payload: the title and category it writes, and the names of the fields it
	// would write or explicitly clear (including the notes field when the
	// payload writes notes).
	RequestedTitle    string
	RequestedCategory string
	RequestedFields   []string
}

type pendingV2 struct {
	request     Request
	title       string
	field       string
	action      string
	summary     string
	deadline    time.Time
	epoch       uint64
	cancelEpoch uint64
	stored      itemAnchor
	requested   *itemAnchor
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
	pairHello               uint64 // review phase of the hello slot
	pairAsk                 string // hello id that claimed the review slot
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
	closeOnce               sync.Once
	done                    chan struct{}
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
	return &Connection{writer: writer, notify: notify, seen: map[string]bool{}, neverOrigins: map[string]bool{}, matchedProfiles: map[string]string{}, done: make(chan struct{}), now: time.Now}
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
// It is the direct native-host binding, never a brokered path. A connection
// owned by a Broker has no authority until the owner approves a pairing
// review, so an unlock event can never mint a capability by itself.
func (c *Connection) BindDesktopSession(s *personal.Session, epoch uint64, quickFill bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broker != nil {
		return ErrProtocol
	}
	return c.bindDesktopSessionLocked(s, epoch, quickFill, true, "")
}

func (c *Connection) bindDesktopSession(s *personal.Session, epoch uint64, quickFill, announce bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bindDesktopSessionLocked(s, epoch, quickFill, announce, "")
}

// bindDesktopSessionLocked issues the capability and answers replyID, which
// defaults to the pending hello.
func (c *Connection) bindDesktopSessionLocked(s *personal.Session, epoch uint64, quickFill, announce bool, replyID string) error {
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
	if replyID == "" {
		replyID = c.hello
	}
	if replyID != "" {
		c.hello = ""
		return c.response(Response{ID: replyID, Type: "paired", Capability: c.capability, QuickFill: quickFill, Capabilities: c.pairedCapabilities()})
	}
	if !announce {
		c.changed()
		return nil
	}
	return c.response(Response{Type: "unlocked", Capability: c.capability, QuickFill: quickFill, DesktopConnected: true, Unlocked: true, SessionEpoch: epoch, Capabilities: c.pairedCapabilities()})
}

// pairingBegin claims the single review slot for the hello that just arrived
// on the connection goroutine. A review that already entered the native
// callback keeps that slot: its decision belongs to every hello that landed
// before it, so a later frame waits for it instead of asking twice.
func (c *Connection) pairingBegin() uint64 {
	if c.hello == "" || c.closed.Load() || c.capability != "" || !c.now().Before(c.pairUntil) {
		return 0
	}
	if !c.pairing || c.pairAsk != c.hello {
		c.pairHello++
		c.pairAsk = c.hello
		c.pairing = true
	}
	return c.pairHello
}

// pairingEnd releases the review slot of an exact hello phase.
func (c *Connection) pairingEnd(phase uint64) {
	if phase != 0 && phase == c.pairHello {
		c.pairing = false
	}
}

// requestBrowserPair fulfils the hello Handle claimed through pairingBegin. It
// never claims a slot itself and is the only path that can grant a brokered
// browser a capability. The decision is committed to the hello that claimed
// the slot, and only a hello sent after that frame asks for a new review. The
// peer is OS-authenticated; Browser/Origin are display-only.
func (c *Connection) requestBrowserPair(s *personal.Session, epoch, phase uint64) {
	if s == nil || !s.Unlocked() {
		return
	}
	c.mu.Lock()
	id := c.pairAsk
	hello := c.helloInfo
	peer := c.peer
	b := c.broker
	pairUntil := c.pairUntil
	done := c.done
	if phase == 0 || phase != c.pairHello || !c.pairing || id == "" || c.closed.Load() || c.capability != "" || !c.now().Before(pairUntil) {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.pairingEnd(phase)
		c.mu.Unlock()
	}()
	if b == nil || b.callbacks.ApproveBrowserPair == nil {
		c.finishBrowserPairRefusal(id, phase)
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), pairUntil)
	defer cancel()
	// A closed connection must remove its native pairing review immediately;
	// a late click can then never bind a session.
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	decision, err := b.callbacks.ApproveBrowserPair(ctx, BrowserPairRequest{Peer: peer, Browser: hello.Browser, Origin: hello.Origin})
	if err != nil || !decision.Approved {
		c.finishBrowserPairRefusal(id, phase)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	// The native callback may ignore ctx.Done and return after the hello
	// deadline or cancellation. Commit the decision only to the exact review
	// that requested it, to its still-pending hello and to the session it was
	// reviewed against; a late approval of an expired, cancelled or replaced
	// hello grants nothing.
	if c.closed.Load() || c.capability != "" || !c.pairing || phase != c.pairHello ||
		c.hello != id || !c.now().Before(c.pairUntil) || !s.Unlocked() || !c.pairSessionCurrentLocked(s, epoch) {
		return
	}
	c.pairAuthorized = true
	c.pairQuickFill = decision.QuickFill
	if err := c.bindDesktopSessionLocked(s, epoch, decision.QuickFill, false, id); err != nil {
		c.hello = ""
		if !c.closed.Load() {
			go c.refuse(id)
		}
	}
}

// pairSessionCurrentLocked reports whether the session a review was requested
// for is still the one desktop authority serves. A brokered connection has no
// session of its own before it is paired, so there the broker is asked; a
// direct bind keeps the session this connection already holds. The caller must
// hold c.mu.
func (c *Connection) pairSessionCurrentLocked(s *personal.Session, epoch uint64) bool {
	if c.broker != nil && c.broker.callbacks.CurrentSession != nil {
		cur, curEpoch, ok := c.broker.callbacks.CurrentSession()
		return ok && cur == s && curEpoch == epoch && cur.Unlocked()
	}
	if held := c.session.Load(); held != nil {
		return held == s && c.sessionEpoch == epoch
	}
	return true
}

// reviewBrowserHello claims the slot of the pending hello and runs the only
// review that can grant a brokered browser a capability. A hello that does not
// exist, has expired, or was already claimed by another frame is not reviewed.
//
// Callers outside Handle run under c.mu; Handle already holds it and calls
// reviewBrowserHelloLocked so the in-goroutine reentry cannot deadlock.
func (c *Connection) reviewBrowserHello(s *personal.Session, epoch uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reviewBrowserHelloLocked(s, epoch)
}

// reviewBrowserHelloLocked implements reviewBrowserHello. The caller must hold
// c.mu.
func (c *Connection) reviewBrowserHelloLocked(s *personal.Session, epoch uint64) bool {
	if s == nil || !s.Unlocked() {
		return false
	}
	phase := c.pairingBegin()
	if phase == 0 {
		return false
	}
	go c.requestBrowserPair(s, epoch, phase)
	return true
}

// offerBrowserSession hands a session unlocked after a pending hello to that
// hello's review. A hello accepted before the session existed could not claim
// a slot then, so a pending claim starts its review here. Unlock alone never
// starts a review and never issues a capability.
func (c *Connection) offerBrowserSession(s *personal.Session, epoch uint64) bool {
	return c.reviewBrowserHello(s, epoch)
}

func (c *Connection) finishBrowserPairRefusal(id string, phase uint64) {
	c.mu.Lock()
	if c.hello == id {
		c.hello = ""
	}
	// A refused review must also release its in-flight slot.
	c.pairingEnd(phase)
	closed := c.closed.Load()
	c.mu.Unlock()
	if id != "" && !closed {
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
	// The native pairing consent is bound to one unlocked session. Lock,
	// expiry and capability revocation drop it; a later unlock must obtain a
	// new explicit approval instead of silently renewing quick-fill.
	c.pairAuthorized = false
	c.pairQuickFill = false
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
		// Lock must revoke secret authority synchronously. The desktop's
		// RequestLock callback dispatches UI work asynchronously, so relying on
		// it alone would leave other paired connections able to disclose until
		// the UI loop runs.
		if s := c.session.Load(); s != nil {
			s.RequestLock()
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
	// Removal is destructive and never silently authorized by quick fill.
	if (!c.quickFill || destructiveV2Operation(r.Type)) && requiresV2NativeApproval(r.Type) {
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
				if c.broker != nil {
					// A brokered connection only ever obtains a capability from
					// the explicit native pairing decision. An in-flight review
					// owns its hello, but a hello claimed without one (e.g. one
					// left behind by a refused direct bind) must not block the
					// owner's next explicit approval.
					if c.hello != "" && c.pairing {
						return c.refuse(r.ID)
					}
					c.hello = r.ID
					c.pairUntil = c.now().Add(time.Minute)
					if !c.reviewBrowserHelloLocked(s, c.sessionEpoch) {
						c.hello = ""
						return c.refuse(r.ID)
					}
					return nil
				}
				return c.bindDesktopSessionLocked(s, c.sessionEpoch, c.quickFill, false, r.ID)
			}
			// A brokered connection may only obtain a capability through the
			// explicit native pairing callback. Keep the hello pending; an
			// unlock only offers it to that review, never grants by itself.
			if c.broker != nil {
				if c.broker.callbacks.CurrentSession != nil {
					if s, epoch, ok := c.broker.callbacks.CurrentSession(); ok && s != nil && s.Unlocked() {
						if c.hello != "" {
							return c.refuse(r.ID)
						}
						c.hello = r.ID
						c.pairUntil = c.now().Add(time.Minute)
						if !c.reviewBrowserHelloLocked(s, epoch) {
							c.hello = ""
							return c.refuse(r.ID)
						}
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
	c.closeOnce.Do(func() { close(c.done) })
	c.revokeClipboard(true)
	if s := c.session.Load(); s != nil && !c.desktopShared {
		s.RequestLock()
	}
	c.writer.Close()
	c.Invalidate()
}

// destructiveV2Operation lists removals that always return to the native
// owner, even in quick-fill mode. Nothing here is part of ordinary fill.
func destructiveV2Operation(kind string) bool {
	return kind == "passkey-remove" || kind == "attachment-remove"
}

func requiresV2NativeApproval(kind string) bool {
	switch kind {
	case "item-get",
		"item-copy-field", "item-reveal-field", "item-create", "item-edit", "item-save",
		"item-state", "item-restore-history", "passkey-remove",
		"stage-save", "commit-staged-save",
		"attachment-read", "attachment-commit", "attachment-remove":
		return true
	}
	return false
}

// v2ApprovalReview describes the requested operation using public selectors
// only. It must never copy a field value, password or mutation payload.
func v2ApprovalReview(r Request) (field, action, summary string) {
	switch r.Type {
	case "item-get":
		action, summary = "读取条目详情", "包含身份信息和非隐藏字段值"
	case "item-copy-field", "item-reveal-field":
		field = r.Field
		action = r.FieldAction
		if action == "" {
			if r.Type == "item-reveal-field" {
				action = "显示字段"
			} else {
				action = "复制字段"
			}
		} else if action == "copy" {
			action = "复制字段"
		} else if action == "reveal" {
			action = "显示字段"
		}
		summary = "把所选字段交给当前浏览器页面"
	case "item-create":
		action, summary = "新建条目", "写入一个新条目"
	case "item-edit", "item-save":
		action, summary = "编辑条目", "修改条目字段并生成新修订"
	case "item-state":
		action = r.StateAction
		switch r.StateAction {
		case "favorite":
			summary = "把条目标记为收藏"
		case "unfavorite":
			summary = "取消条目的收藏标记"
		case "archive":
			summary = "把条目移入归档"
		case "unarchive":
			summary = "从归档恢复条目"
		case "trash":
			summary = "把条目移入回收站"
		case "untrash":
			summary = "从回收站恢复条目"
		default:
			summary = "修改条目状态"
		}
	case "item-restore-history":
		action, summary = "恢复历史版本", "用历史内容替换当前条目"
	case "passkey-remove":
		action, summary = "删除 Passkey", "移除该条目的一个 Passkey"
	case "stage-save":
		action, summary = "暂存登录", "暂存浏览器提交的登录信息"
	case "commit-staged-save":
		action, summary = "提交暂存登录", "把暂存登录写入金库"
	case "attachment-read":
		field = "attachment:" + r.AttachmentID
		action, summary = "读取附件", "把附件内容交给当前浏览器页面"
	case "attachment-commit":
		action, summary = "写入附件", "向条目添加一个附件"
	case "attachment-remove":
		field = "attachment:" + r.AttachmentID
		action, summary = "删除附件", "从条目移除一个附件"
	}
	return field, action, summary
}

// itemAnchor is bounded, name-only metadata about one item. It never carries a
// field value, note text, secret, passkey material or the raw item_json.
type itemAnchor struct {
	title, category, revision string
	fields                    []string
	// clears maps a lower-cased "section:id" pair to the stored field's public
	// label, so an explicit clear can be named by the field it empties.
	clears map[string]string
}

// Bounds shared by every review list. They are label lists, so a few dozen
// entries already covers real items; anything longer is cut, not expanded.
const (
	v2AnchorMaxLabel = 64
	v2AnchorMaxList  = 48
)

// projectionListLen keeps the test suite able to prove truncation with a few
// synthetic entries instead of a maximally sized item. The production value is
// v2AnchorMaxList.
var projectionListLen = v2AnchorMaxList

// v2PublicLabel turns one name into a bounded, single-line label. Control
// characters and line separators become visible escapes so a crafted label
// cannot inject another review row or line in the native view.
func v2PublicLabel(raw string) string {
	var out strings.Builder
	for _, r := range raw {
		switch {
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&out, `\u{%X}`, r)
		case r == utf8.RuneError:
			continue
		default:
			out.WriteRune(r)
		}
	}
	label := strings.TrimSpace(out.String())
	if runes := []rune(label); len(runes) > v2AnchorMaxLabel {
		label = strings.TrimSpace(string(runes[:v2AnchorMaxLabel]))
	}
	return label
}

// v2FieldLabel names a custom field by its label without letting the label
// impersonate one of the review's own prefixes ("清除：" etc.).
func v2FieldLabel(raw string) string {
	label := v2PublicLabel(raw)
	if label == "" {
		return "未命名字段"
	}
	if strings.Contains(label, "：") || strings.HasPrefix(label, "stored:") {
		return "「" + label + "」"
	}
	return label
}

// v2SortedNames returns a deduplicated, sorted, bounded copy of the member
// names whose value is present. Non-empty strings and true flags count.
func v2SortedNames(members map[string]any) []string {
	seen := make([]string, 0, len(members))
	for name, value := range members {
		present := false
		switch v := value.(type) {
		case string:
			present = v != ""
		case bool:
			present = v
		}
		if present {
			seen = append(seen, name)
		}
	}
	sort.Strings(seen)
	if len(seen) > projectionListLen {
		seen = seen[:projectionListLen]
	}
	return seen
}

// v2FieldTypeSensitive reports whether a custom field type is stored as a
// secret. Only such fields can be explicitly cleared through clear_fields.
func v2FieldTypeSensitive(typ vault.FieldType) bool {
	switch typ {
	case vault.FieldTypeConcealed, vault.FieldTypeOTP, vault.FieldTypeTOTP:
		return true
	}
	return false
}

// v2DetailFieldNames projects the public field names the approved item detail
// would show: every login builtin member, card and identity member with a
// value, and every custom section field label. Values are never read.
func v2DetailFieldNames(it vault.Item) []string {
	category := categoryOf(it)
	// The authenticated anchor always names the item title and the members
	// the detail frame defines; value-bearing members are added below.
	fields := []string{"标题", "用户名", "验证码", "网址", "备注", "标签", "收藏", "自动提交"}
	if it.Password != "" && (category == "login" || category == "password") {
		fields = append(fields, "密码")
	}
	if card := it.NormalizedCreditCard(); card != nil {
		present := map[string]any{
			"持卡人": card.CardholderName, "卡类型": card.Type, "卡号": card.Number,
			"安全码": card.Verification, "有效期": card.ExpiryDate, "生效日期": card.ValidFrom,
			"PIN": card.PIN, "发卡银行": card.IssuingBank,
		}
		for _, name := range v2SortedNames(present) {
			fields = append(fields, "信用卡·"+name)
		}
	}
	if ident := it.NormalizedIdentity(); ident != nil {
		present := map[string]any{
			"称谓": ident.Title, "名": ident.FirstName, "中间名": ident.MiddleName, "姓": ident.LastName,
			"生日": ident.BirthDate, "公司": ident.Company, "部门": ident.Department, "职位": ident.JobTitle,
			"邮箱": ident.Email, "电话": ident.Phone,
			"地址行 1": ident.AddressLine1, "地址行 2": ident.AddressLine2,
			"城市": ident.City, "州/省": ident.State, "邮编": ident.PostalCode, "国家": ident.Country,
			"网站": ident.Website,
		}
		for _, name := range v2SortedNames(present) {
			fields = append(fields, "身份·"+name)
		}
	}
	for _, sec := range it.Sections {
		for _, f := range sec.Fields {
			label := v2PublicLabel(f.Label)
			if label == "" {
				label = "未命名字段"
			}
			fields = append(fields, "自定义字段："+label)
		}
	}
	return fields
}

// v2RequestedAnchor projects the public names one mutation payload asks to
// write. Decoding uses the same decodeMutation the approval executes, and the
// member order mirrors mergeMeta / v2ItemFromMutation / applyClearFields so only
// members that are actually applied are named.
func (c *Connection) v2RequestedAnchor(target, raw string) itemAnchor {
	m, err := decodeMutation(raw)
	if err != nil {
		// handleItemSave refuses this payload; the review still names the
		// request without trusting any of it.
		return itemAnchor{category: "（无效请求）", fields: []string{}}
	}
	var fields []string
	if m.Title != "" {
		fields = append(fields, "标题")
	}
	if m.Username != nil {
		fields = append(fields, "用户名")
	}
	// v2ItemFromMutation keeps the stored password when an edit sends an empty
	// value; only a creation writes it then.
	if m.Password != nil && (*m.Password != "" || m.Category == "login" || m.Category == "password") {
		fields = append(fields, "密码")
	}
	if m.OTP != nil {
		fields = append(fields, "验证码")
	}
	if m.URL != nil || m.URLs != nil {
		fields = append(fields, "网址")
	}
	if m.Notes != nil {
		fields = append(fields, "备注")
	}
	if m.Favorite != nil {
		fields = append(fields, "收藏")
	}
	if m.AutoSubmit != nil {
		fields = append(fields, "自动提交")
	}
	if m.Tags != nil {
		fields = append(fields, "标签")
	}
	if m.VaultID != "" {
		fields = append(fields, "保管库")
	}
	if card := m.CreditCard; card != nil {
		// mergeMeta applies only the member when its own input is present.
		present := map[string]any{
			"持卡人": card.CardholderName, "卡类型": card.Type, "卡号": card.Number != nil,
			"安全码": card.Verification != nil, "有效期": card.ExpiryDate, "生效日期": card.ValidFrom,
			"PIN": card.PIN != nil, "发卡银行": card.IssuingBank,
		}
		for _, name := range v2SortedNames(present) {
			fields = append(fields, "信用卡·"+name)
		}
	}
	if ident := m.Identity; ident != nil {
		present := map[string]any{
			"称谓": ident.Title, "名": ident.FirstName, "中间名": ident.MiddleName, "姓": ident.LastName,
			"生日": ident.BirthDate, "公司": ident.Company, "部门": ident.Department, "职位": ident.JobTitle,
			"邮箱": ident.Email, "电话": ident.Phone,
			"地址行 1": ident.AddressLine1, "地址行 2": ident.AddressLine2,
			"城市": ident.City, "州/省": ident.State, "邮编": ident.PostalCode, "国家": ident.Country,
			"网站": ident.Website,
		}
		for _, name := range v2SortedNames(present) {
			fields = append(fields, "身份·"+name)
		}
	}
	if m.Sections != nil {
		// Supplied sections replace the structure; each listed field would be
		// written (a nil value preserves the stored value under that id).
		for _, sec := range m.Sections {
			for _, f := range sec.Fields {
				fields = append(fields, "自定义字段："+v2FieldLabel(f.Label))
			}
		}
	}
	anchor := itemAnchor{title: v2PublicLabel(m.Title), category: m.Category, fields: fields}
	if len(m.ClearFields) != 0 {
		// Resolve every explicit clear against the item the approval would
		// edit, so a payload without the target's label still names it.
		stored, err := c.v2StoredAnchor(target)
		if err != nil {
			stored = itemAnchor{}
		}
		for _, key := range m.ClearFields {
			fields = append(fields, "清除："+v2ClearLabel(m, key, stored))
		}
	}
	anchor.fields = v2BoundedLabels(fields)
	return anchor
}

// v2StoredAnchor reads one authenticated item through the existing
// ReadAuthenticatedItems(false) view and projects only its title, category,
// revision and the public field names its detail frame would show. No item,
// section or value escapes this call.
func (c *Connection) v2StoredAnchor(id string) (itemAnchor, error) {
	s := c.session.Load()
	if s == nil {
		return itemAnchor{}, ErrProtocol
	}
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		return itemAnchor{}, err
	}
	it, ok := c.findItem(items, id)
	if !ok || revisions[it.ID] == "" {
		return itemAnchor{}, ErrProtocol
	}
	anchor := itemAnchor{title: v2PublicLabel(it.Title), category: categoryOf(it), revision: revisions[it.ID]}
	anchor.fields = v2BoundedLabels(v2DetailFieldNames(it))
	for _, sec := range it.Sections {
		for _, f := range sec.Fields {
			if !v2FieldTypeSensitive(f.Type) && !f.Protected {
				continue
			}
			if anchor.clears == nil {
				anchor.clears = map[string]string{}
			}
			anchor.clears[strings.ToLower(sec.ID)+":"+strings.ToLower(f.ID)] = "自定义隐藏字段：" + v2FieldLabel(f.Label)
		}
	}
	return anchor, nil
}

// v2ClearLabel names one explicit clear by the field it empties. The payload's
// own section labels win; otherwise the stored item's label is used.
func v2ClearLabel(m BrowserItemMutation, key string, stored itemAnchor) string {
	if key == "notes" {
		return "备注"
	}
	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return "自定义字段"
	}
	// The stored item knows whether the target is stored as a secret; that
	// classification wins over the payload's own echo.
	if label := stored.clears[strings.ToLower(parts[1])+":"+strings.ToLower(parts[2])]; label != "" {
		return label
	}
	for _, sec := range m.Sections {
		if !strings.EqualFold(sec.ID, parts[1]) {
			continue
		}
		for _, f := range sec.Fields {
			if strings.EqualFold(f.ID, parts[2]) && f.Label != "" {
				return "自定义字段：" + v2FieldLabel(f.Label)
			}
		}
	}
	return "自定义字段（ID " + v2PublicLabel(parts[1]+":"+parts[2]) + "）"
}

// v2BoundedLabels trims, de-duplicates, caps and copies a label list.
func v2BoundedLabels(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		label := v2PublicLabel(raw)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	if len(out) > projectionListLen {
		out = out[:projectionListLen]
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// startV2Approval reserves one public review. The caller holds c.mu. The
// request payload stays private in memory and is cleared on rejection, expiry,
// lock or disconnect.
//
// The review also prepares bounded metadata for the native owner: the
// authenticated anchor (title, category, public field names) of an existing
// item, and the public names a mutation asks to write. Only names are copied;
// items, values and the payload itself are never retained by the view.
func (c *Connection) startV2Approval(r Request) error {
	title := r.Title
	if title == "" {
		title = r.Origin
	}
	field, action, summary := v2ApprovalReview(r)
	review := &pendingV2{title: title, field: field, action: action, summary: summary, deadline: c.now().Add(30 * time.Second), epoch: c.epoch, cancelEpoch: c.cancelEpoch.Load()}
	switch r.Type {
	case "item-get":
		// An omitted revision is pinned to the authenticated revision read
		// now. The approval still runs the unchanged handleItemGet, which
		// rechecks the exact revision and refuses if it moved.
		if stored, err := c.v2StoredAnchor(r.ItemID); err == nil {
			review.stored = stored
			if r.Revision == "" && stored.revision != "" {
				r.Revision = stored.revision
			}
		}
	case "item-edit", "item-save":
		if stored, err := c.v2StoredAnchor(r.ItemID); err == nil && stored.revision == r.Revision {
			review.stored = stored
		} else {
			// The edit names an item this host cannot anchor right now; the
			// approval path still rechecks it. Show only the request names.
			review.stored = itemAnchor{}
		}
	}
	if r.Type == "item-create" || r.Type == "item-edit" || r.Type == "item-save" {
		requested := c.v2RequestedAnchor(r.ItemID, r.ItemJSON)
		review.requested = &requested
	}
	review.request = r
	c.v2pending = review
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
		v.V2 = &V2ApprovalView{ID: p.request.ID, Type: p.request.Type, Origin: p.request.Origin, ItemID: p.request.ItemID, Revision: p.request.Revision, Title: p.title, Field: p.field, Action: p.action, Summary: p.summary, Deadline: p.deadline}
		// Independent copies: a snapshot never aliases the pending review, and
		// mutating one snapshot cannot reach the connection or another one.
		v.V2.RevisionPinned = p.request.Type == "item-get" && p.stored.revision != "" && p.stored.revision == p.request.Revision
		v.V2.StoredTitle, v.V2.StoredCategory = p.stored.title, p.stored.category
		v.V2.StoredFields = append([]string(nil), p.stored.fields...)
		if p.requested != nil {
			v.V2.RequestedTitle, v.V2.RequestedCategory = p.requested.title, p.requested.category
			v.V2.RequestedFields = append([]string(nil), p.requested.fields...)
		}
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
