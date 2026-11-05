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
	Save          *SaveView
	SaveStatus    string
	SaveRequestID string
	Pair          bool
	Paired        bool
	Closed        bool
	Pending       *Pending
	Busy          bool
}
type Connection struct {
	save           *pendingSave
	saveAuth       *pendingSave
	saveOutcome    atomic.Uint32
	saveRequestID  string
	generation     atomic.Uint64
	cancelEpoch    atomic.Uint64
	pendingEpoch   uint64
	epoch          uint64
	mu             sync.Mutex
	authMu         sync.Mutex
	authCapability string
	authEpoch      uint64
	authUntil      time.Time
	closed         atomic.Bool
	session        atomic.Pointer[personal.Session]
	writer         *Writer
	notify         func()
	seen           map[string]bool
	received       int
	hello          string
	pairUntil      time.Time
	capability     string
	until          time.Time
	context        personal.BrowserContext
	rows           []personal.Row
	pending        *Request
	pendingUntil   time.Time
	now            func() time.Time
}

func NewConnection(writer *Writer, notify func()) *Connection {
	return &Connection{writer: writer, notify: notify, seen: map[string]bool{}, now: time.Now}
}
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
	if c.closed.Load() || c.received > 128 {
		return false, ErrProtocol
	}
	if c.seen[r.ID] {
		return false, nil
	}
	c.seen[r.ID] = true
	if r.Type == "hello" {
		return true, nil
	}
	allowed := c.authCapability != "" && r.Capability == c.authCapability && c.authEpoch == c.generation.Load() && c.now().Before(c.authUntil)
	if allowed && r.Type == "cancel" {
		c.cancelEpoch.Add(1)
	}
	if allowed && r.Type == "cancel-save" && c.saveAuth != nil && c.saveAuth.request.ID == r.RequestID {
		if !c.saveAuth.gate.Cancel() && c.saveAuth.gate.CommitWon() {
			c.saveAuth.uncertain.Store(true)
		}
	}
	return allowed, nil
}
func (c *Connection) Handle(r Request) error {
	defer r.Clear()
	allowed, err := c.registerRequest(r)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	if !allowed {
		return c.refuse(r.ID)
	}
	if r.Type == "hello" {
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
		if c.save != nil {
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
	if handled, e := c.saveMessage(r); handled {
		return e
	}
	if c.pending != nil || c.save != nil {
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
				copy := r
				c.pending = &copy
				c.pendingEpoch = c.cancelEpoch.Load()
				c.pendingUntil = c.now().Add(30 * time.Second)
				return nil
			}
		}
	}
	return c.refuse(r.ID)
}
func (c *Connection) ApprovePair(s *personal.Session) error {
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
	return c.response(Response{ID: id, Type: "paired", Capability: c.capability})
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
	consumeErr := s.ConsumeBrowserFill(f, func(user, pass []byte) error {
		// This is the write linearization point. Cancellation cannot recall bytes
		// already emitted; the extension must still enforce documentId on injection.
		if c.pendingEpoch != c.cancelEpoch.Load() || epoch != c.generation.Load() || c.closed.Load() || !c.now().Before(c.until) || s == nil || !c.now().Before(c.pendingUntil) {
			return ErrProtocol
		}
		return c.response(Response{ID: r.ID, Type: "fill", Username: string(user), Password: string(pass)})
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
	if c.save != nil {
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
	v.Save, v.SaveStatus = c.saveSnapshot()
	v.SaveRequestID = c.saveRequestID
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
