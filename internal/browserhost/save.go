package browserhost

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

const (
	saveIdle uint32 = iota
	saveWaiting
	saveApproved
	saveWriting
	saveSucceeded
	saveRefused
	saveUnknown
)

type SaveView struct {
	ID, Origin, ItemID, Revision, Title, Mode, Stage string
	Until                                            time.Time
}
type pendingSave struct {
	request              Request
	target               personal.BrowserSaveTarget
	payload              *savePayload
	gate                 *personal.BrowserSaveGate
	session              *personal.Session
	until                time.Time
	nonce                [32]byte
	challenged, consumed bool
	committing           bool
	commitID             string
	epoch                uint64
	timer                *time.Timer
	uncertain            atomic.Bool
}

func (*pendingSave) String() string               { return "[private browser save]" }
func (*pendingSave) GoString() string             { return "[private browser save]" }
func (*pendingSave) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (c *Connection) saveMessage(r Request) (bool, error) {
	switch r.Type {
	case "save-new", "save-update":
		if c.pending != nil || c.save != nil || c.otp != nil {
			return true, c.refuse(r.ID)
		}
		s := c.session.Load()
		if s == nil {
			return true, c.refuse(r.ID)
		}
		title := r.Origin
		if r.Type == "save-update" {
			title = ""
			found := false
			if c.context.Origin != r.Origin || c.context.TabID != r.TabID || c.context.DocumentID != r.DocumentID {
				return true, c.refuse(r.ID)
			}
			for _, row := range c.rows {
				if row.ID == r.ItemID && row.Revision == r.Revision {
					title = row.Title
					found = true
					break
				}
			}
			if !found {
				return true, c.refuse(r.ID)
			}
		}
		until := minTime(c.now().Add(30*time.Second), c.until)
		g := personal.NewBrowserSaveGate(until)
		if s.RegisterBrowserSave(g) != nil {
			return true, c.refuse(r.ID)
		}
		p := &pendingSave{request: r, target: personal.BrowserSaveTarget{Context: r.SaveContext(), ID: r.ItemID, Revision: r.Revision}, payload: r.payload.take(), gate: g, session: s, until: until, epoch: c.epoch}
		p.request.payload = nil
		if r.Type == "save-new" {
			p.target.Title = title
		}
		c.save = p
		c.saveRequestID = r.ID
		c.otpStatus = ""
		c.authMu.Lock()
		c.saveAuth = p
		c.authMu.Unlock()
		c.saveOutcome.Store(saveWaiting)
		p.timer = time.AfterFunc(time.Until(until), func() { c.expireSave(p) })
		return true, nil
	case "cancel-save":
		p := c.save
		if p == nil || p.request.ID != r.RequestID {
			return true, c.refuse(r.ID)
		}
		// Classify this cancellation by its CAS result, independently of the
		// read loop's earlier authenticated cancellation attempt.
		if !p.gate.Cancel() && p.gate.CommitWon() {
			p.uncertain.Store(true)
			c.saveOutcome.Store(saveUnknown)
			return true, c.response(Response{ID: r.ID, Type: "unknown"})
		}
		if p.committing {
			c.saveOutcome.Store(saveRefused)
		} else {
			challenged := p.challenged
			original := p.request.ID
			c.clearSave(p)
			c.saveOutcome.Store(saveRefused)
			if !challenged {
				if e := c.refuse(original); e != nil {
					return true, e
				}
			}
		}
		return true, c.response(Response{ID: r.ID, Type: "cancelled"})
	case "commit-ready":
		p := c.save
		if p == nil || p.request.ID != r.RequestID || !p.challenged || p.consumed || !p.gate.Pending() || !c.now().Before(p.until) {
			return true, c.refuse(r.ID)
		}
		nonce, e := hex.DecodeString(r.Nonce)
		if e != nil || subtle.ConstantTimeCompare(nonce, p.nonce[:]) != 1 {
			clear(nonce)
			return true, c.refuse(r.ID)
		}
		clear(nonce)
		p.consumed = true
		clear(p.nonce[:])
		p.commitID = r.ID
		p.committing = true
		payload := p.payload
		p.payload = nil
		c.saveOutcome.Store(saveWriting)
		go c.commitSave(p, payload)
		return true, nil
	}
	return false, nil
}
func (c *Connection) clearSave(p *pendingSave) {
	if p == nil {
		return
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	p.gate.Cancel()
	p.payload.clear()
	p.payload = nil
	clear(p.nonce[:])
	p.session.ReleaseBrowserSave(p.gate)
	if c.save == p {
		c.save = nil
	}
	c.authMu.Lock()
	if c.saveAuth == p {
		c.saveAuth = nil
	}
	c.authMu.Unlock()
}
func (c *Connection) expireSave(p *pendingSave) {
	p.gate.Cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	if c.save != p || p.epoch != c.generation.Load() {
		return
	}
	if p.gate.CommitWon() {
		p.uncertain.Store(true)
		c.saveOutcome.Store(saveUnknown)
		return
	}
	// The worker owns the commit RPC's only terminal response once launched.
	// Expiry revokes its gate immediately but must not answer the same id twice.
	if p.committing {
		c.saveOutcome.Store(saveRefused)
		return
	}
	id := p.request.ID
	if p.challenged {
		id = ""
	}
	if p.commitID != "" {
		id = p.commitID
	}
	c.clearSave(p)
	c.saveOutcome.Store(saveRefused)
	if id != "" {
		_ = c.refuse(id)
	}
}

// Native approval sends only a one-use challenge. Browser API revalidation is
// still required before the transaction worker may compete for persistence.
func (c *Connection) ApproveSave(id, title string) error {
	return c.approveSaveWithTouch(id, title, func(p *pendingSave) error {
		return p.session.TouchBrowserSave(p.gate)
	})
}
func (c *Connection) approveSaveWithTouch(id, title string, touch func(*pendingSave) error) error {
	c.mu.Lock()
	c.syncEpoch()
	c.expire()
	p := c.save
	if p == nil || p.request.ID != id || p.challenged || !p.gate.Pending() || !c.valid(p.request.Capability) || !c.now().Before(p.until) {
		c.mu.Unlock()
		return ErrProtocol
	}
	if p.request.Type == "save-new" {
		if len(title) == 0 || len(title) > 1024 {
			c.mu.Unlock()
			return ErrProtocol
		}
	}
	c.mu.Unlock()
	if e := touch(p); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	if c.save != p || p.challenged || p.epoch != c.generation.Load() || !p.gate.Pending() || !c.now().Before(p.until) {
		return ErrProtocol
	}
	if p.request.Type == "save-new" {
		p.target.Title = title
	}
	if _, e := rand.Read(p.nonce[:]); e != nil {
		p.gate.Cancel()
		c.clearSave(p)
		return ErrProtocol
	}
	p.challenged = true
	p.until = minTime(p.until, c.now().Add(3*time.Second))
	p.gate.Shorten(p.until)
	if p.timer != nil {
		p.timer.Stop()
	}
	p.timer = time.AfterFunc(time.Until(p.until), func() { c.expireSave(p) })
	c.saveOutcome.Store(saveApproved)
	return c.response(Response{ID: p.request.ID, Type: "save-ready", Nonce: hex.EncodeToString(p.nonce[:])})
}
func (c *Connection) commitSave(p *pendingSave, payload *savePayload) {
	c.commitSaveWith(p, payload, p.session.SaveBrowser)
}
func (c *Connection) commitSaveWith(p *pendingSave, payload *savePayload, execute func(personal.BrowserSaveTarget, []byte, []byte, *personal.BrowserSaveGate) (personal.BrowserSaveReceipt, error)) {
	defer payload.clear()
	receipt, e := execute(p.target, payload.username, payload.password, p.gate)
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	if c.save != p || p.epoch != c.generation.Load() || c.closed.Load() {
		return
	}
	defer c.clearSave(p)
	c.rows = nil
	c.context = personal.BrowserContext{}
	if p.uncertain.Load() || errors.Is(e, personal.ErrBrowserSaveUnknown) || !p.session.Unlocked() || !c.now().Before(c.until) {
		c.saveOutcome.Store(saveUnknown)
		_ = c.response(Response{ID: p.commitID, Type: "unknown"})
		return
	}
	if e != nil {
		c.saveOutcome.Store(saveRefused)
		_ = c.refuse(p.commitID)
		return
	}
	c.saveOutcome.Store(saveSucceeded)
	if c.response(Response{ID: p.commitID, Type: "saved", ItemID: receipt.ID, Revision: receipt.Revision}) != nil {
		c.saveOutcome.Store(saveUnknown)
	}
}
func (c *Connection) SaveUnknown() bool { return c.saveOutcome.Load() == saveUnknown }
func (c *Connection) saveSnapshot() (*SaveView, string) {
	status := ""
	switch c.saveOutcome.Load() {
	case saveWaiting:
		status = "等待原生批准保存"
	case saveApproved:
		status = "已批准，正在核对当前页面"
	case saveWriting:
		status = "正在保存"
	case saveSucceeded:
		status = "已保存"
	case saveRefused:
		status = "未保存"
	case saveUnknown:
		status = "结果未确认，请在金库核实，勿重复保存"
	}
	p := c.save
	if p == nil {
		return nil, status
	}
	mode := "new"
	title := p.target.Title
	if p.request.Type == "save-update" {
		mode = "update"
		for _, row := range c.rows {
			if row.ID == p.target.ID {
				title = row.Title
			}
		}
	}
	stage := "pending"
	if p.challenged {
		stage = "approved"
	}
	if p.committing {
		stage = "committing"
	}
	return &SaveView{ID: p.request.ID, Origin: p.target.Context.Origin, ItemID: p.target.ID, Revision: p.target.Revision, Title: title, Mode: mode, Stage: stage, Until: p.until}, status
}

// A late native callback must never reject a newer pending request.
func (c *Connection) RejectSave(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	p := c.save
	if p == nil || p.request.ID != id {
		return ErrProtocol
	}
	if !p.gate.Cancel() && p.gate.CommitWon() {
		p.uncertain.Store(true)
		c.saveOutcome.Store(saveUnknown)
		return nil
	}
	c.saveOutcome.Store(saveRefused)
	if p.committing {
		return nil
	}
	challenged := p.challenged
	c.clearSave(p)
	if !challenged {
		return c.refuse(id)
	}
	return nil
}
