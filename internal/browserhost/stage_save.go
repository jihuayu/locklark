package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/personal"
)

type stagedSave struct {
	id, origin, username, title, mode string
	payload                           *savePayload
	existingID, existingRevision      string
	windowID                          int64
	tabID                             int64
	documentID                        string
	until                             time.Time
}

func (*stagedSave) String() string               { return "[private staged save]" }
func (*stagedSave) GoString() string             { return "[private staged save]" }
func (*stagedSave) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }

func (p *stagedSave) clear() {
	if p != nil {
		p.payload.clear()
		p.payload = nil
	}
}

func (p *stagedSave) view() *BrowserStagedSave {
	if p == nil {
		return nil
	}
	return &BrowserStagedSave{StageID: p.id, Origin: p.origin, Username: p.username, Title: p.title, Mode: p.mode, ExistingItemID: p.existingID, ExistingRevision: p.existingRevision, ExpiresAt: p.until.UnixMilli()}
}

func newStageID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrProtocol
	}
	return hex.EncodeToString(b[:]), nil
}

func (c *Connection) setNeverOrigin(origin string) {
	c.neverOrigins[origin] = true
	if c.broker != nil {
		c.broker.addNeverOrigin(origin)
	}
}

func (c *Connection) isNeverOrigin(origin string) bool {
	if c.neverOrigins[origin] {
		return true
	}
	if c.broker != nil {
		return c.broker.hasNeverOrigin(origin)
	}
	return false
}

func (c *Connection) clearStaged() {
	for _, p := range c.staged {
		p.clear()
	}
	c.staged = nil
}

func (c *Connection) pruneStaged() {
	now := c.now()
	out := c.staged[:0]
	for _, p := range c.staged {
		if !now.Before(p.until) {
			p.clear()
			continue
		}
		out = append(out, p)
	}
	c.staged = out
}

func (c *Connection) stageMessage(r Request) (bool, error) {
	switch r.Type {
	case "stage-save":
		return true, c.stageSave(r)
	case "pending-save":
		return true, c.pendingSave(r)
	case "commit-staged-save":
		return true, c.commitStagedSave(r)
	case "dismiss-save":
		return true, c.dismissSave(r)
	}
	return false, nil
}

func (c *Connection) stageSave(r Request) error {
	payload := r.payload.take()
	if payload == nil {
		return c.refuse(r.ID)
	}
	defer func() {
		if payload != nil {
			payload.clear()
		}
	}()
	if c.isNeverOrigin(r.Origin) {
		return c.response(Response{ID: r.ID, Type: "save-staged", StagedSave: &BrowserStagedSave{Origin: r.Origin, Mode: "never", Username: string(payload.username)}})
	}
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	site := r.Origin
	mode := "new"
	existingID, existingRev, title := "", "", r.Title
	var usernameMatch *string
	for _, it := range items {
		if it.State != "" || it.Kind != "login" || it.URL == "" {
			continue
		}
		itSite, err := origin.Website(it.URL)
		if err != nil || itSite != site {
			continue
		}
		if it.Username == string(payload.username) && it.Password == string(payload.password) {
			mode = "unchanged"
			existingID, existingRev, title = it.ID, revisions[it.ID], it.Title
			break
		}
		if r.ItemID != "" && it.ID == r.ItemID {
			mode = "update"
			existingID, existingRev, title = it.ID, revisions[it.ID], it.Title
			break
		}
		if it.Username == string(payload.username) && usernameMatch == nil {
			id, rev, t := it.ID, revisions[it.ID], it.Title
			usernameMatch = &id
			existingRev, title = rev, t
		}
	}
	if mode != "update" && mode != "unchanged" && usernameMatch != nil {
		mode = "update"
		existingID = *usernameMatch
	}
	if mode == "unchanged" {
		return c.response(Response{ID: r.ID, Type: "save-staged", StagedSave: &BrowserStagedSave{Origin: r.Origin, Username: string(payload.username), Title: title, Mode: mode, ExistingItemID: existingID, ExistingRevision: existingRev, ExpiresAt: c.now().Add(5 * time.Minute).UnixMilli()}})
	}
	id, e := newStageID()
	if e != nil {
		return c.refuse(r.ID)
	}
	if title == "" {
		title = r.Origin
	}
	if len(title) > 1024 || strings.TrimSpace(title) == "" {
		return c.refuse(r.ID)
	}
	p := &stagedSave{id: id, origin: r.Origin, username: string(payload.username), title: title, mode: mode, payload: payload, existingID: existingID, existingRevision: existingRev, windowID: r.WindowID, tabID: r.TabID, documentID: r.DocumentID, until: c.now().Add(5 * time.Minute)}
	payload = nil // ownership moved to the staged entry
	c.staged = append(c.staged, p)
	return c.response(Response{ID: r.ID, Type: "save-staged", StagedSave: p.view()})
}

func (c *Connection) pendingSave(r Request) error {
	c.pruneStaged()
	for _, p := range c.staged {
		if p.origin != r.Origin || p.tabID != r.TabID || r.WindowID != 0 && p.windowID != r.WindowID {
			continue
		}
		return c.response(Response{ID: r.ID, Type: "save-pending", StagedSave: p.view()})
	}
	return c.response(Response{ID: r.ID, Type: "save-pending"})
}

func (c *Connection) commitStagedSave(r Request) error {
	c.pruneStaged()
	var p *stagedSave
	for _, candidate := range c.staged {
		if candidate.id == r.StageID && candidate.origin == r.Origin && (candidate.windowID == r.WindowID || r.WindowID == 0) && candidate.tabID == r.TabID {
			p = candidate
			break
		}
	}
	if p == nil || p.mode == "never" {
		return c.refuse(r.ID)
	}
	if p.mode == "unchanged" {
		view := p.view()
		c.removeStaged(p)
		return c.response(Response{ID: r.ID, Type: "saved", ItemID: view.ExistingItemID, Revision: view.ExistingRevision})
	}
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	target := personal.BrowserSaveTarget{Context: r.SaveContext(), ID: p.existingID, Revision: p.existingRevision}
	if target.ID == "" {
		title := p.title
		if r.Title != "" {
			title = r.Title
		}
		if len(title) == 0 || len(title) > 1024 {
			return c.refuse(r.ID)
		}
		target.Title = title
	}
	until := minTime(c.until, p.until)
	gate := personal.NewBrowserSaveGate(until)
	if s.RegisterBrowserSave(gate) != nil {
		return c.refuse(r.ID)
	}
	if e := s.TouchBrowserSave(gate); e != nil {
		s.ReleaseBrowserSave(gate)
		return c.refuse(r.ID)
	}
	payload := p.payload
	p.payload = nil
	user, password := payload.username, payload.password
	payload.username, payload.password = nil, nil
	// SaveBrowser takes ownership and clears both buffers on every path.
	receipt, e := s.SaveBrowser(target, user, password, gate)
	clear(user)
	clear(password)
	c.removeStaged(p)
	if e != nil {
		return c.refuse(r.ID)
	}
	return c.response(Response{ID: r.ID, Type: "saved", ItemID: receipt.ID, Revision: receipt.Revision})
}

func (c *Connection) removeStaged(p *stagedSave) {
	out := c.staged[:0]
	for _, candidate := range c.staged {
		if candidate == p {
			candidate.clear()
			continue
		}
		out = append(out, candidate)
	}
	c.staged = out
}

func (c *Connection) dismissSave(r Request) error {
	c.pruneStaged()
	if r.StageID != "" {
		var found *stagedSave
		for _, p := range c.staged {
			if p.id == r.StageID {
				found = p
				break
			}
		}
		if found != nil {
			if r.Origin != "" && found.origin != r.Origin {
				return c.refuse(r.ID)
			}
			c.removeStaged(found)
		}
	} else if r.Origin != "" {
		out := c.staged[:0]
		for _, p := range c.staged {
			if p.origin == r.Origin {
				p.clear()
				continue
			}
			out = append(out, p)
		}
		c.staged = out
	}
	if boolValue(r.NeverForOrigin, false) && r.Origin != "" {
		c.setNeverOrigin(r.Origin)
	}
	return c.response(Response{ID: r.ID, Type: "save-dismissed", NeverOrigins: c.neverOriginList()})
}

func (c *Connection) neverOriginList() []string {
	seen := map[string]bool{}
	out := []string{}
	for k := range c.neverOrigins {
		seen[k] = true
		out = append(out, k)
	}
	if c.broker != nil {
		for _, k := range c.broker.neverOrigins() {
			if !seen[k] {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}
