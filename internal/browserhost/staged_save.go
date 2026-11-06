package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

const stagedSaveTTL = 5 * time.Minute
const maxStagedSaves = 8

var ErrStagedSave = errors.New("staged browser save refused")

// stagedSave keeps a submitted credential across a post-submit navigation. The
// password is private memory only and is cleared on commit, dismiss, expiry,
// lock, disconnect or capability invalidation.
type stagedSave struct {
	id                 string
	mode               string
	title              string
	origin             string
	tabID              int64
	windowID           int64
	itemID             string
	revision           string
	username, password []byte
	until              time.Time
	timer              *time.Timer
}

func (s *stagedSave) String() string             { return "[private staged browser save]" }
func (s *stagedSave) GoString() string           { return "[private staged browser save]" }
func (*stagedSave) MarshalJSON() ([]byte, error) { return nil, ErrStagedSave }

func (s *stagedSave) clear() {
	if s == nil {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	clear(s.username)
	clear(s.password)
	s.username, s.password = nil, nil
}

func (s *stagedSave) view() StagedSave {
	return StagedSave{
		StageID:          s.id,
		Origin:           s.origin,
		Username:         string(s.username),
		Title:            s.title,
		Mode:             s.mode,
		ExistingItemID:   s.itemID,
		ExistingRevision: s.revision,
		ExpiresAt:        s.until.UnixMilli(),
	}
}

func newStageID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", ErrStagedSave
	}
	return hex.EncodeToString(value[:]), nil
}

func (c *Connection) neverOriginList() []string {
	if len(c.neverOrigins) == 0 {
		return nil
	}
	origins := make([]string, 0, len(c.neverOrigins))
	for origin := range c.neverOrigins {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}

func (c *Connection) clearStaged() {
	for id, staged := range c.staged {
		staged.clear()
		delete(c.staged, id)
	}
}

func (c *Connection) expireStaged() {
	now := c.now()
	for id, staged := range c.staged {
		if !now.Before(staged.until) {
			staged.clear()
			delete(c.staged, id)
		}
	}
}

func (c *Connection) findStaged(id string) *stagedSave {
	staged := c.staged[id]
	if staged == nil || !c.now().Before(staged.until) {
		if staged != nil {
			staged.clear()
			delete(c.staged, id)
		}
		return nil
	}
	return staged
}

func (c *Connection) findStagedForTab(origin string, tabID int64) *stagedSave {
	var newest *stagedSave
	for _, staged := range c.staged {
		if staged.origin != origin || staged.tabID != tabID || !c.now().Before(staged.until) {
			continue
		}
		if newest == nil || staged.until.After(newest.until) {
			newest = staged
		}
	}
	return newest
}

func (c *Connection) stagedMessage(r Request) (bool, error) {
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
	if c.save != nil || c.pending != nil || c.otp != nil || c.passkey != nil || c.stagedBusy {
		return c.refuse(r.ID)
	}
	session := c.session.Load()
	if session == nil || !session.Unlocked() {
		return c.refuse(r.ID)
	}
	if c.neverOrigins[r.Origin] {
		return c.refuse(r.ID)
	}
	if r.Mode == "update" {
		rows, err := session.BrowserMatch(r.Context())
		if err != nil {
			return c.refuse(r.ID)
		}
		found := false
		for _, row := range rows {
			if row.ID == r.ItemID && row.Revision == r.Revision {
				found = true
				break
			}
		}
		if !found {
			return c.refuse(r.ID)
		}
	}
	if c.staged == nil {
		c.staged = map[string]*stagedSave{}
	}
	c.expireStaged()
	// A later submission for the same tab replaces the earlier staged values.
	for id, staged := range c.staged {
		if staged.origin == r.Origin && staged.tabID == r.TabID {
			staged.clear()
			delete(c.staged, id)
		}
	}
	if len(c.staged) >= maxStagedSaves {
		var oldest *stagedSave
		for _, staged := range c.staged {
			if oldest == nil || staged.until.Before(oldest.until) {
				oldest = staged
			}
		}
		if oldest != nil {
			oldest.clear()
			delete(c.staged, oldest.id)
		}
	}
	id, err := newStageID()
	if err != nil {
		return c.refuse(r.ID)
	}
	until := c.now().Add(stagedSaveTTL)
	if c.until.Before(until) {
		until = c.until
	}
	title := r.Title
	if title == "" {
		title = r.Origin
	}
	// Take ownership of the mutable credential buffers. Request.Clear runs
	// after this handler returns and must not zero the bytes retained for a
	// later commit.
	payload := r.payload.take()
	staged := &stagedSave{
		id:       id,
		mode:     r.Mode,
		title:    title,
		origin:   r.Origin,
		tabID:    r.TabID,
		windowID: r.WindowID,
		itemID:   r.ItemID,
		revision: r.Revision,
		username: payload.username,
		password: payload.password,
		until:    until,
	}
	payload.username, payload.password = nil, nil
	c.staged[id] = staged
	staged.timer = time.AfterFunc(time.Until(until), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.staged[id] == staged {
			staged.clear()
			delete(c.staged, id)
		}
	})
	return c.response(Response{ID: r.ID, Type: "save-staged", Staged: pointer(staged.view())})
}

func (c *Connection) pendingStaged() bool {
	for _, staged := range c.staged {
		if c.now().Before(staged.until) {
			return true
		}
	}
	return false
}

func (c *Connection) pendingSave(r Request) error {
	c.expireStaged()
	staged := c.findStagedForTab(r.Origin, r.TabID)
	if staged == nil {
		return c.response(Response{ID: r.ID, Type: "save-pending"})
	}
	return c.response(Response{ID: r.ID, Type: "save-pending", Staged: pointer(staged.view())})
}

func (c *Connection) commitStagedSave(r Request) error {
	c.expireStaged()
	staged := c.findStaged(r.StageID)
	if staged == nil || staged.origin != r.Origin || staged.tabID != r.TabID {
		return c.refuse(r.ID)
	}
	session := c.session.Load()
	if session == nil || !session.Unlocked() || c.stagedBusy || c.save != nil || c.pending != nil || c.otp != nil || c.passkey != nil {
		return c.refuse(r.ID)
	}
	mode := r.Mode
	itemID, rev := r.ItemID, r.Revision
	if itemID == "" && staged.itemID != "" {
		itemID, rev = staged.itemID, staged.revision
	}
	if mode == "update" {
		if !token.MatchString(itemID) || !revision.MatchString(rev) {
			return c.refuse(r.ID)
		}
		rows, err := session.BrowserMatch(r.Context())
		if err != nil {
			return c.refuse(r.ID)
		}
		found := false
		for _, row := range rows {
			if row.ID == itemID && row.Revision == rev {
				found = true
				break
			}
		}
		if !found {
			return c.refuse(r.ID)
		}
	} else {
		itemID, rev = "", ""
	}
	title := ""
	if mode == "new" {
		title = r.Title
		if title == "" {
			title = staged.title
		}
	}
	until := c.now().Add(30 * time.Second)
	if c.until.Before(until) {
		until = c.until
	}
	if staged.until.Before(until) {
		until = staged.until
	}
	gate := personal.NewBrowserSaveGate(until)
	if err := session.RegisterBrowserSave(gate); err != nil {
		return c.refuse(r.ID)
	}
	target := personal.BrowserSaveTarget{
		Context:  r.SaveContext(),
		ID:       itemID,
		Revision: rev,
		Title:    title,
	}
	username, password := staged.username, staged.password
	staged.username, staged.password = nil, nil
	staged.clear()
	delete(c.staged, staged.id)
	c.stagedBusy = true
	go c.commitStagedSaveWith(r.ID, session, target, username, password, gate)
	return nil
}

func (c *Connection) commitStagedSaveWith(id string, session *personal.Session, target personal.BrowserSaveTarget, username, password []byte, gate *personal.BrowserSaveGate) {
	receipt, err := session.SaveBrowser(target, username, password, gate)
	clear(username)
	clear(password)
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.stagedBusy = false
	if errors.Is(err, personal.ErrBrowserSaveUnknown) {
		_ = c.response(Response{ID: id, Type: "unknown"})
		return
	}
	if err != nil {
		_ = c.refuse(id)
		return
	}
	_ = c.response(Response{ID: id, Type: "saved", ItemID: receipt.ID, Revision: receipt.Revision})
}

func (c *Connection) dismissSave(r Request) error {
	staged := c.findStaged(r.StageID)
	if staged != nil {
		if r.NeverForOrigin {
			if c.neverOrigins == nil {
				c.neverOrigins = map[string]bool{}
			}
			c.neverOrigins[staged.origin] = true
		}
		staged.clear()
		delete(c.staged, staged.id)
	}
	return c.response(Response{ID: r.ID, Type: "save-dismissed", NeverOrigins: c.neverOriginList()})
}
