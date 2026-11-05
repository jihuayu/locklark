package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
)

const browserFillAction = "item.browser.fill"
const maxBrowserField = 16 << 10

var ErrBrowserFill = errors.New("browser fill refused or delivery unknown")

// BrowserContext is an assertion by the allowlisted extension, obtained using
// browser APIs. Native messaging cannot independently attest the browser tab.
type BrowserContext struct {
	RequestID  string `json:"request_id"`
	Origin     string `json:"origin"`
	TabID      int64  `json:"tab_id"`
	DocumentID string `json:"document_id"`
}
type BrowserFillTarget struct {
	ID, Revision string
	Context      BrowserContext
}
type NativeBrowserFill struct {
	username, password []byte
	until              time.Time
}

func (*NativeBrowserFill) MarshalJSON() ([]byte, error) { return nil, ErrBrowserFill }
func (*NativeBrowserFill) String() string               { return "[native browser fill]" }
func (*NativeBrowserFill) GoString() string             { return "[native browser fill]" }
func (f *NativeBrowserFill) clear() {
	if f != nil {
		clear(f.username)
		clear(f.password)
		f.username = nil
		f.password = nil
	}
}

func (c BrowserContext) Valid() bool {
	o, e := origin.Parse(c.Origin)
	if e != nil || o != c.Origin || !idOK(c.RequestID) || c.TabID < 1 || c.TabID > 9007199254740991 || len(c.DocumentID) == 0 || len(c.DocumentID) > 128 {
		return false
	}
	for _, r := range c.DocumentID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func (t BrowserFillTarget) valid() bool {
	return t.Context.Valid() && idOK(t.ID) && digestOK(t.Revision)
}
func (t BrowserFillTarget) binding(key []byte) (string, error) {
	raw, e := json.Marshal(t.Context)
	if e != nil {
		return "", e
	}
	defer clear(raw)
	derived, e := hkdf.Key(sha256.New, key, nil, "locklark/personal/browser-fill/key/v1", 32)
	if e != nil {
		return "", ErrBrowserFill
	}
	defer clear(derived)
	m := hmac.New(sha256.New, derived)
	m.Write([]byte("locklark/browser-fill/v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// BrowserMatch never renews idle time: an extension cannot keep a vault unlocked.
func (s *Session) BrowserMatch(c BrowserContext) ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !c.Valid() {
		return nil, ErrBrowserFill
	}
	r, e := s.executeActive(matchAction, vault.Item{}, nil, commandOption{match: &matchRequest{c.Origin, c.Origin}}, false)
	if len(r.rows) > 100 {
		return nil, ErrBrowserFill
	}
	for _, row := range r.rows {
		if len(row.Title) > 1024 {
			return nil, ErrBrowserFill
		}
	}
	if !browserCandidateBudget(r.rows) {
		return nil, ErrBrowserFill
	}
	return r.rows, e
}

// Budget actual JSON bytes, including HTML escaping, with space for the native
// envelope. Oversized metadata is a business refusal, never a broken pipe.
func browserCandidateBudget(rows []Row) bool {
	raw, e := json.Marshal(rows)
	defer clear(raw)
	return e == nil && len(raw) <= 192<<10
}

// PrepareBrowserFill is called only after a native user confirms this exact
// context and revision. The authenticated transaction checks all selectors and
// commits the intent before returning either field. It never calls PrepareField.
func (s *Session) PrepareBrowserFill(t BrowserFillTarget) (*NativeBrowserFill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.valid() {
		return nil, ErrBrowserFill
	}
	if e := s.active(false); e != nil {
		return nil, e
	}
	if len(s.browserPending) >= 2 {
		return nil, ErrBrowserFill
	}
	r, e := s.execute(browserFillAction, vault.Item{}, &Edit{ID: t.ID, Revision: t.Revision}, commandOption{browser: &t})
	if e != nil {
		r.browser.clear()
		return nil, e
	}
	r.browser.until = time.Now().Add(5 * time.Second)
	if s.browserPending == nil {
		s.browserPending = make(map[*NativeBrowserFill]bool)
	}
	s.browserPending[r.browser] = true
	return r.browser, nil
}

// ConsumeBrowserFill runs a bounded native transport callback exactly once.
// The transport must enforce its own cancellation and finite write deadline.
func (s *Session) ConsumeBrowserFill(f *NativeBrowserFill, deliver func([]byte, []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	if f == nil || !s.browserPending[f] || deliver == nil {
		return ErrBrowserFill
	}
	delete(s.browserPending, f)
	defer f.clear()
	if e := deliver(f.username, f.password); e != nil {
		return ErrBrowserFill
	}
	return nil
}
func (s *Session) DiscardBrowserFill(f *NativeBrowserFill) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browserPending[f] {
		delete(s.browserPending, f)
		f.clear()
	}
}
