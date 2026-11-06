package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
)

const browserNewAction = "item.browser.save.new"
const browserUpdateAction = "item.browser.save.update"

var ErrBrowserSaveRefused = errors.New("browser save refused")
var ErrBrowserSaveCancelled = errors.New("browser save cancelled before persistence")
var ErrBrowserSaveUnknown = errors.New("browser save result unknown; reopen the vault; do not retry automatically")

type BrowserSaveContext struct {
	BrowserContext
	WindowID int64 `json:"window_id"`
}

func (c BrowserSaveContext) Valid() bool {
	return c.BrowserContext.Valid() && c.WindowID > 0 && c.WindowID <= 9007199254740991
}

type BrowserSaveTarget struct {
	Context             BrowserSaveContext
	ID, Revision, Title string
}
type BrowserSaveReceipt struct {
	ID       string `json:"item_id"`
	Revision string `json:"revision"`
}
type browserSaveRequest struct {
	target             BrowserSaveTarget
	username, password []byte
	gate               *BrowserSaveGate
}

func (*browserSaveRequest) String() string               { return "[private browser save request]" }
func (*browserSaveRequest) GoString() string             { return "[private browser save request]" }
func (*browserSaveRequest) MarshalJSON() ([]byte, error) { return nil, ErrBrowserSaveRefused }

func browserSaveAction(a string) bool { return a == browserNewAction || a == browserUpdateAction }
func validBrowserText(v []byte) bool {
	if len(v) > maxBrowserField || !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
func (r *browserSaveRequest) valid() bool {
	if r == nil || r.gate == nil || !r.target.Context.Valid() || !validBrowserText(r.username) || !validBrowserText(r.password) || len(r.password) == 0 {
		return false
	}
	if r.target.ID == "" {
		return r.target.Revision == "" && len(r.target.Title) <= 1024 && strings.TrimSpace(r.target.Title) != "" && validBrowserText([]byte(r.target.Title))
	}
	return idOK(r.target.ID) && digestOK(r.target.Revision) && r.target.Title == ""
}
func (r *browserSaveRequest) binding(key []byte) (string, error) {
	derived, e := hkdf.Key(sha256.New, key, nil, "locklark/personal/browser-save/key/v1", 32)
	if e != nil {
		return "", e
	}
	defer clear(derived)
	mode := "new"
	if r.target.ID != "" {
		mode = "update"
	}
	raw, e := json.Marshal(struct {
		Version                   int
		Mode, ID, Revision, Title string
		Context                   BrowserSaveContext
	}{1, mode, r.target.ID, r.target.Revision, r.target.Title, r.target.Context})
	if e != nil {
		return "", e
	}
	defer clear(raw)
	m := hmac.New(sha256.New, derived)
	m.Write([]byte("locklark/browser-save/v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// saveMu never guards disk or pipe operations. RequestLock and registration
// share it with the transaction's final gate arbitration; neither can miss a
// newly registered request or wait for a database lock.
func (s *Session) RegisterBrowserSave(g *BrowserSaveGate) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if g == nil || !g.Pending() || s.saveGate != nil || s.lockRequested.Load() {
		if g != nil {
			g.Cancel()
		}
		return ErrBrowserSaveCancelled
	}
	s.saveGate = g
	return nil
}
func (s *Session) ReleaseBrowserSave(g *BrowserSaveGate) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveGate == g {
		g.Cancel()
		s.saveGate = nil
	}
}
func (s *Session) cancelBrowserSave() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.lockRequested.Store(true)
	s.sshPending.Range(func(key, _ any) bool { (&SSHSignIntent{key.(*sshSignState)}).Cancel(); return true })
	s.otpCaps.Range(func(key, value any) bool { key.(*otpCap).cancel(); return true })
	s.browserOTPControls.Range(func(key, _ any) bool { (&BrowserOTPControl{inner: key.(*browserOTPState)}).Cancel(); return true })
	if s.saveGate != nil {
		s.saveGate.Cancel()
	}
}
func (s *Session) TouchBrowserSave(g *BrowserSaveGate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveGate != g || !g.Pending() || s.lockRequested.Load() {
		return ErrBrowserSaveCancelled
	}
	s.last = time.Now()
	return nil
}
func (s *Session) winBrowserSave(g *BrowserSaveGate) bool {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveGate != g || s.lockRequested.Load() || len(s.material) == 0 || time.Since(s.last) >= s.idle {
		g.Cancel()
		return false
	}
	return g.win()
}

// SaveBrowser takes ownership of both mutable buffers and clears them on every
// return path. Callers must not read or reuse them, including during execution.
func (s *Session) SaveBrowser(t BrowserSaveTarget, user, password []byte, g *BrowserSaveGate) (BrowserSaveReceipt, error) {
	return s.saveBrowser(t, user, password, g, nil)
}
func (s *Session) saveBrowser(t BrowserSaveTarget, user, password []byte, g *BrowserSaveGate, run func() (result, error)) (BrowserSaveReceipt, error) {
	defer clear(user)
	defer clear(password)
	defer func() {
		if g != nil {
			g.Cancel()
			s.ReleaseBrowserSave(g)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	request := &browserSaveRequest{target: t, username: user, password: password, gate: g}
	if !request.valid() {
		return BrowserSaveReceipt{}, ErrBrowserSaveRefused
	}
	s.saveMu.Lock()
	registered := s.saveGate == g && g.Pending()
	s.saveMu.Unlock()
	if !registered {
		return BrowserSaveReceipt{}, ErrBrowserSaveCancelled
	}
	if e := s.active(false); e != nil {
		return BrowserSaveReceipt{}, ErrBrowserSaveCancelled
	}
	action := browserNewAction
	if t.ID != "" {
		action = browserUpdateAction
	}
	if run == nil {
		run = func() (result, error) {
			return command(s.path, "", nil, action, vault.Item{}, nil, commandOption{unlocked: s, browserSave: request})
		}
	}
	r, e := run()
	if errors.Is(e, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if g.CommitWon() && (!active || e != nil && !errors.Is(e, ErrBrowserSaveRefused) && !errors.Is(e, ErrConflict) && !errors.Is(e, ErrNotFound)) {
		return BrowserSaveReceipt{}, ErrBrowserSaveUnknown
	}
	if !active {
		return BrowserSaveReceipt{}, ErrBrowserSaveCancelled
	}
	if e != nil {
		return BrowserSaveReceipt{}, e
	}
	return BrowserSaveReceipt{r.id, r.revision}, nil
}
