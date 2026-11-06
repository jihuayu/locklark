package personal

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrSessionLocked = errors.New("desktop vault is locked; unlock again")
var ErrDesktopDelivery = errors.New("native disclosure failed; intent recorded, delivery unknown")

// Session holds only the unlocked identity, never the master password or Secret
// Key. Operations are serialized and revalidate the slot, snapshot and history.
// No exported method exposes arbitrary commands or key material to a renderer.
type Session struct {
	sshPending           sync.Map
	sshRows              map[string]SSHKeyRow
	browserOTPControls   sync.Map
	browserOTPPrepared   map[*BrowserOTP]bool
	browserOTPDeliveries map[*BrowserOTPDelivery]bool
	otpPrepared          map[*NativeOTP]bool
	otpDeliveries        map[*NativeOTPDelivery]bool
	otpNow               func() time.Time
	otpCaps              sync.Map
	saveMu               sync.Mutex
	saveGate             *BrowserSaveGate
	lockRequested        atomic.Bool
	mu                   sync.Mutex
	path                 string
	material             []byte
	slotDigest           [32]byte
	last                 time.Time
	idle                 time.Duration
	fullUnlock           time.Time
	pending              map[*NativeField]bool
	browserPending       map[*NativeBrowserFill]bool
}

// NativeField is a one-use native-only delivery. It cannot be JSON-serialized.
// Consume must run on the native UI thread; its callback must not reenter Session.
type NativeField struct {
	value []byte
	until time.Time
}

func (*NativeField) MarshalJSON() ([]byte, error) { return nil, ErrDesktopDelivery }
func (*NativeField) String() string               { return "[native field]" }
func (*Session) MarshalJSON() ([]byte, error)     { return nil, ErrSessionLocked }
func (*Session) String() string                   { return "[desktop session]" }
func desktopFieldAction(action string) bool {
	switch action {
	case "item.desktop.show.username", "item.desktop.show.password", "item.desktop.copy.username", "item.desktop.copy.password", "item.desktop.show.notes", "item.desktop.copy.notes", "item.desktop.edit.notes":
		return true
	}
	return false
}

// Native notes disclosure is deliberately independent of ValidRevealTarget,
// which remains the narrower username/password capability for other channels.
func validNativeFieldTarget(target RevealTarget, purpose string) bool {
	return idOK(target.ID) && digestOK(target.Revision) && desktopFieldAction("item.desktop."+purpose+"."+target.Field)
}
func UnlockSession(path string, password, key []byte, idle time.Duration) (*Session, error) {
	if idle < time.Second || idle > 15*time.Minute {
		return nil, ErrSessionLocked
	}
	r, e := command(path, string(password), key, "desktop.unlock", vault.Item{}, nil)
	if e != nil {
		clear(r.material)
		return nil, e
	}
	return &Session{path: path, material: r.material, slotDigest: r.slotDigest, last: time.Now(), fullUnlock: time.Now(), idle: idle, pending: make(map[*NativeField]bool)}, nil
}
func (s *Session) lock() {
	s.sshPending.Range(func(key, _ any) bool {
		x := key.(*sshSignState)
		(&SSHSignIntent{x}).Cancel()
		x.clear()
		s.sshPending.Delete(x)
		return true
	})
	s.sshRows = nil
	for p := range s.browserOTPPrepared {
		p.cap.clear()
		s.otpCaps.Delete(p.cap)
		delete(s.browserOTPPrepared, p)
	}
	for d := range s.browserOTPDeliveries {
		d.cap.clear()
		s.otpCaps.Delete(d.cap)
		delete(s.browserOTPDeliveries, d)
	}
	for p := range s.otpPrepared {
		p.cap.clear()
		s.otpCaps.Delete(p.cap)
		delete(s.otpPrepared, p)
	}
	for p := range s.otpDeliveries {
		p.cap.clear()
		s.otpCaps.Delete(p.cap)
		delete(s.otpDeliveries, p)
	}
	s.cancelBrowserSave()
	for f := range s.browserPending {
		f.clear()
		delete(s.browserPending, f)
	}
	clear(s.material)
	s.material = nil
	for f := range s.pending {
		clear(f.value)
		f.value = nil
		delete(s.pending, f)
	}
}

// RequestLock immediately prevents new operations without waiting for a transaction.
func (s *Session) RequestLock() { s.cancelBrowserSave() }
func (s *Session) Lock()        { s.RequestLock(); s.mu.Lock(); defer s.mu.Unlock(); s.lock() }
func (s *Session) sessionLocked() bool {
	if s == nil {
		return true
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return s.lockRequested.Load() || len(s.material) == 0 || time.Since(s.last) >= s.idle
}

// IdleDeadline reports when the session will expire from inactivity if no
// further active operations occur, or false when the session is locked.
func (s *Session) IdleDeadline() (time.Time, bool) {
	if s == nil || s.lockRequested.Load() {
		return time.Time{}, false
	}
	if !s.mu.TryLock() {
		return time.Now().Add(time.Second), true
	}
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return time.Time{}, false
	}
	return s.last.Add(s.idle), true
}
func (s *Session) active(touch bool) error {
	now := time.Now()
	for f := range s.browserPending {
		if !now.Before(f.until) {
			f.clear()
			delete(s.browserPending, f)
		}
	}
	if s.lockRequested.Load() || len(s.material) == 0 || now.Sub(s.last) >= s.idle {
		s.lock()
		return ErrSessionLocked
	}
	for f := range s.pending {
		if !now.Before(f.until) {
			clear(f.value)
			f.value = nil
			delete(s.pending, f)
		}
	}
	if touch {
		s.last = now
	}
	return nil
}
func (s *Session) Unlocked() bool {
	if s.lockRequested.Load() {
		return false
	}
	// UI status polling must not wait for disk operations. Active operations
	// themselves check idle expiry under the mutex.
	if !s.mu.TryLock() {
		return true
	}
	defer s.mu.Unlock()
	return s.active(false) == nil
}
func (s *Session) execute(action string, add vault.Item, edit *Edit, option commandOption) (result, error) {
	return s.executeActive(action, add, edit, option, true)
}
func (s *Session) executeActive(action string, add vault.Item, edit *Edit, option commandOption, touch bool) (result, error) {
	if e := s.active(touch); e != nil {
		return result{}, e
	}
	option.unlocked = s
	r, e := command(s.path, "", nil, action, add, edit, option)
	if errors.Is(e, invalid) {
		s.lock()
	}
	if s.active(false) != nil {
		r.browser.clear()
		clear(r.material)
		clear(r.value)
		clear(r.sshSeed)
		clear(r.archive)
		if r.otp != nil {
			r.otp.Clear()
		}
		return result{}, ErrSessionLocked
	}
	return r, e
}
func (s *Session) List(state string) ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidStateFilter(state) {
		return nil, invalid
	}
	action := "item.list"
	if state != "active" {
		action += "." + state
	}
	r, e := s.execute(action, vault.Item{}, nil, commandOption{})
	return r.rows, e
}
func (s *Session) Search(query, state string) ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(searchAction, vault.Item{}, nil, commandOption{search: &searchRequest{query, state}})
	return r.rows, e
}
func (s *Session) Audit() ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute("audit.list", vault.Item{}, nil, commandOption{})
	return r.events, e
}
func (s *Session) AddLogin(title, username, password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute("item.add", vault.Item{Kind: "login", Title: title, Username: username, Password: password}, nil, commandOption{})
	return r.id, e
}
func (s *Session) Edit(edit Edit) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidEditTarget(edit.ID, edit.Revision, edit.Field) {
		return "", invalid
	}
	r, e := s.execute("item.edit."+edit.Field, vault.Item{}, &edit, commandOption{})
	return r.revision, e
}
func (s *Session) SetState(id, revision, action string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidEditTarget(id, revision, "title") || (!lifecycleAction(action) && !trashAction(action)) {
		return "", invalid
	}
	defer s.cancelSSHTarget(id)
	r, e := s.execute(action, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{})
	return r.revision, e
}
func (s *Session) PrepareField(target RevealTarget, purpose string) (*NativeField, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	action := "item.desktop." + purpose + "." + target.Field
	if !validNativeFieldTarget(target, purpose) {
		return nil, invalid
	}
	if e := s.active(false); e != nil {
		return nil, e
	}
	// Bound the number and lifetime of unconsumed native deliveries.
	if len(s.pending) >= 8 {
		return nil, ErrDesktopDelivery
	}
	r, e := s.execute(action, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{})
	if e != nil {
		clear(r.value)
		return nil, e
	}
	f := &NativeField{value: r.value, until: time.Now().Add(10 * time.Second)}
	s.pending[f] = true
	return f, nil
}
func (s *Session) Consume(field *NativeField, deliver func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	if field == nil || !s.pending[field] || deliver == nil {
		return ErrDesktopDelivery
	}
	delete(s.pending, field)
	defer clear(field.value)
	defer func() { field.value = nil }()
	if e := deliver(field.value); e != nil {
		return ErrDesktopDelivery
	}
	return nil
}

func (*NativeField) GoString() string { return "[native field]" }
func (*Session) GoString() string     { return "[desktop session]" }
func (s *Session) Health() (HealthReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(healthAction, vault.Item{}, nil, commandOption{})
	return r.health, e
}
func (s *Session) PlanImport(source string) (ImportReceipt, error) {
	return s.importSource(source, "", importPlanAction)
}
func (s *Session) Import(source, expected string) (ImportReceipt, error) {
	if !digestOK(expected) {
		return ImportReceipt{}, ErrImportChanged
	}
	return s.importSource(source, expected, importAction)
}
func (s *Session) importSource(source, expected, action string) (ImportReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(action, vault.Item{}, nil, commandOption{migration: &importRequest{read: func() ([]byte, error) { return readInspectionSource(source) }, expected: expected}})
	if e != nil {
		return ImportReceipt{}, e
	}
	status := "planned-" + onepux.LoginProfile
	if action == importAction {
		status = "imported-" + onepux.LoginProfile
	}
	return ImportReceipt{Status: status, Session: r.session, Event: r.intent, ReportDigest: r.reportDigest, Report: r.migration}, nil
}
func (s *Session) Export(password, dest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vault.ValidateExportPassword(password) != nil || !strings.EqualFold(filepath.Ext(dest), ".kdbx") {
		return ErrExportOutput
	}
	r, e := s.execute(exportAction, vault.Item{}, nil, commandOption{export: &exportRequest{password: password}})
	defer clear(r.archive)
	if e != nil {
		return e
	}
	if e = publishExport(r.archive, dest); e != nil {
		return ErrExportOutput
	}
	return nil
}

// Discard destroys a prepared value when its native view is no longer current.
func (s *Session) Discard(field *NativeField) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if field != nil && s.pending[field] {
		clear(field.value)
		field.value = nil
		delete(s.pending, field)
	}
}
