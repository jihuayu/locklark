package personal

import (
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

const (
	maxBrowserProfilePending = 2
	browserProfileTTL        = 30 * time.Second
)

// pruneBrowserProfiles drops this session's own expired grants so a dead grant
// can never consume one of the bounded pending slots. Foreign grants have no
// entry in this registry and are therefore never touched.
func (s *Session) pruneBrowserProfiles(now time.Time) {
	for p := range s.profilePending {
		if !now.Before(p.until) {
			p.clear()
			delete(s.profilePending, p)
		}
	}
}

// PrepareBrowserProfileFill is called only after the native owner explicitly
// approved this exact request, context, category and revision. The
// authenticated transaction rechecks every selector and commits the read intent
// before returning any field. A granted target expires with the session idle
// deadline and is never renewed by the extension.
func (s *Session) PrepareBrowserProfileFill(t BrowserProfileTarget) (*NativeBrowserProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.valid() {
		return nil, ErrBrowserProfileFill
	}
	if e := s.active(false); e != nil {
		return nil, e
	}
	s.pruneBrowserProfiles(time.Now())
	if len(s.profilePending) >= maxBrowserProfilePending {
		return nil, ErrBrowserProfileFill
	}
	r, e := s.execute(browserProfileFillAction, vault.Item{}, &Edit{ID: t.ID, Revision: t.Revision}, commandOption{browserProfile: &t})
	if e != nil {
		r.browserProfile.clear()
		return nil, e
	}
	until := time.Now().Add(browserProfileTTL)
	if idle := s.last.Add(s.idle); idle.Before(until) {
		until = idle
	}
	r.browserProfile.until = until
	if s.profilePending == nil {
		s.profilePending = make(map[*NativeBrowserProfile]bool)
	}
	s.profilePending[r.browserProfile] = true
	return r.browserProfile, nil
}

// ConsumeBrowserProfileFill runs one bounded native writer callback exactly
// once. The caller must own the serializer and recheck cancellation before
// calling, and must not re-read the vault.
func (s *Session) ConsumeBrowserProfileFill(p *NativeBrowserProfile, deliver func(*BrowserProfileContent) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	if p == nil || p.content == nil || deliver == nil || !s.profilePending[p] {
		return ErrBrowserProfileFill
	}
	// An expired grant of this session is deleted and cleared so it no longer
	// occupies a bounded pending slot. It is never deliverable.
	if !time.Now().Before(p.until) {
		delete(s.profilePending, p)
		p.clear()
		return ErrBrowserProfileFill
	}
	delete(s.profilePending, p)
	defer p.clear()
	if e := deliver(p.content); e != nil {
		return ErrBrowserProfileFill
	}
	return nil
}

// DiscardBrowserProfileFill drops a grant that was never consumed. Only this
// session's own registry member is cleared: a grant minted by a different
// session is a no-op, so one session can never wipe another's pending target.
func (s *Session) DiscardBrowserProfileFill(p *NativeBrowserProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p != nil && s.profilePending[p] {
		delete(s.profilePending, p)
		p.clear()
	}
}
