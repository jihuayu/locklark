package browserhost

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

const clipboardCapability = "native-clipboard-lease-v1"

// maxClipboardLease bounds an uncommitted offer and the copy handshake.
const maxClipboardLease = 10 * time.Second

// maxClipboardClear is the largest configured clipboard cleanup interval the
// desktop settings allow. It is deliberately separate from the offer lease.
const maxClipboardClear = time.Hour

// clipboardState is immutable once installed on a connection. The callback is
// invoked once per broker connection, so one connection can never borrow the
// native manager or clear TTL of another. desktop is captured while setup is
// serialized so protocol admission never reads Connection.desktopShared.
type clipboardState struct {
	manager       *nativeclipboard.Manager
	fixedClearTTL time.Duration
	clearDuration func() time.Duration
	desktop       bool
}

// currentClearTTL resolves the settings getter at prepare time. A negative or
// oversize interval fails closed instead of silently disabling cleanup; zero
// means the user turned automatic clearing off.
func (s *clipboardState) currentClearTTL() (time.Duration, bool) {
	ttl := s.fixedClearTTL
	if s.clearDuration != nil {
		ttl = s.clearDuration()
	}
	if ttl < 0 || ttl > maxClipboardClear {
		return 0, false
	}
	return ttl, true
}

// clipboardGrant is the single uncommitted grant for one connection. It keeps
// only selectors and authority deadlines; the value is owned by Manager.
type clipboardGrant struct {
	ticket     string
	itemID     string
	revision   string
	field      string
	session    *personal.Session
	capability string
	until      time.Time
	clearUntil time.Time
	epoch      uint64
	generation uint64
	cancel     uint64
}

func isClipboardOperation(kind string) bool {
	switch kind {
	case "prepare-copy-field", "commit-copy-field", "cancel-copy-field":
		return true
	}
	return false
}

func clipboardTicketMatches(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// setClipboard installs the per-connection callback state. ttl is the fallback
// clear interval used when no live settings getter is wired. Zero disables
// automatic clearing; an invalid interval fails closed.
func (c *Connection) setClipboard(m *nativeclipboard.Manager, ttl time.Duration) {
	c.setClipboardWithDuration(m, ttl, nil)
}

func (c *Connection) setClipboardWithDuration(m *nativeclipboard.Manager, ttl time.Duration, current func() time.Duration) {
	if m == nil || ttl < 0 || ttl > maxClipboardClear || !nativeclipboard.NativeLeaseSupported() {
		c.clipboard.Store(nil)
		return
	}
	c.clipboard.Store(&clipboardState{manager: m, fixedClearTTL: ttl, clearDuration: current, desktop: c.desktopShared})
}

func (c *Connection) clipboardAuthSnapshot() (string, uint64, time.Time) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.authCapability, c.authEpoch, c.authUntil
}

// clipboardAuthority is deliberately non-blocking: neither Connection.mu nor
// the Manager lock may be taken here. Session.Unlocked uses TryLock; authMu is
// held only for the three-field snapshot.
func (c *Connection) clipboardAuthority(g *clipboardGrant) func() bool {
	return func() bool {
		if g == nil || g.session == nil || c.closed.Load() || c.session.Load() != g.session ||
			c.generation.Load() != g.generation || c.cancelEpoch.Load() != g.cancel {
			return false
		}
		now := c.now()
		if !now.Before(g.until) {
			return false
		}
		c.authMu.Lock()
		ok := c.authCapability == g.capability && c.authEpoch == g.epoch && now.Before(c.authUntil)
		c.authMu.Unlock()
		return ok && g.session.Unlocked()
	}
}

// clipboardGrantCurrent is the exact admission recheck performed while holding
// clipboardMu. It covers the auth window, session, start generation and start
// cancellation captured before the slow secret read.
func (c *Connection) clipboardGrantCurrent(g *clipboardGrant) bool {
	if g == nil || g.session == nil || c.closed.Load() || c.session.Load() != g.session ||
		c.generation.Load() != g.generation || c.cancelEpoch.Load() != g.cancel {
		return false
	}
	now := c.now()
	if !now.Before(g.until) {
		return false
	}
	c.authMu.Lock()
	ok := c.authCapability == g.capability && c.authEpoch == g.epoch && now.Before(c.authUntil)
	c.authMu.Unlock()
	return ok && g.session.Unlocked()
}

func (c *Connection) handleClipboard(r Request, allowed bool) error {
	state := c.clipboard.Load()
	if !allowed || state == nil || state.manager == nil || !state.desktop || c.closed.Load() {
		return c.refuse(r.ID)
	}
	capability, epoch, until := c.clipboardAuthSnapshot()
	if capability == "" || r.Capability != capability || epoch != c.generation.Load() || !c.now().Before(until) {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	switch r.Type {
	case "prepare-copy-field":
		return c.prepareCopyField(r, s, state, capability, epoch, until)
	case "commit-copy-field":
		return c.commitCopyField(r, s, state, capability, epoch, until)
	case "cancel-copy-field":
		return c.cancelCopyField(r, state)
	}
	return c.refuse(r.ID)
}

// clipboardDeadline is the earliest of the fixed protocol lease, the current
// auth window, the real native idle deadline and (for OTP) the absolute code
// expiry.
func (c *Connection) clipboardDeadline(s *personal.Session, authUntil, otpExpiry time.Time) time.Time {
	until := c.now().Add(maxClipboardLease)
	if authUntil.Before(until) {
		until = authUntil
	}
	if idle := s.AuthorityDeadline(); !idle.IsZero() && idle.Before(until) {
		until = idle
	}
	if !otpExpiry.IsZero() && otpExpiry.Before(until) {
		until = otpExpiry
	}
	return until
}

func (c *Connection) clipboardRemainingSeconds(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	remaining := t.Sub(c.now())
	if remaining <= 0 {
		return 0
	}
	return int((remaining + time.Second - 1) / time.Second)
}

func (c *Connection) prepareCopyField(r Request, s *personal.Session, state *clipboardState, capability string, epoch uint64, authUntil time.Time) error {
	ttl, ok := state.currentClearTTL()
	if !ok {
		return c.refuse(r.ID)
	}
	// Snapshot the exact admission authority before the slow secret read. The
	// continuation may not substitute a newer generation or cancel epoch.
	generation := c.generation.Load()
	cancel := c.cancelEpoch.Load()
	return c.withFieldValue(r, func(id, revision, value string, expires int, otpExpiry time.Time) error {
		now := c.now()
		until := c.clipboardDeadline(s, authUntil, otpExpiry)
		if r.Field == "otp" && (otpExpiry.IsZero() || !now.Before(otpExpiry)) || !now.Before(until) {
			return c.refuse(r.ID)
		}
		// The configured interval starts after resolution and audit, never
		// before the slow read.
		clearUntil := time.Time{}
		if ttl > 0 {
			clearUntil = now.Add(ttl)
		}
		if !otpExpiry.IsZero() && (clearUntil.IsZero() || otpExpiry.Before(clearUntil)) {
			clearUntil = otpExpiry
		}
		if !clearUntil.IsZero() && clearUntil.Before(until) {
			until = clearUntil
		}
		g := &clipboardGrant{
			itemID: id, revision: revision, field: r.Field, session: s,
			capability: capability, until: until, clearUntil: clearUntil,
			epoch: epoch, generation: generation, cancel: cancel,
		}
		raw := []byte(value)
		ticket, installed := c.prepareClipboardGrant(state, g, raw)
		clear(raw)
		if !installed {
			return c.refuse(r.ID)
		}
		return c.response(Response{ID: r.ID, Type: "copy-prepared", ItemID: id, Revision: revision,
			Field: r.Field, CopyTicket: ticket, CopyMode: "native",
			CleanupTTLSeconds: c.clipboardRemainingSeconds(clearUntil),
			ExpiresInSeconds:  c.clipboardRemainingSeconds(until)})
	})
}

// prepareClipboardGrant is the single admission boundary between the slow
// secret read and Manager.Prepare. Invalidate advances generation before it
// takes clipboardMu here, so a grant admitted from a stale continuation is
// either rejected by the recheck or revoked by the waiting invalidation.
func (c *Connection) prepareClipboardGrant(state *clipboardState, g *clipboardGrant, value []byte) (string, bool) {
	c.clipboardMu.Lock()
	defer c.clipboardMu.Unlock()
	if c.clipboardGrant != nil && !c.clipboardGrantCurrent(c.clipboardGrant) {
		stale := c.clipboardGrant
		c.clipboardGrant = nil
		if stale.ticket != "" {
			state.manager.CancelOffer(stale.ticket)
		}
	}
	if c.clipboardGrant != nil || c.clipboardTicket != "" || !c.clipboardGrantCurrent(g) {
		return "", false
	}
	ticket, err := state.manager.Prepare(value, g.until, g.clearUntil, c.clipboardAuthority(g))
	if err != nil || ticket == "" {
		return "", false
	}
	g.ticket = ticket
	c.clipboardGrant = g
	return ticket, true
}

func (c *Connection) clearActiveTicket(ticket string) {
	c.clipboardMu.Lock()
	if c.clipboardTicket == ticket {
		c.clipboardTicket = ""
	}
	c.clipboardMu.Unlock()
}

// commitCopyField consumes the prepared grant once, revalidates the exact
// authenticated item/revision, then lets Manager write. Handle never waits for
// the native outcome or UI while Connection.mu is held.
func (c *Connection) commitCopyField(r Request, s *personal.Session, state *clipboardState, capability string, epoch uint64, authUntil time.Time) error {
	c.clipboardMu.Lock()
	g := c.clipboardGrant
	if g == nil || c.clipboardTicket != "" || !clipboardTicketMatches(g.ticket, r.CopyTicket) {
		c.clipboardMu.Unlock()
		return c.refuse(r.ID)
	}
	c.clipboardGrant = nil
	c.clipboardTicket = g.ticket
	c.clipboardMu.Unlock()
	refuse := func() error {
		// The offer still holds the secret buffer; drop it immediately rather
		// than waiting for its deadline. A wrong ticket never reaches here and
		// therefore cannot cancel a newer grant.
		state.manager.CancelOffer(g.ticket)
		c.clearActiveTicket(g.ticket)
		return c.refuse(r.ID)
	}
	if g.session != s || !c.clipboardGrantCurrent(g) || !c.now().Before(authUntil) {
		return refuse()
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return refuse()
	}
	it, ok := c.findItem(items, g.itemID)
	if !ok || revisions[it.ID] != g.revision || it.State == "trashed" || !c.clipboardAuthority(g)() {
		return refuse()
	}
	done := state.manager.Commit(context.Background(), g.ticket)
	go func(ticket string) {
		outcome, ok := <-done
		c.clearActiveTicket(ticket)
		if !ok {
			outcome = nativeclipboard.Unknown
		}
		if c.closed.Load() {
			return
		}
		stateName := "unknown"
		copied := false
		switch outcome {
		case nativeclipboard.Confirmed:
			stateName, copied = "confirmed", true
		case nativeclipboard.Refused:
			stateName = "refused"
		}
		_ = c.response(Response{ID: r.ID, Type: "copy-result", CopyTicket: ticket,
			CopyMode: "native", Copied: copied, State: stateName})
	}(g.ticket)
	return nil
}

// cancelCopyField acts only on the exact ticket. CancelOffer never clears a
// confirmed native lease, so a late popup cancel cannot blank a value the user
// is about to paste.
func (c *Connection) cancelCopyField(r Request, state *clipboardState) error {
	c.clipboardMu.Lock()
	if g := c.clipboardGrant; g != nil && clipboardTicketMatches(g.ticket, r.CopyTicket) {
		c.clipboardGrant = nil
		c.clipboardMu.Unlock()
		state.manager.CancelOffer(g.ticket)
		return c.response(Response{ID: r.ID, Type: "copy-cancelled", CopyTicket: g.ticket, CopyMode: "native"})
	}
	if c.clipboardTicket != "" && clipboardTicketMatches(c.clipboardTicket, r.CopyTicket) {
		ticket := c.clipboardTicket
		c.clipboardMu.Unlock()
		state.manager.CancelOffer(ticket)
		return c.response(Response{ID: r.ID, Type: "copy-cancelled", CopyTicket: ticket, CopyMode: "native", State: "pending"})
	}
	c.clipboardMu.Unlock()
	return c.refuse(r.ID)
}

// cancelClipboardPending clears only uncommitted offers/jobs. A confirmed
// native lease survives a generic page cancellation; lock or close uses
// revokeClipboard instead.
func (c *Connection) cancelClipboardPending() {
	c.clipboardMu.Lock()
	g := c.clipboardGrant
	active := c.clipboardTicket
	c.clipboardGrant = nil
	c.clipboardMu.Unlock()
	state := c.clipboard.Load()
	if state == nil || state.manager == nil {
		return
	}
	if g != nil {
		state.manager.CancelOffer(g.ticket)
	}
	if active != "" && (g == nil || active != g.ticket) {
		state.manager.CancelOffer(active)
	}
}

// revokeClipboard is lease invalidation: Clear cancels pending buffers and
// clears only this connection's confirmed lease. Close additionally closes the
// manager so queued work writes nothing and an in-flight write reports Unknown.
func (c *Connection) revokeClipboard(closeManager bool) {
	state := c.clipboard.Load()
	c.clipboardMu.Lock()
	c.clipboardGrant = nil
	c.clipboardTicket = ""
	c.clipboardMu.Unlock()
	if state == nil || state.manager == nil {
		return
	}
	state.manager.Clear()
	if closeManager {
		state.manager.Close()
	}
}

// clipboardIdle refuses every selector or payload field that is not part of
// the exact clipboard operation. Wire decoding applies the same whitelist.
func clipboardIdle(r Request, selectors bool) bool {
	if r.Options != "" || r.Mode != "" || r.Title != "" || r.StageID != "" || r.NeverForOrigin ||
		r.Category != "" || r.IncludeHIBP || r.WindowID != 0 || r.RequestID != "" || r.Nonce != "" ||
		r.Origin != "" || r.TabID != 0 || r.DocumentID != "" || r.FieldAction != "" ||
		r.StateAction != "" || r.ItemJSON != "" || r.ProfileKind != "" || r.payload != nil ||
		r.FileName != "" || r.Size != nil || r.SHA256 != "" || r.MimeType != "" ||
		r.TransferID != "" || r.Offset != 0 || r.Data != "" || r.AttachmentID != "" ||
		r.CredentialID != "" || r.Length != 0 || r.Digits != nil || r.Symbols != nil ||
		r.SaveHistory != nil || r.Query != "" || r.VaultID != "" || r.Tag != "" ||
		r.StateFilter != "" || r.FavoritesOnly != nil || r.PasskeysOnly != nil {
		return false
	}
	if selectors {
		return true
	}
	return r.ItemID == "" && r.Revision == "" && r.Field == ""
}
