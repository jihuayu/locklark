package browserhost

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

type profileFlow struct {
	t    *testing.T
	c    *Connection
	out  *memoryPipe
	s    *personal.Session
	cap  string
	next int
	id   string
	rev  string
}

func profileGate(t *testing.T, s *personal.Session) *personal.MutationGate {
	t.Helper()
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(g); e != nil {
		t.Fatal(e)
	}
	return g
}

func newProfileFixture(t *testing.T, quick bool) (*profileFlow, *personal.Session, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.ll")
	key := bytes.Repeat([]byte{8}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, 2*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	// A real durable login proves quick mode itself is active, so the profile
	// assertions below cannot pass merely because pairing was not quick.
	loginID, e := s.AddLogin("Owner Login", "owner", "owner-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.Edit(personal.Edit{ID: loginID, Revision: rows[0].Revision, Field: "url", Value: "https://shop.example.test/login"}); e != nil {
		t.Fatal(e)
	}
	cardID, _, e := s.AddItem(vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Owner Card", CreditCard: &vault.CreditCardDetails{
		CardholderName: "Card Holder", Type: "visa", Number: "4242424242424242", Verification: "123", ExpiryDate: "2028-12", PIN: "4321",
	}}, profileGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	identID, _, e := s.AddItem(vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Owner Identity", Identity: &vault.IdentityDetails{
		FirstName: "Alice", LastName: "Smith", Email: "alice@example.test", Phone: "+1 555 0101",
		AddressLine1: "1 Main St", City: "Springfield", State: "CA", PostalCode: "90210", Country: "US",
		BirthDate: "1990-01-02", SSN: "123-45-6789", PassportNumber: "P-999888", LicenseNumber: "D-777666",
	}}, profileGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e := c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if quick {
		e = c.ApproveQuickPair(s)
	} else {
		e = c.ApprovePair(s)
	}
	if e != nil {
		t.Fatal(e)
	}
	cap := out.responses(t)[0].Capability
	return &profileFlow{t: t, c: c, out: out, s: s, cap: cap, id: "https://shop.example.test", next: 5000}, s, cardID, identID
}

func (f *profileFlow) nextID() string {
	f.next++
	return reqID(f.next)
}

func (f *profileFlow) match(tab int64, doc, kind string) []BrowserProfileSummary {
	f.t.Helper()
	r := v2Handle(f.t, f.c, f.out, map[string]any{
		"v": 1, "id": f.nextID(), "type": "match-profiles", "capability": f.cap,
		"origin": f.id, "tab_id": tab, "document_id": doc, "profile_kind": kind,
	})
	if r.Type != "profiles" {
		f.t.Fatalf("match-profiles: %#v", r)
	}
	return r.Profiles
}

func (f *profileFlow) reserve(tab int64, doc, itemID, revision string) string {
	f.t.Helper()
	id := f.nextID()
	before := len(f.out.responses(f.t))
	v2Send(f.t, f.c, map[string]any{
		"v": 1, "id": id, "type": "fill-profile", "capability": f.cap,
		"origin": f.id, "tab_id": tab, "document_id": doc, "item_id": itemID, "revision": revision,
	})
	if got := len(f.out.responses(f.t)); got != before {
		f.t.Fatalf("fill-profile wrote a response before native approval: %d -> %d", before, got)
	}
	view := f.c.Snapshot()
	if view.Profile == nil || view.Profile.ID != id || view.Profile.ItemID != itemID || view.Profile.Revision != revision || view.Profile.Origin != f.id {
		f.t.Fatalf("public profile review: %#v", view.Profile)
	}
	return id
}

func profileSummary(t *testing.T, profiles []BrowserProfileSummary, category string) BrowserProfileSummary {
	t.Helper()
	for _, p := range profiles {
		if p.Category == category {
			return p
		}
	}
	t.Fatalf("missing %s profile in %#v", category, profiles)
	return BrowserProfileSummary{}
}

func profileRaw(out *memoryPipe) []byte {
	out.Lock()
	defer out.Unlock()
	return bytes.Clone(out.Buffer.Bytes())
}

func profileResponsesOfType(out *memoryPipe, t *testing.T, kind string) int {
	count := 0
	for _, r := range out.responses(t) {
		if r.Type == kind {
			count++
		}
	}
	return count
}

func waitProfileResponse(t *testing.T, out *memoryPipe, id, kind string) Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range out.responses(t) {
			if r.ID == id && (kind == "" || r.Type == kind) {
				return r
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no %q response for %s", kind, id)
	return Response{}
}

func TestFillProfileNeverDeliversBeforeNativeApproval(t *testing.T) {
	f, s, cardID, identityID := newProfileFixture(t, false)
	profiles := f.match(7, "doc-9", "all")
	card := profileSummary(t, profiles, "credit_card")
	requestID := f.reserve(7, "doc-9", card.ID, card.Revision)
	view := f.c.Snapshot()
	if view.Profile.Title != card.Title || view.Profile.Category != "credit_card" || view.Profile.Deadline.IsZero() {
		t.Fatalf("profile review selectors: %#v", view.Profile)
	}
	// At most one profile reservation, and no other vault operation may run in
	// parallel with the pending owner review.
	if got := v2Handle(t, f.c, f.out, map[string]any{"v": 1, "id": f.nextID(), "type": "generate", "capability": f.cap, "mode": "random", "length": 16}); got.Type != "error" || got.Error != "refused" {
		t.Fatalf("generate ran while profile review pending: %#v", got)
	}
	if got := v2Handle(t, f.c, f.out, map[string]any{"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap, "origin": f.id, "tab_id": 7, "document_id": "doc-9", "item_id": card.ID, "revision": card.Revision}); got.Type != "error" {
		t.Fatalf("second profile reservation accepted: %#v", got)
	}
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("private profile frame before native approval")
	}
	if e := f.c.ApproveProfile(requestID); e != nil {
		t.Fatal(e)
	}
	fill := waitProfileResponse(t, f.out, requestID, "profile-fill")
	if fill.ProfileFill == nil || fill.ProfileFill.Category != "credit_card" || fill.ProfileFill.ItemID != card.ID || fill.ProfileFill.Revision != card.Revision {
		t.Fatalf("approved card fill: %#v", fill.ProfileFill)
	}
	for _, key := range []string{"cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-exp-year-short", "cc-csc", "cc-type"} {
		if fill.ProfileFill.Fields[key] == "" {
			t.Fatalf("approved card field %q missing: %#v", key, fill.ProfileFill.Fields)
		}
	}
	if fill.ProfileFill.Fields["cc-exp-month"] != "12" || fill.ProfileFill.Fields["cc-exp-year-short"] != "28" {
		t.Fatalf("card expiry mapping: %#v", fill.ProfileFill.Fields)
	}
	if fill.ProfileFill.CreditCard == nil || fill.ProfileFill.CreditCard.PIN != "" || fill.ProfileFill.CreditCard.Number != "4242424242424242" {
		t.Fatalf("structured card fill: %#v", fill.ProfileFill.CreditCard)
	}
	raw := profileRaw(f.out)
	if bytes.Contains(raw, []byte("4321")) || bytes.Contains(raw, []byte(`"pin"`)) {
		t.Fatal("approved card response exposed the card PIN")
	}
	// The audited intent must exist for the exact item, before the writer grant
	// emitted the private projection.
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	intent := 0
	for _, ev := range events {
		if ev.Action == "item.browser.profile.fill" && ev.Result == "intent" && ev.Item == cardID {
			intent++
		}
	}
	if intent != 1 {
		t.Fatalf("profile intent events for card = %d", intent)
	}
	// The grant is one use: a second native approval cannot replay it.
	before := len(f.out.responses(t))
	if e := f.c.ApproveProfile(requestID); e == nil {
		t.Fatal("replayed approval accepted")
	}
	if got := len(f.out.responses(t)); got != before {
		t.Fatal("replayed approval wrote a response")
	}
	// Identity fields are approved separately and only through the same button.
	_ = identityID
}

func TestFillProfileRejectAndStaleRevisionRefuse(t *testing.T) {
	f, _, cardID, _ := newProfileFixture(t, false)
	profiles := f.match(8, "doc-10", "credit_card")
	card := profileSummary(t, profiles, "credit_card")
	requestID := f.reserve(8, "doc-10", card.ID, card.Revision)
	if e := f.c.RejectProfile(requestID); e != nil {
		t.Fatal(e)
	}
	refused := waitProfileResponse(t, f.out, requestID, "error")
	if refused.Error != "refused" || f.c.Snapshot().Profile != nil {
		t.Fatalf("reject: %#v profile=%#v", refused, f.c.Snapshot().Profile)
	}
	if e := f.c.ApproveProfile(requestID); e == nil {
		t.Fatal("approval after reject accepted")
	}
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("rejected request still disclosed fields")
	}
	// A stale revision is refused at reservation: the durable revision moved
	// after the public profile list was produced.
	if moved, e := f.s.SetFavorite(cardID, card.Revision, true, profileGate(t, f.s)); e != nil || moved == card.Revision {
		t.Fatalf("fixture revision did not move: %q %v", moved, e)
	}
	before := len(f.out.responses(t))
	v2Send(t, f.c, map[string]any{"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap, "origin": f.id, "tab_id": 8, "document_id": "doc-10", "item_id": cardID, "revision": card.Revision})
	if got := f.out.responses(t); len(got) == before || got[len(got)-1].Type != "error" {
		t.Fatalf("stale revision accepted: %#v", got)
	}
	if f.c.Snapshot().Profile != nil {
		t.Fatal("stale revision left a pending profile")
	}
}

func TestFillProfileQuickModeCannotBypass(t *testing.T) {
	f, _, _, _ := newProfileFixture(t, true)
	if !f.c.Snapshot().QuickFill {
		t.Fatal("fixture is not in quick mode")
	}
	// Prove quick mode really auto-approves the ordinary login path.
	rows := v2Handle(t, f.c, f.out, map[string]any{"v": 1, "id": f.nextID(), "type": "match", "capability": f.cap, "origin": f.id, "tab_id": 9, "document_id": "doc-11"})
	if rows.Type != "candidates" || len(rows.Candidates) != 1 {
		t.Fatalf("quick login match: %#v", rows)
	}
	loginID := f.nextID()
	v2Send(t, f.c, map[string]any{"v": 1, "id": loginID, "type": "fill", "capability": f.cap, "origin": f.id, "tab_id": 9, "document_id": "doc-11", "item_id": rows.Candidates[0].ID, "revision": rows.Candidates[0].Revision})
	login := waitProfileResponse(t, f.out, loginID, "fill")
	if login.Type != "fill" || login.Password != "owner-password" {
		t.Fatalf("quick login fill: %#v", login)
	}
	profiles := f.match(9, "doc-11", "credit_card")
	card := profileSummary(t, profiles, "credit_card")
	requestID := f.reserve(9, "doc-11", card.ID, card.Revision)
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("quick mode bypassed native profile approval")
	}
	if e := f.c.ApproveProfile(requestID); e != nil {
		t.Fatal(e)
	}
	fill := waitProfileResponse(t, f.out, requestID, "profile-fill")
	if fill.ProfileFill == nil || fill.ProfileFill.CreditCard == nil || fill.ProfileFill.CreditCard.Number != "4242424242424242" {
		t.Fatalf("approved quick profile fill: %#v", fill.ProfileFill)
	}
}

func TestFillProfileExpiryLockAndCancelClearPending(t *testing.T) {
	// Expiry: the reservation must refuse at its deadline and never disclose.
	f, _, _, _ := newProfileFixture(t, false)
	profiles := f.match(10, "doc-12", "credit_card")
	card := profileSummary(t, profiles, "credit_card")
	var offset atomic.Int64
	base := time.Now()
	f.c.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
	requestID := f.reserve(10, "doc-12", card.ID, card.Revision)
	offset.Add(int64(31 * time.Second))
	if f.c.Snapshot().Profile != nil {
		t.Fatal("expired profile review still pending")
	}
	refused := waitProfileResponse(t, f.out, requestID, "error")
	if refused.Error != "refused" {
		t.Fatalf("expiry refusal: %#v", refused)
	}
	if e := f.c.ApproveProfile(requestID); e == nil {
		t.Fatal("expired approval accepted")
	}
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("expired request disclosed fields")
	}

	// Lock: a native lock invalidates the reservation immediately.
	f2, _, _, _ := newProfileFixture(t, false)
	profiles = f2.match(11, "doc-13", "credit_card")
	card = profileSummary(t, profiles, "credit_card")
	requestID = f2.reserve(11, "doc-13", card.ID, card.Revision)
	f2.c.Invalidate()
	if f2.c.Snapshot().Profile != nil {
		t.Fatal("locked profile review still pending")
	}
	if e := f2.c.ApproveProfile(requestID); e == nil {
		t.Fatal("approval after lock accepted")
	}
	if profileResponsesOfType(f2.out, t, "profile-fill") != 0 {
		t.Fatal("locked request disclosed fields")
	}

	// Cancel: an authenticated browser cancel clears the reservation and emits
	// the fixed refusal, never a private frame.
	f3, _, _, _ := newProfileFixture(t, false)
	profiles = f3.match(12, "doc-14", "credit_card")
	card = profileSummary(t, profiles, "credit_card")
	requestID = f3.reserve(12, "doc-14", card.ID, card.Revision)
	if e := f3.c.Handle(Request{V: 1, ID: f3.nextID(), Type: "cancel", Capability: f3.cap}); e != nil {
		t.Fatal(e)
	}
	if f3.c.Snapshot().Profile != nil {
		t.Fatal("cancelled profile review still pending")
	}
	if got := waitProfileResponse(t, f3.out, requestID, "error"); got.Error != "refused" {
		t.Fatalf("cancel refusal: %#v", got)
	}
	if e := f3.c.ApproveProfile(requestID); e == nil {
		t.Fatal("approval after cancel accepted")
	}
	if profileResponsesOfType(f3.out, t, "profile-fill") != 0 {
		t.Fatal("cancelled request disclosed fields")
	}
}

func TestFillProfileQueuedWriterCancelAndLock(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		f, _, cardID, _ := newProfileFixture(t, false)
		profiles := f.match(13, "doc-15", "credit_card")
		card := profileSummary(t, profiles, "credit_card")
		requestID := f.reserve(13, "doc-15", card.ID, card.Revision)
		release, e := f.c.writer.acquire(time.Now().Add(5*time.Second), nil)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- f.c.ApproveProfile(requestID) }()
		if !waitForStack(t, "(*Connection).ApproveProfile", "(*Writer).acquire") {
			release()
			t.Fatal("approval did not reach writer acquisition")
		}
		// The authenticated intent must exist even while the payload is still
		// queued behind another writer.
		events, e := f.s.Audit()
		if e != nil {
			release()
			t.Fatal(e)
		}
		intent := 0
		for _, ev := range events {
			if ev.Action == "item.browser.profile.fill" && ev.Result == "intent" && ev.Item == cardID {
				intent++
			}
		}
		if intent != 1 {
			release()
			t.Fatalf("queued profile intent = %d", intent)
		}
		cancelled := make(chan error, 1)
		go func() {
			cancelled <- f.c.Handle(Request{V: 1, ID: f.nextID(), Type: "cancel", Capability: f.cap})
		}()
		if !waitForStack(t, "(*Connection).Handle", "sync.(*Mutex).Lock") {
			release()
			t.Fatal("cancel did not reach the vault mutex")
		}
		release()
		if e := <-done; e == nil {
			t.Fatal("queued approval succeeded after cancel")
		}
		if e := <-cancelled; e != nil {
			t.Fatal(e)
		}
		if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
			t.Fatal("queued cancel still wrote profile fields")
		}
	})
	t.Run("lock", func(t *testing.T) {
		f, _, _, _ := newProfileFixture(t, false)
		profiles := f.match(14, "doc-16", "credit_card")
		card := profileSummary(t, profiles, "credit_card")
		requestID := f.reserve(14, "doc-16", card.ID, card.Revision)
		release, e := f.c.writer.acquire(time.Now().Add(5*time.Second), nil)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- f.c.ApproveProfile(requestID) }()
		if !waitForStack(t, "(*Connection).ApproveProfile", "(*Writer).acquire") {
			release()
			t.Fatal("approval did not reach writer acquisition")
		}
		f.c.Invalidate()
		release()
		if e := <-done; e == nil {
			t.Fatal("queued approval succeeded after lock")
		}
		if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
			t.Fatal("queued lock still wrote profile fields")
		}
	})
}

func TestFillProfileIdentityWhitelist(t *testing.T) {
	f, _, _, identID := newProfileFixture(t, false)
	profiles := f.match(15, "doc-17", "identity")
	ident := profileSummary(t, profiles, "identity")
	requestID := f.reserve(15, "doc-17", ident.ID, ident.Revision)
	if e := f.c.ApproveProfile(requestID); e != nil {
		t.Fatal(e)
	}
	fill := waitProfileResponse(t, f.out, requestID, "profile-fill")
	if fill.ProfileFill == nil || fill.ProfileFill.Identity == nil || fill.ProfileFill.ItemID != identID {
		t.Fatalf("identity fill: %#v", fill.ProfileFill)
	}
	for _, key := range []string{"given-name", "family-name", "name", "email", "tel", "street-address", "address-level2", "postal-code", "country", "bday"} {
		if fill.ProfileFill.Fields[key] == "" {
			t.Fatalf("identity field %q missing: %#v", key, fill.ProfileFill.Fields)
		}
	}
	if fill.ProfileFill.Fields["given-name"] != "Alice" || fill.ProfileFill.Fields["family-name"] != "Smith" {
		t.Fatalf("identity mapping: %#v", fill.ProfileFill.Fields)
	}
	raw := profileRaw(f.out)
	for _, secret := range []string{"123-45-6789", "P-999888", "D-777666", "4321"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("identity response leaked private identifier %q", secret)
		}
	}
	rawLower := strings.ToLower(string(raw))
	for _, key := range []string{`"ssn"`, `"passport_number"`, `"license_number"`, `"pin"`} {
		if strings.Contains(rawLower, key) {
			t.Fatalf("identity response exposed private field %q", key)
		}
	}
	// A profile-fill response is public DTO only after approval; the audit log
	// itself must never carry a private value.
	events, e := f.s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	logged, _ := json.Marshal(events)
	for _, secret := range []string{"123-45-6789", "P-999888", "D-777666", "4242424242424242"} {
		if bytes.Contains(logged, []byte(secret)) {
			t.Fatalf("audit leaked private value %q", secret)
		}
	}
}
