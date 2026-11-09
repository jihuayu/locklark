package browserhost

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	checkoutTopOrigin   = "https://shop.example.test"
	checkoutFrameOrigin = "https://pay.example.test"
	checkoutTopDoc      = "top-doc-1"
	checkoutFrameDoc    = "frame-doc-1"
)

func readRawRequest(t *testing.T, raw string) (Request, error) {
	t.Helper()
	return ReadRequest(bytes.NewReader(frame(raw)))
}

func checkoutRaw(kind, extra string) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"type":%q,"capability":%q,"origin":%q,"tab_id":7,"document_id":%q%s}`,
		reqID(1), kind, strings.Repeat("ab", 16), checkoutFrameOrigin, checkoutFrameDoc, extra)
}

// The wire contract for the nested assertion: exact keys, exact types, no
// duplicates, no aliases, no unknown fields, no null-as-permission, and only on
// the two profile operations with an explicit credit_card profile kind.
func TestCheckoutRequestContract(t *testing.T) {
	valid := map[string]any{"top_origin": checkoutTopOrigin, "top_document_id": checkoutTopDoc, "frame_id": float64(2)}
	accept := []struct {
		name string
		raw  string
	}{
		{"match-profiles", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"fill-profile", checkoutRaw("fill-profile", fmt.Sprintf(`,"profile_kind":"credit_card","item_id":%q,"revision":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))},
	}
	for _, tc := range accept {
		r, e := readRawRequest(t, tc.raw)
		if e != nil {
			t.Fatalf("%s: valid checkout proposal refused: %v", tc.name, e)
		}
		if r.Checkout == nil || r.Checkout.TopOrigin != checkoutTopOrigin || r.Checkout.TopDocumentID != checkoutTopDoc || r.Checkout.FrameID != 2 {
			t.Fatalf("%s: parsed checkout = %#v", tc.name, r.Checkout)
		}
	}
	_ = valid
	refuse := []struct {
		name string
		raw  string
	}{
		{"duplicate checkout key", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2},"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"case alias key", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","Checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"unknown nested key", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2,"extra":1}`)},
		{"nested duplicate", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_origin":"https://evil.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"nested case alias", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"Top_Origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"nested missing frame id", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1"}`)},
		{"nested null value", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":null,"top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout null", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":null`)},
		{"checkout array", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":[]`)},
		{"frame id string", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":"2"}`)},
		{"frame id fraction", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":1.5}`)},
		{"top origin number", checkoutRaw("match-profiles", `,"profile_kind":"credit_card","checkout":{"top_origin":7,"top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout without credit_card kind", checkoutRaw("match-profiles", `,"profile_kind":"all","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout without kind", checkoutRaw("match-profiles", `,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout on login match", checkoutRaw("match", `,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout on login fill", checkoutRaw("fill", fmt.Sprintf(`,"item_id":%q,"revision":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))},
		{"checkout on item-get", checkoutRaw("item-get", fmt.Sprintf(`,"item_id":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16)))},
		{"checkout on passkey-get", checkoutRaw("passkey-get", `,"options":"{}","checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`)},
		{"checkout on otp", checkoutRaw("otp", fmt.Sprintf(`,"window_id":3,"item_id":%q,"revision":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))},
		{"checkout on identity fill", checkoutRaw("fill-profile", fmt.Sprintf(`,"profile_kind":"identity","item_id":%q,"revision":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))},
	}
	for _, tc := range refuse {
		if r, e := readRawRequest(t, tc.raw); e == nil {
			t.Fatalf("%s: unsafe checkout proposal accepted: %#v", tc.name, r.Checkout)
		}
	}
}

func checkoutMatch(t *testing.T, f *profileFlow, kind string) Response {
	t.Helper()
	return v2Handle(t, f.c, f.out, map[string]any{
		"v": 1, "id": f.nextID(), "type": "match-profiles", "capability": f.cap,
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc, "profile_kind": kind,
		"checkout": map[string]any{"top_origin": checkoutTopOrigin, "top_document_id": checkoutTopDoc, "frame_id": 2},
	})
}

func checkoutFill(t *testing.T, f *profileFlow, itemID, revision string, checkout map[string]any) string {
	t.Helper()
	id := f.nextID()
	value := map[string]any{
		"v": 1, "id": id, "type": "fill-profile", "capability": f.cap, "profile_kind": "credit_card",
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc,
		"item_id": itemID, "revision": revision,
	}
	if checkout != nil {
		value["checkout"] = checkout
	}
	before := len(f.out.responses(t))
	v2Send(t, f.c, value)
	if got := len(f.out.responses(t)); got != before {
		t.Fatalf("fill-profile wrote a response before native approval: %d -> %d", before, got)
	}
	return id
}

func defaultCheckout() map[string]any {
	return map[string]any{"top_origin": checkoutTopOrigin, "top_document_id": checkoutTopDoc, "frame_id": 2}
}

func TestCheckoutCardsOnlyAndNativeApproval(t *testing.T) {
	f, s, cardID, _ := newProfileFixture(t, false)
	resp := checkoutMatch(t, f, "credit_card")
	if resp.Type != "profiles" {
		t.Fatalf("checkout listing: %#v", resp)
	}
	for _, p := range resp.Profiles {
		if p.Category != "credit_card" {
			t.Fatalf("checkout listing leaked a non-card profile: %#v", p)
		}
	}
	card := profileSummary(t, resp.Profiles, "credit_card")
	requestID := checkoutFill(t, f, card.ID, card.Revision, defaultCheckout())
	view := f.c.Snapshot()
	if view.Profile == nil || !view.Profile.Checkout {
		t.Fatalf("checkout review not rendered: %#v", view.Profile)
	}
	if view.Profile.TopOrigin != checkoutTopOrigin || view.Profile.FrameOrigin != checkoutFrameOrigin ||
		view.Profile.TopDocumentID != checkoutTopDoc || view.Profile.FrameDocumentID != checkoutFrameDoc || view.Profile.FrameID != 2 {
		t.Fatalf("review must show both origins and both documents: %#v", view.Profile)
	}
	if view.Profile.Category != "credit_card" || view.Profile.Origin != checkoutFrameOrigin {
		t.Fatalf("review selectors: %#v", view.Profile)
	}
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("checkout review delivered private fields before native approval")
	}
	if e := f.c.ApproveProfile(requestID); e != nil {
		t.Fatal(e)
	}
	fill := waitProfileResponse(t, f.out, requestID, "profile-fill")
	if fill.ProfileFill == nil || fill.ProfileFill.CreditCard == nil ||
		fill.ProfileFill.CreditCard.Number != "4242424242424242" || fill.ProfileFill.Fields["cc-number"] != "4242424242424242" {
		t.Fatalf("approved checkout fill: %#v", fill.ProfileFill)
	}
	if fill.ProfileFill.ItemID != card.ID || fill.ProfileFill.Revision != card.Revision || fill.ProfileFill.Category != "credit_card" {
		t.Fatalf("approved checkout selectors: %#v", fill.ProfileFill)
	}
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
		t.Fatalf("checkout intent events = %d", intent)
	}
	// The reservation is single use: the same checkout cannot fill again until
	// a fresh native card listing.
	before := len(f.out.responses(t))
	v2Send(t, f.c, map[string]any{
		"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap, "profile_kind": "credit_card",
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc,
		"item_id": card.ID, "revision": card.Revision, "checkout": defaultCheckout(),
	})
	got := f.out.responses(t)
	if len(got) == before || got[len(got)-1].Type != "error" {
		t.Fatalf("replayed checkout fill accepted: %#v", got)
	}
}

func TestCheckoutRefusesChangedSelectors(t *testing.T) {
	f, _, cardID, identityID := newProfileFixture(t, false)
	resp := checkoutMatch(t, f, "credit_card")
	card := profileSummary(t, resp.Profiles, "credit_card")
	cases := []struct {
		name     string
		itemID   string
		revision string
		checkout map[string]any
	}{
		{"changed top document", card.ID, card.Revision, map[string]any{"top_origin": checkoutTopOrigin, "top_document_id": "top-doc-2", "frame_id": 2}},
		{"changed frame id", card.ID, card.Revision, map[string]any{"top_origin": checkoutTopOrigin, "top_document_id": checkoutTopDoc, "frame_id": 3}},
		{"changed top origin", card.ID, card.Revision, map[string]any{"top_origin": "https://evil.test", "top_document_id": checkoutTopDoc, "frame_id": 2}},
		{"stale revision", card.ID, strings.Repeat("ef", 32), defaultCheckout()},
		{"identity item", identityID, card.Revision, defaultCheckout()},
	}
	for _, tc := range cases {
		before := len(f.out.responses(t))
		value := map[string]any{
			"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap, "profile_kind": "credit_card",
			"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc,
			"item_id": tc.itemID, "revision": tc.revision,
		}
		if tc.checkout != nil {
			value["checkout"] = tc.checkout
		}
		v2Send(t, f.c, value)
		got := f.out.responses(t)
		if len(got) == before || got[len(got)-1].Type != "error" {
			t.Fatalf("%s: accepted: %#v", tc.name, got)
		}
		if f.c.Snapshot().Profile != nil {
			t.Fatalf("%s: left a pending review", tc.name)
		}
	}
	// A plain fill that drops the checkout assertion is refused too.
	beforePlain := len(f.out.responses(t))
	v2Send(t, f.c, map[string]any{
		"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap,
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc,
		"item_id": card.ID, "revision": card.Revision,
	})
	if got := f.out.responses(t); len(got) == beforePlain || got[len(got)-1].Type != "error" {
		t.Fatalf("fill without the checkout assertion accepted: %#v", got)
	}
	// A changed frame document is refused by the ordinary context compare.
	before := len(f.out.responses(t))
	v2Send(t, f.c, map[string]any{
		"v": 1, "id": f.nextID(), "type": "fill-profile", "capability": f.cap, "profile_kind": "credit_card",
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": "frame-doc-2",
		"item_id": card.ID, "revision": card.Revision, "checkout": defaultCheckout(),
	})
	got := f.out.responses(t)
	if len(got) == before || got[len(got)-1].Type != "error" || f.c.Snapshot().Profile != nil {
		t.Fatalf("changed frame document accepted: %#v", got)
	}
	_ = cardID
}

func TestCheckoutRefusedBeforeMetadata(t *testing.T) {
	f, _, _, _ := newProfileFixture(t, false)
	for _, proposal := range []map[string]any{
		{"top_origin": "https://evil.test", "top_document_id": checkoutTopDoc, "frame_id": 2},
		{"top_origin": "http://shop.example.test", "top_document_id": checkoutTopDoc, "frame_id": 2},
		{"top_origin": "null", "top_document_id": checkoutTopDoc, "frame_id": 2},
		{"top_origin": checkoutFrameOrigin, "top_document_id": checkoutTopDoc, "frame_id": 2},
		{"top_origin": checkoutTopOrigin, "top_document_id": checkoutFrameDoc, "frame_id": 2},
		{"top_origin": checkoutTopOrigin, "top_document_id": checkoutTopDoc, "frame_id": 0},
		{"top_origin": "https://alice.github.io", "top_document_id": checkoutTopDoc, "frame_id": 2},
	} {
		resp := v2Handle(t, f.c, f.out, map[string]any{
			"v": 1, "id": f.nextID(), "type": "match-profiles", "capability": f.cap,
			"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc, "profile_kind": "credit_card",
			"checkout": proposal,
		})
		if resp.Type != "error" || profileResponsesOfType(f.out, t, "profiles") != 0 {
			t.Fatalf("unsafe checkout reached profile metadata: %#v proposal=%#v", resp, proposal)
		}
	}
	// Another tenant of the same private suffix is a different site.
	github := v2Handle(t, f.c, f.out, map[string]any{
		"v": 1, "id": f.nextID(), "type": "match-profiles", "capability": f.cap,
		"origin": "https://bob.github.io", "tab_id": 7, "document_id": checkoutFrameDoc, "profile_kind": "credit_card",
		"checkout": map[string]any{"top_origin": "https://alice.github.io", "top_document_id": checkoutTopDoc, "frame_id": 2},
	})
	if github.Type != "error" {
		t.Fatalf("private-suffix cross-tenant checkout accepted: %#v", github)
	}
	// The refused proposals left no wedged state: a same-site listing still works.
	resp := checkoutMatch(t, f, "credit_card")
	if resp.Type != "profiles" {
		t.Fatalf("same-site listing after refusals: %#v", resp)
	}
	profileSummary(t, resp.Profiles, "credit_card")
}

func TestCheckoutQuickModeStillNeedsNativeApproval(t *testing.T) {
	f, _, _, _ := newProfileFixture(t, true)
	if !f.c.Snapshot().QuickFill {
		t.Fatal("fixture is not in quick mode")
	}
	rows := v2Handle(t, f.c, f.out, map[string]any{"v": 1, "id": f.nextID(), "type": "match", "capability": f.cap, "origin": f.id, "tab_id": 9, "document_id": "login-doc"})
	if rows.Type != "candidates" || len(rows.Candidates) == 0 {
		t.Fatalf("quick login match: %#v", rows)
	}
	loginID := f.nextID()
	v2Send(t, f.c, map[string]any{"v": 1, "id": loginID, "type": "fill", "capability": f.cap, "origin": f.id, "tab_id": 9, "document_id": "login-doc", "item_id": rows.Candidates[0].ID, "revision": rows.Candidates[0].Revision})
	if login := waitProfileResponse(t, f.out, loginID, "fill"); login.Type != "fill" {
		t.Fatalf("quick login fill: %#v", login)
	}
	resp := checkoutMatch(t, f, "credit_card")
	card := profileSummary(t, resp.Profiles, "credit_card")
	requestID := checkoutFill(t, f, card.ID, card.Revision, defaultCheckout())
	if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
		t.Fatal("quick mode bypassed the checkout approval")
	}
	if e := f.c.ApproveProfile(requestID); e != nil {
		t.Fatal(e)
	}
	if fill := waitProfileResponse(t, f.out, requestID, "profile-fill"); fill.ProfileFill == nil {
		t.Fatalf("approved checkout fill: %#v", fill)
	}
}

func TestCheckoutLockCancelAndExpiryPreventSecret(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		f, _, _, _ := newProfileFixture(t, false)
		card := profileSummary(t, checkoutMatch(t, f, "credit_card").Profiles, "credit_card")
		requestID := checkoutFill(t, f, card.ID, card.Revision, defaultCheckout())
		f.c.Invalidate()
		if f.c.Snapshot().Profile != nil {
			t.Fatal("lock left the checkout review pending")
		}
		if e := f.c.ApproveProfile(requestID); e == nil {
			t.Fatal("approval after lock accepted")
		}
		if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
			t.Fatal("locked checkout delivered private fields")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		f, _, _, _ := newProfileFixture(t, false)
		card := profileSummary(t, checkoutMatch(t, f, "credit_card").Profiles, "credit_card")
		requestID := checkoutFill(t, f, card.ID, card.Revision, defaultCheckout())
		v2Send(t, f.c, map[string]any{"v": 1, "id": f.nextID(), "type": "cancel", "capability": f.cap})
		if f.c.Snapshot().Profile != nil {
			t.Fatal("cancel left the checkout review pending")
		}
		if e := f.c.ApproveProfile(requestID); e == nil {
			t.Fatal("approval after cancel accepted")
		}
		if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
			t.Fatal("cancelled checkout delivered private fields")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		f, _, _, _ := newProfileFixture(t, false)
		card := profileSummary(t, checkoutMatch(t, f, "credit_card").Profiles, "credit_card")
		requestID := checkoutFill(t, f, card.ID, card.Revision, defaultCheckout())
		f.c.mu.Lock()
		if f.c.profile != nil {
			f.c.profile.deadline = time.Now().Add(-time.Second)
		}
		f.c.mu.Unlock()
		if e := f.c.ApproveProfile(requestID); e == nil {
			t.Fatal("approval after expiry accepted")
		}
		if profileResponsesOfType(f.out, t, "profile-fill") != 0 {
			t.Fatal("expired checkout delivered private fields")
		}
	})
}
