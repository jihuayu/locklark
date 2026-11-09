package browserhost

import (
	"fmt"
	"strings"
	"testing"
)

// The allowlisted extension advertises the observed checkout context on both
// profile operations, but it only repeats profile_kind on the listing. The fill
// therefore arrives as `{capability, origin, tab_id, document_id, item_id,
// revision, checkout}` with no profile_kind at all. Native must accept exactly
// that shape: the card-only rule is enforced by the pinned checkout reservation
// plus the pinned item category, never by the client repeating the kind.
func extensionCheckoutFillRaw() string {
	return checkoutRaw("fill-profile", fmt.Sprintf(`,"item_id":%q,"revision":%q,"checkout":{"top_origin":%q,"top_document_id":%q,"frame_id":2}`,
		strings.Repeat("cd", 16), strings.Repeat("ef", 32), checkoutTopOrigin, checkoutTopDoc))
}

func TestCheckoutFillWithoutProfileKindIsAccepted(t *testing.T) {
	r, e := readRawRequest(t, extensionCheckoutFillRaw())
	if e != nil {
		t.Fatalf("extension-shaped checkout fill refused on the wire: %v", e)
	}
	if r.ProfileKind != "" {
		t.Fatalf("parsed profile kind = %q, want empty", r.ProfileKind)
	}
	if r.Checkout == nil || r.Checkout.TopOrigin != checkoutTopOrigin || r.Checkout.TopDocumentID != checkoutTopDoc || r.Checkout.FrameID != 2 {
		t.Fatalf("parsed checkout = %#v", r.Checkout)
	}
	// A checkout fill that does declare a non-card kind stays refused.
	if got, e := readRawRequest(t, checkoutRaw("fill-profile", fmt.Sprintf(`,"profile_kind":"identity","item_id":%q,"revision":%q,"checkout":{"top_origin":"https://shop.example.test","top_document_id":"top-doc-1","frame_id":2}`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))); e == nil {
		t.Fatalf("identity checkout fill accepted: %#v", got.Checkout)
	}
	// So does a plain (non-checkout) fill that invents a profile kind.
	if got, e := readRawRequest(t, checkoutRaw("fill-profile", fmt.Sprintf(`,"profile_kind":"credit_card","item_id":%q,"revision":%q`, strings.Repeat("cd", 16), strings.Repeat("ef", 32)))); e == nil {
		t.Fatalf("checkout-less fill with profile kind accepted: %#v", got)
	}
}

// The whole native path must work end to end for the extension's real shape:
// listing, pinned reservation, native approval and the granted card delivery.
func TestCheckoutFillFlowMatchesExtensionWire(t *testing.T) {
	f, _, cardID, _ := newProfileFixture(t, false)
	resp := checkoutMatch(t, f, "credit_card")
	card := profileSummary(t, resp.Profiles, "credit_card")
	if card.ID != cardID {
		t.Fatalf("card selector = %#v", card)
	}
	id := f.nextID()
	before := len(f.out.responses(t))
	v2Send(t, f.c, map[string]any{
		"v": 1, "id": id, "type": "fill-profile", "capability": f.cap,
		"origin": checkoutFrameOrigin, "tab_id": 7, "document_id": checkoutFrameDoc,
		"item_id": card.ID, "revision": card.Revision, "checkout": defaultCheckout(),
	})
	if got := len(f.out.responses(t)); got != before {
		t.Fatalf("extension-shaped checkout fill answered before native approval: %#v", f.out.responses(t)[got-1])
	}
	view := f.c.Snapshot()
	if view.Profile == nil || !view.Profile.Checkout || view.Profile.Category != "credit_card" {
		t.Fatalf("native review not reserved: %#v", view.Profile)
	}
	if view.Profile.TopOrigin != checkoutTopOrigin || view.Profile.FrameOrigin != checkoutFrameOrigin {
		t.Fatalf("review must show both origins: %#v", view.Profile)
	}
	if e := f.c.ApproveProfile(id); e != nil {
		t.Fatalf("native approval of the extension-shaped checkout fill: %v", e)
	}
	fill := waitProfileResponse(t, f.out, id, "profile-fill")
	if fill.ProfileFill == nil || fill.ProfileFill.CreditCard == nil || fill.ProfileFill.CreditCard.Number != "4242424242424242" {
		t.Fatalf("approved card delivery: %#v", fill.ProfileFill)
	}
	if fill.ProfileFill.Category != "credit_card" || fill.ProfileFill.ItemID != card.ID || fill.ProfileFill.Revision != card.Revision {
		t.Fatalf("delivered selectors: %#v", fill.ProfileFill)
	}
	if fill.ProfileFill.CreditCard.PIN != "" || fill.ProfileFill.Fields["cc-pin"] != "" {
		t.Fatal("checkout fill delivered a card PIN")
	}
}
