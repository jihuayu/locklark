package personal

import (
	"strings"
	"testing"
)

func frameContext(origin, document string) BrowserContext {
	return BrowserContext{RequestID: strings.Repeat("ab", 16), Origin: origin, TabID: 7, DocumentID: document}
}

func TestBrowserCheckoutContextSameSitePolicy(t *testing.T) {
	frame := frameContext("https://pay.example.com", "frame-doc")
	allowed := []struct {
		name     string
		checkout BrowserCheckoutContext
	}{
		{"sibling subdomains", BrowserCheckoutContext{"https://shop.example.com", "top-doc", 1}},
		{"root and subdomain", BrowserCheckoutContext{"https://example.com", "top-doc", 42}},
		{"schemeful port", BrowserCheckoutContext{"https://example.com:8443", "top-doc", 3}},
		{"private psl sibling", BrowserCheckoutContext{"https://checkout.pay.example.com", "top-doc", 9007199254740991}},
	}
	for _, tc := range allowed {
		if !tc.checkout.Valid(frame) {
			t.Fatalf("%s: same-site checkout refused: %#v", tc.name, tc.checkout)
		}
	}
	if !(BrowserCheckoutContext{"https://shop.alice.github.io", "top-doc", 5}).Valid(frameContext("https://pay.alice.github.io", "frame-doc")) {
		t.Fatal("same private-suffix tenant refused")
	}
	refused := []struct {
		name     string
		checkout BrowserCheckoutContext
		frame    BrowserContext
	}{
		{"same origin", BrowserCheckoutContext{"https://pay.example.com", "top-doc", 1}, frame},
		{"same document", BrowserCheckoutContext{"https://shop.example.com", "frame-doc", 1}, frame},
		{"zero frame id", BrowserCheckoutContext{"https://shop.example.com", "top-doc", 0}, frame},
		{"negative frame id", BrowserCheckoutContext{"https://shop.example.com", "top-doc", -1}, frame},
		{"oversized frame id", BrowserCheckoutContext{"https://shop.example.com", "top-doc", 9007199254740992}, frame},
		{"empty top document", BrowserCheckoutContext{"https://shop.example.com", "", 1}, frame},
		{"bad top document", BrowserCheckoutContext{"https://shop.example.com", "top doc", 1}, frame},
		{"cross-site", BrowserCheckoutContext{"https://evil.test", "top-doc", 1}, frame},
		{"different private tenant", BrowserCheckoutContext{"https://alice.github.io", "top-doc", 1}, frameContext("https://bob.github.io", "frame-doc")},
		{"http top", BrowserCheckoutContext{"http://shop.example.com", "top-doc", 1}, frame},
		{"ip top", BrowserCheckoutContext{"https://127.0.0.1", "top-doc", 1}, frame},
		{"idn top", BrowserCheckoutContext{"https://xn--bcher-kva.example.com", "top-doc", 1}, frame},
		{"opaque top", BrowserCheckoutContext{"null", "top-doc", 1}, frame},
		{"public suffix top", BrowserCheckoutContext{"https://co.uk", "top-doc", 1}, frame},
		{"trailing slash", BrowserCheckoutContext{"https://shop.example.com/", "top-doc", 1}, frame},
		{"uppercase host", BrowserCheckoutContext{"https://SHOP.example.com", "top-doc", 1}, frame},
		{"empty top origin", BrowserCheckoutContext{"", "top-doc", 1}, frame},
		{"invalid frame document", BrowserCheckoutContext{"https://shop.example.com", "top-doc", 1}, frameContext("https://pay.example.com", "")},
		{"opaque frame", BrowserCheckoutContext{"https://shop.example.com", "top-doc", 1}, frameContext("null", "frame-doc")},
	}
	for _, tc := range refused {
		if tc.checkout.Valid(tc.frame) {
			t.Fatalf("%s: unsafe checkout accepted: %#v %#v", tc.name, tc.checkout, tc.frame)
		}
	}
}

func TestBrowserProfileTargetCheckoutIsCardOnlyAndBound(t *testing.T) {
	frame := frameContext("https://pay.example.com", "frame-doc")
	checkout := &BrowserCheckoutContext{"https://shop.example.com", "top-doc", 4}
	target := BrowserProfileTarget{ID: strings.Repeat("cd", 16), Revision: strings.Repeat("ef", 32), Category: "credit_card", Context: frame, Checkout: checkout}
	if !target.valid() {
		t.Fatal("valid card checkout target refused")
	}
	identity := target
	identity.Category = "identity"
	if identity.valid() {
		t.Fatal("identity target accepted a checkout assertion")
	}
	unsafe := target
	unsafe.Checkout = &BrowserCheckoutContext{"https://evil.test", "top-doc", 4}
	if unsafe.valid() {
		t.Fatal("cross-site target accepted")
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	base, err := target.binding(key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := BrowserProfileTarget{ID: target.ID, Revision: target.Revision, Category: target.Category, Context: frame}.binding(key)
	if err != nil {
		t.Fatal(err)
	}
	if base == plain {
		t.Fatal("checkout selectors are not covered by the binding")
	}
	// Every checkout selector must be signed: changing any one of them changes
	// the recorded intent link.
	for _, mutate := range []func(*BrowserCheckoutContext){
		func(c *BrowserCheckoutContext) { c.TopOrigin = "https://other.example.com" },
		func(c *BrowserCheckoutContext) { c.TopDocumentID = "other-doc" },
		func(c *BrowserCheckoutContext) { c.FrameID = 5 },
	} {
		changed := *checkout
		mutate(&changed)
		next := target
		next.Checkout = &changed
		link, err := next.binding(key)
		if err != nil {
			t.Fatal(err)
		}
		if link == base || link == plain {
			t.Fatal("checkout selector not bound into the intent")
		}
	}
}
