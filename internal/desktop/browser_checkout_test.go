package desktop

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func checkoutDesktopFixture(t *testing.T) (*App, *personal.Session, *browserhost.Connection, *browserPipe, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checkout.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	cardID, _, e := s.AddItem(vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Owner Card", CreditCard: &vault.CreditCardDetails{
		CardholderName: "Card Holder", Type: "visa", Number: "4242424242424242", Verification: "123", ExpiryDate: "2028-12",
	}}, gate)
	if e != nil {
		t.Fatal(e)
	}
	out := &browserPipe{}
	connection := browserhost.NewConnection(browserhost.NewWriter(out, time.Second), nil)
	rid := func(n int) string { return fmt.Sprintf("%032x", n) }
	if connection.Handle(browserhost.Request{V: 1, ID: rid(1), Type: "hello"}) != nil || connection.ApprovePair(s) != nil {
		t.Fatal("pair")
	}
	out.Lock()
	raw := out.String()
	out.Unlock()
	marker := `"capability":"`
	start := strings.Index(raw, marker) + len(marker)
	capability := raw[start : start+32]
	a := New()
	a.session = s
	a.browser = connection
	a.browserLabel = "fixed development extension"
	return a, s, connection, out, capability, cardID
}

func checkoutRequest(id, kind, capability, itemID, revision string) browserhost.Request {
	return browserhost.Request{
		V: 1, ID: id, Type: kind, Capability: capability, ProfileKind: "credit_card",
		Origin: "https://pay.example.test", TabID: 3, DocumentID: "frame-doc",
		ItemID: itemID, Revision: revision,
		Checkout: &browserhost.BrowserCheckout{TopOrigin: "https://shop.example.test", TopDocumentID: "top-doc", FrameID: 2},
	}
}

// The native owner must see both sides of the cross-origin frame and a dedicated
// card button; the ordinary review keeps its unchanged heading and buttons.
func TestNativeCheckoutReviewShowsBothOrigins(t *testing.T) {
	a, s, connection, _, capability, cardID := checkoutDesktopFixture(t)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	revision := ""
	for _, row := range rows {
		if row.ID == cardID {
			revision = row.Revision
		}
	}
	if revision == "" {
		t.Fatal("card revision missing")
	}
	rid := func(n int) string { return fmt.Sprintf("%032x", n) }
	if e := connection.Handle(checkoutRequest(rid(10), "match-profiles", capability, "", "")); e != nil {
		t.Fatal(e)
	}
	if e := connection.Handle(checkoutRequest(rid(11), "fill-profile", capability, cardID, revision)); e != nil {
		t.Fatal(e)
	}
	tester := ui.NewTester(a.View, 1000, 780)
	for _, want := range []string{
		"跨源结账银行卡",
		"顶层页面来源：https://shop.example.test",
		"目标框架来源：https://pay.example.test",
		"顶层文档：top-doc",
		"框架文档：frame-doc",
		"框架 ID：2",
		"批准本次跨源银行卡填充",
		"拒绝本次跨源银行卡填充",
	} {
		if !tester.HasText(want) {
			t.Fatalf("checkout review missing %q", want)
		}
	}
	// The default review keeps its own heading and buttons.
	if e := connection.RejectProfile(rid(11)); e != nil {
		t.Fatal(e)
	}
	plain := checkoutRequest(rid(12), "match-profiles", capability, "", "")
	plain.Checkout = nil
	plain.ProfileKind = "credit_card"
	if e := connection.Handle(plain); e != nil {
		t.Fatal(e)
	}
	plainFill := checkoutRequest(rid(13), "fill-profile", capability, cardID, revision)
	plainFill.Checkout = nil
	plainFill.ProfileKind = ""
	if e := connection.Handle(plainFill); e != nil {
		t.Fatal(e)
	}
	tester = ui.NewTester(a.View, 1000, 780)
	if !tester.HasText("本次敏感字段填充") || !tester.HasText("批准本次敏感字段填充") {
		t.Fatal("default profile review changed")
	}
	if tester.HasText("跨源结账银行卡") {
		t.Fatal("default review rendered a checkout heading")
	}
}
