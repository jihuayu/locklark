package desktop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

// desktopCreateReviewFixture extends the two-credential fixture with a pending
// passkey creation review for the same login, exactly as a browser
// passkey-create does when the login already owns Passkeys.
func desktopCreateReviewFixture(t *testing.T) (*App, *browserhost.Connection, *browserPipe) {
	t.Helper()
	a, c, out, _ := desktopMultiPasskeyFixture(t)
	pending := c.Snapshot().Passkey
	if pending == nil {
		t.Fatal("missing review")
	}
	if e := c.RejectPasskey(pending.ID); e != nil {
		t.Fatal(e)
	}
	capability := ""
	for _, response := range desktopFrameResponses(t, out) {
		if response.Type == "paired" {
			capability = response.Capability
		}
	}
	create := browserhost.Request{
		V: 1, ID: fmt.Sprintf("%032x", 400), Type: "passkey-create", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", Options: desktopPasskeyCreateOptions,
	}
	if e := c.Handle(create); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		view := c.Snapshot().Passkey
		if view != nil && view.Create && !view.Working && len(view.Choices) == 1 {
			if len(view.ChoicePasskeys) != 1 || view.ChoicePasskeys[0] != 2 {
				t.Fatalf("creation counts: %#v", view.ChoicePasskeys)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("creation review timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return a, c, out
}

// TestNativePasskeyCreateChoiceClickableInDefaultWindow reproduces the physical
// failure: in the real 1000x780 window the reviewed creation choice and the
// cancel control must sit inside the viewport and pass the driver's hit test,
// not merely exist in the accessibility tree.
func TestNativePasskeyCreateChoiceClickableInDefaultWindow(t *testing.T) {
	t.Run("choice", func(t *testing.T) {
		a, _, _ := desktopCreateReviewFixture(t)
		launched := 0
		a.launch = func(func()) { launched++ }
		a.dispatch = func(fn func()) { fn() }
		tester := ui.NewTester(a.View, 1000, 780)
		labels := desktopTextsWithPrefix(tester, "保存到：")
		if len(labels) != 1 {
			t.Fatalf("creation choice buttons: %#v", labels)
		}
		box, ok := tester.Find(labels[0])
		if !ok || box.Y < 0 || box.Y+box.H > 780 {
			t.Fatalf("choice button is outside the 1000x780 window: %+v", box)
		}
		if e := tester.Click(labels[0]); e != nil {
			t.Fatal(e)
		}
		if launched != 1 {
			t.Fatalf("choice click did not reach the approval path: %d", launched)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		a, _, _ := desktopCreateReviewFixture(t)
		launched := 0
		a.launch = func(func()) { launched++ }
		a.dispatch = func(fn func()) { fn() }
		tester := ui.NewTester(a.View, 1000, 780)
		box, ok := tester.Find("取消 / 使用其他验证器")
		if !ok || box.Y < 0 || box.Y+box.H > 780 {
			t.Fatalf("cancel button is outside the 1000x780 window: %+v", box)
		}
		if e := tester.Click("取消 / 使用其他验证器"); e != nil {
			t.Fatal(e)
		}
		if launched != 1 {
			t.Fatalf("cancel click did not reach the host: %d", launched)
		}
	})
}

// TestNativePasskeyChoicePanelScrollsWithCancelPinned renders the review alone
// with the height the window chrome leaves (1000x780 minus the fixed browser
// header). Fifty choices must stay in one bounded, scrollable panel while the
// cancel control stays inside the viewport, so no choice can push it away.
func TestNativePasskeyChoicePanelScrollsWithCancelPinned(t *testing.T) {
	view := browserhost.PasskeyView{
		ID: strings.Repeat("b", 32), Create: true,
		Origin: "https://login.locklark.test", RPID: "login.locklark.test", Username: "passkey-test",
	}
	for n := 0; n < 50; n++ {
		view.Choices = append(view.Choices, personal.PasskeyChoice{
			ID: fmt.Sprintf("choice-%d", n), Title: "passkey-test", Username: "passkey-test",
			CredentialID: fmt.Sprintf("%08x%024x", 600+n, 600+n),
		})
		view.ChoicePasskeys = append(view.ChoicePasskeys, 1)
	}
	a := New()
	launched := 0
	a.launch = func(func()) { launched++ }
	a.dispatch = func(fn func()) { fn() }
	tester := ui.NewTester(func(c *ui.Context) { a.browserPasskeyView(c, view, "") }, 1000, 640)
	if !tester.HasText("添加第二个 Passkey 会升级该登录的加密格式；旧客户端将拒绝打开金库。请仅在核对账号后明确批准。") {
		t.Fatal("missing explicit upgrade warning")
	}
	labels := desktopTextsWithPrefix(tester, "保存到：")
	if len(labels) != 50 {
		t.Fatalf("choice buttons: %d", len(labels))
	}
	cancel, ok := tester.Find("取消 / 使用其他验证器")
	if !ok || cancel.Y < 0 || cancel.Y+cancel.H > 640 {
		t.Fatalf("cancel button left the viewport: %+v", cancel)
	}
	first, ok := tester.Find(labels[0])
	if !ok || first.Y < 0 || first.Y+first.H > 640 {
		t.Fatalf("first choice left the viewport: %+v", first)
	}
	if e := tester.Click(labels[0]); e != nil {
		t.Fatal(e)
	}
	if launched != 1 {
		t.Fatalf("first choice was not clickable: %d", launched)
	}
	last, ok := tester.Find(labels[49])
	if !ok {
		t.Fatalf("far choice disappeared from the tree: %q", labels[49])
	}
	if last.Y+last.H <= 640 {
		t.Fatalf("fifty choices grew the view instead of scrolling: %+v", last)
	}
	// The panel is bounded rather than growing with the list: the far choice is
	// laid out below the viewport, while the cancel control stays inside it.
	if again, ok := tester.Find("取消 / 使用其他验证器"); !ok || again.Y+again.H > 640 {
		t.Fatalf("cancel button moved out of the viewport while scrolling: %+v", again)
	}
}
