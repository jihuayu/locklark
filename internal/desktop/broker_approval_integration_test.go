package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

type brokerFrameClient struct {
	in     *io.PipeWriter
	out    *io.PipeReader
	frames chan map[string]any
}

func (c *brokerFrameClient) send(t *testing.T, value map[string]any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := c.in.Write(desktopFrame(raw)); e != nil {
		t.Fatal(e)
	}
}

func (c *brokerFrameClient) recvType(t *testing.T, want string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case frame, ok := <-c.frames:
			if !ok {
				t.Fatalf("relay closed before %q", want)
			}
			if frame["type"] == want {
				return frame
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func startBrokerFrameClient(t *testing.T) *brokerFrameClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &brokerFrameClient{in: inW, out: outR, frames: make(chan map[string]any, 64)}
	go func() {
		defer close(c.frames)
		_ = browserhost.RelayStdio(browserhost.Chromium, []string{"chrome-extension://" + browserhost.ChromiumID + "/"}, inR, outW)
	}()
	go func() {
		for {
			raw, e := desktopReadFrame(outR)
			if e != nil {
				return
			}
			var frame map[string]any
			if json.Unmarshal(raw, &frame) == nil {
				c.frames <- frame
			}
		}
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		_ = outR.Close()
	})
	return c
}

func desktopBrokerSocket(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "llb-desktop-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private test directory")
	}
	return filepath.Join(dir, "b.sock")
}

func brokeredDesktopFixture(t *testing.T) (*App, *personal.Session, *brokerFrameClient, *browserhost.Connection, string) {
	t.Helper()
	return brokeredDesktopFixtureWithQuick(t, true)
}

func brokeredDesktopFixtureWithQuick(t *testing.T, quickFill bool) (*App, *personal.Session, *brokerFrameClient, *browserhost.Connection, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "brokered.ll")
	key := bytes.Repeat([]byte{13}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	itemID, e := s.AddLogin("Broker Passkey", "broker-alice", "broker-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	revision := ""
	for _, row := range rows {
		if row.ID == itemID {
			revision = row.Revision
		}
	}
	updated, e := s.Edit(personal.Edit{ID: itemID, Revision: revision, Field: "url", Value: "https://example.test/login"})
	if e != nil {
		t.Fatal(e)
	}
	revision = updated
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	created, e := s.PerformPasskey(personal.PasskeyTarget{
		Context:  personal.BrowserContext{RequestID: fmt.Sprintf("%032x", 900), Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"},
		Create:   true,
		ID:       itemID,
		Revision: revision,
		Options:  []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`),
	}, false, gate)
	if e != nil {
		t.Fatal(e)
	}
	if created.ID == "" {
		t.Fatal("fixture passkey missing")
	}

	t.Setenv("LOCKLARK_BROWSER_SOCKET", desktopBrokerSocket(t))
	a := New()
	a.launch = func(fn func()) { fn() }
	a.session = s
	a.v2Mode = true
	a.page = "vault"
	a.browserPairApprover = func(ctx context.Context, req browserhost.BrowserPairRequest) (browserhost.BrowserPairDecision, error) {
		return browserhost.BrowserPairDecision{Approved: true, QuickFill: quickFill}, nil
	}
	a.startBrowserBroker()
	if a.broker == nil {
		t.Fatal("desktop broker did not start")
	}
	t.Cleanup(a.stopBrowserBroker)
	a.brokerMu.Lock()
	a.brokerSession, a.brokerEpoch = s, 1
	a.brokerMu.Unlock()

	client := startBrokerFrameClient(t)
	client.send(t, map[string]any{"v": 1, "id": fmt.Sprintf("%032x", 1), "type": "hello"})
	paired := client.recvType(t, "paired", 5*time.Second)
	capability, _ := paired["capability"].(string)
	if len(capability) != 32 {
		t.Fatalf("pairing capability: %#v", paired)
	}
	conns := a.broker.Connections()
	if len(conns) != 1 {
		t.Fatalf("broker connections: %d", len(conns))
	}
	return a, s, client, conns[0], capability
}

func waitBrokeredPasskey(t *testing.T, a *App) *browserhost.Connection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn := a.brokeredBrowserApproval(); conn != nil {
			if view := conn.Snapshot().Passkey; view != nil && !view.Working {
				return conn
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("brokered passkey review did not surface")
	return nil
}

func waitBrokeredSignal(t *testing.T, a *App) *browserhost.Connection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn := a.brokeredBrowserApproval(); conn != nil {
			if view := conn.Snapshot().Signal; view != nil && !view.Working {
				return conn
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("brokered passkey signal did not surface")
	return nil
}

func waitBrokeredProfile(t *testing.T, a *App) *browserhost.Connection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn := a.brokeredBrowserApproval(); conn != nil {
			if view := conn.Snapshot().Profile; view != nil {
				return conn
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("brokered checkout review did not surface")
	return nil
}

func TestBrokeredDesktopRendersAndRoutesInteractiveApprovals(t *testing.T) {
	a, s, client, _, capability := brokeredDesktopFixture(t)

	// passkey-get: the V2 desktop must expose the originating broker connection
	// and route the native choice back to it.
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 100), "type": "passkey-get", "capability": capability,
		"origin": "https://example.test", "tab_id": 1, "document_id": "doc-1",
		"options": `{"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2"}`,
	})
	conn := waitBrokeredPasskey(t, a)
	passkey := conn.Snapshot().Passkey
	if passkey == nil || len(passkey.Choices) == 0 {
		t.Fatalf("passkey get review: %#v", passkey)
	}
	tester := ui.NewTester(a.View, 1200, 2400)
	if !tester.HasText("使用 Passkey 登录") {
		t.Fatal("v2 desktop did not render the brokered passkey review")
	}
	label := passkeyChoiceLabel(*passkey, passkey.Choices[0], false, 0)
	if e := tester.Click(label); e != nil {
		t.Fatalf("click passkey choice: %v", e)
	}
	if got := client.recvType(t, "passkey-result", 10*time.Second); got["credential"] == nil {
		t.Fatalf("passkey-get result: %#v", got)
	}

	// passkey-create: a second explicit approval creates the login/credential.
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 101), "type": "passkey-create", "capability": capability,
		"origin": "https://example.test", "tab_id": 1, "document_id": "doc-1",
		"options": `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjI","name":"bob","displayName":"Bob"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`,
	})
	conn = waitBrokeredPasskey(t, a)
	tester = ui.NewTester(a.View, 1200, 2400)
	if !tester.HasText("保存 Passkey") || !tester.HasText("创建新登录并保存 Passkey") {
		t.Fatal("v2 desktop did not render the brokered passkey creation")
	}
	if e := tester.Click("创建新登录并保存 Passkey"); e != nil {
		t.Fatalf("click passkey create: %v", e)
	}
	if got := client.recvType(t, "passkey-result", 10*time.Second); got["credential"] == nil {
		t.Fatalf("passkey-create result: %#v", got)
	}

	// passkey-signal: ACK first, then the native review is rendered and routed.
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 102), "type": "passkey-signal", "capability": capability,
		"origin": "https://example.test", "tab_id": 1, "document_id": "doc-1",
		"options": `{"kind":"user","rpId":"example.test","userId":"dXNlcjE","name":"renamed","displayName":"Renamed"}`,
	})
	client.recvType(t, "passkey-signal-accepted", 5*time.Second)
	conn = waitBrokeredSignal(t, a)
	tester = ui.NewTester(a.View, 1200, 2400)
	if !tester.HasText("网站请求更新 Passkey 账号") || !tester.HasText("确认应用这些更新") {
		t.Fatal("v2 desktop did not render the brokered passkey signal")
	}
	if e := tester.Click("确认应用这些更新"); e != nil {
		t.Fatalf("click passkey signal: %v", e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for conn.Snapshot().Signal != nil {
		if time.Now().After(deadline) {
			t.Fatal("brokered passkey signal approval did not complete")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Cross-origin checkout: the V2 desktop renders both sides and routes the
	// approval to the exact brokered connection.
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	cardID, cardRev, e := s.AddItem(vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Broker Card", CreditCard: &vault.CreditCardDetails{
		CardholderName: "Card Holder", Type: "visa", Number: "4242424242424242", Verification: "123", ExpiryDate: "2028-12",
	}}, gate)
	if e != nil {
		t.Fatal(e)
	}
	checkout := map[string]any{"top_origin": "https://shop.example.test", "top_document_id": "top-doc", "frame_id": 2}
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 103), "type": "match-profiles", "capability": capability,
		"profile_kind": "credit_card", "origin": "https://pay.example.test", "tab_id": 3, "document_id": "frame-doc",
		"checkout": checkout,
	})
	if got := client.recvType(t, "profiles", 5*time.Second); got == nil {
		t.Fatal("checkout profile list missing")
	}
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 104), "type": "fill-profile", "capability": capability,
		"profile_kind": "credit_card", "origin": "https://pay.example.test", "tab_id": 3, "document_id": "frame-doc",
		"item_id": cardID, "revision": cardRev, "checkout": checkout,
	})
	conn = waitBrokeredProfile(t, a)
	tester = ui.NewTester(a.View, 1200, 2400)
	if !tester.HasText("跨源结账银行卡") || !tester.HasText("顶层页面来源：https://shop.example.test") || !tester.HasText("目标框架来源：https://pay.example.test") {
		t.Fatal("v2 desktop did not render the brokered checkout review")
	}
	if e := tester.Click("批准本次跨源银行卡填充"); e != nil {
		t.Fatalf("click checkout approval: %v", e)
	}
	fill := client.recvType(t, "profile-fill", 10*time.Second)
	card, _ := fill["profile_fill"].(map[string]any)
	credit, _ := card["credit_card"].(map[string]any)
	if credit["number"] != "4242424242424242" {
		t.Fatalf("checkout fill routed to the wrong connection: %#v", fill)
	}
	if conn.Snapshot().Profile != nil {
		t.Fatal("approved checkout review remained pending")
	}
}

// A non-quick brokered connection must return a sensitive V2 disclosure to the
// V2 desktop, and the rendered button must call the originating connection's
// ApproveV2 rather than the standalone-only App.browser.
func TestBrokeredV2DisclosureRendersNativeApproval(t *testing.T) {
	a, s, client, _, capability := brokeredDesktopFixtureWithQuick(t, false)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	var itemID, revision string
	for _, row := range rows {
		if row.Title == "Broker Passkey" {
			itemID, revision = row.ID, row.Revision
		}
	}
	if itemID == "" {
		t.Fatal("fixture login missing")
	}
	client.send(t, map[string]any{
		"v": 1, "id": fmt.Sprintf("%032x", 200), "type": "item-reveal-field", "capability": capability,
		"item_id": itemID, "revision": revision, "field": "password",
	})
	var conn *browserhost.Connection
	deadline := time.Now().Add(5 * time.Second)
	for {
		if candidate := a.brokeredBrowserApproval(); candidate != nil {
			if view := candidate.Snapshot().V2; view != nil && view.Type == "item-reveal-field" {
				conn = candidate
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("brokered V2 disclosure review did not surface")
		}
		time.Sleep(time.Millisecond)
	}
	tester := ui.NewTester(a.View, 1200, 2400)
	if !tester.HasText("确认披露金库字段") || !tester.HasText("批准本次字段披露") ||
		!tester.HasText("字段选择器：password") || !tester.HasText("操作：显示字段") || !tester.HasText("变更摘要：把所选字段交给当前浏览器页面") {
		t.Fatal("v2 desktop did not render the brokered field selectors")
	}
	if e := tester.Click("批准本次字段披露"); e != nil {
		t.Fatalf("click V2 disclosure approval: %v", e)
	}
	reply := client.recvType(t, "field-value", 10*time.Second)
	if reply["value"] != "broker-password" {
		t.Fatalf("brokered V2 disclosure result: %#v", reply)
	}
	if conn.Snapshot().V2 != nil {
		t.Fatal("approved V2 review remained pending")
	}
}

// brokeredV2Review waits for the exact brokered V2 review of one request.
func brokeredV2Review(t *testing.T, a *App, id string) *browserhost.Connection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn := a.brokeredBrowserApproval(); conn != nil {
			if view := conn.Snapshot().V2; view != nil && view.ID == id {
				return conn
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("brokered V2 review %s did not surface", id)
	return nil
}

// The brokered native approval view shows the current item and the request as
// separate, name-only summaries. Every synthetic secret sentinel must stay out
// of the rendered texts while the approved disclosure still delivers the real
// value.
func TestBrokeredV2ApprovalRendersPublicFieldSummary(t *testing.T) {
	a, s, client, _, capability := brokeredDesktopFixtureWithQuick(t, false)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	var itemID, revision string
	for _, row := range rows {
		if row.Title == "Broker Passkey" {
			itemID, revision = row.ID, row.Revision
		}
	}
	if itemID == "" {
		t.Fatal("fixture login missing")
	}

	const sentinel = "SYNTHETIC-SECRET-SENTINEL-7f3c"
	requestID := fmt.Sprintf("%032x", 300)
	payload := `{"category":"login","title":"Requested Sanitized Login","username":"` + sentinel + `","password":"` + sentinel +
		`","otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","url":"https://requested.example.test/` + sentinel +
		`","notes":"` + sentinel + `","favorite":true,"sections":[{"id":"requested","title":"Requested","fields":[{"id":"recovery","label":"Recovery Code","type":"concealed","value":"` + sentinel + `"}]}]}`
	client.send(t, map[string]any{
		"v": 1, "id": requestID, "type": "item-edit", "capability": capability,
		"item_id": itemID, "revision": revision, "item_json": payload,
	})
	conn := brokeredV2Review(t, a, requestID)
	view := conn.Snapshot().V2
	if view == nil || view.Type != "item-edit" {
		t.Fatalf("brokered edit review: %#v", view)
	}
	tester := ui.NewTester(a.View, 1200, 2400)
	for _, want := range []string{
		"确认浏览器修改金库",
		"当前条目：", "当前名称：Broker Passkey", "当前类别：登录（login）", "当前字段名：",
		"请求：", "请求名称：Requested Sanitized Login", "请求类别：登录（login）", "请求字段名称：",
		"用户名", "密码", "验证码", "网址", "备注", "收藏", "自定义字段：Recovery Code",
		"以上仅为字段名称，不包含任何字段值。",
		"批准本次金库写入", "拒绝本次金库写入",
		"此操作不是快捷填充；请求 30 秒后失效。",
	} {
		if !tester.HasText(want) {
			t.Fatalf("v2 desktop did not render %q", want)
		}
	}
	if !tester.HasText("操作：编辑条目") {
		t.Fatal("v2 desktop stopped rendering the operation summary")
	}
	texts := strings.Join(tester.Texts(), "\n")
	if strings.Contains(texts, sentinel) || strings.Contains(texts, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("field value leaked into the native approval texts: %s", texts)
	}
	if e := tester.Click("批准本次金库写入"); e != nil {
		t.Fatalf("click V2 edit approval: %v", e)
	}
	saved := client.recvType(t, "item-saved", 10*time.Second)
	if saved["title"] != nil && saved["title"] != "Requested Sanitized Login" {
		t.Fatalf("approved edit result: %#v", saved)
	}
	deadline := time.Now().Add(10 * time.Second)
	for conn.Snapshot().V2 != nil {
		if time.Now().After(deadline) {
			t.Fatal("approved V2 edit review remained pending")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A non-quick item-get without a revision is pinned to the authenticated revision read when the review is
// reserved, and the desktop renders the pinned selector.
func TestBrokeredV2ItemGetPinsRevisionInNativeView(t *testing.T) {
	a, s, client, _, capability := brokeredDesktopFixtureWithQuick(t, false)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	var itemID, revision string
	for _, row := range rows {
		if row.Title == "Broker Passkey" {
			itemID, revision = row.ID, row.Revision
		}
	}
	if itemID == "" || revision == "" {
		t.Fatal("fixture login missing")
	}
	requestID := fmt.Sprintf("%032x", 310)
	client.send(t, map[string]any{
		"v": 1, "id": requestID, "type": "item-get", "capability": capability, "item_id": itemID,
	})
	conn := brokeredV2Review(t, a, requestID)
	view := conn.Snapshot().V2
	if view == nil || view.Revision != revision || !view.RevisionPinned {
		t.Fatalf("pinned review: %#v", view)
	}
	tester := ui.NewTester(a.View, 1200, 2400)
	for _, want := range []string{
		"确认浏览器敏感操作", "精确修订：" + revision, "修订已固定：按批准时的当前修订执行；条目若已改变则拒绝。",
		"当前名称：Broker Passkey", "当前类别：登录（login）", "批准本次操作", "拒绝本次操作",
	} {
		if !tester.HasText(want) {
			t.Fatalf("v2 desktop did not render %q", want)
		}
	}
	if e := tester.Click("拒绝本次操作"); e != nil {
		t.Fatalf("click V2 reject: %v", e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for conn.Snapshot().V2 != nil {
		if time.Now().After(deadline) {
			t.Fatal("rejected V2 review remained pending")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
