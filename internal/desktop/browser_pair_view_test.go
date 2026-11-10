package desktop

import (
	"context"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
)

// The native pairing prompt must show the OS-authenticated peer and let the
// owner choose quick fill independently from approval. The browser-declared
// origin is displayed but cannot fill in either decision.
func TestBrowserPairingReviewRendersPeerAndChoosesQuickFill(t *testing.T) {
	a := New()
	decisions := make(chan browserhost.BrowserPairDecision, 1)
	go func() {
		decision, _ := a.approveBrowserPair(context.Background(), browserhost.BrowserPairRequest{
			Peer:    browserhost.Peer{User: "UID 501", PID: 4242, Process: "locklark-browser-chromium"},
			Browser: browserhost.Chromium,
			Origin:  "chrome-extension://" + browserhost.ChromiumID + "/",
		})
		decisions <- decision
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.brokerMu.Lock()
		pending := len(a.browserPairs)
		a.brokerMu.Unlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pairing review did not surface")
		}
		time.Sleep(time.Millisecond)
	}
	tester := ui.NewTester(a.View, 1000, 780)
	for _, want := range []string{
		"批准浏览器连接桌面金库",
		"本机用户：UID 501",
		"调用进程：PID 4242 · locklark-browser-chromium",
		"连接并启用快捷填充",
		"确认连接（每次敏感操作需批准）",
		"拒绝连接",
	} {
		if !tester.HasText(want) {
			t.Fatalf("pairing prompt missing %q", want)
		}
	}
	if e := tester.Click("连接并启用快捷填充"); e != nil {
		t.Fatalf("click pairing choice: %v", e)
	}
	select {
	case decision := <-decisions:
		if !decision.Approved || !decision.QuickFill {
			t.Fatalf("pairing decision: %#v", decision)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pairing decision was not routed")
	}
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if len(a.browserPairs) != 0 {
		t.Fatal("pairing review survived its decision")
	}
}
