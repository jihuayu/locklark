package desktop

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

func cliPendingBindingFixture(id string) *cliRunPending {
	return &cliRunPending{
		id:   id,
		peer: browserhost.Peer{PID: 99, User: "tester", Process: "gh.exe"},
		request: browserhost.BrokerCLIRequest{
			V:         1,
			VaultPath: "/fixture/personal.ll",
			Targets: []personal.CLIBrokerTarget{{
				Slot:     "GH_TOKEN",
				ID:       "0123456789abcdef0123456789abcdef",
				Revision: "fedcba9876543210fedcba9876543210",
				Field:    "password",
			}},
		},
		decision: make(chan bool, 1),
	}
}

func cliPendingDecision(p *cliRunPending) (bool, bool) {
	select {
	case value := <-p.decision:
		return value, true
	default:
		return false, false
	}
}

func setCLIPending(a *App, p *cliRunPending, rendered string) {
	a.brokerMu.Lock()
	a.cliPending = p
	a.approvalWinPending = rendered
	a.brokerMu.Unlock()
}

func setCLIApprovalPopup(a *App, p *cliRunPending, popup *cliApprovalPopup) {
	a.brokerMu.Lock()
	a.cliPending = p
	p.popup = popup
	a.approvalPopup = popup
	a.approvalWinPending = popup.id
	a.approvalWin = nil
	a.brokerMu.Unlock()
}

// A rendered p1 must not be able to approve, refuse, or hide after p2 has
// replaced it. These are the exact closures both approval views wire.
func TestStaleCLIApprovalRenderCannotDecideReplacement(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")
	popup1 := &cliApprovalPopup{id: p1.id}
	popup2 := &cliApprovalPopup{id: p2.id}
	setCLIApprovalPopup(a, p1, popup1)

	// Capture p1's rendered callbacks, then replace it before any click.
	approve1, refuse1 := a.cliRunDecisionHandlers(p1)
	setCLIApprovalPopup(a, p2, popup2)
	approve1()
	refuse1()
	if a.hideApprovalWindowFor(p1.id) {
		t.Fatal("stale open/main action hid the replacement window")
	}
	if p1.decided || p2.decided {
		t.Fatalf("a stale rendered prompt decided a request (p1=%v p2=%v)", p1.decided, p2.decided)
	}
	if _, ok := cliPendingDecision(p1); ok {
		t.Fatal("stale p1 received a decision")
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("stale p1 decided replacement p2")
	}
	a.brokerMu.Lock()
	current, rendered := a.cliPending, a.approvalWinPending
	a.brokerMu.Unlock()
	if current != p2 || rendered != p2.id {
		t.Fatal("stale click changed the replacement pending binding")
	}

	// A current p2 view decides exactly once; a second decision is ignored.
	currentView := ui.NewTester(a.cliApprovalPopupContent(popup2), 560, 430)
	if err := currentView.Click("仅批准本次 CLI 请求"); err != nil {
		t.Fatal(err)
	}
	if value, ok := cliPendingDecision(p2); !ok || !value {
		t.Fatalf("current p2 approval = %v, %v", value, ok)
	}
	approve2, _ := a.cliRunDecisionHandlers(p2)
	approve2()
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("p2 received a second decision")
	}
	if !p2.decided || p1.decided {
		t.Fatal("decision marker was not bound to the exact pending id")
	}
}

// Cleanup and a delayed p1 window-close event must not reject, retire, or hide
// the rendered p2 popup. A genuine p2 close refuses exactly once.
func TestStaleCLIApprovalWindowCloseCannotRejectReplacement(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")
	popup1 := &cliApprovalPopup{id: p1.id}
	popup2 := &cliApprovalPopup{id: p2.id}
	setCLIApprovalPopup(a, p1, popup1)
	// Capture p1's permanent close closure before p2 replaces both the pending
	// request and the rendered popup.
	close1 := a.cliRunCloseHandler(popup1)
	setCLIApprovalPopup(a, p2, popup2)

	// A stale queued show must not replace p2's rendered popup either.
	a.showApprovalWindow(p1.id)
	// The delayed p1 close runs first, then stale cleanup runs while p2 is
	// current. Neither may reject, retire, or hide p2's popup.
	close1(&mygo.CloseEvent{})
	if a.hideApprovalWindowFor(p1.id) {
		t.Fatal("stale cleanup retired p2's popup")
	}
	a.retireCLIRunPendingWindow(p1)
	close1(&mygo.CloseEvent{})

	a.brokerMu.Lock()
	current, rendered := a.cliPending, a.approvalWinPending
	currentPopup, p2Popup := a.approvalPopup, p2.popup
	p1Retired, p2Retired := popup1.retired, popup2.retired
	a.brokerMu.Unlock()
	if current != p2 || rendered != p2.id || currentPopup != popup2 || p2Popup != popup2 {
		t.Fatal("stale p1 action changed p2's rendered popup binding")
	}
	if !p1Retired || p2Retired {
		t.Fatalf("popup retirement p1=%v p2=%v, want p1 retired and p2 live", p1Retired, p2Retired)
	}
	if p1.decided || p2.decided {
		t.Fatal("stale p1 close decided a request")
	}
	if _, ok := cliPendingDecision(p1); ok {
		t.Fatal("stale p1 close decided p1")
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("stale p1 close rejected replacement p2")
	}

	// A different retired pending's own cleanup also retires only its popup.
	p1b := cliPendingBindingFixture("pending-1b")
	popup1b := &cliApprovalPopup{id: p1b.id}
	a.brokerMu.Lock()
	p1b.popup = popup1b
	a.brokerMu.Unlock()
	a.retireCLIRunPendingWindow(p1b)
	a.brokerMu.Lock()
	p1bRetired := popup1b.retired
	currentPopup = a.approvalPopup
	p2Live := !popup2.retired
	a.brokerMu.Unlock()
	if !p1bRetired || !p2Live || currentPopup != popup2 {
		t.Fatalf("stale pending cleanup p1b=%v p2=%v current=%v", p1bRetired, p2Live, currentPopup)
	}

	// The genuine p2 close closure still decides p2 exactly once.
	close2 := a.cliRunCloseHandler(popup2)
	close2(&mygo.CloseEvent{})
	close2(&mygo.CloseEvent{})
	if value, ok := cliPendingDecision(p2); !ok || value {
		t.Fatalf("current p2 close refusal = %v, %v", value, ok)
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("p2 close decided more than once")
	}
	a.brokerMu.Lock()
	rendered, currentPopup = a.approvalWinPending, a.approvalPopup
	p2Retired = popup2.retired
	a.brokerMu.Unlock()
	if !p2.decided || !p2Retired || rendered != "" || currentPopup != nil {
		t.Fatalf("p2 close state decided=%v retired=%v rendered=%q popup=%v", p2.decided, p2Retired, rendered, currentPopup)
	}
	if _, ok := cliPendingDecision(p1); ok {
		t.Fatal("p2 close decided p1")
	}
}

// A captured p1 content callback must never reread the global pending and
// build p2's body or decision controls after p2 replaces it.
func TestStaleCLIApprovalContentCannotRenderReplacement(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")
	p2.peer.Process = "p2-process"
	p2.request.VaultPath = "/fixture/p2-visible.ll"
	p2.request.Targets[0].Slot = "P2_SLOT"
	popup1 := &cliApprovalPopup{id: p1.id}
	popup2 := &cliApprovalPopup{id: p2.id}
	setCLIApprovalPopup(a, p1, popup1)
	staleRender := a.cliApprovalPopupContent(popup1)

	// Replace both the pending request and the rendered popup owner, then
	// invoke the content callback captured for p1.
	setCLIApprovalPopup(a, p2, popup2)
	staleView := ui.NewTester(staleRender, 560, 430)
	for _, leaked := range []string{"p2-visible.ll", "p2-process", "P2_SLOT",
		"批准本地 CLI 凭据请求", "打开主窗口", "拒绝本次请求", "仅批准本次 CLI 请求"} {
		if staleView.HasText(leaked) {
			t.Fatalf("retired p1 content rendered p2 detail or action %q", leaked)
		}
	}
	if !staleView.HasText("暂无待处理的 CLI 凭据请求") {
		t.Fatal("retired p1 content did not render the neutral empty state")
	}
	if p2.decided {
		t.Fatal("retired p1 content decided p2")
	}

	// The live p2 content still renders its own body and actions.
	liveView := ui.NewTester(a.cliApprovalPopupContent(popup2), 560, 430)
	for _, want := range []string{"p2-visible.ll", "p2-process", "P2_SLOT",
		"批准本地 CLI 凭据请求", "打开主窗口", "拒绝本次请求", "仅批准本次 CLI 请求"} {
		if !liveView.HasText(want) {
			t.Fatalf("live p2 content missing %q", want)
		}
	}
	if liveView.HasText("GH_TOKEN") {
		t.Fatal("live p2 content rendered retired p1 details")
	}
	if err := liveView.Click("仅批准本次 CLI 请求"); err != nil {
		t.Fatal(err)
	}
	if value, ok := cliPendingDecision(p2); !ok || !value {
		t.Fatalf("live p2 action = %v, %v", value, ok)
	}
}

// Concurrent stale and current callbacks must decide the current id once.
func TestCLIApprovalConcurrentDecisionIsOnceAndCurrentID(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")
	setCLIPending(a, p2, p2.id)

	const workers = 64
	var accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			id := p1.id
			if i%2 == 0 {
				id = p2.id
			}
			if a.approveCLIRun(id, i%4 == 0) {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted decisions = %d, want exactly 1", got)
	}
	if !p2.decided || p1.decided {
		t.Fatal("concurrent decisions were not bound to p2")
	}
	if _, ok := cliPendingDecision(p1); ok {
		t.Fatal("stale p1 received a decision")
	}
	if _, ok := cliPendingDecision(p2); !ok {
		t.Fatal("p2 received no decision")
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("p2 received more than one decision")
	}
}
