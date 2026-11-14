package desktop

import (
	"sync"
	"sync/atomic"
	"testing"

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

// A rendered p1 must not be able to approve, refuse, or hide after p2 has
// replaced it. These are the exact closures both approval views wire.
func TestStaleCLIApprovalRenderCannotDecideReplacement(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")
	setCLIPending(a, p1, p1.id)

	// Capture p1's rendered callbacks, then replace it before any click.
	approve1, refuse1 := a.cliRunDecisionHandlers(p1)
	setCLIPending(a, p2, p2.id)
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

	// A current p2 view decides exactly once; a second click is ignored.
	currentView := ui.NewTester(a.cliApprovalPopupView, 560, 430)
	if err := currentView.Click("仅批准本次 CLI 请求"); err != nil {
		t.Fatal(err)
	}
	if value, ok := cliPendingDecision(p2); !ok || !value {
		t.Fatalf("current p2 approval = %v, %v", value, ok)
	}
	if err := currentView.Click("仅批准本次 CLI 请求"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("p2 received a second decision")
	}
	if !p2.decided || p1.decided {
		t.Fatal("decision marker was not bound to the exact pending id")
	}
}

// Cleanup and window-close actions captured for p1 must not reject or hide p2
// once the replacement is current.
func TestStaleCLIApprovalCloseAndCleanupCannotTouchReplacement(t *testing.T) {
	a := New()
	p1 := cliPendingBindingFixture("pending-1")
	p2 := cliPendingBindingFixture("pending-2")

	// p1's cleanup runs after p2 is rendered: it may hide only its own window.
	setCLIPending(a, p2, p2.id)
	if a.hideApprovalWindowFor(p1.id) {
		t.Fatal("stale cleanup hid the replacement window")
	}
	a.brokerMu.Lock()
	current, rendered := a.cliPending, a.approvalWinPending
	a.brokerMu.Unlock()
	if current != p2 || rendered != p2.id {
		t.Fatal("stale cleanup changed the replacement binding")
	}

	// A close callback for a p1 window queued before p2 is shown must not
	// reject p2. The stale owner is cleared, then p2 can bind and be refused.
	setCLIPending(a, p2, p1.id)
	a.rejectRenderedCLIRun()
	if p1.decided || p2.decided {
		t.Fatal("stale close decided a request")
	}
	if _, ok := cliPendingDecision(p2); ok {
		t.Fatal("stale close rejected replacement p2")
	}
	a.brokerMu.Lock()
	current = a.cliPending
	rendered = a.approvalWinPending
	a.brokerMu.Unlock()
	if current != p2 || rendered != "" {
		t.Fatal("stale close did not retire only its own window binding")
	}

	setCLIPending(a, p2, p2.id)
	a.rejectRenderedCLIRun()
	if value, ok := cliPendingDecision(p2); !ok || value {
		t.Fatalf("current p2 close refusal = %v, %v", value, ok)
	}
	if !p2.decided {
		t.Fatal("current close did not mark p2 decided")
	}
	a.brokerMu.Lock()
	rendered = a.approvalWinPending
	a.brokerMu.Unlock()
	if rendered != "" {
		t.Fatal("current close left the window binding installed")
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
