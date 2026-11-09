package desktop

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

type cliV2Fixture struct {
	app     *App
	session *personal.Session
	row     personal.Row
}

// newCLIRunV2Fixture unlocks a real vault session, stores one real login and
// binds it to the desktop broker exactly as the unlock path does. No window,
// credential store or network endpoint is involved.
func newCLIRunV2Fixture(t *testing.T) *cliV2Fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if err := personal.Create(path, "v2-fixture", key); err != nil {
		t.Fatal(err)
	}
	s, err := personal.UnlockSession(path, []byte("v2-fixture"), key, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddLogin("CLI v2 login", "v2-user", "v2-password"); err != nil {
		s.Lock()
		t.Fatal(err)
	}
	rows, err := s.List("active")
	if err != nil || len(rows) != 1 {
		s.Lock()
		t.Fatalf("rows %v %v", rows, err)
	}
	a := New()
	// The UI dispatcher runs inline on the test goroutine; only the approval
	// callback itself runs concurrently, as in the real serialized UI loop.
	a.launch = func(fn func()) { fn() }
	a.session = s
	a.notifyBrowserBrokerUnlocked()
	t.Cleanup(func() {
		a.cancelPendingCLIRun()
		s.Lock()
	})
	return &cliV2Fixture{app: a, session: s, row: rows[0]}
}

func (f *cliV2Fixture) epoch() uint64 {
	f.app.brokerMu.Lock()
	defer f.app.brokerMu.Unlock()
	return f.app.brokerEpoch
}

// scope builds a fully populated trusted scope for the real "deepseek"
// built-in, exactly the shape the broker hands to PrepareCLIRunV2.
func (f *cliV2Fixture) scope(t *testing.T) browserhost.CLIRunV2Scope {
	t.Helper()
	profile, ok := cliprofile.Lookup("deepseek")
	if !ok {
		t.Fatal("missing deepseek profile")
	}
	spec := profile.Spec()
	digest := strings.Repeat("ab", 32)
	return browserhost.CLIRunV2Scope{
		Peer:       browserhost.Peer{User: "UID 1000", PID: 4242, Process: "/usr/local/bin/locklark"},
		VaultPath:  f.session.VaultPath(),
		Root:       filepath.Join(t.TempDir(), "client-root"),
		ProfileID:  "deepseek",
		SpecID:     spec.ID,
		SpecDigest: digest,
		Spec:       spec,
		Request: personal.RunBundleRequest{
			Program:        "/usr/bin/env",
			Args:           []string{"deepseek", "--model", "chat"},
			Directory:      t.TempDir(),
			TimeoutSeconds: 30,
			HelperPath:     []string{"/usr/bin", "/opt/locklark/bin"},
			Passthrough:    map[string]string{"DEEPSEEK_MODEL": "deepseek-chat", "NO_COLOR": "1"},
			Spec:           cliprofile.CloneSpec(spec),
		},
		Targets:     []personal.BundleTarget{{Slot: "token", ID: f.row.ID, Revision: f.row.Revision, Field: "password"}},
		Nonce:       strings.Repeat("01", 16),
		Epoch:       f.epoch(),
		ScopeDigest: digest,
	}
}

type cliV2Call struct {
	done   chan struct{}
	native *browserhost.NativeCLIRunV2
	err    error
}

func callPrepareCLIRunV2(a *App, ctx context.Context, scope browserhost.CLIRunV2Scope) *cliV2Call {
	call := &cliV2Call{done: make(chan struct{})}
	go func() {
		call.native, call.err = a.PrepareCLIRunV2(ctx, scope)
		close(call.done)
	}()
	return call
}

func (c *cliV2Call) wait(t *testing.T) (*browserhost.NativeCLIRunV2, error) {
	t.Helper()
	select {
	case <-c.done:
		if c.native != nil && c.native.Grant != nil {
			grant := c.native.Grant
			t.Cleanup(grant.Discard)
		}
		return c.native, c.err
	case <-time.After(10 * time.Second):
		t.Fatal("PrepareCLIRunV2 did not return")
		return nil, nil
	}
}

func waitCLIRunV2Pending(t *testing.T, a *App) *cliRunV2Pending {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.brokerMu.Lock()
		pending := a.cliV2Pending
		a.brokerMu.Unlock()
		if pending != nil {
			return pending
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("v2 approval was never published")
	return nil
}

func currentCLIRunV2Pending(a *App) *cliRunV2Pending {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	return a.cliV2Pending
}

func pendingDecided(a *App, p *cliRunV2Pending) bool {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	return p.decided
}

func cliV2TestHex(value string, n int) bool {
	if len(value) != n*2 {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		return false
	}
	defer clear(raw)
	return hex.EncodeToString(raw) == value
}

// TestPrepareCLIRunV2ApprovesRealSessionIntent proves the whole product flow:
// a real authenticated session, one published pending approval holding the
// cloned full scope, an explicit owner decision, and a one-use native grant
// whose consumed values come from the real vault item.
func TestPrepareCLIRunV2ApprovesRealSessionIntent(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	legacyCalls := 0
	f.app.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		legacyCalls++
		return true, nil
	}
	scope := f.scope(t)
	call := callPrepareCLIRunV2(f.app, context.Background(), scope)
	pending := waitCLIRunV2Pending(t, f.app)

	if pending.session != f.session {
		t.Fatal("pending approval is not bound to the owning session")
	}
	got := pending.scope
	if got.Peer != scope.Peer || got.VaultPath != scope.VaultPath || got.Root != scope.Root ||
		got.ProfileID != "deepseek" || got.SpecID != scope.SpecID || got.SpecDigest != scope.SpecDigest ||
		got.Nonce != scope.Nonce || got.Epoch != scope.Epoch || got.ScopeDigest != scope.ScopeDigest {
		t.Fatalf("pending scope lost identity fields: %#v", got)
	}
	if got.Request.Program != scope.Request.Program || got.Request.Directory != scope.Request.Directory ||
		got.Request.TimeoutSeconds != scope.Request.TimeoutSeconds || got.Request.TokenEnvName != scope.Request.TokenEnvName {
		t.Fatalf("pending scope lost request fields: %#v", got.Request)
	}
	if len(got.Request.Args) != len(scope.Request.Args) || len(got.Request.HelperPath) != len(scope.Request.HelperPath) || len(got.Targets) != len(scope.Targets) {
		t.Fatalf("pending scope lost list fields: %#v", got)
	}

	// The pending approval owns cloned slices and maps: mutating the caller's
	// declarations after publication must never change what the owner sees.
	scope.Request.Args[0] = "mutated"
	scope.Request.HelperPath[0] = "/mutated"
	scope.Request.Passthrough["DEEPSEEK_MODEL"] = "mutated"
	scope.Targets[0].Field = "username"
	scope.Spec.Slots[0].Name = "mutated-spec"
	scope.Request.Spec.Slots[0].Name = "mutated-request-spec"
	if got.Request.Args[0] != "deepseek" || got.Request.HelperPath[0] != "/usr/bin" ||
		got.Request.Passthrough["DEEPSEEK_MODEL"] != "deepseek-chat" ||
		got.Targets[0].Field != "password" || got.Spec.Slots[0].Name != "token" || got.Request.Spec.Slots[0].Name != "token" {
		t.Fatalf("pending approval shares caller memory: %#v", got)
	}

	f.app.decideCLIRunV2(pending.id, true)
	native, err := call.wait(t)
	if err != nil || native == nil || native.Session != f.session || native.Grant == nil {
		t.Fatalf("approved callback: native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("approved pending approval was not retired")
	}

	var value string
	var receipt personal.RunBundleGrantReceipt
	if err := f.session.ConsumeRunBundleGrant(context.Background(), native.Grant, func(values map[string][]byte, r personal.RunBundleGrantReceipt) error {
		value = string(values["token"])
		receipt = r
		return nil
	}); err != nil {
		t.Fatalf("consume approved grant: %v", err)
	}
	if value != "v2-password" {
		t.Fatalf("consumed value = %q", value)
	}
	if !cliV2TestHex(receipt.Session, 16) || !cliV2TestHex(receipt.Intent, 32) || !cliV2TestHex(receipt.TargetDigest, 32) {
		t.Fatalf("non-canonical receipt: %#v", receipt)
	}
	// The grant is one-use and never a reusable lease.
	if err := f.session.ConsumeRunBundleGrant(context.Background(), native.Grant, func(map[string][]byte, personal.RunBundleGrantReceipt) error {
		return nil
	}); err == nil {
		t.Fatal("grant was reusable")
	}
	if legacyCalls != 0 {
		t.Fatal("legacy v1 cliApprover hook decided a v2 request")
	}
}

func TestPrepareCLIRunV2RefusalLeavesNoGrant(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	call := callPrepareCLIRunV2(f.app, context.Background(), f.scope(t))
	pending := waitCLIRunV2Pending(t, f.app)

	// Publication alone never approves anything.
	time.Sleep(20 * time.Millisecond)
	if pendingDecided(f.app, pending) {
		t.Fatal("published approval auto-decided")
	}
	f.app.decideCLIRunV2(pending.id, false)
	native, err := call.wait(t)
	if err == nil || native != nil {
		t.Fatalf("refused callback returned native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("refused pending approval was not retired")
	}
}

func TestPrepareCLIRunV2LockClearsOnlyOwnedPending(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	call := callPrepareCLIRunV2(f.app, context.Background(), f.scope(t))
	pending := waitCLIRunV2Pending(t, f.app)

	f.app.Lock()
	native, err := call.wait(t)
	if err == nil || native != nil {
		t.Fatalf("lock published native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("lock left a pending v2 approval")
	}
	// A late owner click for the locked request decides nothing and creates no
	// newer approval.
	f.app.decideCLIRunV2(pending.id, true)
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("late approval recreated a pending request")
	}
	// Nothing may be prepared once the broker session is gone.
	if native, err := f.app.PrepareCLIRunV2(context.Background(), f.scope(t)); err == nil || native != nil {
		t.Fatalf("locked broker prepared native=%#v err=%v", native, err)
	}
}

func TestPrepareCLIRunV2ContextAndLateDecisionIsolation(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	ctxA, cancelA := context.WithCancel(context.Background())
	callA := callPrepareCLIRunV2(f.app, ctxA, f.scope(t))
	pendingA := waitCLIRunV2Pending(t, f.app)
	cancelA()
	if native, err := callA.wait(t); err == nil || native != nil {
		t.Fatalf("cancelled callback native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("cancelled pending approval was not retired")
	}

	callB := callPrepareCLIRunV2(f.app, context.Background(), f.scope(t))
	pendingB := waitCLIRunV2Pending(t, f.app)
	if pendingB.id == pendingA.id {
		t.Fatal("pending ids are not unique")
	}
	// A late decision carrying the retired request's id must not decide the
	// newer request.
	f.app.decideCLIRunV2(pendingA.id, true)
	if currentCLIRunV2Pending(f.app) != pendingB || pendingDecided(f.app, pendingB) {
		t.Fatal("late approval affected the newer pending request")
	}
	f.app.decideCLIRunV2(pendingB.id, false)
	if _, err := callB.wait(t); err == nil {
		t.Fatal("refused newer request was approved")
	}
}

func TestPrepareCLIRunV2RejectsStaleBrokerState(t *testing.T) {
	f := newCLIRunV2Fixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if native, err := f.app.PrepareCLIRunV2(ctx, f.scope(t)); err == nil || native != nil {
		t.Fatalf("cancelled ctx prepared native=%#v err=%v", native, err)
	}
	//lint:ignore SA1012 an explicit nil context must be refused, never dereferenced
	if native, err := f.app.PrepareCLIRunV2(nil, f.scope(t)); err == nil || native != nil {
		t.Fatalf("nil ctx prepared native=%#v err=%v", native, err)
	}

	wrongVault := f.scope(t)
	wrongVault.VaultPath = filepath.Join(t.TempDir(), "other.ll")
	if native, err := f.app.PrepareCLIRunV2(context.Background(), wrongVault); err == nil || native != nil {
		t.Fatalf("stale vault prepared native=%#v err=%v", native, err)
	}

	relativeRoot := f.scope(t)
	relativeRoot.Root = "relative/client-root"
	if native, err := f.app.PrepareCLIRunV2(context.Background(), relativeRoot); err == nil || native != nil {
		t.Fatalf("relative root prepared native=%#v err=%v", native, err)
	}

	// A scope pinned to a previous session epoch must be refused even though
	// the live session and vault path still match.
	staleEpoch := f.scope(t)
	f.app.brokerMu.Lock()
	f.app.brokerEpoch++
	f.app.brokerMu.Unlock()
	if native, err := f.app.PrepareCLIRunV2(context.Background(), staleEpoch); err == nil || native != nil {
		t.Fatalf("stale epoch prepared native=%#v err=%v", native, err)
	}
	f.app.brokerMu.Lock()
	f.app.brokerEpoch--
	f.app.brokerMu.Unlock()

	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("a rejected request left a pending approval")
	}
}

func TestPrepareCLIRunV2BusyRefusesSecondRequest(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	callA := callPrepareCLIRunV2(f.app, context.Background(), f.scope(t))
	pending := waitCLIRunV2Pending(t, f.app)

	if native, err := f.app.PrepareCLIRunV2(context.Background(), f.scope(t)); err == nil || native != nil {
		t.Fatalf("busy broker prepared native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != pending {
		t.Fatal("busy refusal replaced the owned pending approval")
	}
	f.app.decideCLIRunV2(pending.id, true)
	if native, err := callA.wait(t); err != nil || native == nil || native.Grant == nil {
		t.Fatalf("first request lost its approval: native=%#v err=%v", native, err)
	}
}

// TestCLIRunV2SummaryShowsFullEscapedScope pins the exact approval summary:
// every caller-controlled field is present, full-length and escaped, and target
// revisions are never truncated.
func TestCLIRunV2SummaryShowsFullEscapedScope(t *testing.T) {
	id := strings.Repeat("c", 32)
	revision := strings.Repeat("d", 64)
	digest := strings.Repeat("ab", 32)
	scope := browserhost.CLIRunV2Scope{
		Peer:       browserhost.Peer{User: "UID 1000", PID: 4242, Process: "/opt/locklark/desktop"},
		VaultPath:  "/vaults/work vault.ll",
		Root:       "/tmp/client root",
		ProfileID:  "deepseek",
		SpecID:     "deepseek-harness-v1",
		SpecDigest: digest,
		Request: personal.RunBundleRequest{
			Program:        "/usr/bin/env\nPROGRAM",
			Args:           []string{"a\nb", "plain", "x\x1b[31m"},
			Directory:      "/srv/work\tcwd",
			TimeoutSeconds: 45,
			HelperPath:     []string{"/opt/tools", "/usr/bin"},
			Passthrough:    map[string]string{"B_VAR": "two", "A_VAR": "one\nline"},
		},
		Targets: []personal.BundleTarget{{Slot: "token", Field: "password", ID: id, Revision: revision}},
		Epoch:   7,
	}
	want := []string{
		"Vault: /vaults/work vault.ll",
		"Root: /tmp/client root",
		"Profile: deepseek · Spec: deepseek-harness-v1",
		"SpecDigest: " + digest,
		"Epoch: 7",
		"Peer: UID 1000 · PID 4242",
		"Process: /opt/locklark/desktop",
		"Program: /usr/bin/env\\u{A}PROGRAM",
		"CWD: /srv/work\\u{9}cwd",
		"Timeout: 45s",
		"TokenEnv: ",
		"Args (3):",
		"  [1] a\\u{A}b",
		"  [2] plain",
		"  [3] x\\u{1B}[31m",
		"HelperPath (2):",
		"  [1] /opt/tools",
		"  [2] /usr/bin",
		"Passthrough (2):",
		"  A_VAR=one\\u{A}line",
		"  B_VAR=two",
		"Targets (1):",
		"  token ← password · " + id + " · " + revision,
	}
	got := cliV2SummaryLines(scope)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("summary mismatch:\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(strings.Join(got, "\n"), revision) || len(revision) != 64 {
		t.Fatal("summary truncated the full target revision")
	}
}

// TestCLIRunV2ApprovalViewPinsDecision proves the approval layout: a long scope
// scrolls in a bounded area while both decision buttons stay visible in the
// window, and a click on the visible button decides exactly that request.
func TestCLIRunV2ApprovalViewPinsDecision(t *testing.T) {
	f := newCLIRunV2Fixture(t)
	scope := f.scope(t)
	args := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		args = append(args, strings.Repeat("argument-", 8)+intString(i))
	}
	scope.Request.Args = args
	pending := &cliRunV2Pending{id: "layout-pending", scope: cloneCLIRunV2Scope(scope), decision: make(chan bool, 1)}
	f.app.brokerMu.Lock()
	f.app.cliV2Pending = pending
	f.app.brokerMu.Unlock()
	t.Cleanup(func() {
		f.app.brokerMu.Lock()
		if f.app.cliV2Pending == pending {
			f.app.cliV2Pending = nil
		}
		f.app.brokerMu.Unlock()
	})

	const width, height = 640, 480
	view := ui.NewTester(f.app.cliV2ApprovalView, width, height)
	if !view.HasText("Program: " + scope.Request.Program) {
		t.Fatal("approval view did not show the exact program")
	}
	approve, ok := view.Find(cliV2ApproveLabel)
	if !ok {
		t.Fatal("approval button missing")
	}
	refuse, ok := view.Find(cliV2RefuseLabel)
	if !ok {
		t.Fatal("refusal button missing")
	}
	for name, rect := range map[string]ui.Rect{cliV2ApproveLabel: approve, cliV2RefuseLabel: refuse} {
		if rect.X < 0 || rect.Y < 0 || rect.X+rect.W > width || rect.Y+rect.H > height {
			t.Fatalf("%s is not pinned inside the window: %#v", name, rect)
		}
		if rect.Y < height/2 {
			t.Fatalf("%s is not pinned below the scrolling scope: %#v", name, rect)
		}
	}
	if approve.Y != refuse.Y {
		t.Fatalf("decision buttons are not on the same pinned row: %#v %#v", approve, refuse)
	}
	// The deep end of the full argument list lies outside the visible window:
	// the scope is bounded and scrolled, not stretched to fit.
	last := "  [64] " + visible(args[63])
	lastRect, ok := view.Find(last)
	if !ok {
		t.Fatal("approval view did not build the full argument list")
	}
	if lastRect.Y+lastRect.H <= height {
		t.Fatalf("long scope was not clipped into the bounded scroll area: %#v", lastRect)
	}
	if err := view.Click(cliV2RefuseLabel); err != nil {
		t.Fatalf("pinned refusal button is not clickable: %v", err)
	}
	select {
	case approved := <-pending.decision:
		if approved {
			t.Fatal("refusal button approved the request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refusal button did not decide the pending request")
	}
}
