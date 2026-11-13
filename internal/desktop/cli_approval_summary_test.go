package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/localpath"
	"github.com/jihuayu/locklark/internal/personal"
)

// desktopPassthroughSentinel is deliberately synthetic: it must never appear in
// the native approval text, which lists passthrough names only.
const desktopPassthroughSentinel = "SYNTHETIC-PASSTHROUGH-VALUE-91c2"

// desktopNonceFixture is a well-formed nonce: protocol metadata that the
// native approval must neither display nor otherwise echo.
const desktopNonceFixture = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// desktopCLITargetID is a well-formed 32-hex item ID for the display-only
// fixture target. Request tests replace it with the seeded vault row's real ID
// and revision, which preparation needs to find.
const desktopCLITargetID = "00112233445566778899aabbccddeeff"

// desktopCLIScopeFixture is a fully populated, valid CLI-run scope for the
// built-in "gh" profile, including the platform naming rules the scope check
// requires. It carries a synthetic passthrough value and nonce so summary tests
// can prove neither appears.
func desktopCLIScopeFixture() browserhost.CLIRunScope {
	return browserhost.CLIRunScope{
		Profile:     "gh",
		TTY:         "/dev/ttys-fixture",
		TTYPlatform: runtime.GOOS,
		Nonce:       desktopNonceFixture,
		Program:     "/fixture/bin/gh",
		ProgramSH:   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		CWD:         "/fixture/work",
		TempRoot:    "/fixture/run-root",
		Args:        []string{"--hostname", "fixture", "api", "user"},
		Helper:      []string{"/fixture/helpers/one", "/fixture/helpers/two"},
		Passthru:    map[string]string{"GH_HOST": desktopPassthroughSentinel},
		Timeout:     90,
	}
}

func desktopCLITargetsFixture() []personal.CLIBrokerTarget {
	return []personal.CLIBrokerTarget{
		{Slot: "token", ID: desktopCLITargetID, Revision: "aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111", Field: "password"},
	}
}

func desktopPeerFixture() browserhost.Peer {
	return browserhost.Peer{User: "UID 501", PID: 4242, Process: "/fixture/bin/locklark"}
}

// summaryTexts joins every presented line, so absence checks cannot miss a
// value hiding in any section.
func summaryTexts(summary cliRunApprovalSummary) []string {
	all := append([]string(nil), summary.Peer...)
	for _, section := range summary.Sections {
		all = append(all, section.Heading)
		all = append(all, section.Lines...)
	}
	return append(all, summary.Warnings...)
}

func TestCLIRunApprovalSummaryPresentsFullScopeWithoutSecrets(t *testing.T) {
	peer, scope, targets := desktopPeerFixture(), desktopCLIScopeFixture(), desktopCLITargetsFixture()
	summary := cliRunApprovalSummaryFor(peer, "/fixture/vault.ll", scope, targets)
	texts := strings.Join(summaryTexts(summary), "\n")
	for _, want := range []string{
		// Authenticated peer, each user-supplied value quoted.
		`金库路径："/fixture/vault.ll"`,
		`本机用户："UID 501"`,
		`调用进程：PID 4242 · "/fixture/bin/locklark"`,
		// Every scope field that authorizes the run.
		`配置档："gh"`,
		`终端标识："/dev/ttys-fixture"`,
		`执行程序："/fixture/bin/gh"`,
		`程序固定：已固定 SHA-256 "` + scope.ProgramSH + `"`,
		`工作目录："/fixture/work"`,
		"超时限制：90 秒",
		`临时运行目录："/fixture/run-root"`,
		`[0] "--hostname"`, `[1] "fixture"`, `[2] "api"`, `[3] "user"`,
		`"/fixture/helpers/one"`, `"/fixture/helpers/two"`,
		// Targets with slot, field, ID and revision.
		`"token" ← "password"`,
		`条目 "` + targets[0].ID + `" · 修订 "` + targets[0].Revision + `"`,
		// Passthrough names only.
		"透传环境变量名（不显示值）",
		`"GH_HOST"`,
	} {
		if !strings.Contains(texts, want) {
			t.Fatalf("approval summary omitted %q:\n%s", want, texts)
		}
	}
	// Neither the passthrough value nor the nonce is part of the review text.
	for _, hidden := range []string{desktopPassthroughSentinel, desktopNonceFixture, scope.Nonce} {
		if strings.Contains(texts, hidden) {
			t.Fatalf("approval summary leaked %q:\n%s", hidden, texts)
		}
	}
	if strings.Contains(strings.ToLower(texts), "nonce") || strings.Contains(texts, "一次性随机数") {
		t.Fatalf("approval summary still names the nonce:\n%s", texts)
	}
	if len(summary.Warnings) < 2 {
		t.Fatalf("approval summary lacks the one-time disclosure warnings: %#v", summary.Warnings)
	}
}

// TestCLIRunApprovalSummaryQuotesControlCharacters proves no untrusted value can
// inject or hide a review line. Every user-supplied field carries CR/LF and a
// forged approval line; the summary must show the text only escaped inside
// quotes, keep each label on exactly one line, and never reveal a passthrough
// value or the nonce.
func TestCLIRunApprovalSummaryQuotesControlCharacters(t *testing.T) {
	const forged = "已伪造的批准范围行"
	const control = "\r\n" + forged + "："
	scope := desktopCLIScopeFixture()
	scope.TTY = "/dev/ttys-a" + control + "b"
	scope.Program = "/fixture/bin/gh" + control
	scope.CWD = "/fixture/work" + control
	scope.TempRoot = "/fixture/run-root" + control
	scope.Args = []string{"--hostname\r\n--token", "value\x1b[2J"}
	scope.Helper = []string{"/fixture/helpers" + control}
	scope.Passthru = map[string]string{"GH_HOST": desktopPassthroughSentinel}
	targets := desktopCLITargetsFixture()
	targets[0].Slot = "token" + control
	targets[0].Field = "password" + control
	peer := browserhost.Peer{User: "UID 501" + control, PID: 4242, Process: "/fixture/bin/locklark" + control}

	summary := cliRunApprovalSummaryFor(peer, "/fixture/vault.ll"+control, scope, targets)
	texts := summaryTexts(summary)
	joined := strings.Join(texts, "\n")
	// Escaped text is visible, in its quoted form only.
	for _, want := range []string{
		`金库路径："/fixture/vault.ll\r\n` + forged + `："`,
		`本机用户："UID 501\r\n` + forged + `："`,
		`调用进程：PID 4242 · "/fixture/bin/locklark\r\n` + forged + `："`,
		`终端标识："/dev/ttys-a\r\n` + forged + `：b"`,
		`执行程序："/fixture/bin/gh\r\n` + forged + `："`,
		`工作目录："/fixture/work\r\n` + forged + `："`,
		`临时运行目录："/fixture/run-root\r\n` + forged + `："`,
		`[0] "--hostname\r\n--token"`,
		`[1] "value\x1b[2J"`,
		`"/fixture/helpers\r\n` + forged + `："`,
		`"token\r\n` + forged + `：" ← "password\r\n` + forged + `："`,
		`"GH_HOST"`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("approval summary omitted escaped %q:\n%s", want, joined)
		}
	}
	// No raw CR, LF, escape, or other control character reached the text, and
	// no line starts with the forged approval text.
	for _, text := range texts {
		for _, r := range text {
			if unicode.IsControl(r) {
				t.Fatalf("control character %q reached the approval text: %q", r, text)
			}
		}
		if strings.HasPrefix(text, forged) {
			t.Fatalf("forged approval line injected: %q", text)
		}
	}
	// The forged text appears only inside quoted values: every occurrence
	// follows an escaped CR/LF.
	if got, want := strings.Count(joined, forged), 10; got != want {
		t.Fatalf("forged text appears %d times, want %d:\n%s", got, want, joined)
	}
	if got, want := strings.Count(joined, `\r\n`+forged), 10; got != want {
		t.Fatalf("forged text appears outside an escaped CR/LF %d times, want %d:\n%s", got, want, joined)
	}
	// The passthrough value and the nonce are still absent.
	for _, hidden := range []string{desktopPassthroughSentinel, desktopNonceFixture} {
		if strings.Contains(joined, hidden) {
			t.Fatalf("approval summary leaked %q:\n%s", hidden, joined)
		}
	}
}

// desktopSpoofRunes are runes that must never reach displayed text next to an
// invalid byte: C1 controls, the Unicode line/paragraph separators, and the
// bidi embedding/override controls.
var desktopSpoofRunes = []rune{0x85, 0x2028, 0x2029, 0x202b, 0x202e}

// desktopSpoofPath mixes one invalid byte with graphics, a C1 control, the
// Unicode line separator, and bidi overrides: "vault-<U+0085><U+2028><U+202B>
// edir","<U+202E>x\xff.pdf".
var desktopSpoofPath = "/fixture/vault-\u0085\u2028\u202bedir\",\"\u202ex\xff.pdf"

// desktopSpoofEscaped is the full visible escape of desktopSpoofPath as a Go
// string literal, with only printable, non-space runes kept verbatim.
const desktopSpoofEscaped = `"/fixture/vault-\u0085\u2028\u202bedir\",\"\u202ex\xff.pdf"`

// TestCLIRunApprovalSummaryQuotesInvalidUTF8 proves that a value with an
// invalid byte is escaped consistently with strconv.Quote for every other rune:
// visible graphics are kept, the invalid byte becomes a visible \xNN escape,
// and C1, line-separator, and bidi runes are escaped so they cannot reorder
// or hide the displayed path. The rendered view is checked too.
func TestCLIRunApprovalSummaryQuotesInvalidUTF8(t *testing.T) {
	scope := desktopCLIScopeFixture()
	scope.TTY = "/dev/ttys-\xff\xfe"
	summary := cliRunApprovalSummaryFor(desktopPeerFixture(), "/fixture/vault.ll", scope, nil)
	if got, want := summary.Sections[0].Lines[1], `终端标识："/dev/ttys-\xff\xfe"`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	peer := desktopPeerFixture()
	peer.User = desktopSpoofPath
	texts := summaryTexts(cliRunApprovalSummaryFor(peer, "/fixture/vault.ll", scope, nil))
	joined := strings.Join(texts, "\n")
	if !strings.Contains(joined, "本机用户："+desktopSpoofEscaped) {
		t.Fatalf("spoof path was not rendered as %s:\n%s", desktopSpoofEscaped, joined)
	}
	for _, r := range desktopSpoofRunes {
		if strings.ContainsRune(joined, r) {
			t.Fatalf("run %U reached the approval text:\n%s", r, joined)
		}
	}
	for _, want := range []string{`\u0085`, `\u2028`, `\u202b`, `\u202e`, `\xff`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("escaped %s missing from the approval text:\n%s", want, joined)
		}
	}

	a := dailyAppFixture(t)
	a.brokerMu.Lock()
	a.cliPending = &cliRunPending{
		id:      "fixture",
		peer:    peer,
		summary: cliRunApprovalSummaryFor(peer, "/fixture/vault.ll", desktopCLIScopeFixture(), desktopCLITargetsFixture()),
	}
	a.brokerMu.Unlock()
	tester := ui.NewTester(a.View, 1200, 3600)
	if !tester.HasText("本机用户：" + desktopSpoofEscaped) {
		t.Fatalf("native approval view did not render the escaped spoof path:\n%s", strings.Join(tester.Texts(), "\n"))
	}
	rendered := strings.Join(tester.Texts(), "\n")
	for _, r := range desktopSpoofRunes {
		if strings.ContainsRune(rendered, r) {
			t.Fatalf("run %U reached the native approval view:\n%s", r, rendered)
		}
	}
	a.brokerMu.Lock()
	a.cliPending = nil
	a.brokerMu.Unlock()
}

func TestCLIRunApprovalSummaryShowsUnpinnedProgramAndEmptyCollections(t *testing.T) {
	scope := desktopCLIScopeFixture()
	scope.ProgramSH = ""
	scope.Args = nil
	scope.Helper = nil
	scope.Passthru = nil
	scope.TokenEnv = ""
	texts := strings.Join(summaryTexts(cliRunApprovalSummaryFor(desktopPeerFixture(), "/fixture/vault.ll", scope, nil)), "\n")
	for _, want := range []string{
		"程序固定：未固定 · " + cliRunUnpinnedLabel,
		"命令参数（共 0 项）", cliRunEmptyLabel,
		"辅助 PATH 目录", "透传环境变量名（不显示值）",
		`终端标识："/dev/ttys-fixture"`,
	} {
		if !strings.Contains(texts, want) {
			t.Fatalf("unpinned summary omitted %q:\n%s", want, texts)
		}
	}
	if strings.Contains(texts, cliRunTokenEnvPrefix) {
		t.Fatalf("empty dynamic token name still rendered:\n%s", texts)
	}
	if strings.Contains(texts, desktopNonceFixture) {
		t.Fatalf("nonce rendered:\n%s", texts)
	}
}

// TestCLIRunApprovalSummaryShowsCanonicalProfile checks that a fully populated
// scope for the built-in gh profile passes the shared request check, the same
// check that runs before native approval, and still renders without secrets.
func TestCLIRunApprovalSummaryShowsCanonicalProfile(t *testing.T) {
	scope, targets := desktopCLIScopeFixture(), desktopCLITargetsFixture()
	request := browserhost.CLIRunBrokerRequest{V: 1, VaultPath: "/fixture/vault.ll", Scope: scope, Targets: targets}
	wire, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(wire, []byte(`"tty_identity":"/dev/ttys-fixture"`)) || !bytes.Contains(wire, []byte(`"passthrough_env":{"GH_HOST":`)) {
		t.Fatalf("scope wire names are not snake_case: %s", wire)
	}
	summary := cliRunApprovalSummaryFor(desktopPeerFixture(), "/fixture/vault.ll", scope, targets)
	texts := strings.Join(summaryTexts(summary), "\n")
	if !strings.Contains(texts, `配置档："gh"`) || !strings.Contains(texts, `"GH_HOST"`) {
		t.Fatalf("canonical profile summary incomplete:\n%s", texts)
	}
	if strings.Contains(texts, desktopPassthroughSentinel) || strings.Contains(texts, desktopNonceFixture) {
		t.Fatalf("canonical profile summary leaked secret material:\n%s", texts)
	}
}

// The native view must render the same scope it presents, keep the peer line
// and the explicit approve-once/refuse buttons, and silently refuse to render
// when nothing is pending. It must show neither the nonce nor a passthrough
// value.
func TestCLIRunApprovalViewRendersScopeWithoutSecrets(t *testing.T) {
	a := dailyAppFixture(t)
	a.brokerMu.Lock()
	a.cliPending = &cliRunPending{
		id:      "fixture",
		peer:    desktopPeerFixture(),
		summary: cliRunApprovalSummaryFor(desktopPeerFixture(), "/fixture/vault.ll", desktopCLIScopeFixture(), desktopCLITargetsFixture()),
		decided: false,
	}
	a.brokerMu.Unlock()

	tester := ui.NewTester(a.View, 1200, 3600)
	for _, want := range []string{
		cliRunApprovalTitle,
		`调用进程：PID 4242 · "/fixture/bin/locklark"`,
		`配置档："gh"`,
		`终端标识："/dev/ttys-fixture"`,
		`执行程序："/fixture/bin/gh"`,
		`工作目录："/fixture/work"`,
		"超时限制：90 秒",
		`临时运行目录："/fixture/run-root"`,
		`"token" ← "password"`,
		desktopCLITargetID,
		`"GH_HOST"`,
		cliRunApproveLabel, cliRunRefuseLabel,
	} {
		if !tester.HasText(want) {
			t.Fatalf("native CLI approval did not render %q", want)
		}
	}
	texts := strings.Join(tester.Texts(), "\n")
	for _, hidden := range []string{desktopPassthroughSentinel, desktopNonceFixture} {
		if strings.Contains(texts, hidden) {
			t.Fatalf("native CLI approval rendered %q: %s", hidden, texts)
		}
	}

	a.brokerMu.Lock()
	a.cliPending = nil
	a.brokerMu.Unlock()
	tester = ui.NewTester(a.View, 1200, 3600)
	if tester.HasText(cliRunApprovalTitle) || tester.HasText(cliRunApproveLabel) {
		t.Fatal("native CLI approval rendered without a pending request")
	}
}

// cliRunCapturedHandlers are the closures the native view wired for one review.
type cliRunCapturedHandlers struct {
	approve, refuse func()
}

// captureCLIRunHandlers installs a factory that records the approve and refuse
// closures cliApprovalView builds: next returns the last pair built since its
// previous call. The wrapper passes through to the production factory, so the
// captured closures are the real handlers the view wired. The previous factory
// is restored when the test ends.
func captureCLIRunHandlers(t *testing.T) func() cliRunCapturedHandlers {
	t.Helper()
	previous := defaultCLIRunHandlerFactory
	t.Cleanup(func() { defaultCLIRunHandlerFactory = previous })
	var mu sync.Mutex
	var captured cliRunCapturedHandlers
	built := false
	defaultCLIRunHandlerFactory = func(a *App, current, snapshot *cliRunPending) (approve, refuse func()) {
		approve, refuse = previous(a, current, snapshot)
		mu.Lock()
		captured, built = cliRunCapturedHandlers{approve: approve, refuse: refuse}, true
		mu.Unlock()
		return approve, refuse
	}
	return func() cliRunCapturedHandlers {
		mu.Lock()
		defer mu.Unlock()
		if !built {
			t.Fatal("native approval view did not build its handlers")
		}
		built = false
		return captured
	}
}

// TestCLIRunApprovalStaleButtonsStayBoundToRenderedReview renders review A and
// captures the exact approve/refuse closures cliApprovalView wired for it,
// then retires A and makes B pending, which renders at A's geometry (only the
// same-length vault path differs in case). Invoking A's captured closures must
// not decide B, which stays current and undecided. B's own approve closure,
// built by the same factory the view uses, decides B exactly once.
//
// The closures are invoked directly rather than clicked: the UI tester
// hit-tests the latest frame, which already shows B, so a click through A's
// window cannot reach A's handlers once B has laid out.
func TestCLIRunApprovalStaleButtonsStayBoundToRenderedReview(t *testing.T) {
	a := dailyAppFixture(t)
	a.notifyBrowserBrokerUnlocked()
	peer := desktopPeerFixture()
	scope := desktopCLIScopeFixture()
	targets := desktopCLITargetsFixture()
	// A and B are bound like a production review: the exact unlocked session
	// and broker epoch are current when B is approved. Each call still returns
	// a distinct pointer, so stale pointers never alias a newer review.
	pending := func(id, vault string) *cliRunPending {
		a.brokerMu.Lock()
		s, epoch := a.brokerSession, a.brokerEpoch
		a.brokerMu.Unlock()
		return &cliRunPending{
			id:       id,
			peer:     peer,
			summary:  cliRunApprovalSummaryFor(peer, vault, scope, targets),
			session:  s,
			epoch:    epoch,
			decision: make(chan bool, 1),
		}
	}
	next := captureCLIRunHandlers(t)

	reviewA := pending("review-a", "/Fixture/vault.ll")
	a.brokerMu.Lock()
	a.cliPending = reviewA
	a.brokerMu.Unlock()
	view := ui.NewTester(a.View, 1200, 3600)
	approveA, _ := view.Find(cliRunApproveLabel)
	refuseA, _ := view.Find(cliRunRefuseLabel)
	handlersA := next()

	// A frame after the swap runs its input pass before building, so the
	// decision input pass already sees B as pending and may build no handlers.
	// Retire A and install B under one lock acquisition, exactly as
	// finishCLIRunApproval followed by B's installation does in production.
	reviewB := pending("review-b", "/Fixture/vault.ll")
	a.brokerMu.Lock()
	if a.cliPending == reviewA {
		a.cliPending = nil
	}
	a.cliPending = reviewB
	a.brokerMu.Unlock()
	// The next render builds B: the summary differs from A's, so the frame
	// cannot reuse A's layout.
	view.Frame()
	handlersB := next()
	// B's summary lines lay out exactly as A's, so a stale view cannot be told
	// apart by geometry; only the behaviour can.
	if approveB, _ := view.Find(cliRunApproveLabel); approveB != approveA {
		t.Fatalf("fixture lost its point: A's button at %v, B's at %v", approveA, approveB)
	}
	if got, _ := view.Find(cliRunRefuseLabel); got != refuseA {
		t.Fatal("review B did not render at A's layout")
	}

	// A's captured closures decide nothing now: B stays current and undecided,
	// and A is never signalled.
	handlersA.approve()
	handlersA.refuse()
	select {
	case d := <-reviewB.decision:
		t.Fatalf("A's stale approve/refuse decided B: %v", d)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case d := <-reviewA.decision:
		t.Fatalf("a stale A handler signalled A: %v", d)
	case <-time.After(20 * time.Millisecond):
	}
	a.brokerMu.Lock()
	current, aDecided, bDecided := a.cliPending, reviewA.decided, reviewB.decided
	a.brokerMu.Unlock()
	if current != reviewB || aDecided || bDecided {
		t.Fatalf("stale handlers changed state: B current=%v A.decided=%v B.decided=%v", current == reviewB, aDecided, bDecided)
	}

	// B's own approve closure, built by the same factory, decides B once.
	handlersB.approve()
	select {
	case d := <-reviewB.decision:
		if !d {
			t.Fatal("B refused despite approve")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B's own approve handler did not decide B")
	}
	handlersB.refuse()
	handlersA.approve()
	select {
	case d := <-reviewB.decision:
		t.Fatalf("B was decided twice: %v", d)
	case <-time.After(20 * time.Millisecond):
	}
}

// TestCLIRunApprovalViewRacesFinish renders while finishCLIRunApproval keeps
// replacing the pending summary. The view snapshots it under brokerMu and
// renders outside the lock; run with -race, this fails if the slice headers are
// copied after the lock is released. It also proves a retired review renders
// nothing.
func TestCLIRunApprovalViewRacesFinish(t *testing.T) {
	a := dailyAppFixture(t)
	summary := cliRunApprovalSummaryFor(desktopPeerFixture(), "/fixture/vault.ll", desktopCLIScopeFixture(), desktopCLITargetsFixture())
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			p := &cliRunPending{id: "fixture", peer: desktopPeerFixture(), summary: summary}
			a.brokerMu.Lock()
			a.cliPending = p
			a.brokerMu.Unlock()
			a.finishCLIRunApproval(p)
		}
	}()
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		tester := ui.NewTester(a.View, 1200, 3600)
		for _, text := range tester.Texts() {
			if strings.Contains(text, "调用进程") && !strings.Contains(text, `"PID 4242"`) && !strings.Contains(text, `PID 4242 · "/fixture/bin/locklark"`) {
				t.Fatalf("partially rendered summary line: %q", text)
			}
		}
	}
	close(stop)
	<-done
	a.brokerMu.Lock()
	pending := a.cliPending
	a.brokerMu.Unlock()
	if pending != nil {
		t.Fatal("review left pending")
	}
	tester := ui.NewTester(a.View, 1200, 3600)
	if tester.HasText(cliRunApprovalTitle) {
		t.Fatal("retired review still rendered")
	}
}

// desktopHandlerFixtureDirs are the private directories the handler fixture
// creates below its one resolved root.
var desktopHandlerFixtureDirs = []string{"bin", "work", "helpers-one", "helpers-two"}

// desktopCLIRunFixture unlocks a fresh app, seeds one login in its vault, and
// binds the broker to that unlocked session. It returns the exact request: the
// desktopCLI* fixtures with the wire target ID and revision taken from the
// seeded row, which the preparation path needs to find, and host-native
// private names (TTY, program, working directory, helper directories and the
// real run root) under one resolved private root, which preparation validates
// and binds.
func desktopCLIRunFixture(t *testing.T) (*App, browserhost.BrokerCLIRequest) {
	t.Helper()
	a := dailyAppFixture(t)
	if _, e := a.session.AddLogin("CLI login", "cli-user", "cli-password"); e != nil {
		t.Fatal(e)
	}
	rows, e := a.session.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	a.notifyBrowserBrokerUnlocked()
	scope := desktopCLIScopeFixture()
	// Preparation binds the private run root it validates and executes the
	// request, so only this handler fixture replaces every POSIX display name
	// with a host-native name below one private, resolved directory: the
	// declared TTY, the program (.exe on Windows), the working directory, the
	// helper directories and the real run root. Every one is absolute and
	// clean under the host's own filepath rules, and each exists. Summary-only
	// fixtures keep the fixed /fixture/ names for their expected display text;
	// live-request tests that need the real terminal replace the TTY later.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal("private root:", e)
	}
	dirs := make(map[string]string, len(desktopHandlerFixtureDirs))
	for _, name := range desktopHandlerFixtureDirs {
		dir := filepath.Join(root, name)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal("private fixture directory:", e)
		}
		dirs[name] = dir
	}
	program := filepath.Join(dirs["bin"], "gh")
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	if e := os.WriteFile(program, []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
		t.Fatal("fixture program:", e)
	}
	scope.TTY = filepath.Join(root, "ttys-fixture")
	scope.Program = program
	scope.CWD = dirs["work"]
	scope.Helper = []string{dirs["helpers-one"], dirs["helpers-two"]}
	scope.TempRoot = filepath.Join(root, "run-root")
	// A live request needs a fresh single-use nonce for every test: the broker
	// consumes it per peer for the whole process. Summary-only fixtures keep
	// the static one because they never reach the broker.
	scope.Nonce = desktopFreshNonce(t)
	req := browserhost.BrokerCLIRequest{V: 1, VaultPath: a.session.VaultPath(), Scope: scope, Targets: desktopCLITargetsFixture()}
	req.Targets[0].ID, req.Targets[0].Revision = rows[0].ID, rows[0].Revision
	return a, req
}

// TestCLIRunHandlerReturnsExactPreparedValuesAndReceipt asserts the positive
// contract directly: an approved request over the exact unlocked session
// returns V=1 with the exact prepared vault bytes and the canonical
// RunBundlePreparationReceipt (not a legacy Values payload), and the handler
// clears the callback request containers afterwards.
func TestCLIRunHandlerReturnsExactPreparedValuesAndReceipt(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	want := desktopVaultPassword(t, a.session, req.Targets)
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return true, nil }
	resp, e := a.handleCLIRunUnit(context.Background(), desktopPeerFixture(), req)
	desktopAssertCLIPrepared(t, "direct", resp, e, desktopCLITargetsFixture())
	desktopAssertCLIPreparedBytes(t, "direct", resp, "token", want)
	desktopReleaseCLIPrepared(resp)
	desktopAssertCallerTargetsCleared(t, "direct", req)
}

// desktopSkipOrFailWithoutTTY records that a terminal-dependent check could
// not run because this process has no controlling terminal. Under the PTY
// smoke run (BROWSERHOST_TTY_SMOKE=1) a controlling terminal is required, so
// the same condition fails instead of skipping.
func desktopSkipOrFailWithoutTTY(t *testing.T, reason string) {
	t.Helper()
	if smoke := os.Getenv("BROWSERHOST_TTY_SMOKE"); smoke != "" {
		t.Fatalf("PTY smoke requires a controlling terminal: %s", reason)
	}
	t.Skipf("no controlling terminal: %s", reason)
}

// desktopSelfTTYScope points scope at this process's own controlling terminal
// exactly as the CLI would declare it. It keeps TTYPeerID empty: the broker
// refuses any supplied peer ID. The kernel self identity is the only guard: a
// process without a controlling terminal has no positive socket case, which
// skips outside strict mode and fails under BROWSERHOST_TTY_SMOKE=1. Whether
// the broker's peer terminal is attestable is decided by the live request.

func desktopSelfTTYScope(t *testing.T, scope browserhost.CLIRunScope) browserhost.CLIRunScope {
	t.Helper()
	name, _, e := browserhost.CurrentTTYIdentity()
	if e != nil || name == "" {
		desktopSkipOrFailWithoutTTY(t, "self terminal identity unavailable")
	}
	scope.TTY = name
	scope.TTYPlatform = browserhost.CLIRunTTYPlatform()
	scope.TTYPeerID = ""
	return scope
}

// desktopStartBrokerEndpoint starts a real desktop broker with callbacks on a
// private socket in /tmp (some CI TMPDIR ancestors are not trusted for local
// IPC) and returns its endpoint. It reports whether the environment supports
// the socket path at all.
func desktopStartBrokerEndpoint(t *testing.T, a *App, callbacks browserhost.BrokerCallbacks) (string, bool) {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "llb-")
	if e != nil || os.Chmod(dir, 0700) != nil {
		t.Fatal("private test directory")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if _, e := localpath.TrustedTemporaryParent(dir); e != nil {
		return "", false
	}
	sock := filepath.Join(dir, "b.sock")
	t.Setenv("LOCKLARK_BROWSER_SOCKET", sock)
	b := browserhost.NewBroker(callbacks)
	if e := b.Start(sock); e != nil {
		t.Fatalf("broker did not start: %v", e)
	}
	a.brokerMu.Lock()
	a.broker = b
	a.brokerEndpoint = sock
	a.brokerMu.Unlock()
	t.Cleanup(a.stopBrowserBroker)
	return sock, true
}

// TestCLIRunSocketReturnsExactPreparedValuesAndReceipt drives the handler
// through the production socket path with the real client: a broker listener,
// the production controlling-terminal gate, the strict client decoder, and the
// broker's slot-bound reply encoder. The decoded reply must be V=1 with the
// exact prepared bytes and the canonical RunBundlePreparationReceipt, and the
// handler's own reply (observed before the broker zeroes its copy after
// encoding) must carry those same values.
func TestCLIRunSocketReturnsExactPreparedValuesAndReceipt(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	req.Scope = desktopSelfTTYScope(t, req.Scope)
	want := desktopVaultPassword(t, a.session, req.Targets)
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return true, nil }
	seen := make(chan browserhost.BrokerCLIResponse, 1)
	callbacks := a.browserBrokerCallbacks()
	inner := callbacks.HandleCLIRun
	callbacks.HandleCLIRun = func(ctx context.Context, peer browserhost.Peer, got browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
		resp, e := inner(ctx, peer, got)
		seen <- resp
		return resp, e
	}
	if _, ok := desktopStartBrokerEndpoint(t, a, callbacks); !ok {
		desktopSkipOrFailWithoutTTY(t, "trusted temporary directory unavailable")
	}
	resp, e := browserhost.RequestCLIRun(context.Background(), req)
	if e != nil {
		t.Fatalf("socket approved CLI: %v", e)
	}
	desktopAssertCLIPrepared(t, "socket client", resp, nil, req.Targets)
	desktopAssertCLIPreparedBytes(t, "socket client", resp, "token", want)
	var observed browserhost.BrokerCLIResponse
	select {
	case observed = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("broker callback was not reached")
	}
	// The handler handed the broker the audited receipt the client then
	// decoded. Its byte buffers are zeroed by the broker before the callback
	// returns (clearCLIRunResponse), so they cannot be compared here; the
	// exact bytes are asserted on the client side above and on the direct path.
	if observed.V != 1 || observed.Receipt != resp.Receipt || observed.Receipt.Status != personal.RunBundlePreparationStatus {
		t.Fatalf("callback reply lost the audited receipt: %#v vs %#v", observed.Receipt, resp.Receipt)
	}
	desktopReleaseCLIPrepared(resp)
}

// TestCLIRunHandlerRefusesStaleOrChangedSession runs the explicit-refusal matrix
// through the request-level handler and proves no value is prepared or left
// behind: an approver denial, an approver error, a cancellation, a vault
// mismatch, a session replaced after approval, and a stale broker epoch.
func TestCLIRunHandlerRefusesStaleOrChangedSession(t *testing.T) {
	approve := func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return true, nil }
	cases := []struct {
		name  string
		setup func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error)
		ctx   func() context.Context
	}{
		{name: "denied", setup: func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
			return func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return false, nil }
		}},
		{name: "approver-error", setup: func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
			return func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
				return true, errors.New("approval transport failed")
			}
		}},
		{name: "cancelled", setup: func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
			return approve
		}, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{name: "session-replaced-after-approval", setup: func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
			return func(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (bool, error) {
				a.notifyBrowserBrokerUnlocked()
				a.brokerMu.Lock()
				a.brokerEpoch++
				a.brokerMu.Unlock()
				return true, nil
			}
		}},
		{name: "locked-after-approval", setup: func(a *App) func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
			return func(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (bool, error) {
				// Lock the exact session the handler captured, synchronously, so
				// the recheck after this approval sees it locked.
				a.brokerMu.Lock()
				captured := a.brokerSession
				a.brokerMu.Unlock()
				if captured == nil || !captured.Unlocked() {
					t.Error("approval ran without a captured unlocked session")
				}
				captured.Lock()
				return true, nil
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, req := desktopCLIRunFixture(t)
			a.cliApprover = tc.setup(a)
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			resp, e := a.handleCLIRunUnit(ctx, desktopPeerFixture(), req)
			if e == nil || errors.Is(e, browserhost.ErrBrokerUnavailable) || !errors.Is(e, errCLIRunRefused) {
				t.Fatalf("want the fixed refusal, got %v", e)
			}
			// A refusal is proven by its reply: no values, no partial receipt.
			if desktopHasCLIPrepared(resp) || resp.V != 0 || resp.Receipt != (personal.RunBundlePreparationReceipt{}) {
				t.Fatalf("%s: refused run returned a partial reply: %#v", tc.name, resp)
			}
		})
	}
}

// TestCLIRunHandlerVaultMismatchIsRefusal proves a different vault path is a
// fixed refusal, not the unavailable sentinel, and discloses nothing.
func TestCLIRunHandlerVaultMismatchIsRefusal(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return true, nil }
	req.VaultPath = "/fixture/other.ll"
	resp, e := a.handleCLIRunUnit(context.Background(), desktopPeerFixture(), req)
	if e != errCLIRunRefused || desktopHasCLIPrepared(resp) {
		t.Fatalf("vault mismatch: %v %#v", e, resp)
	}
	desktopAssertCallerTargetsCleared(t, "vault-mismatch", req)
}

// TestCLIRunHandlerEntryUnavailableIsExactSentinel proves the two distinct
// starting states are classified differently and that neither can fall back
// after approval. A request that begins with no unlocked broker session (none,
// or one that is already locked) is the exact browserhost.ErrBrokerUnavailable
// entry state; a request whose captured session becomes locked after approval
// is the fixed refusal, never unavailable. No path reached native approval in
// the unavailable cases.
func TestCLIRunHandlerEntryUnavailableIsExactSentinel(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T, a *App)
	}{
		{name: "no-session", install: func(t *testing.T, a *App) {
			a.brokerMu.Lock()
			a.brokerSession = nil
			a.brokerMu.Unlock()
		}},
		{name: "starting-locked", install: func(t *testing.T, a *App) {
			// A temporarily unlocked session that is locked when the request
			// starts: the lock is requested before entry, so the entry state
			// itself admits no idle expiry.
			locked, e := personal.UnlockSession(a.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			locked.Lock()
			a.brokerMu.Lock()
			a.brokerSession = locked
			a.brokerMu.Unlock()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, req := desktopCLIRunFixture(t)
			a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
				t.Fatal("unavailable entry state still requested native approval")
				return false, nil
			}
			tc.install(t, a)
			resp, e := a.handleCLIRunUnit(context.Background(), desktopPeerFixture(), req)
			if e != browserhost.ErrBrokerUnavailable {
				t.Fatalf("want the exact unavailable sentinel, got %v", e)
			}
			if desktopHasCLIPrepared(resp) {
				t.Fatalf("unavailable run disclosed values: %#v", resp)
			}
		})
	}
}

// A pending review never outlives its lock: locking the app while the native
// review is waiting makes the request waiter return the fixed refusal, and the
// request-level handler then discloses nothing. Every byte buffer is cleared
// and the callback request containers no longer hold the approved scope.
func TestCLIRunApprovalScopeIsDiscardedOnLock(t *testing.T) {
	a, req := desktopCLIRunFixture(t)
	a.notifyBrowserBrokerUnlocked()
	result := make(chan cliRunApprovalResult, 1)
	go func() {
		resp, e := a.handleCLIRunUnit(context.Background(), desktopPeerFixture(), req)
		result <- cliRunApprovalResult{approved: desktopHasCLIPrepared(resp), err: e}
	}()
	waitCLIRunApprovalPending(t, a)
	a.Lock()
	r := waitCLIRunApprovalResult(t, result)
	if r.approved || !errors.Is(r.err, errCLIRunRefused) {
		t.Fatalf("lock did not refuse the pending disclosure: %+v", r)
	}
	a.brokerMu.Lock()
	pending := a.cliPending
	a.brokerMu.Unlock()
	if pending != nil {
		t.Fatal("lock left the pending review behind")
	}
}
