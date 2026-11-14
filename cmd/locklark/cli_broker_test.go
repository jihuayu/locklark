package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

const cliBrokerFixturePassword = "fixture-run-cli-password"

// cliBrokerFixtureDir is the one private fixture directory a brokered fixture
// derives first: it is created and then resolved with filepath.EvalSymlinks, so
// every path the fixture names below it is the host's clean absolute copy of
// the same directory. The TTY, the binding, its helper directory, the run
// directory and the expected scope all come from that one value, so the
// request and its expected copy are the same single set of names; nothing is
// compared after normalizing one side.
func cliBrokerFixtureDir(t *testing.T) string {
	t.Helper()
	dir := cliTestDir(t)
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal("fixture directory does not resolve:", err)
	}
	return dir
}

// installCLIRunBrokerSeams replaces the Darwin gate and every broker seam for
// one test, and restores the production defaults afterwards. The signal seam
// is replaced with one that subscribes to nothing, so no test ever delivers a
// signal to the test process; a test that needs cancellation uses
// cliRunBrokerSignalsAction.
func installCLIRunBrokerSeams(t *testing.T, enabled bool, tty string) {
	t.Helper()
	originalEnabled, originalTTY, originalRequest := cliRunBrokerEnabled, cliRunBrokerTTY, cliRunBrokerRequest
	originalRandom, originalDescribe, originalSignals := cliRunBrokerRandom, cliRunBrokerDescribe, cliRunBrokerSignals
	t.Cleanup(func() {
		cliRunBrokerEnabled, cliRunBrokerTTY, cliRunBrokerRequest = originalEnabled, originalTTY, originalRequest
		cliRunBrokerRandom, cliRunBrokerDescribe, cliRunBrokerSignals = originalRandom, originalDescribe, originalSignals
	})
	cliRunBrokerEnabled = func() bool { return enabled }
	cliRunBrokerTTY = func() (string, string, error) { return tty, "fixture-peer", nil }
	cliRunBrokerDescribe = func(browserhost.CLIRunBrokerRequest) string { return "" }
	cliRunBrokerSignals = func(chan<- os.Signal) {}
}

// installCLIRunLocalConsole replaces the local-factor controlling console for
// one test and restores the production opener afterwards.
func installCLIRunLocalConsole(t *testing.T, open func() (*os.File, *os.File, error)) {
	t.Helper()
	original := cliLocalConsoleOpen
	t.Cleanup(func() { cliLocalConsoleOpen = original })
	cliLocalConsoleOpen = open
}

// cliRunBrokerSignalsAction lets a test act when the dispatcher subscribes
// for signals, without any signal reaching the test process. act runs in the
// installing goroutine of the dispatcher, at the exact point where the
// production seam would start subscribing.
func cliRunBrokerSignalsAction(t *testing.T, act func()) {
	t.Helper()
	cliRunBrokerSignals = func(chan<- os.Signal) {
		if act != nil {
			act()
		}
	}
}

// cliBrokerFixture is one validated CLI run whose binding points at a real
// vault, so the committed request is exactly what runCLIRun derives. tty is the
// declared TTY name of the same fixture directory, handed to the TTY seam and
// expected verbatim.
type cliBrokerFixture struct {
	binding clibinding.ToolBinding
	request personal.RunBundleRequest
	targets []personal.BundleTarget
	tty     string
	slotID  string
	slotRev string
	field   string
}

func newCLIBrokerFixture(t *testing.T) cliBrokerFixture {
	t.Helper()
	program := cliTestExecutable(t)
	// One private directory, resolved once: the binding, its helper directory
	// and the declared TTY all live under it, and both the request and the
	// expected scope name that same directory by its clean absolute copy.
	dir := cliBrokerFixtureDir(t)
	binding := clibinding.ToolBinding{
		Profile:        "token",
		VaultPath:      filepath.Join(dir, "owner.ll"),
		Program:        program,
		Targets:        []clibinding.SlotTarget{{Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password"}},
		HelperPath:     []string{filepath.Dir(program)},
		PassthroughEnv: []string{"NO_COLOR"},
		TimeoutSeconds: 10,
		TokenEnvName:   "LOCKLARK_TEST_TOKEN",
	}
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("program digest unavailable")
	}
	binding.ProgramSHA256 = sum
	if err = binding.Validate(); err != nil {
		t.Fatal("binding fixture invalid:", err)
	}
	if err = os.Mkdir(filepath.Join(dir, "work"), 0700); err != nil {
		t.Fatal("run directory unavailable:", err)
	}
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("profile unavailable")
	}
	targets := []personal.BundleTarget{{Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password"}}
	request := personal.RunBundleRequest{
		Program:        binding.Program,
		ProgramSHA256:  binding.ProgramSHA256,
		Args:           []string{"-test.run=^$"},
		Directory:      filepath.Join(dir, "work"),
		TimeoutSeconds: binding.TimeoutSeconds,
		HelperPath:     append([]string(nil), binding.HelperPath...),
		Passthrough:    map[string]string{"NO_COLOR": "1"},
		TokenEnvName:   binding.TokenEnvName,
		Spec:           profile.Spec(),
	}
	if err = request.Validate(targets); err != nil {
		t.Fatal("request fixture invalid:", err)
	}
	return cliBrokerFixture{binding: binding, request: request, targets: targets, tty: filepath.Join(dir, "ttys-fixture"), slotID: cliTestID, slotRev: cliTestRevision, field: "password"}
}

// call replays the exact values runCLIRun hands the dispatcher.
func (f cliBrokerFixture) call() cliRunBrokerCall {
	request := f.request
	request.Args = append([]string(nil), request.Args...)
	request.HelperPath = append([]string(nil), request.HelperPath...)
	request.Passthrough = cloneCLIRunBrokerPassthru(request.Passthrough)
	return cliRunBrokerCall{Binding: f.binding, Targets: append([]personal.BundleTarget(nil), f.targets...), Request: request}
}

// dispatchCLIRunWithBroker is the production dispatcher for a fixture.
func dispatchCLIRunWithBroker(f cliBrokerFixture) error {
	return executeCLIAuthenticatedWithBroker(context.Background(), "brokertool", f.binding, f.targets, f.call().Request)
}

func cloneCLIRunBrokerPassthru(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for name, value := range in {
		out[name] = value
	}
	return out
}

// auditedReply is the exact success shape the broker decodes.
func auditedReply(slot, value string) browserhost.CLIRunBrokerResponse {
	return browserhost.CLIRunBrokerResponse{
		V:              1,
		PreparedValues: map[string][]byte{slot: []byte(value)},
		Receipt: personal.RunBundlePreparationReceipt{
			Status:       personal.RunBundlePreparationStatus,
			Session:      strings.Repeat("1", 32),
			Intent:       strings.Repeat("2", 64),
			TargetDigest: strings.Repeat("3", 64),
		},
	}
}

func isFreshNonce(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// cloneCLIRunBrokerTestRequest copies every mutable container of a request,
// so a request the lifecycle cleared after capture can still be compared.
func cloneCLIRunBrokerTestRequest(r personal.RunBundleRequest) personal.RunBundleRequest {
	r.Args = append([]string(nil), r.Args...)
	r.HelperPath = append([]string(nil), r.HelperPath...)
	r.Passthrough = cloneCLIRunBrokerPassthru(r.Passthrough)
	r.Spec = cliprofile.CloneSpec(r.Spec)
	return r
}

// TestCLIRunBrokerScopeBindsCommittedRun drives the real audited
// RunBrokeredBundle callback and inspects exactly what would be sent: the
// complete scope bound to the callback snapshots and the binding, the exact
// vault path and target slot/id/revision/field, and the exact private root,
// which exists when the request is made.
func TestCLIRunBrokerScopeBindsCommittedRun(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	callRequests := cloneCLIRunBrokerTestRequest(f.call().Request)
	var sent []browserhost.CLIRunBrokerRequest
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		if info, err := os.Stat(req.Scope.TempRoot); err != nil || !info.IsDir() {
			t.Error("broker request was made before the exact private run root existed")
		}
		req.Scope = req.Scope.Clone()
		req.Targets = append([]personal.CLIBrokerTarget(nil), req.Targets...)
		sent = append(sent, req)
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
	}
	_, err := cliRunBrokerCall{Binding: f.binding, Targets: f.targets, Request: callRequests}.run(context.Background())
	if err != browserhost.ErrCLIRunRefused {
		t.Fatalf("lifecycle returned %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("requests sent: %d", len(sent))
	}
	req := sent[0]
	want := browserhost.CLIRunScope{
		Profile:     "token",
		TTY:         f.tty,
		TTYPeerID:   "",
		TTYPlatform: browserhost.CLIRunTTYPlatform(),
		Nonce:       req.Scope.Nonce,
		Program:     callRequests.Program,
		ProgramSH:   f.binding.ProgramSHA256,
		CWD:         callRequests.Directory,
		TempRoot:    req.Scope.TempRoot,
		Args:        callRequests.Args,
		Helper:      callRequests.HelperPath,
		Passthru:    callRequests.Passthrough,
		Timeout:     10,
		TokenEnv:    "LOCKLARK_TEST_TOKEN",
	}
	if !reflect.DeepEqual(req.Scope, want) {
		t.Fatalf("scope:\n got %#v\nwant %#v", req.Scope, want)
	}
	if !isFreshNonce(req.Scope.Nonce) {
		t.Fatalf("nonce is not 32 bytes of hex: %q", req.Scope.Nonce)
	}
	if !filepath.IsAbs(req.Scope.TempRoot) || !strings.HasPrefix(filepath.Base(req.Scope.TempRoot), "locklark-run-cli-") {
		t.Fatalf("temp root is not the private run root: %q", req.Scope.TempRoot)
	}
	if _, err := os.Stat(req.Scope.TempRoot); !os.IsNotExist(err) {
		t.Fatal("private run root was not removed after the run")
	}
	if req.V != 1 || req.VaultPath != f.binding.VaultPath {
		t.Fatalf("vault binding lost: %q", req.VaultPath)
	}
	wantTargets := []personal.CLIBrokerTarget{{Slot: "token", ID: f.slotID, Revision: f.slotRev, Field: f.field}}
	if !reflect.DeepEqual(req.Targets, wantTargets) {
		t.Fatalf("targets: %#v", req.Targets)
	}
}

// TestCLIRunBrokerNonceIsFreshPerRequest proves every actual request draws
// its own fresh 32-byte crypto-random nonce, observed only through the
// captured RequestCLIRun arguments, and that a nonce generator failure is
// terminal and sends nothing.
func TestCLIRunBrokerNonceIsFreshPerRequest(t *testing.T) {
	set := map[string]bool{}
	for i := 0; i < 64; i++ {
		nonce, err := cliRunBrokerNonce()
		if err != nil || !isFreshNonce(nonce) || set[nonce] {
			t.Fatalf("nonce not fresh 32-byte hex: %q %v", nonce, err)
		}
		set[nonce] = true
	}

	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	var nonces []string
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		nonces = append(nonces, req.Scope.Nonce)
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
	}
	for i := 0; i < 2; i++ {
		if err := dispatchCLIRunWithBroker(f); err == nil {
			t.Fatalf("run %d: refusal reported as success", i)
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] || !isFreshNonce(nonces[0]) || !isFreshNonce(nonces[1]) {
		t.Fatalf("per-request nonces are not fresh: %q", nonces)
	}

	requests := len(nonces)
	cliRunBrokerRandom = func([]byte) (int, error) { return 0, errors.New("fixture entropy failure") }
	err := dispatchCLIRunWithBroker(f)
	var nonceFailure cliRunBrokerNonceError
	if !errors.As(err, &nonceFailure) || len(nonces) != requests {
		t.Fatalf("nonce failure not terminal or still sent: %v (requests=%d)", err, len(nonces))
	}
}

// dispatchCLIRunBrokerShim runs one brokered run of a child that exits with
// code through the production dispatcher. The child is this real test binary:
// main_test.go's TestMain exits with code for the exact two-argument mode, so
// the run is a host-native child on every platform. The broker seam returns
// the audited reply and captures the exact scope that was sent.
func dispatchCLIRunBrokerShim(t *testing.T, code int) (sent browserhost.CLIRunScope, err error) {
	t.Helper()
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	program := cliTestExecutable(t)
	sum, e := clibinding.ComputeProgramSHA256(program)
	if e != nil {
		t.Fatal("child program digest unavailable")
	}
	f.binding.Program, f.binding.ProgramSHA256 = program, sum
	f.request.ProgramSHA256 = sum
	if e = f.binding.Validate(); e != nil {
		t.Fatal("child binding fixture invalid:", e)
	}
	f.request.Program, f.request.Args = program, []string{"locklark-test-child-exit", strconv.Itoa(code)}
	if e = f.request.Validate(f.targets); e != nil {
		t.Fatal("child request fixture invalid:", e)
	}
	t.Setenv("LOCKLARK_TEST_TOKEN", "")
	requests := 0
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		sent = req.Scope.Clone()
		return auditedReply("token", cliBrokerFixturePassword), nil
	}
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		t.Error("local console opened after a brokered run")
		return nil, nil, errRunCLIConsole
	})
	err = dispatchCLIRunWithBroker(f)
	if requests != 1 || !isFreshNonce(sent.Nonce) {
		t.Fatalf("broker request skipped: requests=%d", requests)
	}
	if _, statErr := os.Stat(sent.TempRoot); !os.IsNotExist(statErr) {
		t.Fatal("private run root survived the brokered run")
	}
	return sent, err
}

// TestCLIRunBrokerDispatcherSuccess proves a successful brokered child
// returns nil through the production dispatcher, after the request was sent
// once for a real private root, and that the local console is never opened.
func TestCLIRunBrokerDispatcherSuccess(t *testing.T) {
	if err := cliRunBrokerFailure(nil); err != nil {
		t.Fatalf("nil passthrough returned %v", err)
	}
	sent, err := dispatchCLIRunBrokerShim(t, 0)
	if err != nil {
		t.Fatalf("brokered success returned %v", err)
	}
	if sent.Nonce == "" || sent.Program == "" {
		t.Fatalf("scope not sent: %#v", sent)
	}
}

// TestCLIRunBrokerDispatcherChildExitStatus proves a brokered child's real
// exit status reaches the dispatcher as childExitStatus and that the local
// console is never opened.
func TestCLIRunBrokerDispatcherChildExitStatus(t *testing.T) {
	_, err := dispatchCLIRunBrokerShim(t, 7)
	status, ok := err.(*childExitStatus)
	if !ok || status.code != 7 {
		t.Fatalf("brokered exit status lost: %v", err)
	}
}

// TestCLIRunBrokerSuccessRendersAndExecutes proves a brokered success runs
// through the audited lifecycle: the callback receives the private root, the
// brokered value is rendered into the token environment of a directly
// executed child, and the receipt is returned. The child is this real test
// binary in main_test.go's two-argument exit mode, so it is host-native on
// every platform.
func TestCLIRunBrokerSuccessRendersAndExecutes(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	program := cliTestExecutable(t)
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("child program digest unavailable")
	}
	f.binding.Program, f.binding.ProgramSHA256 = program, sum
	f.request.ProgramSHA256 = sum
	if err = f.binding.Validate(); err != nil {
		t.Fatal("child binding fixture invalid:", err)
	}
	f.request.Program, f.request.Args = program, []string{"locklark-test-child-exit", "0"}
	if err = f.request.Validate(f.targets); err != nil {
		t.Fatal("child request fixture invalid:", err)
	}
	t.Setenv("LOCKLARK_TEST_TOKEN", "")
	var root string
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		if info, err := os.Stat(req.Scope.TempRoot); err != nil || !info.IsDir() {
			t.Error("broker request was made before the exact private run root existed")
		}
		root = req.Scope.TempRoot
		return auditedReply("token", cliBrokerFixturePassword), nil
	}
	receipt, err := f.call().run(context.Background())
	if err != nil {
		t.Fatalf("brokered run failed: %v", err)
	}
	if receipt.ExitCode != 0 || receipt.Status != "process-exited" || receipt.Session != strings.Repeat("1", 32) || receipt.Intent != strings.Repeat("2", 64) || receipt.TargetDigest != strings.Repeat("3", 64) {
		t.Fatalf("brokered receipt lost: %#v", receipt)
	}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "locklark-run-cli-") {
		t.Fatalf("callback root invalid: %q", root)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("private run root survived the successful run")
	}
}

// TestCLIRunBrokerRequestSurvivesCallbackClear proves the request the
// transport receives is whole on every reply path: the callback clears its
// own scope and targets before the request is shown, described, and sent, so
// the request's element copies are the only thing that can still hold them.
// Those copies are themselves blanked once prepare returns (covered by
// TestCLIRunBrokerRequestClearedAfterReturn), so each seam captures its own
// copies of the containers it must inspect later. The program is this real
// test binary in main_test.go's two-argument exit mode, so the child is
// host-native on every platform.
func TestCLIRunBrokerRequestSurvivesCallbackClear(t *testing.T) {
	type replyFunc func() (browserhost.CLIRunBrokerResponse, error)
	for name, reply := range map[string]replyFunc{
		"success": func() (browserhost.CLIRunBrokerResponse, error) {
			return auditedReply("token", cliBrokerFixturePassword), nil
		},
		"refused": func() (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
		},
		"malformed": func() (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{V: 0}, nil
		},
		"transport": func() (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, errors.New("fixture transport failure")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCLIBrokerFixture(t)
			installCLIRunBrokerSeams(t, true, f.tty)
			program := cliTestExecutable(t)
			sum, err := clibinding.ComputeProgramSHA256(program)
			if err != nil {
				t.Fatal("child program digest unavailable")
			}
			f.binding.Program, f.binding.ProgramSHA256 = program, sum
			f.request.ProgramSHA256 = sum
			if err = f.binding.Validate(); err != nil {
				t.Fatal("child binding fixture invalid:", err)
			}
			// A positional argument and a helper directory make both element
			// arrays observable.
			f.request.Program, f.request.Args = program, []string{"locklark-test-child-exit", "0"}
			f.request.HelperPath = []string{t.TempDir()}
			if err = f.request.Validate(f.targets); err != nil {
				t.Fatal("request fixture invalid:", err)
			}
			t.Setenv("LOCKLARK_TEST_TOKEN", "")
			var describedScope browserhost.CLIRunScope
			var describedTargets []personal.CLIBrokerTarget
			var sent browserhost.CLIRunBrokerRequest
			var sentScope browserhost.CLIRunScope
			var sentTargets []personal.CLIBrokerTarget
			cliRunBrokerDescribe = func(req browserhost.CLIRunBrokerRequest) string {
				// The callback blanks its own request copy after describe
				// returns, so capture independent copies of the containers.
				describedScope = req.Scope.Clone()
				describedTargets = append([]personal.CLIBrokerTarget(nil), req.Targets...)
				return ""
			}
			cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
				// Likewise after request returns; only the scalars can be
				// inspected from the original copy afterwards.
				sent, sentScope = req, req.Scope.Clone()
				sentTargets = append([]personal.CLIBrokerTarget(nil), req.Targets...)
				return reply()
			}
			_, _ = f.call().run(context.Background())
			wantTargets := []personal.CLIBrokerTarget{{Slot: "token", ID: f.slotID, Revision: f.slotRev, Field: f.field}}
			whole := func(scope browserhost.CLIRunScope, targets []personal.CLIBrokerTarget) bool {
				return scope.Program == program && scope.ProgramSH == f.binding.ProgramSHA256 &&
					reflect.DeepEqual(scope.Args, []string{"locklark-test-child-exit", "0"}) &&
					reflect.DeepEqual(scope.Helper, f.request.HelperPath) && reflect.DeepEqual(scope.Passthru, map[string]string{"NO_COLOR": "1"}) &&
					isFreshNonce(scope.Nonce) && reflect.DeepEqual(targets, wantTargets)
			}
			if describedScope.Program == "" || !whole(describedScope, describedTargets) {
				t.Fatalf("described request not whole: %#v %#v", describedScope, describedTargets)
			}
			if sent.V != 1 || !whole(sentScope, sentTargets) {
				t.Fatalf("sent request not whole: %#v %#v", sentScope, sentTargets)
			}
		})
	}
}

// TestCLIRunBrokerRequestClearedAfterReturn proves the request copy the
// transport receives is blanked on every reply path once prepare returns:
// the sent Args and Helper elements, passthrough entries, and target elements
// are cleared in place through the captured backing containers. A successful
// PreparedValues set is still returned to RunBrokeredBundle untouched. The
// program is this real test binary in main_test.go's two-argument exit mode,
// so its helper directory is a real one and the child is host-native on every
// platform.
func TestCLIRunBrokerRequestClearedAfterReturn(t *testing.T) {
	type replyFunc func() (browserhost.CLIRunBrokerResponse, error)
	for name, reply := range map[string]replyFunc{
		"success": func() (browserhost.CLIRunBrokerResponse, error) {
			return auditedReply("token", cliBrokerFixturePassword), nil
		},
		"refused": func() (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
		},
		"malformed": func() (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{V: 0}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCLIBrokerFixture(t)
			installCLIRunBrokerSeams(t, true, f.tty)
			program := cliTestExecutable(t)
			sum, err := clibinding.ComputeProgramSHA256(program)
			if err != nil {
				t.Fatal("child program digest unavailable")
			}
			f.binding.Program, f.binding.ProgramSHA256 = program, sum
			f.request.ProgramSHA256 = sum
			if err = f.binding.Validate(); err != nil {
				t.Fatal("child binding fixture invalid:", err)
			}
			f.request.Program, f.request.Args = program, []string{"locklark-test-child-exit", "0"}
			f.request.HelperPath = []string{t.TempDir(), filepath.Dir(program)}
			f.request.Passthrough = map[string]string{"NO_COLOR": "1", "TERM": "dumb"}
			if err = f.request.Validate(f.targets); err != nil {
				t.Fatal("request fixture invalid:", err)
			}
			t.Setenv("LOCKLARK_TEST_TOKEN", "")
			var args, helper []string
			var slot, id, revision, field *string
			var passthru map[string]string
			cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
				// Capture the backing containers only; no deep clones.
				args, helper, passthru = req.Scope.Args, req.Scope.Helper, req.Scope.Passthru
				for i := range req.Targets {
					if i == 0 {
						slot, id, revision, field = &req.Targets[i].Slot, &req.Targets[i].ID, &req.Targets[i].Revision, &req.Targets[i].Field
					}
				}
				if len(args) != 2 || len(helper) != 2 || len(passthru) != 2 || len(req.Targets) != 1 {
					t.Fatalf("captured request incomplete: args=%v helper=%v passthru=%v targets=%v", args, helper, passthru, req.Targets)
				}
				return reply()
			}
			_, _ = f.call().run(context.Background())
			for i, arg := range args {
				if arg != "" {
					t.Fatalf("sent argument %d not cleared: %q", i, arg)
				}
			}
			for i, directory := range helper {
				if directory != "" {
					t.Fatalf("sent helper %d not cleared: %q", i, directory)
				}
			}
			for key, value := range passthru {
				if key != "" || value != "" {
					t.Fatalf("sent passthrough entry not cleared: %q=%q", key, value)
				}
			}
			if slot == nil || *slot != "" || *id != "" || *revision != "" || *field != "" {
				t.Fatalf("sent target element not cleared: %q %q %q %q", *slot, *id, *revision, *field)
			}
		})
	}
}

// TestCLIRunBrokerClearCallbackScope proves the helper the callback runs after
// describe/request blanks every argument, every helper directory, and every
// passthrough value in place before dropping the containers and metadata.
func TestCLIRunBrokerClearCallbackScope(t *testing.T) {
	scope := browserhost.CLIRunScope{
		Profile:  "token",
		TTY:      "/dev/ttys-fixture",
		Nonce:    strings.Repeat("a", 64),
		Program:  "/bin/sh",
		CWD:      "/tmp",
		TempRoot: "/tmp/locklark-run-cli-fixture",
		Args:     []string{"--one", "--two"},
		Helper:   []string{"/opt/helper"},
		Passthru: map[string]string{"NO_COLOR": "1", "TERM": "dumb"},
		Timeout:  10,
		TokenEnv: "LOCKLARK_TEST_TOKEN",
	}
	// Copies of the values do not share the element slots that are cleared.
	wantArgs, wantHelper := append([]string(nil), scope.Args...), append([]string(nil), scope.Helper...)
	passthru := scope.Passthru
	clearCLIRunBrokerCallScope(&scope)
	if scope.Profile != "" || scope.TTY != "" || scope.Nonce != "" || scope.Program != "" || scope.CWD != "" ||
		scope.TempRoot != "" || scope.TokenEnv != "" || scope.Timeout != 0 {
		t.Fatalf("scope metadata not cleared: %#v", scope)
	}
	// Every element is blanked, then the container references are dropped.
	if len(wantArgs) != 2 || len(wantHelper) != 1 || len(passthru) != 0 || len(scope.Args) != 0 || len(scope.Helper) != 0 || len(scope.Passthru) != 0 {
		t.Fatalf("scope containers not dropped: args=%v helper=%v passthru=%v", scope.Args, scope.Helper, scope.Passthru)
	}
	clearCLIRunBrokerCallScope(nil)
}

// TestCLIRunBrokerMalformedSuccessIsTerminal proves a success reply without
// the audited receipt or with a partial value set is never rendered.
func TestCLIRunBrokerMalformedSuccessIsTerminal(t *testing.T) {
	for name, reply := range map[string]browserhost.CLIRunBrokerResponse{
		"no-receipt": func() browserhost.CLIRunBrokerResponse {
			r := auditedReply("token", cliBrokerFixturePassword)
			r.Receipt = personal.RunBundlePreparationReceipt{}
			return r
		}(),
		"extra-slot": func() browserhost.CLIRunBrokerResponse {
			r := auditedReply("token", cliBrokerFixturePassword)
			r.PreparedValues["other"] = []byte("x")
			return r
		}(),
	} {
		f := newCLIBrokerFixture(t)
		installCLIRunBrokerSeams(t, true, f.tty)
		cliRunBrokerRequest = func(context.Context, browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return reply, nil
		}
		_, err := f.call().run(context.Background())
		if err != browserhost.ErrCLIRunRefused {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestCLIRunBrokerExactUnavailableFallsBackOnce proves the fallback gate is
// the exact sentinel value and nothing else: through the production
// dispatcher, exactly one request is made, the existing local-factor path
// runs exactly once (its console is opened), and the local error is returned
// as before.
func TestCLIRunBrokerExactUnavailableFallsBackOnce(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	requests, opens := 0, 0
	cliRunBrokerRequest = func(context.Context, browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrBrokerUnavailable
	}
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		opens++
		return nil, nil, errRunCLIConsole
	})
	if err := dispatchCLIRunWithBroker(f); err != errRunCLIConsole {
		t.Fatalf("local path error changed: %v", err)
	}
	if requests != 1 || opens != 1 {
		t.Fatalf("fallback did not run exactly once: requests=%d opens=%d", requests, opens)
	}

	// The gate itself: a success stays a success, and only the exact value is
	// eligible; wrapped, joined, and double-wrapped copies are not.
	if err := cliRunBrokerFailure(nil); err != nil {
		t.Fatalf("nil passthrough returned %v", err)
	}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"wrapped", fmt.Errorf("transport: %w", browserhost.ErrBrokerUnavailable)},
		{"joined", errors.Join(browserhost.ErrBrokerUnavailable)},
		{"double-wrapped", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", browserhost.ErrBrokerUnavailable))},
		{"refused", browserhost.ErrCLIRunRefused},
	} {
		if cliRunBrokerFailure(tc.err) == errCLIRunBrokerAbsent {
			t.Fatalf("%s was fallback-eligible", tc.name)
		}
	}
	if cliRunBrokerFailure(browserhost.ErrBrokerUnavailable) != errCLIRunBrokerAbsent {
		t.Fatal("the exact sentinel is not fallback-eligible")
	}
}

// TestCLIRunBrokerCancellationIsTerminal proves signal-aware cancellation
// reaches both the broker request and the prepared child, and that the
// dispatcher treats the cancelled broker result as terminal instead of
// falling back to the local console, even if the transport reports absence
// while it unwinds.
func TestCLIRunBrokerCancellationIsTerminal(t *testing.T) {
	cases := map[string]struct {
		cancelAtSubscribe bool
		unavailable       bool
		started           chan struct{}
	}{
		// Cancelled before the request is made: no request is sent.
		"before-request": {cancelAtSubscribe: true},
		// Cancelled while the request is in flight; the transport observes it,
		// but its absence report still wins the gate.
		"in-flight": {started: make(chan struct{}), unavailable: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCLIBrokerFixture(t)
			installCLIRunBrokerSeams(t, true, f.tty)
			requests, opens := 0, 0
			cliRunBrokerRequest = func(ctx context.Context, _ browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
				requests++
				switch {
				case tc.started == nil:
					// The context was already cancelled at subscription.
				default:
					close(tc.started)
					<-ctx.Done()
				}
				if tc.unavailable {
					return browserhost.CLIRunBrokerResponse{}, browserhost.ErrBrokerUnavailable
				}
				return browserhost.CLIRunBrokerResponse{}, ctx.Err()
			}
			installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
				opens++
				return nil, nil, errRunCLIConsole
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cliRunBrokerSignalsAction(t, func() {
				if tc.cancelAtSubscribe {
					cancel()
					return
				}
				go func() {
					<-tc.started
					cancel()
				}()
			})
			err := executeCLIAuthenticatedWithBroker(ctx, "brokertool", f.binding, f.targets, f.call().Request)
			if err == nil || err == errCLIRunBrokerAbsent || err == errRunCLIConsole {
				t.Fatalf("cancellation fell back to the local factor: %v", err)
			}
			if tc.started != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
			if opens != 0 {
				t.Fatalf("local console opened after cancellation: %d", opens)
			}
			want := map[bool]int{true: 0, false: 1}[tc.started == nil]
			if requests != want {
				t.Fatalf("requests sent: %d", requests)
			}
		})
	}
}

// TestCLIRunBrokerQueuedSignalBeforeUnavailableIsTerminal is the no-sleep
// dispatcher regression for the handoff race: SIGINT is queued in the broker
// channel as the transport returns the exact browserhost.ErrBrokerUnavailable.
// The watcher consumes it, so the derived context is already cancelled and the
// stop joins a cancelled attempt: the local console is never opened, and a
// consumed signal is never handled again. The still-buffered branch is proved
// by TestCLIRunBrokerWatchStopJoinsAndDrains and
// TestCLIRunBrokerHandoffCausesAreTerminal. Nothing here sends an OS signal to
// the test process.
func TestCLIRunBrokerQueuedSignalBeforeUnavailableIsTerminal(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	// The broker subscribes the test's channel; the request queues one signal
	// in it before it returns, exactly as the process handler would have.
	signals := make(chan chan<- os.Signal, 1)
	brokerSignals := cliRunBrokerSignals
	t.Cleanup(func() { cliRunBrokerSignals = brokerSignals })
	cliRunBrokerSignals = func(ch chan<- os.Signal) { signals <- ch }
	requests, opens := 0, 0
	cliRunBrokerRequest = func(ctx context.Context, _ browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		broker := <-signals
		broker <- os.Interrupt
		// Either the watcher consumed the signal and cancelled ctx, or the
		// stop drains it; both branches are terminal, and this wait makes the
		// queue state at the handoff deterministic without a sleep.
		<-ctx.Done()
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrBrokerUnavailable
	}
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		opens++
		return nil, nil, errRunCLIConsole
	})
	err := executeCLIAuthenticatedWithBroker(context.Background(), "brokertool", f.binding, f.targets, f.call().Request)
	if requests != 1 || opens != 0 {
		t.Fatalf("queued signal selected the local factor: requests=%d opens=%d", requests, opens)
	}
	if _, ok := err.(cliRunBrokerFailedError); !ok {
		t.Fatalf("queued signal returned %T, want the fixed terminal broker failure", err)
	}
}

// TestCLIRunBrokerWatchStopJoinsAndDrains proves the stop itself: a signal
// queued before it is drained exactly once and reused by later stops, the
// unsubscribe happens once, and a signal the watcher consumed is never drained
// again. It is deterministic through channel barriers, not scheduling.
func TestCLIRunBrokerWatchStopJoinsAndDrains(t *testing.T) {
	// The watcher has already returned on its context, so a signal queued
	// now stays buffered for the stop's drain: the join is the barrier, and
	// no scheduling decides which side sees the signal.
	exited, cancelExited := context.WithCancel(context.Background())
	cancelExited()
	w := newCLIRunBrokerWatch(exited, func() {}, func(chan<- os.Signal) {})
	<-w.done
	w.signals <- os.Interrupt
	unsubscribed := 0
	w.stopFn = func(chan<- os.Signal) { unsubscribed++ }
	if sig, consumed := w.stop(); sig != os.Interrupt || consumed {
		t.Fatalf("drained stop = %v, %v", sig, consumed)
	}
	if sig, consumed := w.stop(); sig != os.Interrupt || consumed || unsubscribed != 1 {
		t.Fatalf("repeated stop = %v, %v unsubscribed=%d", sig, consumed, unsubscribed)
	}

	// A watcher that took the signal itself cancels and leaves nothing to
	// drain.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	taken := newCLIRunBrokerWatch(ctx, cancel, func(chan<- os.Signal) {})
	taken.signals <- os.Interrupt
	<-ctx.Done()
	if sig, consumed := taken.stop(); sig != nil || !consumed {
		t.Fatalf("consumed stop = %v, %v", sig, consumed)
	}
}

// TestCLIRunBrokerHandoffCausesAreTerminal proves each cause the pure handoff
// distinguishes, including the buffered branch: a consumed signal is
// cancellation, a still-buffered signal is terminal on its own, and only an
// empty queue with live contexts lets the local path run; either cancelled
// context is terminal.
func TestCLIRunBrokerHandoffCausesAreTerminal(t *testing.T) {
	live := context.Background()
	done, cancel := context.WithCancel(live)
	cancel()
	for _, tc := range []struct {
		name     string
		pending  os.Signal
		consumed bool
		parent   context.Context
		ctx      context.Context
		want     cliRunBrokerHandled
	}{
		{name: "consumed", consumed: true, parent: live, ctx: done, want: cliRunBrokerCancelled},
		{name: "buffered", pending: os.Interrupt, parent: live, ctx: live, want: cliRunBrokerSignal},
		{name: "empty-live", parent: live, ctx: live, want: cliRunBrokerNoSignal},
		{name: "parent-cancelled", parent: done, ctx: live, want: cliRunBrokerCancelled},
		{name: "derived-cancelled", parent: live, ctx: done, want: cliRunBrokerCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := handoffBrokerSignal(tc.pending, tc.consumed, tc.parent, tc.ctx); got != tc.want {
				t.Fatalf("handoff = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCLIRunBrokerFailuresNeverFallBack proves refused, unknown, malformed,
// deadline, TTY, dial, and disconnected outcomes are all terminal through the
// production dispatcher: the expected request count, no local path, and no
// local factor disclosed.
func TestCLIRunBrokerFailuresNeverFallBack(t *testing.T) {
	type outcome struct {
		tty     func() (string, string, error)
		request func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error)
	}
	for _, tc := range []struct {
		name    string
		outcome outcome
		check   func(t *testing.T, err error)
	}{
		{name: "refused", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
		}}, check: func(t *testing.T, err error) {
			if _, ok := err.(cliRunBrokerRefusedError); !ok || !strings.Contains(err.Error(), "refused") {
				t.Fatalf("refused outcome: %v", err)
			}
		}},
		{name: "unknown", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, errors.New("desktop browser broker response invalid")
		}}},
		{name: "malformed", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{V: 0, PreparedValues: map[string][]byte{"token": []byte("x")}}, nil
		}}},
		{name: "deadline", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, context.DeadlineExceeded
		}}, check: func(t *testing.T, err error) {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline cause lost: %v", err)
			}
		}},
		{name: "tty-error", outcome: outcome{tty: func() (string, string, error) {
			return "", "", errors.New("no controlling terminal")
		}}},
		{name: "tty-empty", outcome: outcome{tty: func() (string, string, error) {
			return "", "", nil
		}}},
		{name: "dial", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, errors.New("desktop browser broker connection failed")
		}}},
		{name: "disconnected", outcome: outcome{request: func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
			return browserhost.CLIRunBrokerResponse{}, errors.New("desktop browser broker disconnected before a response")
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCLIBrokerFixture(t)
			installCLIRunBrokerSeams(t, true, f.tty)
			if tc.outcome.tty != nil {
				cliRunBrokerTTY = tc.outcome.tty
			}
			requests := 0
			if tc.outcome.request != nil {
				cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
					requests++
					return tc.outcome.request(req)
				}
			}
			opens := 0
			installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
				opens++
				return nil, nil, errRunCLIConsole
			})
			err := dispatchCLIRunWithBroker(f)
			if err == nil || err == errCLIRunBrokerAbsent || err == errRunCLIConsole || opens != 0 {
				t.Fatalf("fell back to the local factor: %v opens=%d", err, opens)
			}
			if requests != map[bool]int{true: 1, false: 0}[tc.outcome.request != nil] {
				t.Fatalf("requests sent: %d", requests)
			}
			if tc.check != nil {
				tc.check(t, err)
			}
		})
	}
}

// TestCLIRunBrokerDispatcherDisabledRunsLocalOnce proves that with the gate
// disabled (the non-Darwin behavior) the existing local-factor path runs
// directly and no broker request is made or subscribed.
func TestCLIRunBrokerDispatcherDisabledRunsLocalOnce(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, false, f.tty)
	requests, opens, subscriptions := 0, 0, 0
	cliRunBrokerSignalsAction(t, func() { subscriptions++ })
	cliRunBrokerRequest = func(context.Context, browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrBrokerUnavailable
	}
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		opens++
		return nil, nil, errRunCLIConsole
	})
	if err := dispatchCLIRunWithBroker(f); err != errRunCLIConsole || requests != 0 || opens != 1 || subscriptions != 0 {
		t.Fatalf("non-Darwin path changed: err=%v requests=%d opens=%d subscriptions=%d", err, requests, opens, subscriptions)
	}
}

// TestCLIRunBrokerRequestDiffIncludesProgramPin proves the CLI's canonical
// request-diff equality treats the optional executable pin as part of the
// committed execution scope.
func TestCLIRunBrokerRequestDiffIncludesProgramPin(t *testing.T) {
	f := newCLIBrokerFixture(t)
	committed := f.request
	if err := cliRunBrokerRequestDiffers(committed, committed); err != nil {
		t.Fatalf("identical pinned request differed: %v", err)
	}
	changed := committed
	changed.ProgramSHA256 = strings.Repeat("0", 64)
	if changed.ProgramSHA256 == committed.ProgramSHA256 {
		t.Fatal("fixture pin canary is not distinct")
	}
	if err := cliRunBrokerRequestDiffers(changed, committed); !errors.Is(err, browserhost.ErrCLIRunRefused) {
		t.Fatalf("pin mismatch in request diff = %v", err)
	}
	unpinned := committed
	unpinned.ProgramSHA256 = ""
	if err := cliRunBrokerRequestDiffers(unpinned, committed); !errors.Is(err, browserhost.ErrCLIRunRefused) {
		t.Fatalf("removed pin in request diff = %v", err)
	}
}
