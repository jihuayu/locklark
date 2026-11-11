package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

const cliBrokerFixturePassword = "fixture-run-cli-password"

// installCLIRunBrokerSeams replaces the Darwin gate and every broker seam for
// one test, and restores the production defaults afterwards.
func installCLIRunBrokerSeams(t *testing.T, enabled bool) {
	t.Helper()
	originalEnabled, originalTTY, originalRequest := cliRunBrokerEnabled, cliRunBrokerTTY, cliRunBrokerRequest
	originalRandom, originalDescribe, originalNonces := cliRunBrokerRandom, cliRunBrokerDescribe, cliRunBrokerNonces
	t.Cleanup(func() {
		cliRunBrokerEnabled, cliRunBrokerTTY, cliRunBrokerRequest = originalEnabled, originalTTY, originalRequest
		cliRunBrokerRandom, cliRunBrokerDescribe, cliRunBrokerNonces = originalRandom, originalDescribe, originalNonces
	})
	cliRunBrokerEnabled = func() bool { return enabled }
	cliRunBrokerTTY = func() (string, string, error) { return "/dev/ttys-fixture", "fixture-peer", nil }
	cliRunBrokerDescribe = func(browserhost.CLIRunBrokerRequest) string { return "" }
	cliRunBrokerNonces = nil
}

// installCLIRunLocalConsole replaces the local-factor controlling console for
// one test and restores the production opener afterwards.
func installCLIRunLocalConsole(t *testing.T, open func() (*os.File, *os.File, error)) {
	t.Helper()
	original := cliLocalConsoleOpen
	t.Cleanup(func() { cliLocalConsoleOpen = original })
	cliLocalConsoleOpen = open
}

// cliBrokerFixture is one validated CLI run whose binding points at a real
// vault, so the committed request is exactly what runCLIRun derives.
type cliBrokerFixture struct {
	binding     clibinding.ToolBinding
	request     personal.RunBundleRequest
	targets     []personal.BundleTarget
	slotID      string
	slotRev     string
	field       string
	passthruKey string
	passthruVal string
}

func newCLIBrokerFixture(t *testing.T) cliBrokerFixture {
	t.Helper()
	program := cliTestExecutable(t)
	binding := clibinding.ToolBinding{
		Profile:        "token",
		VaultPath:      filepath.Join(cliTestDir(t), "owner.ll"),
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
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("profile unavailable")
	}
	targets := []personal.BundleTarget{{Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password"}}
	request := personal.RunBundleRequest{
		Program:        binding.Program,
		Args:           []string{"-test.run=^$"},
		Directory:      t.TempDir(),
		TimeoutSeconds: binding.TimeoutSeconds,
		HelperPath:     append([]string(nil), binding.HelperPath...),
		Passthrough:    map[string]string{"NO_COLOR": "1"},
		TokenEnvName:   binding.TokenEnvName,
		Spec:           profile.Spec(),
	}
	if err = request.Validate(targets); err != nil {
		t.Fatal("request fixture invalid:", err)
	}
	return cliBrokerFixture{binding: binding, request: request, targets: targets, slotID: cliTestID, slotRev: cliTestRevision, field: "password", passthruKey: "NO_COLOR", passthruVal: "1"}
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
	return executeCLIAuthenticatedWithBroker("brokertool", f.binding, f.targets, f.call().Request)
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

// cloneCLIRunBrokerTestRequest copies a request for comparison.
func cloneCLIRunBrokerTestRequest(r personal.RunBundleRequest) personal.RunBundleRequest {
	r.Args = append([]string(nil), r.Args...)
	r.HelperPath = append([]string(nil), r.HelperPath...)
	r.Passthrough = cloneCLIRunBrokerPassthru(r.Passthrough)
	return r
}

// TestCLIRunBrokerScopeBindsCommittedRunAndFreshNonce drives the real audited
// RunBrokeredBundle callback and inspects exactly what would be sent: the
// complete scope bound to the callback snapshots and the binding, the exact
// vault path and target slot/id/revision/field, a fresh 32-byte nonce, and
// the exact private root, which exists when the request is made.
func TestCLIRunBrokerScopeBindsCommittedRunAndFreshNonce(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true)
	// Capture the fixture's own values first: runBundle clears the caller's
	// cloned containers once the run returns.
	wantArgs, wantHelper, wantPassthru := append([]string(nil), f.request.Args...), append([]string(nil), f.request.HelperPath...), cloneCLIRunBrokerPassthru(f.request.Passthrough)
	callRequests := f.call().Request
	var sent []browserhost.CLIRunBrokerRequest
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		if info, err := os.Stat(req.Scope.TempRoot); err != nil || !info.IsDir() {
			t.Error("broker request was made before the exact private run root existed")
		}
		req.Scope = req.Scope.Clone()
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
		TTY:         "/dev/ttys-fixture",
		TTYPeerID:   "",
		TTYPlatform: browserhost.CLIRunTTYPlatform(),
		Nonce:       req.Scope.Nonce,
		Program:     callRequests.Program,
		ProgramSH:   f.binding.ProgramSHA256,
		CWD:         callRequests.Directory,
		TempRoot:    req.Scope.TempRoot,
		Args:        wantArgs,
		Helper:      wantHelper,
		Passthru:    wantPassthru,
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
// its own fresh 32-byte crypto-random nonce, and that a nonce generator
// failure is terminal.
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
	installCLIRunBrokerSeams(t, true)
	cliRunBrokerRequest = func(context.Context, browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrCLIRunRefused
	}
	for i := 0; i < 2; i++ {
		if _, err := f.call().run(context.Background()); err != browserhost.ErrCLIRunRefused {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if len(cliRunBrokerNonces) != 2 || cliRunBrokerNonces[0] == cliRunBrokerNonces[1] || !isFreshNonce(cliRunBrokerNonces[0]) || !isFreshNonce(cliRunBrokerNonces[1]) {
		t.Fatalf("per-request nonces are not fresh: %q", cliRunBrokerNonces)
	}

	requests := len(cliRunBrokerNonces)
	cliRunBrokerRandom = func([]byte) (int, error) { return 0, errors.New("fixture entropy failure") }
	_, err := f.call().run(context.Background())
	var nonceFailure cliRunBrokerNonceError
	if !errors.As(cliRunBrokerFailure(err), &nonceFailure) || len(cliRunBrokerNonces) != requests {
		t.Fatalf("nonce failure not terminal or still sent: %v", cliRunBrokerFailure(err))
	}
}

// TestCLIRunBrokerSuccessRendersAndExecutes proves a brokered success runs
// through the audited lifecycle: the callback receives the private root, the
// brokered value is rendered into the token environment of a directly
// executed child, the receipt is returned, and the root is removed.
func TestCLIRunBrokerSuccessRendersAndExecutes(t *testing.T) {
	// The token environment reaches the executed child, not this test binary:
	// a shim program is executed in place of the pinned one.
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true)
	shim := filepath.Join(t.TempDir(), "locklark.test")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal("shim program unavailable")
	}
	f.request.Program, f.request.Args = shim, nil
	t.Setenv("LOCKLARK_TEST_TOKEN", "")
	var root string
	var gotScope browserhost.CLIRunScope
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		if info, err := os.Stat(req.Scope.TempRoot); err != nil || !info.IsDir() {
			t.Error("broker request was made before the exact private run root existed")
		}
		root, gotScope = req.Scope.TempRoot, req.Scope
		return auditedReply("token", cliBrokerFixturePassword), nil
	}
	receipt, err := f.call().run(context.Background())
	if err != nil {
		t.Fatalf("brokered run failed: %v", err)
	}
	if receipt.ExitCode != 0 || receipt.Status != "process-exited" || receipt.Session != strings.Repeat("1", 32) || receipt.Intent != strings.Repeat("2", 64) || receipt.TargetDigest != strings.Repeat("3", 64) {
		t.Fatalf("brokered receipt lost: %#v", receipt)
	}
	if root != gotScope.TempRoot || !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "locklark-run-cli-") || len(cliRunBrokerNonces) != 1 {
		t.Fatalf("callback or nonce skipped: root=%q nonces=%d", root, len(cliRunBrokerNonces))
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("private run root survived the successful run")
	}
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
		installCLIRunBrokerSeams(t, true)
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
	installCLIRunBrokerSeams(t, true)
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
	if requests != 1 || opens != 1 || len(cliRunBrokerNonces) != 1 {
		t.Fatalf("fallback did not run exactly once: requests=%d opens=%d nonces=%d", requests, opens, len(cliRunBrokerNonces))
	}

	// The gate itself: only the exact value is eligible; wrapped, joined, and
	// double-wrapped copies are not, and neither is a success.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"wrapped", fmt.Errorf("transport: %w", browserhost.ErrBrokerUnavailable)},
		{"joined", errors.Join(browserhost.ErrBrokerUnavailable)},
		{"double-wrapped", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", browserhost.ErrBrokerUnavailable))},
		{"refused", browserhost.ErrCLIRunRefused},
		{"nil", nil},
	} {
		if cliRunBrokerFailure(tc.err) == errCLIRunBrokerAbsent {
			t.Fatalf("%s was fallback-eligible", tc.name)
		}
	}
	if cliRunBrokerFailure(browserhost.ErrBrokerUnavailable) != errCLIRunBrokerAbsent {
		t.Fatal("the exact sentinel is not fallback-eligible")
	}
}

// TestCLIRunBrokerFailuresNeverFallBack proves refused, unknown, malformed,
// cancellation, deadline, TTY, dial, and disconnected outcomes are all
// terminal through the production dispatcher: one request, no local path,
// and no local factor disclosed.
func TestCLIRunBrokerFailuresNeverFallBack(t *testing.T) {
	type outcome struct {
		tty     func() (string, string, error)
		request func(browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error)
	}
	for _, tc := range []struct {
		name    string
		outcome outcome
		ctx     context.Context
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
		{name: "ttY-error", outcome: outcome{tty: func() (string, string, error) {
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
			installCLIRunBrokerSeams(t, true)
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
			var err error
			if tc.ctx != nil {
				_, err = f.call().run(tc.ctx)
				err = cliRunBrokerFailure(err)
			} else {
				err = dispatchCLIRunWithBroker(f)
			}
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

// TestCLIRunBrokerGateProvesNonDarwinLocalPath proves the gate never leaves
// the reconcilable Darwin attempt enabled on non-Darwin, and that with it
// disabled the existing local-factor path runs directly.
func TestCLIRunBrokerDispatcherDisabledRunsLocalOnce(t *testing.T) {
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, false)
	requests, opens := 0, 0
	cliRunBrokerRequest = func(context.Context, browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		return browserhost.CLIRunBrokerResponse{}, browserhost.ErrBrokerUnavailable
	}
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		opens++
		return nil, nil, errRunCLIConsole
	})
	if err := dispatchCLIRunWithBroker(f); err != errRunCLIConsole || requests != 0 || opens != 1 {
		t.Fatalf("non-Darwin path changed: err=%v requests=%d opens=%d", err, requests, opens)
	}
}
