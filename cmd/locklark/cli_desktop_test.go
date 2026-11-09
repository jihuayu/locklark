package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
)

func cliDesktopTestProgram(t *testing.T) string {
	t.Helper()
	program := filepath.Join(cliTestDir(t), "desktop-tool")
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	if err := os.WriteFile(program, []byte("approved-program-v1"), 0700); err != nil {
		t.Fatal("desktop program fixture unavailable")
	}
	return program
}

func cliDesktopTestBinding(t *testing.T, program string) clibinding.ToolBinding {
	t.Helper()
	digest, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("desktop program digest unavailable")
	}
	binding := clibinding.ToolBinding{
		Profile:       "gh",
		VaultPath:     filepath.Join(cliTestDir(t), "owner.ll"),
		Program:       program,
		ProgramSHA256: digest,
		Targets: []clibinding.SlotTarget{{
			Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password",
		}},
		HelperPath:     []string{filepath.Dir(program)},
		TimeoutSeconds: 30,
	}
	if err := binding.Validate(); err != nil {
		t.Fatal("desktop binding fixture invalid:", err)
	}
	return binding
}

func cliDesktopTestRequest(t *testing.T, binding clibinding.ToolBinding) personal.RunBundleRequest {
	t.Helper()
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("desktop profile unavailable")
	}
	return personal.RunBundleRequest{
		Program:        binding.Program,
		ProgramSHA256:  binding.ProgramSHA256,
		Args:           []string{"api", "--json"},
		Directory:      cliTestDir(t),
		TimeoutSeconds: 12,
		HelperPath:     []string{filepath.Dir(binding.Program)},
		Passthrough:    map[string]string{"GH_HOST": "example.test"},
		Spec:           profile.Spec(),
	}
}

func cliDesktopTestTargets() []personal.BundleTarget {
	return []personal.BundleTarget{{
		Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password",
	}}
}

func cliDesktopTestReceipt() browserhost.CLIRunV2Receipt {
	return browserhost.CLIRunV2Receipt{
		Session:      strings.Repeat("1", 32),
		Intent:       strings.Repeat("2", 64),
		TargetDigest: strings.Repeat("3", 64),
	}
}

func TestCLIDesktopRunBundleProviderMapsFullScopeAndReceipt(t *testing.T) {
	original := requestCLIRunV2
	t.Cleanup(func() { requestCLIRunV2 = original })

	program := cliDesktopTestProgram(t)
	binding := cliDesktopTestBinding(t, program)
	request := cliDesktopTestRequest(t, binding)
	targets := cliDesktopTestTargets()
	root := cliTestDir(t)
	secret := []byte("desktop-provider-secret")
	var got browserhost.CLIRunV2Params
	requestCLIRunV2 = func(ctx context.Context, params browserhost.CLIRunV2Params) (browserhost.CLIRunV2Result, error) {
		got = params
		return browserhost.CLIRunV2Result{
			Values:      map[string][]byte{"token": secret},
			Receipt:     cliDesktopTestReceipt(),
			ScopeDigest: strings.Repeat("4", 64),
		}, nil
	}
	result, err := newCLIDesktopRunBundleProvider(binding)(context.Background(), request, targets, root)
	if err != nil {
		t.Fatal("desktop provider failed:", err)
	}
	if got.VaultPath != binding.VaultPath || got.Root != root || got.ProfileID != binding.Profile ||
		got.Program != request.Program || got.Directory != request.Directory ||
		got.TimeoutSeconds != request.TimeoutSeconds || got.TokenEnvName != "" {
		t.Fatalf("desktop provider scope mismatch: %+v", got)
	}
	if len(got.Args) != 2 || got.Args[0] != "api" || got.Args[1] != "--json" {
		t.Fatalf("desktop provider argv mismatch: %v", got.Args)
	}
	if len(got.HelperPath) != 1 || got.HelperPath[0] != request.HelperPath[0] {
		t.Fatalf("desktop provider helper path mismatch: %v", got.HelperPath)
	}
	if len(got.Passthrough) != 1 || got.Passthrough["GH_HOST"] != "example.test" {
		t.Fatalf("desktop provider passthrough mismatch: %v", got.Passthrough)
	}
	if len(got.Targets) != 1 || got.Targets[0] != (browserhost.CLIRunV2Target{Slot: "token", ID: cliTestID, Revision: cliTestRevision, Field: "password"}) {
		t.Fatalf("desktop provider targets mismatch: %+v", got.Targets)
	}
	if len(result.Values) != 1 || string(result.Values["token"]) != string(secret) {
		t.Fatal("desktop provider values were not returned as owned output")
	}
	want := cliDesktopTestReceipt()
	if result.Receipt.Session != want.Session || result.Receipt.Intent != want.Intent || result.Receipt.TargetDigest != want.TargetDigest {
		t.Fatalf("desktop provider receipt mismatch: %+v", result.Receipt)
	}
	clearCLIDesktopValues(result.Values)
}

// TestExecuteCLIAuthenticatedPropagatesApprovedProgramDigest proves the real
// authenticated request literal carries the trusted binding digest into the
// provider/executor, so the post-approval pin is not silently empty.
func TestExecuteCLIAuthenticatedPropagatesApprovedProgramDigest(t *testing.T) {
	originalOpen := openCLIConsole
	originalRun := runCLIBundleWithProvider
	t.Cleanup(func() { openCLIConsole = originalOpen; runCLIBundleWithProvider = originalRun })
	program := cliDesktopTestProgram(t)
	binding := cliDesktopTestBinding(t, program)
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("desktop profile unavailable")
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal("null device unavailable:", err)
	}
	defer null.Close()
	openCLIConsole = func() (*os.File, *os.File, error) { return null, null, nil }
	var got personal.RunBundleRequest
	runCLIBundleWithProvider = func(_ context.Context, _ []personal.BundleTarget, request personal.RunBundleRequest, _ personal.RunBundleProvider) (personal.RunReceipt, error) {
		got = request
		return personal.RunReceipt{Status: "process-exited", ExitCode: 0}, nil
	}
	if err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30); err != nil {
		t.Fatalf("authenticated provider path failed: %v", err)
	}
	if got.ProgramSHA256 != binding.ProgramSHA256 || got.Program != binding.Program {
		t.Fatalf("provider request pin = %q program = %q, want %q %q", got.ProgramSHA256, got.Program, binding.ProgramSHA256, binding.Program)
	}
}

func TestCLIDesktopRunBundleProviderRechecksProgramAndZerosValues(t *testing.T) {
	original := requestCLIRunV2
	t.Cleanup(func() { requestCLIRunV2 = original })

	program := cliDesktopTestProgram(t)
	binding := cliDesktopTestBinding(t, program)
	request := cliDesktopTestRequest(t, binding)
	targets := cliDesktopTestTargets()
	root := cliTestDir(t)
	secret := []byte("must-be-zeroed")
	requestCLIRunV2 = func(ctx context.Context, params browserhost.CLIRunV2Params) (browserhost.CLIRunV2Result, error) {
		// Simulate a program replaced while the native approval was open.
		if err := os.WriteFile(program, []byte("replaced-during-approval"), 0700); err != nil {
			t.Fatal("program replacement fixture failed:", err)
		}
		return browserhost.CLIRunV2Result{
			Values:  map[string][]byte{"token": secret},
			Receipt: cliDesktopTestReceipt(),
		}, nil
	}
	if _, err := newCLIDesktopRunBundleProvider(binding)(context.Background(), request, targets, root); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatalf("post-approval program change was not refused: %v", err)
	}
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("program recheck failure left byte %d undisclosed", i)
		}
	}
}

func TestCLIDesktopRunBundleProviderPropagatesPreConnectUnavailable(t *testing.T) {
	original := requestCLIRunV2
	t.Cleanup(func() { requestCLIRunV2 = original })
	binding := cliDesktopTestBinding(t, cliDesktopTestProgram(t))
	requestCLIRunV2 = func(context.Context, browserhost.CLIRunV2Params) (browserhost.CLIRunV2Result, error) {
		return browserhost.CLIRunV2Result{}, browserhost.ErrBrokerUnavailable
	}
	_, err := newCLIDesktopRunBundleProvider(binding)(context.Background(), cliDesktopTestRequest(t, binding), cliDesktopTestTargets(), cliTestDir(t))
	if !errors.Is(err, browserhost.ErrBrokerUnavailable) {
		t.Fatalf("pre-connect unavailable was not preserved: %v", err)
	}
}

func TestCLIRunBundleFallbackOnlyForPreConnectUnavailable(t *testing.T) {
	original := runCLIBundleWithProvider
	t.Cleanup(func() { runCLIBundleWithProvider = original })
	localErr := errors.New("local full-factor path entered")
	genericErr := errors.New("provider failure")
	cases := []struct {
		name      string
		receipt   personal.RunReceipt
		err       error
		wantLocal int
		wantErr   error
		wantExit  int
	}{
		{
			name:      "pre-connect-unavailable",
			err:       browserhost.ErrBrokerUnavailable,
			wantLocal: 1, wantErr: localErr,
		},
		{
			name:      "wrapped-pre-connect-unavailable",
			err:       fmt.Errorf("dial: %w", browserhost.ErrBrokerUnavailable),
			wantLocal: 1, wantErr: localErr,
		},
		{
			name: "refused-is-final",
			err:  browserhost.ErrBrokerRefused, wantErr: browserhost.ErrBrokerRefused,
		},
		{
			name: "unknown-is-final",
			err:  browserhost.ErrBrokerUnknown, wantErr: browserhost.ErrBrokerUnknown,
		},
		{
			name: "context-is-final",
			err:  context.Canceled, wantErr: context.Canceled,
		},
		{
			name: "cleanup-is-final",
			err:  personal.ErrRunCleanup, wantErr: personal.ErrRunCleanup,
		},
		{
			name: "temporary-is-final",
			err:  personal.ErrRunTemporary, wantErr: personal.ErrRunTemporary,
		},
		{
			name: "provider-error-is-final",
			err:  genericErr, wantErr: genericErr,
		},
		{
			name:    "success-zero",
			receipt: personal.RunReceipt{Status: "process-exited", ExitCode: 0},
		},
		{
			name:     "success-nonzero",
			receipt:  personal.RunReceipt{Status: "process-exited", ExitCode: 7},
			wantExit: 7,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
				return test.receipt, test.err
			}
			localCalls := 0
			got := runCLIBundleWithDesktopOrLocal(context.Background(), nil, personal.RunBundleRequest{}, nil, func() error {
				localCalls++
				return localErr
			})
			if localCalls != test.wantLocal {
				t.Fatalf("local fallback calls = %d, want %d", localCalls, test.wantLocal)
			}
			if test.wantExit != 0 {
				var child *childExitStatus
				if !errors.As(got, &child) || child.code != test.wantExit {
					t.Fatalf("desktop success exit status lost: %v", got)
				}
				return
			}
			if !errors.Is(got, test.wantErr) {
				t.Fatalf("outcome classification = %v, want %v", got, test.wantErr)
			}
			if test.wantLocal == 1 && got != localErr {
				t.Fatalf("local fallback error was not propagated: %v", got)
			}
		})
	}
}

func TestExecuteCLIAuthenticatedValidatesBeforeOpeningConsole(t *testing.T) {
	originalOpen := openCLIConsole
	t.Cleanup(func() { openCLIConsole = originalOpen })
	opened := 0
	openCLIConsole = func() (*os.File, *os.File, error) {
		opened++
		return nil, nil, errors.New("must not open")
	}
	binding := cliDesktopTestBinding(t, cliDesktopTestProgram(t))
	binding.Targets[0].Field = "username"
	profile, _ := cliprofile.Lookup(binding.Profile)
	if err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30); !errors.Is(err, cliUsage) {
		t.Fatalf("invalid request was not refused before console open: %v", err)
	}
	if opened != 0 {
		t.Fatal("controlling console was opened before request validation")
	}
}

func TestExecuteCLIAuthenticatedTriesDesktopBeforeLocalFactors(t *testing.T) {
	originalOpen := openCLIConsole
	originalRaw := makeCLIConsoleRaw
	originalProvider := runCLIBundleWithProvider
	t.Cleanup(func() {
		openCLIConsole = originalOpen
		makeCLIConsoleRaw = originalRaw
		runCLIBundleWithProvider = originalProvider
	})
	openCLIConsole = func() (*os.File, *os.File, error) {
		in, err := os.CreateTemp(t.TempDir(), "console-in")
		if err != nil {
			return nil, nil, err
		}
		out, err := os.CreateTemp(t.TempDir(), "console-out")
		if err != nil {
			in.Close()
			return nil, nil, err
		}
		return in, out, nil
	}
	makeRawCalls := 0
	makeCLIConsoleRaw = func(int) (*term.State, error) {
		makeRawCalls++
		return nil, errors.New("local factors must not start before the desktop attempt")
	}
	binding := cliDesktopTestBinding(t, cliDesktopTestProgram(t))
	profile, _ := cliprofile.Lookup(binding.Profile)

	t.Run("desktop-success-never-enters-local-prompts", func(t *testing.T) {
		makeRawCalls = 0
		providerAttempted := false
		runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
			providerAttempted = true
			return personal.RunReceipt{Status: "process-exited", ExitCode: 0}, nil
		}
		if err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30); err != nil {
			t.Fatal("desktop success path failed:", err)
		}
		if !providerAttempted || makeRawCalls != 0 {
			t.Fatalf("desktop success ordering wrong: provider=%v raw=%d", providerAttempted, makeRawCalls)
		}
	})

	t.Run("refused-never-enters-local-prompts", func(t *testing.T) {
		makeRawCalls = 0
		runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
			return personal.RunReceipt{}, browserhost.ErrBrokerRefused
		}
		err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30)
		if !errors.Is(err, browserhost.ErrBrokerRefused) || makeRawCalls != 0 {
			t.Fatalf("refused outcome entered local factors: %v raw=%d", err, makeRawCalls)
		}
	})

	t.Run("pre-connect-unavailable-enters-local-path", func(t *testing.T) {
		makeRawCalls = 0
		runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
			return personal.RunReceipt{}, browserhost.ErrBrokerUnavailable
		}
		err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30)
		if err == nil || !strings.Contains(err.Error(), "cannot disable terminal echo") || makeRawCalls != 1 {
			t.Fatalf("pre-connect unavailable did not reach local factors: %v raw=%d", err, makeRawCalls)
		}
	})
}

// TestExecuteCLIAuthenticatedUnpinnedBindingSkipsDesktopLease proves an
// explicitly unpinned binding never creates or reuses a session-native desktop
// lease and never invents a post-contact "unavailable" outcome: it enters the
// existing full-factor local one-shot path before any broker call. The factor
// step is still required, so the local path is not weakened.
func TestExecuteCLIAuthenticatedUnpinnedBindingSkipsDesktopLease(t *testing.T) {
	originalOpen := openCLIConsole
	originalRaw := makeCLIConsoleRaw
	originalProvider := runCLIBundleWithProvider
	originalRequest := requestCLIRunV2
	t.Cleanup(func() {
		openCLIConsole = originalOpen
		makeCLIConsoleRaw = originalRaw
		runCLIBundleWithProvider = originalProvider
		requestCLIRunV2 = originalRequest
	})
	openCLIConsole = func() (*os.File, *os.File, error) {
		in, err := os.CreateTemp(t.TempDir(), "console-in")
		if err != nil {
			return nil, nil, err
		}
		out, err := os.CreateTemp(t.TempDir(), "console-out")
		if err != nil {
			in.Close()
			return nil, nil, err
		}
		return in, out, nil
	}
	makeRawCalls := 0
	makeCLIConsoleRaw = func(int) (*term.State, error) {
		makeRawCalls++
		return nil, errors.New("local factors required")
	}
	providerCalls, brokerCalls := 0, 0
	runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
		providerCalls++
		return personal.RunReceipt{Status: "process-exited", ExitCode: 0}, nil
	}
	requestCLIRunV2 = func(context.Context, browserhost.CLIRunV2Params) (browserhost.CLIRunV2Result, error) {
		brokerCalls++
		return browserhost.CLIRunV2Result{}, nil
	}
	binding := cliDesktopTestBinding(t, cliDesktopTestProgram(t))
	binding.ProgramSHA256 = ""
	if err := binding.Validate(); err != nil {
		t.Fatal("unpinned binding fixture invalid:", err)
	}
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("desktop profile unavailable")
	}
	err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30)
	if providerCalls != 0 || brokerCalls != 0 {
		t.Fatalf("unpinned binding contacted the desktop provider: provider=%d broker=%d", providerCalls, brokerCalls)
	}
	if makeRawCalls != 1 {
		t.Fatalf("unpinned local factor step calls = %d, want exactly 1 (full factors still required)", makeRawCalls)
	}
	if err == nil || !strings.Contains(err.Error(), "cannot disable terminal echo") {
		t.Fatalf("unpinned path did not enter local full-factor flow: %v", err)
	}
}

// TestExecuteCLIAuthenticatedRefusesPinnedShebangBeforeConsole proves the
// common program policy is applied before the controlling console opens or a
// desktop provider/broker request is sent. A pinned shebang would otherwise be
// executed under a rewritten $0 by the sealed snapshot path.
func TestExecuteCLIAuthenticatedRefusesPinnedShebangBeforeConsole(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pinned-shebang sealed-snapshot policy is Linux-specific")
	}
	originalOpen := openCLIConsole
	originalProvider := runCLIBundleWithProvider
	t.Cleanup(func() {
		openCLIConsole = originalOpen
		runCLIBundleWithProvider = originalProvider
	})
	opened, providerCalls := 0, 0
	openCLIConsole = func() (*os.File, *os.File, error) {
		opened++
		return nil, nil, errors.New("must not open")
	}
	runCLIBundleWithProvider = func(context.Context, []personal.BundleTarget, personal.RunBundleRequest, personal.RunBundleProvider) (personal.RunReceipt, error) {
		providerCalls++
		return personal.RunReceipt{Status: "process-exited", ExitCode: 0}, nil
	}
	program := filepath.Join(cliTestDir(t), "pinned-script")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf script\n"), 0700); err != nil {
		t.Fatal("pinned script fixture unavailable:", err)
	}
	binding := cliDesktopTestBinding(t, program)
	profile, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		t.Fatal("desktop profile unavailable")
	}
	if err := executeCLIAuthenticated("gh", binding, profile.Spec(), []string{"api"}, cliTestDir(t), 30); !errors.Is(err, personal.ErrRunProgramScriptPinUnsupported) {
		t.Fatalf("pinned shebang was not refused before console/provider: %v", err)
	}
	if opened != 0 || providerCalls != 0 {
		t.Fatalf("pinned shebang reached console/provider: opened=%d provider=%d", opened, providerCalls)
	}
}
