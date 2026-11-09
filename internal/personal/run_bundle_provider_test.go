package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

func providerTestTargets() []BundleTarget {
	id := "00112233445566778899aabbccddeeff"
	revision := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	return []BundleTarget{
		{Slot: "token", ID: id, Revision: revision, Field: "password"},
		{Slot: "username", ID: id, Revision: revision, Field: "username"},
		{Slot: "password", ID: id, Revision: revision, Field: "password"},
		{Slot: "kubeconfig", ID: id, Revision: revision, Field: "attachment"},
	}
}

func providerTestReceipt() RunBundleGrantReceipt {
	return RunBundleGrantReceipt{
		Session:      strings.Repeat("1", 32),
		Intent:       strings.Repeat("2", 64),
		TargetDigest: strings.Repeat("3", 64),
	}
}

func providerTestRequest(t *testing.T, mode string) RunBundleRequest {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	return RunBundleRequest{
		Program:        executable,
		Args:           bundleChildArgs(mode),
		Directory:      t.TempDir(),
		TimeoutSeconds: 15,
		HelperPath:     []string{filepath.Dir(executable)},
		Passthrough:    map[string]string{"BUNDLE_TEST_REGION": "test-region", "NO_COLOR": "1"},
		Spec:           bundleTestSpec(),
	}
}

func providerTestStreams(t *testing.T, inputText string) (runCLIStreams, *os.File, *os.File) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stdin"), []byte(inputText), 0600); err != nil {
		t.Fatal("stdin fixture unavailable")
	}
	input, err := os.Open(filepath.Join(dir, "stdin"))
	if err != nil {
		t.Fatal("stdin unavailable")
	}
	t.Cleanup(func() { input.Close() })
	output, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("stdout unavailable")
	}
	t.Cleanup(func() { output.Close() })
	errout, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("stderr unavailable")
	}
	t.Cleanup(func() { errout.Close() })
	return runCLIStreams{input, output, errout}, output, errout
}

func providerTestValueRefs(values map[string][]byte) [][]byte {
	refs := make([][]byte, 0, len(values))
	for _, name := range []string{"token", "username", "password", "kubeconfig"} {
		if value, ok := values[name]; ok {
			refs = append(refs, value)
		}
	}
	return refs
}

func assertProviderValuesZero(t *testing.T, refs [][]byte) {
	t.Helper()
	for i, value := range refs {
		for j, b := range value {
			if b != 0 {
				t.Fatalf("provider value %d byte %d was not zeroed", i, j)
			}
		}
	}
}

func assertProviderRootsRemoved(t *testing.T, roots []string) {
	t.Helper()
	for _, root := range roots {
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("temporary provider root survived: %s", root)
		}
	}
}

func TestRunBundleWithProviderRealChildPrivateRootAndStreams(t *testing.T) {
	request := providerTestRequest(t, "probe")
	targets := providerTestTargets()
	create, roots := testBundleTempCreatorTracked(t)
	streams, output, errout := providerTestStreams(t, "bundle input")

	var gotRequest RunBundleRequest
	var gotTargets []BundleTarget
	var gotRoot string
	var valueRefs [][]byte
	calls := 0
	provider := func(ctx context.Context, providedRequest RunBundleRequest, providedTargets []BundleTarget, root string) (RunBundleProviderResult, error) {
		calls++
		gotRequest, gotTargets, gotRoot = providedRequest, providedTargets, root
		// Mutating the provider clones must not change the caller request or the
		// slot set the adapter validates against.
		providedRequest.Args[0] = "provider-mutated"
		providedTargets[0].Slot = "provider-mutated"
		values := bundleTestValues()
		valueRefs = providerTestValueRefs(values)
		return RunBundleProviderResult{Values: values, Receipt: providerTestReceipt()}, nil
	}
	receipt, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, streams)
	}, os.RemoveAll)
	if err != nil || calls != 1 {
		t.Fatalf("provider run failed: %v calls=%d", err, calls)
	}
	if receipt.Status != "process-exited" || receipt.ExitCode != 0 ||
		receipt.Session != providerTestReceipt().Session ||
		receipt.Intent != providerTestReceipt().Intent ||
		receipt.TargetDigest != providerTestReceipt().TargetDigest {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if !filepath.IsAbs(gotRoot) {
		t.Fatalf("provider root is not absolute: %q", gotRoot)
	}
	if _, err = os.Stat(gotRoot); !os.IsNotExist(err) {
		t.Fatalf("provider root survived: %v", err)
	}
	if gotRequest.Args[0] != "provider-mutated" || request.Args[0] == "provider-mutated" {
		t.Fatal("provider request clone was not isolated")
	}
	if gotTargets[0].Slot != "provider-mutated" || targets[0].Slot == "provider-mutated" {
		t.Fatal("provider target clone was not isolated")
	}
	proof, err := os.ReadFile(filepath.Join(request.Directory, "child-proof"))
	if err != nil || string(proof) != gotRoot {
		t.Fatalf("child did not receive the actual provider root: %q %v", proof, err)
	}
	for _, file := range []*os.File{output, errout} {
		if _, err = file.Seek(0, 0); err != nil {
			t.Fatal("stream seek failed")
		}
		raw, readErr := io.ReadAll(file)
		if readErr != nil || string(raw) != bundleTestPassword {
			t.Fatal("child stream was not inherited")
		}
		clear(raw)
	}
	assertProviderValuesZero(t, valueRefs)
	assertProviderRootsRemoved(t, roots())
}

func TestRunBundleWithProviderPrivateRootPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows private temporary directories use ACLs rather than Unix mode bits")
	}
	request := providerTestRequest(t, "probe")
	request.Args = []string{"-test.run=^$"}
	targets := providerTestTargets()
	create, roots := testBundleTempCreatorTracked(t)
	var root string
	provider := func(ctx context.Context, providedRequest RunBundleRequest, providedTargets []BundleTarget, gotRoot string) (RunBundleProviderResult, error) {
		root = gotRoot
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Errorf("provider root is not a private directory: %v %v", info, err)
		}
		for _, name := range []string{"home", "gh", "config", "cache", "data", "tmp"} {
			info, err := os.Stat(filepath.Join(root, name))
			if err != nil || !info.IsDir() {
				t.Errorf("bundle directory %s missing: %v", name, err)
			}
		}
		return RunBundleProviderResult{Values: bundleTestValues(), Receipt: providerTestReceipt()}, nil
	}
	receipt, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
		return 0, nil
	}, os.RemoveAll)
	if err != nil || receipt.ExitCode != 0 {
		t.Fatalf("provider root check failed: %v %+v", err, receipt)
	}
	if root == "" {
		t.Fatal("provider was not invoked")
	}
	assertProviderRootsRemoved(t, roots())
}

func TestRunBundleWithProviderNonzeroChildExitStatus(t *testing.T) {
	request := providerTestRequest(t, "exit")
	targets := providerTestTargets()
	create, roots := testBundleTempCreatorTracked(t)
	streams, _, _ := providerTestStreams(t, "")
	provider := func(context.Context, RunBundleRequest, []BundleTarget, string) (RunBundleProviderResult, error) {
		return RunBundleProviderResult{Values: bundleTestValues(), Receipt: providerTestReceipt()}, nil
	}
	receipt, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, streams)
	}, os.RemoveAll)
	if err != nil || receipt.ExitCode != 7 || receipt.Status != "process-exited" {
		t.Fatalf("nonzero child exit lost: %v %+v", err, receipt)
	}
	assertProviderRootsRemoved(t, roots())
}

func TestRunBundleWithProviderCancellationZerosAndCleans(t *testing.T) {
	request := providerTestRequest(t, "probe")
	targets := providerTestTargets()
	create, roots := testBundleTempCreatorTracked(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var valueRefs [][]byte
	executed := 0
	provider := func(context.Context, RunBundleRequest, []BundleTarget, string) (RunBundleProviderResult, error) {
		values := bundleTestValues()
		valueRefs = providerTestValueRefs(values)
		cancel()
		return RunBundleProviderResult{Values: values, Receipt: providerTestReceipt()}, nil
	}
	receipt, err := runBundleWithProvider(ctx, targets, request, provider, create, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
		executed++
		return 0, nil
	}, os.RemoveAll)
	if !errors.Is(err, ErrRunCancelled) || receipt != (RunReceipt{}) || executed != 0 {
		t.Fatalf("cancelled provider run was not refused: %v %+v %d", err, receipt, executed)
	}
	assertProviderValuesZero(t, valueRefs)
	assertProviderRootsRemoved(t, roots())
}

func TestRunBundleWithProviderErrorZerosAndCleansBeforeFallback(t *testing.T) {
	request := providerTestRequest(t, "probe")
	targets := providerTestTargets()
	create, roots := testBundleTempCreatorTracked(t)
	unavailable := errors.New("provider endpoint unavailable before connect")
	var valueRefs [][]byte
	executed := 0
	provider := func(context.Context, RunBundleRequest, []BundleTarget, string) (RunBundleProviderResult, error) {
		values := bundleTestValues()
		valueRefs = providerTestValueRefs(values)
		return RunBundleProviderResult{Values: values, Receipt: providerTestReceipt()}, unavailable
	}
	receipt, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
		executed++
		return 0, nil
	}, os.RemoveAll)
	if !errors.Is(err, unavailable) || receipt != (RunReceipt{}) || executed != 0 {
		t.Fatalf("provider error was not classified: %v %+v %d", err, receipt, executed)
	}
	assertProviderValuesZero(t, valueRefs)
	assertProviderRootsRemoved(t, roots())
}

func TestRunBundleWithProviderCleanupFailureNeverReportsSuccess(t *testing.T) {
	request := providerTestRequest(t, "probe")
	targets := providerTestTargets()
	create := testBundleTempCreator(t)
	var valueRefs [][]byte
	provider := func(context.Context, RunBundleRequest, []BundleTarget, string) (RunBundleProviderResult, error) {
		values := bundleTestValues()
		valueRefs = providerTestValueRefs(values)
		return RunBundleProviderResult{Values: values, Receipt: providerTestReceipt()}, nil
	}
	receipt, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
		return 0, nil
	}, func(root string) error {
		os.RemoveAll(root)
		return errors.New("private cleanup failure")
	})
	if !errors.Is(err, ErrRunCleanup) || receipt != (RunReceipt{}) {
		t.Fatalf("cleanup failure was not distinguished: %v %+v", err, receipt)
	}
	assertProviderValuesZero(t, valueRefs)
}

func TestRunBundleWithProviderRejectsMalformedResults(t *testing.T) {
	request := providerTestRequest(t, "probe")
	targets := providerTestTargets()
	cases := []struct {
		name   string
		mutate func(map[string][]byte, *RunBundleGrantReceipt)
	}{
		{"extra-slot", func(values map[string][]byte, _ *RunBundleGrantReceipt) { values["extra"] = []byte("x") }},
		{"missing-slot", func(values map[string][]byte, _ *RunBundleGrantReceipt) { delete(values, "token") }},
		{"oversized-value", func(values map[string][]byte, _ *RunBundleGrantReceipt) {
			values["token"] = bytes.Repeat([]byte("x"), runBundleProviderMaxValueBytes+1)
		}},
		{"nil-values", func(_ map[string][]byte, _ *RunBundleGrantReceipt) {}},
		{"short-session", func(_ map[string][]byte, receipt *RunBundleGrantReceipt) {
			receipt.Session = strings.Repeat("1", 30)
		}},
		{"uppercase-session", func(_ map[string][]byte, receipt *RunBundleGrantReceipt) {
			receipt.Session = strings.Repeat("A", 32)
		}},
		{"noncanonical-intent", func(_ map[string][]byte, receipt *RunBundleGrantReceipt) {
			receipt.Intent = strings.Repeat("2", 63)
		}},
		{"noncanonical-target", func(_ map[string][]byte, receipt *RunBundleGrantReceipt) {
			receipt.TargetDigest = strings.Repeat("3", 64) + "0"
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			create, roots := testBundleTempCreatorTracked(t)
			values := bundleTestValues()
			receipt := providerTestReceipt()
			test.mutate(values, &receipt)
			if test.name == "nil-values" {
				values = nil
			}
			valueRefs := providerTestValueRefs(values)
			executed := 0
			provider := func(context.Context, RunBundleRequest, []BundleTarget, string) (RunBundleProviderResult, error) {
				return RunBundleProviderResult{Values: values, Receipt: receipt}, nil
			}
			got, err := runBundleWithProvider(context.Background(), targets, request, provider, create, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
				executed++
				return 0, nil
			}, os.RemoveAll)
			if !errors.Is(err, ErrRunCredential) || got != (RunReceipt{}) || executed != 0 {
				t.Fatalf("malformed provider result accepted: %v %+v %d", err, got, executed)
			}
			if values != nil && len(values) != 0 {
				t.Fatal("malformed provider values were not dropped")
			}
			assertProviderValuesZero(t, valueRefs)
			assertProviderRootsRemoved(t, roots())
		})
	}
}

func TestAdaptRunBundleProviderResultValueBound(t *testing.T) {
	targets := []BundleTarget{{Slot: "token", ID: strings.Repeat("a", 32), Revision: strings.Repeat("b", 64), Field: "password"}}
	receipt := providerTestReceipt()
	exact := RunBundleProviderResult{Values: map[string][]byte{"token": bytes.Repeat([]byte("x"), runBundleProviderMaxValueBytes)}, Receipt: receipt}
	adapted, err := adaptRunBundleProviderResult(exact, targets)
	if err != nil || len(adapted.values) != 1 {
		t.Fatalf("exact 64 KiB value was refused: %v", err)
	}
	clearBundleValues(adapted.values)
	oversizedValue := bytes.Repeat([]byte("y"), runBundleProviderMaxValueBytes+1)
	oversized := map[string][]byte{"token": oversizedValue}
	provided := RunBundleProviderResult{Values: oversized, Receipt: receipt}
	if _, err = adaptRunBundleProviderResult(provided, targets); !errors.Is(err, ErrRunCredential) {
		t.Fatalf("oversized value was accepted: %v", err)
	}
	if len(oversized) != 0 {
		t.Fatal("oversized value was not dropped")
	}
	for _, b := range oversizedValue {
		if b != 0 {
			t.Fatal("oversized value was not zeroed")
		}
	}
}

func TestRunBundleProviderResultRedactsFormattingAndJSON(t *testing.T) {
	secret := "provider-secret-value"
	result := RunBundleProviderResult{
		Values:  map[string][]byte{"token": []byte(secret)},
		Receipt: providerTestReceipt(),
	}
	for _, format := range []string{"%v", "%+v", "%s", "%#v"} {
		text := fmt.Sprintf(format, result)
		if strings.Contains(text, secret) {
			t.Fatalf("format %s exposed provider value: %s", format, text)
		}
	}
	if text := fmt.Sprintf("%v", &result); strings.Contains(text, secret) {
		t.Fatalf("pointer formatting exposed provider value: %s", text)
	}
	for _, value := range []any{result, &result} {
		raw, err := json.Marshal(value)
		if !errors.Is(err, ErrRunBundleProviderOpaque) || bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("JSON marshalling did not redact provider result: %q %v", raw, err)
		}
	}
	if result.String() != "[run bundle provider result]" || result.GoString() != "[run bundle provider result]" {
		t.Fatal("redacted carrier markers changed")
	}
}
