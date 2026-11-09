//go:build linux

package personal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

func runBundlePinNull(t *testing.T) *os.File {
	t.Helper()
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("null device unavailable: %v", err)
	}
	t.Cleanup(func() { _ = null.Close() })
	return null
}

// runBundlePinShell copies the real /bin/sh so the test executes an owned,
// ordinary binary image and never fabricates a shell/interpreter result.
func runBundlePinShell(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("/bin/sh")
	if err != nil || len(raw) == 0 {
		t.Fatalf("real shell image unavailable: %v", err)
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "pinned-sh")
	if err = os.WriteFile(program, raw, 0o700); err != nil {
		t.Fatalf("owned program copy unavailable: %v", err)
	}
	sum := sha256.Sum256(raw)
	return program, hex.EncodeToString(sum[:])
}

// TestExecuteRunBundleExecutesPinnedBytesAfterPathReplacement pauses after the
// program descriptor is pinned and before the child starts, atomically replaces
// the caller-visible path, and proves the child still executed the original
// bytes with the original argv0.
func TestExecuteRunBundleExecutesPinnedBytesAfterPathReplacement(t *testing.T) {
	program, digest := runBundlePinShell(t)
	null := runBundlePinNull(t)
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	defer output.Close()
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  digest,
		Args:           []string{"-c", "printf %s \"$0\""},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	oldSeam := runBundleBeforeStart
	replaced := false
	runBundleBeforeStart = func() {
		if replaced {
			t.Fatal("before-start seam ran twice")
		}
		replaced = true
		if err := os.Remove(program); err != nil {
			t.Fatalf("remove pinned path: %v", err)
		}
		if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf replaced\n"), 0o700); err != nil {
			t.Fatalf("replace pinned path: %v", err)
		}
	}
	t.Cleanup(func() { runBundleBeforeStart = oldSeam })

	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{null, output, null})
	if err != nil || code != 0 {
		t.Fatalf("pinned execution failed: %v code=%d", err, code)
	}
	if !replaced {
		t.Fatal("path replacement was not exercised")
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatalf("stdout seek: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("stdout read: %v", err)
	}
	if string(got) != program {
		t.Fatalf("child argv0 = %q, want the approved program path %q", got, program)
	}
	now, err := os.ReadFile(program)
	if err != nil {
		t.Fatalf("replacement path unreadable: %v", err)
	}
	if string(now) != "#!/bin/sh\nprintf replaced\n" {
		t.Fatal("path replacement did not take effect; the race was not exercised")
	}
}

// TestExecuteRunBundleExecutesPinnedBytesAfterInPlaceMutation truncates and
// rewrites the original inode after the sealed snapshot is taken. The child must
// still run the old image; a plain descriptor pin would run the new bytes or
// fail, and a path re-read would run them. The original argv0 must survive.
func TestExecuteRunBundleExecutesPinnedBytesAfterInPlaceMutation(t *testing.T) {
	program, digest := runBundlePinShell(t)
	null := runBundlePinNull(t)
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	defer output.Close()
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  digest,
		Args:           []string{"-c", `printf %s "$0"`},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	oldSeam := runBundleBeforeStart
	mutated := false
	runBundleBeforeStart = func() {
		if mutated {
			t.Fatal("before-start seam ran twice")
		}
		mutated = true
		file, err := os.OpenFile(program, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			t.Fatalf("open pinned path for mutation: %v", err)
		}
		if _, err = file.Write([]byte("#!/bin/sh\nprintf replaced\n")); err != nil {
			_ = file.Close()
			t.Fatalf("mutate pinned path: %v", err)
		}
		if err = file.Close(); err != nil {
			t.Fatalf("close mutated path: %v", err)
		}
	}
	t.Cleanup(func() { runBundleBeforeStart = oldSeam })

	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{null, output, null})
	if err != nil || code != 0 {
		t.Fatalf("pinned execution after in-place mutation failed: %v code=%d", err, code)
	}
	if !mutated {
		t.Fatal("in-place mutation was not exercised")
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatalf("stdout seek: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("stdout read: %v", err)
	}
	if string(got) != program {
		t.Fatalf("child argv0 = %q, want the approved program path %q (new bytes ran?)", got, program)
	}
	now, err := os.ReadFile(program)
	if err != nil {
		t.Fatalf("mutated path unreadable: %v", err)
	}
	if string(now) != "#!/bin/sh\nprintf replaced\n" {
		t.Fatal("in-place mutation did not take effect; the race was not exercised")
	}
}

// TestExecuteRunBundleRefusesPinnedShebangScript is the explicit-refusal
// replacement for the old sealed-shebang-snapshot test. A pinned shebang script
// must never run from the sealed memfd: the kernel would pass the /proc/self/fd
// path as the script's $0, silently changing relative-asset and Node-style
// package context. The refusal happens before any child starts and leaves no
// artifact.
func TestExecuteRunBundleRefusesPinnedShebangScript(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "pinned-script")
	marker := filepath.Join(dir, "child-ran")
	script := []byte("#!/bin/sh\nprintf child-ran > " + strconv.Quote(marker) + "\n")
	if err := os.WriteFile(program, script, 0o700); err != nil {
		t.Fatalf("script fixture unavailable: %v", err)
	}
	sum := sha256.Sum256(script)
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	defer output.Close()
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  hex.EncodeToString(sum[:]),
		Directory:      dir,
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	started := false
	oldSeam := runBundleBeforeStart
	runBundleBeforeStart = func() { started = true }
	t.Cleanup(func() { runBundleBeforeStart = oldSeam })

	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{runBundlePinNull(t), output, runBundlePinNull(t)})
	if !errors.Is(err, ErrRunProgramScriptPinUnsupported) {
		t.Fatalf("pinned shebang was not refused with the script-pin error: %v code=%d", err, code)
	}
	refusal := err
	if code != 0 {
		t.Fatalf("pinned shebang refusal returned code %d", code)
	}
	if started {
		t.Fatal("pinned shebang reached the child start seam")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pinned shebang child ran or left an artifact: %v", statErr)
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatalf("stdout seek: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil || len(got) != 0 {
		t.Fatalf("pinned shebang produced child output %q err=%v", got, err)
	}
	if !strings.Contains(refusal.Error(), "--pin-sha256 false") || !strings.Contains(refusal.Error(), "interpreter") {
		t.Fatalf("pinned shebang refusal is not actionable: %v", refusal)
	}
}

// TestCheckRunBundleProgramPinPreflightRefusesOnlyPinnedScripts proves the
// cheap pre-provider policy refuses a pinned shebang script, still accepts an
// explicit unpinned script (direct original path) and still accepts a pinned
// native executable image.
func TestCheckRunBundleProgramPinPreflightRefusesOnlyPinnedScripts(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "preflight-script")
	raw := []byte("#!/bin/sh\nprintf preflight\n")
	if err := os.WriteFile(script, raw, 0o700); err != nil {
		t.Fatalf("script fixture unavailable: %v", err)
	}
	sum := sha256.Sum256(raw)
	if err := CheckRunBundleProgramPinPreflight(script, hex.EncodeToString(sum[:])); !errors.Is(err, ErrRunProgramScriptPinUnsupported) {
		t.Fatalf("pinned shebang preflight was not refused: %v", err)
	}
	if err := CheckRunBundleProgramPinPreflight(script, ""); err != nil {
		t.Fatalf("unpinned script preflight was refused: %v", err)
	}
	program, digest := runBundlePinShell(t)
	if err := CheckRunBundleProgramPinPreflight(program, digest); err != nil {
		t.Fatalf("pinned native executable preflight was refused: %v", err)
	}
}

// TestExecuteRunBundleUnpinnedShebangPreservesOriginalPathAndAssets proves the
// explicit unpinned scope keeps direct-exec script semantics: the child sees
// its original $0 path, so assets resolved relative to the script and
// Node-style package context keep working. No sealed memfd copy is involved.
func TestExecuteRunBundleUnpinnedShebangPreservesOriginalPathAndAssets(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "unpinned-script")
	if err := os.WriteFile(filepath.Join(dir, "asset.txt"), []byte("asset-ok"), 0o600); err != nil {
		t.Fatalf("asset fixture unavailable: %v", err)
	}
	script := []byte("#!/bin/sh\ncat \"$(dirname \"$0\")/asset.txt\"\nprintf '|%s' \"$0\"\n")
	if err := os.WriteFile(program, script, 0o700); err != nil {
		t.Fatalf("script fixture unavailable: %v", err)
	}
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	defer output.Close()
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  "",
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{runBundlePinNull(t), output, runBundlePinNull(t)})
	if err != nil || code != 0 {
		t.Fatalf("unpinned shebang execution failed: %v code=%d", err, code)
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatalf("stdout seek: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("stdout read: %v", err)
	}
	if want := "asset-ok|" + program; string(got) != want {
		t.Fatalf("unpinned shebang output = %q, want %q (original $0 and relative assets must survive)", got, want)
	}
}

// TestExecuteRunBundlePinnedInterpreterKeepsScriptContext proves the supported
// workaround: pin an explicit trusted interpreter ELF and pass the original
// script path as an argument. The interpreter snapshot is exact, while the
// script keeps its own $0 and relative assets. The pin covers only the
// interpreter; the script argument, its assets and its dependencies are not
// implicitly pinned.
func TestExecuteRunBundlePinnedInterpreterKeepsScriptContext(t *testing.T) {
	interpreter, digest := runBundlePinShell(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "asset.txt"), []byte("asset-ok"), 0o600); err != nil {
		t.Fatalf("asset fixture unavailable: %v", err)
	}
	scriptPath := filepath.Join(dir, "worker-harness.sh")
	script := []byte("cat \"$(dirname \"$0\")/asset.txt\"\nprintf '|%s' \"$0\"\n")
	if err := os.WriteFile(scriptPath, script, 0o700); err != nil {
		t.Fatalf("script fixture unavailable: %v", err)
	}
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	defer output.Close()
	request := RunBundleRequest{
		Program:        interpreter,
		ProgramSHA256:  digest,
		Args:           []string{scriptPath},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{runBundlePinNull(t), output, runBundlePinNull(t)})
	if err != nil || code != 0 {
		t.Fatalf("pinned interpreter execution failed: %v code=%d", err, code)
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatalf("stdout seek: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("stdout read: %v", err)
	}
	if want := "asset-ok|" + scriptPath; string(got) != want {
		t.Fatalf("pinned interpreter script output = %q, want %q", got, want)
	}
}

// TestExecuteRunBundleRefusesPostApprovalPathReplacement proves that a caller
// which approved one image refuses when the path already names different bytes
// by the time execution starts. This is the VerifyProgram-to-exec window.
func TestExecuteRunBundleRefusesPostApprovalPathReplacement(t *testing.T) {
	program, digest := runBundlePinShell(t)
	null := runBundlePinNull(t)
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  digest,
		Args:           []string{"-c", "printf replaced"},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	// Replace the approved path with a different native executable image so
	// this test keeps exercising the digest-mismatch refusal rather than the
	// dedicated pinned-shebang policy above.
	replacement, err := os.ReadFile("/bin/echo")
	if err != nil || len(replacement) == 0 {
		t.Fatalf("replacement native image unavailable: %v", err)
	}
	if err := os.Remove(program); err != nil {
		t.Fatalf("remove approved path: %v", err)
	}
	if err := os.WriteFile(program, replacement, 0o700); err != nil {
		t.Fatalf("replace approved path: %v", err)
	}
	if _, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{null, null, null}); !errors.Is(err, ErrRunResult) {
		t.Fatalf("post-approval replacement was not refused: %v", err)
	}
}

// TestExecuteRunBundleRefusesPinnedDigestMismatch proves that an explicitly
// wrong pin is refused before any child exists.
func TestExecuteRunBundleRefusesPinnedDigestMismatch(t *testing.T) {
	program, _ := runBundlePinShell(t)
	null := runBundlePinNull(t)
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  strings.Repeat("00", 32),
		Args:           []string{"-c", "printf started"},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{"/bin"},
		Spec:           bundleTestSpec(),
	}
	if _, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, runCLIStreams{null, null, null}); !errors.Is(err, ErrRunResult) {
		t.Fatalf("pinned digest mismatch was not refused: %v", err)
	}
}

// TestRunBundlePropagatesPinnedShebangRefusal proves the public local bundle
// path (the one the full-factor CLI path calls) surfaces the fixed actionable
// refusal instead of collapsing it into the generic result error.
func TestRunBundlePropagatesPinnedShebangRefusal(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "bundle-pinned-script")
	raw := []byte("#!/bin/sh\nprintf bundle\n")
	if err := os.WriteFile(program, raw, 0o700); err != nil {
		t.Fatalf("script fixture unavailable: %v", err)
	}
	sum := sha256.Sum256(raw)
	spec := cliprofile.Spec{
		ID:         "pinned-shebang-test-v1",
		Slots:      []cliprofile.Slot{{Name: "token", Kind: "login", Field: cliprofile.FieldPassword}},
		MaxTimeout: 60,
	}
	targets := []BundleTarget{{
		Slot: "token", ID: "0123456789abcdef0123456789abcdef", Revision: strings.Repeat("ab", 32), Field: "password",
	}}
	request := RunBundleRequest{
		Program:        program,
		ProgramSHA256:  hex.EncodeToString(sum[:]),
		Directory:      dir,
		TimeoutSeconds: 10,
		Spec:           spec,
	}
	null := runBundlePinNull(t)
	_, err := runBundle(context.Background(), targets, request,
		func() (string, error) { return t.TempDir(), nil },
		func(*runBundleStoreRequest) (result, error) {
			return result{
				values:            map[string][]byte{"token": []byte("test-only-value")},
				session:           strings.Repeat("1", 32),
				intent:            strings.Repeat("2", 64),
				destinationDigest: strings.Repeat("3", 64),
			}, nil
		},
		func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
			return executeRunBundle(ctx, req, root, rendered, runCLIStreams{null, null, null})
		},
		func(string) error { return nil })
	if !errors.Is(err, ErrRunProgramScriptPinUnsupported) {
		t.Fatalf("local bundle path lost the pinned-shebang refusal: %v", err)
	}
}
