//go:build windows

package personal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

// runBundleWindowsHelper copies this test executable into its own temporary
// directory, so every pin test runs an ordinary Windows CLI binary (a real PE
// image) that is owned by the test, in its own directory, and is not a shell,
// PowerShell or interpreter wrapper. The copy re-executes this test binary in
// child mode.
func runBundleWindowsHelper(t *testing.T) (string, []byte) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable unavailable: %v", err)
	}
	raw, err := os.ReadFile(exe)
	if err != nil || len(raw) == 0 {
		t.Fatalf("test executable image unavailable: %v", err)
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "locklark-pin-helper.exe")
	if err = os.WriteFile(program, raw, 0o700); err != nil {
		t.Fatalf("owned helper image unavailable: %v", err)
	}
	return program, raw
}

// runBundleWindowsRename retries a rename for a short while so that the
// post-release assertions prove the guard is gone instead of racing the tail of
// the child's process teardown.
func runBundleWindowsRename(t *testing.T, from, to string) {
	t.Helper()
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		if err = os.Rename(from, to); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("rename %q -> %q did not succeed after the pin was released: %v", from, to, err)
}

func runBundleWindowsDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// runBundleWindowsStdio gives the run real files for all three standard streams
// and returns a reader for what the child wrote to them.
func runBundleWindowsStdio(t *testing.T, stdin string) (runCLIStreams, func() (string, string)) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "stdin")
	if err := os.WriteFile(input, []byte(stdin), 0o600); err != nil {
		t.Fatalf("stdin fixture unavailable: %v", err)
	}
	in, err := os.Open(input)
	if err != nil {
		t.Fatalf("stdin unavailable: %v", err)
	}
	out, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("stdout fixture unavailable: %v", err)
	}
	errOut, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("stderr fixture unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = out.Close()
		_ = errOut.Close()
	})
	read := func() (string, string) {
		t.Helper()
		readAll := func(file *os.File, name string) string {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatalf("%s seek: %v", name, err)
			}
			raw, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("%s read: %v", name, err)
			}
			return string(raw)
		}
		return readAll(out, "stdout"), readAll(errOut, "stderr")
	}
	return runCLIStreams{in, out, errOut}, read
}

func runBundleWindowsRequest(t *testing.T, program, digest, mode string) RunBundleRequest {
	t.Helper()
	return RunBundleRequest{
		Program:        program,
		ProgramSHA256:  digest,
		Args:           []string{"-test.run=^TestRunBundleWindowsPinChild$", "--", "pin-child", mode},
		Directory:      t.TempDir(),
		TimeoutSeconds: 30,
		HelperPath:     []string{filepath.Dir(program)},
		Spec:           bundleTestSpec(),
	}
}

// TestExecuteRunBundleWindowsPinsImageAndAncestry proves, through the real
// executeRunBundle path with the real pin, that while the guard handles are held
// no other handle may truncate, overwrite, rename or delete the approved image
// and no directory on its path can be renamed; the attempts are made both from
// this process and from a separate attacker process started before the child
// exists. The child must still start from the approved bytes and exit 0, and the
// same operations must succeed once the guard is released.
func TestExecuteRunBundleWindowsPinsImageAndAncestry(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	streams, read := runBundleWindowsStdio(t, "guarded-stdin")
	request := runBundleWindowsRequest(t, program, runBundleWindowsDigest(raw), "echo")
	parent := filepath.Dir(program)
	movedParent := parent + "-moved"
	oldSeam := runBundleBeforeStart
	guarded := false
	runBundleBeforeStart = func() {
		if guarded {
			t.Fatal("before-start seam ran twice")
		}
		guarded = true
		if err := os.Rename(program, program+".moved"); err == nil {
			t.Fatal("pinned image was renamed while the guard handle was held")
		}
		truncate, err := os.OpenFile(program, os.O_WRONLY|os.O_TRUNC, 0)
		if err == nil {
			_ = truncate.Close()
			t.Fatal("pinned image was truncated while the guard handle was held")
		}
		if err = os.Remove(program); err == nil {
			t.Fatal("pinned image was deleted while the guard handle was held")
		}
		if err = os.Rename(parent, movedParent); err == nil {
			_ = os.Rename(movedParent, parent)
			t.Fatal("pinned image parent directory was renamed while the guard handle was held")
		}
		// The same attempts from a second, independent process. No child of the
		// pin exists yet, so nothing but the guard handles can make them fail.
		attacker, err := os.Executable()
		if err != nil {
			t.Fatalf("attacker image unavailable: %v", err)
		}
		out, err := exec.Command(attacker, "-test.run=^TestRunBundleWindowsPinChild$", "--", "pin-child", "attack", program).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "attack-blocked") {
			t.Fatalf("separate process was not blocked by the pin: err=%v output=%q", err, out)
		}
	}
	t.Cleanup(func() { runBundleBeforeStart = oldSeam })

	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams)
	if err != nil || code != 0 {
		t.Fatalf("guarded execution failed: %v code=%d", err, code)
	}
	if !guarded {
		t.Fatal("guard window was not exercised")
	}
	stdout, stderr := read()
	if !strings.Contains(stdout, "argv0="+program+"\n") {
		t.Fatalf("child argv0 = %q, want the approved program path %q", stdout, program)
	}
	if !strings.Contains(stdout, "stdin=guarded-stdin") {
		t.Fatalf("child did not read the caller's stdin directly: %q", stdout)
	}
	if !strings.Contains(stderr, "pin-child-stderr") {
		t.Fatalf("child did not write the caller's stderr directly: %q", stderr)
	}
	// The guard is released when the child exits, so the operations that failed
	// above must now succeed. That ties the earlier failures to the pin.
	runBundleWindowsRename(t, parent, movedParent)
	runBundleWindowsRename(t, movedParent, parent)
	runBundleWindowsRename(t, program, program+".moved")
	runBundleWindowsRename(t, program+".moved", program)
}

// TestExecuteRunBundleWindowsRefusesStaleProgramImage proves the approval digest
// is compared against the bytes the pin opened: a different real image at the
// approved path is refused before any child exists, and the very same image is
// accepted when it is the approved one.
func TestExecuteRunBundleWindowsRefusesStaleProgramImage(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	approved := runBundleWindowsDigest(raw)
	stale := append(append([]byte(nil), raw...), []byte("\x00locklark-stale-image\x00")...)
	staleDigest := runBundleWindowsDigest(stale)
	if staleDigest == approved {
		t.Fatal("stale image digest is not distinct")
	}
	if err := os.WriteFile(program, stale, 0o700); err != nil {
		t.Fatalf("stale image fixture unavailable: %v", err)
	}
	streams, read := runBundleWindowsStdio(t, "")
	request := runBundleWindowsRequest(t, program, approved, "echo")
	if _, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams); !errors.Is(err, ErrRunResult) {
		t.Fatalf("stale image was accepted for the approved digest: %v", err)
	}
	if stdout, stderr := read(); stdout != "" || stderr != "" {
		t.Fatalf("child ran for a stale image: stdout=%q stderr=%q", stdout, stderr)
	}
	request = runBundleWindowsRequest(t, program, staleDigest, "echo")
	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams)
	if err != nil || code != 0 {
		t.Fatalf("approved stale image did not run: %v code=%d", err, code)
	}
	if stdout, _ := read(); !strings.Contains(stdout, "argv0="+program+"\n") {
		t.Fatalf("approved image child argv0 missing: %q", stdout)
	}
}

// TestExecuteRunBundleWindowsExactDigestRefusesAnotherImage proves a pin taken
// for one approved image refuses a different, still runnable image at the same
// path, and that a wrong digest for the approved image itself is refused too.
func TestExecuteRunBundleWindowsExactDigestRefusesAnotherImage(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	approved := runBundleWindowsDigest(raw)
	other := append(append([]byte(nil), raw...), []byte("\x00locklark-other-image\x00")...)
	if err := os.WriteFile(program, other, 0o700); err != nil {
		t.Fatalf("other image fixture unavailable: %v", err)
	}
	streams, read := runBundleWindowsStdio(t, "")
	request := runBundleWindowsRequest(t, program, approved, "echo")
	if _, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams); !errors.Is(err, ErrRunResult) {
		t.Fatalf("other image accepted for the approved digest: %v", err)
	}
	if stdout, _ := read(); stdout != "" {
		t.Fatalf("child ran for an unapproved image: %q", stdout)
	}
	request = runBundleWindowsRequest(t, program, strings.Repeat("00", 32), "echo")
	if _, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams); !errors.Is(err, ErrRunResult) {
		t.Fatalf("wrong digest accepted: %v", err)
	}
	if stdout, _ := read(); stdout != "" {
		t.Fatalf("child ran for an explicitly wrong digest: %q", stdout)
	}
}

// TestExecuteRunBundleWindowsDirectStreamsAndSingleChild proves the child is one
// direct child of this process: it receives the original stdin/stdout/stderr and
// argv0, and its parent is this process rather than a shell, PowerShell or any
// capture wrapper.
func TestExecuteRunBundleWindowsDirectStreamsAndSingleChild(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	streams, read := runBundleWindowsStdio(t, "direct-stdin-line")
	request := runBundleWindowsRequest(t, program, runBundleWindowsDigest(raw), "echo")
	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams)
	if err != nil || code != 0 {
		t.Fatalf("direct execution failed: %v code=%d", err, code)
	}
	stdout, stderr := read()
	for _, want := range []string{
		"argv0=" + program + "\n",
		"stdin=direct-stdin-line",
		fmt.Sprintf("ppid=%d\n", os.Getpid()),
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("child stdout %q is missing %q", stdout, want)
		}
	}
	if !strings.Contains(stderr, "pin-child-stderr") {
		t.Fatalf("child stderr %q is missing its own output", stderr)
	}
}

// TestNewRunBundleCommandWindowsEmptyDigestIsExplicitlyUnpinned proves an empty
// approved digest is the explicit unpinned scope: the original program path is
// executed directly and no write or delete guard is held while the command is
// pending.
func TestNewRunBundleCommandWindowsEmptyDigestIsExplicitlyUnpinned(t *testing.T) {
	program, _ := runBundleWindowsHelper(t)
	args := []string{"-test.run=^TestRunBundleWindowsPinChild$", "--", "pin-child", "echo"}
	streams, read := runBundleWindowsStdio(t, "unpinned-stdin")
	cmd, closeProgram, err := newRunBundleCommand(context.Background(), program, args, "")
	if err != nil {
		t.Fatalf("explicitly unpinned run was refused: %v", err)
	}
	if cmd.Path != program || len(cmd.Args) != len(args)+1 || cmd.Args[0] != program {
		t.Fatalf("command does not name the original program directly: path=%q args=%q", cmd.Path, cmd.Args)
	}
	for i := range args {
		if cmd.Args[i+1] != args[i] {
			t.Fatalf("child argument %d = %q, want %q", i, cmd.Args[i+1], args[i])
		}
	}
	// The empty-digest path must not hold the image guard: a second writer may
	// open it and the name may be renamed while the command is still pending.
	writer, err := os.OpenFile(program, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("write guard was held for an empty digest: %v", err)
	}
	_ = writer.Close()
	moved := program + ".unpinned"
	if err = os.Rename(program, moved); err != nil {
		t.Fatalf("delete guard was held for an empty digest: %v", err)
	}
	if err = os.Rename(moved, program); err != nil {
		t.Fatalf("restore unpinned helper: %v", err)
	}
	closeProgram() // no-op: nothing has to be released before the child runs
	cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.in, streams.out, streams.err
	if err = cmd.Run(); err != nil {
		t.Fatalf("explicitly unpinned direct exec failed: %v", err)
	}
	stdout, stderr := read()
	if !strings.Contains(stdout, "argv0="+program+"\n") {
		t.Fatalf("child argv0 = %q, want the original program path %q", stdout, program)
	}
	if !strings.Contains(stdout, "stdin=unpinned-stdin") {
		t.Fatalf("child did not read the caller's stdin directly: %q", stdout)
	}
	if !strings.Contains(stderr, "pin-child-stderr") {
		t.Fatalf("child did not write the caller's stderr directly: %q", stderr)
	}
}

// TestNewRunBundleCommandWindowsEmptyDigestRequiresOrdinaryExe proves the
// explicit unpinned path still refuses a relative path, a directory, an empty
// image, a missing file and a non-.exe name instead of executing them.
func TestNewRunBundleCommandWindowsEmptyDigestRequiresOrdinaryExe(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	dir := t.TempDir()
	directory := filepath.Join(dir, "directory.exe")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("directory fixture unavailable: %v", err)
	}
	empty := filepath.Join(dir, "empty.exe")
	if err := os.WriteFile(empty, nil, 0o700); err != nil {
		t.Fatalf("empty fixture unavailable: %v", err)
	}
	noExtension := filepath.Join(dir, "helper-no-extension")
	if err := os.WriteFile(noExtension, raw, 0o700); err != nil {
		t.Fatalf("extension fixture unavailable: %v", err)
	}
	for _, test := range []struct {
		name    string
		program string
	}{
		{"relative path", filepath.Base(program)},
		{"directory", directory},
		{"empty image", empty},
		{"missing file", filepath.Join(dir, "missing.exe")},
		{"no executable extension", noExtension},
	} {
		cmd, closeProgram, err := newRunBundleCommand(context.Background(), test.program, []string{"--", "pin-child", "echo"}, "")
		if err == nil {
			if closeProgram != nil {
				closeProgram()
			}
			if cmd != nil {
				t.Fatalf("%s was accepted for an empty digest: %q", test.name, cmd.Path)
			}
			t.Fatalf("%s was accepted for an empty digest", test.name)
		}
		if !errors.Is(err, ErrRunResult) {
			t.Fatalf("%s refused with %v, want ErrRunResult", test.name, err)
		}
	}
}

// TestExecuteRunBundleWindowsHonoursContext proves cancellation and the run
// deadline stop the child instead of leaving an unpinned fallback to run it.
func TestExecuteRunBundleWindowsHonoursContext(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	digest := runBundleWindowsDigest(raw)
	streams, read := runBundleWindowsStdio(t, "")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request := runBundleWindowsRequest(t, program, digest, "echo")
	if _, err := executeRunBundle(cancelled, request, t.TempDir(), cliprofile.RenderedBundle{}, streams); !errors.Is(err, ErrRunCancelled) {
		t.Fatalf("cancelled context ran the child: %v", err)
	}
	if stdout, _ := read(); stdout != "" {
		t.Fatalf("cancelled context produced child output: %q", stdout)
	}

	request = runBundleWindowsRequest(t, program, digest, "sleep")
	request.TimeoutSeconds = 1
	start := time.Now()
	code, err := executeRunBundle(context.Background(), request, t.TempDir(), cliprofile.RenderedBundle{}, streams)
	if !errors.Is(err, ErrRunResult) || code != 0 {
		t.Fatalf("deadline did not fail the run: code=%d err=%v", code, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("deadline did not interrupt the child: %v", elapsed)
	}
}

// TestPinRunBundleProgramWindowsRefusesUnsafePrograms covers the local refusals
// that do not need a second process: a directory named like an executable, an
// empty image, a missing file, a non-.exe name and a digest for another image.
func TestPinRunBundleProgramWindowsRefusesUnsafePrograms(t *testing.T) {
	program, raw := runBundleWindowsHelper(t)
	dir := t.TempDir()
	directory := filepath.Join(dir, "directory.exe")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("directory fixture unavailable: %v", err)
	}
	empty := filepath.Join(dir, "empty.exe")
	if err := os.WriteFile(empty, nil, 0o700); err != nil {
		t.Fatalf("empty fixture unavailable: %v", err)
	}
	noExtension := filepath.Join(dir, "helper-no-extension")
	if err := os.WriteFile(noExtension, raw, 0o700); err != nil {
		t.Fatalf("extension fixture unavailable: %v", err)
	}
	for _, test := range []struct {
		name    string
		program string
		digest  string
	}{
		{"directory", directory, ""},
		{"empty image", empty, ""},
		{"missing file", filepath.Join(dir, "missing.exe"), ""},
		{"no executable extension", noExtension, ""},
		{"digest for another image", program, strings.Repeat("ab", 32)},
	} {
		pinned, err := pinRunBundleProgram(test.program, test.digest)
		if err == nil {
			pinned.close()
			t.Fatalf("%s was pinned", test.name)
		}
		if !errors.Is(err, ErrRunResult) {
			t.Fatalf("%s refused with %v, want ErrRunResult", test.name, err)
		}
	}
	pinned, err := pinRunBundleProgram(program, runBundleWindowsDigest(raw))
	if err != nil {
		t.Fatalf("ordinary helper refused: %v", err)
	}
	if pinned.image == nil || len(pinned.ancestry) == 0 {
		t.Fatal("pin did not hold the image and ancestry guards")
	}
	pinned.close()
	if pinned.image != nil || len(pinned.ancestry) != 0 {
		t.Fatal("pin did not release its guards")
	}
	pinned.close() // idempotent release
}

// TestRunBundleWindowsPinChild is the child mode of the helper image. It only
// acts when it is invoked with the pin-child marker and never runs during a
// normal test pass.
func TestRunBundleWindowsPinChild(t *testing.T) {
	mode := ""
	for i, arg := range os.Args {
		if arg == "pin-child" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			break
		}
	}
	if mode == "" {
		return
	}
	switch mode {
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "attack":
		// A separate process must not be able to replace, truncate or delete the
		// image while the pin is held.
		target := os.Args[len(os.Args)-1]
		var allowed []string
		if file, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
			_ = file.Close()
			allowed = append(allowed, "truncate")
		}
		if err := os.Rename(target, target+".moved"); err == nil {
			allowed = append(allowed, "rename")
		}
		if err := os.Remove(target); err == nil {
			allowed = append(allowed, "delete")
		}
		if len(allowed) > 0 {
			fmt.Fprintf(os.Stdout, "attack-allowed=%s\n", strings.Join(allowed, ","))
			os.Exit(74)
		}
		fmt.Fprintf(os.Stdout, "attack-blocked\n")
		os.Exit(0)
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(72)
	}
	fmt.Fprintf(os.Stdout, "argv0=%s\n", os.Args[0])
	fmt.Fprintf(os.Stdout, "ppid=%d\n", os.Getppid())
	fmt.Fprintf(os.Stdout, "stdin=%s\n", stdin)
	fmt.Fprintf(os.Stderr, "pin-child-stderr\n")
	os.Exit(0)
}
