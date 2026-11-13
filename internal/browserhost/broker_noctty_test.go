//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	browserhostNoCTTYChildEnv  = "LOCKLARK_BROWSER_NO_CTTY_CHILD"
	browserhostNoCTTYStatLimit = 64 << 10
	browserhostNoCTTYFail      = "no-CTTY child failed the legacy contract"
	browserhostNoCTTYStatPath  = "/proc/self/stat"
)

// runLegacyNoCTTYTest makes Linux-only legacy-gate contracts execute in a real
// child with no controlling terminal, regardless of the parent's TTY. Other
// platforms keep their original in-process behavior. Child output is never
// echoed; the parent reports only a fixed failure.
func runLegacyNoCTTYTest(t *testing.T, name string, body func(*testing.T)) {
	t.Helper()
	if runtime.GOOS != "linux" {
		body(t)
		return
	}
	if os.Getenv(browserhostNoCTTYChildEnv) == "1" {
		if !noCTTYStatField7IsZero(browserhostNoCTTYStatPath) {
			t.Fatal("no-CTTY child is not attested by a zero tty_nr")
		}
		body(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^"+regexp.QuoteMeta(name)+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), browserhostNoCTTYChildEnv+"=1")
	cmd.Stdin = strings.NewReader("")
	var childOutput bytes.Buffer
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(browserhostNoCTTYFail)
	}
	waitErr := cmd.Wait()
	if waitErr != nil || !noCTTYChildTargetPassed(childOutput.Bytes(), name) {
		t.Fatal(browserhostNoCTTYFail)
	}
}

// noCTTYStatField7IsZero reads /proc/self/stat directly and without trusting
// the production controlling-terminal resolver: that resolver also performs
// namespace and devpts work, so an unavailable result would not prove tty_nr
// is zero. The read is bounded, the command name is skipped at its final ')'
// (it may itself contain spaces or parentheses), and field 7's original token
// must be exactly "0".
func noCTTYStatField7IsZero(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, browserhostNoCTTYStatLimit+1))
	if err != nil || len(data) > browserhostNoCTTYStatLimit {
		return false
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+1 >= len(data) {
		return false
	}
	fields := strings.Fields(string(data[end+1:]))
	return len(fields) >= 5 && fields[4] == "0"
}

// noCTTYChildTargetPassed accepts only a verbose result for the exact test:
// both its RUN marker and its PASS marker are required, and any SKIP or a
// no-tests-to-run warning rejects the whole result. Exit status alone is not
// evidence that the intended test matched and ran.
func noCTTYChildTargetPassed(output []byte, name string) bool {
	runPrefix := "=== RUN   " + name
	sawRun := false
	sawPass := false
	for _, raw := range bytes.Split(output, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, "--- SKIP: ") ||
			strings.HasPrefix(line, "testing: warning: no tests to run") {
			return false
		}
		if line == runPrefix {
			sawRun = true
			continue
		}
		if noCTTYExactResult(line, "PASS", name) {
			sawPass = true
		}
	}
	return sawRun && sawPass
}

func noCTTYExactResult(line, status, name string) bool {
	prefix := "--- " + status + ": " + name
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	rest := line[len(prefix):]
	return rest == "" || rest[0] == ' ' || rest[0] == '\t'
}

func TestBrowserhostNoCTTYStatField7(t *testing.T) {
	for _, tc := range []struct {
		name string
		stat string
		want bool
	}{
		{"zero", "123 (worker) S 1 2 3 0 4 5\n", true},
		{"zero without newline", "123 (worker) S 1 2 3 0 4 5", true},
		{"comm parentheses and spaces", "123 (x) (y) S 1 2 3 0 4 5\n", true},
		{"nonzero", "123 (worker) S 1 2 3 1 4 5\n", false},
		{"noncanonical zero", "123 (worker) S 1 2 3 00 4 5\n", false},
		{"negative zero", "123 (worker) S 1 2 3 -0 4 5\n", false},
		{"missing close paren", "123 worker S 1 2 3 0 4 5\n", false},
		{"missing tty field", "123 (worker) S 1 2 3\n", false},
	} {
		if got := noCTTYStatField7IsZero(writeNoCTTYStat(t, tc.stat)); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestBrowserhostNoCTTYStatReadIsBounded(t *testing.T) {
	stat := "123 (worker) S 1 2 3 0 " + strings.Repeat("x", browserhostNoCTTYStatLimit)
	if noCTTYStatField7IsZero(writeNoCTTYStat(t, stat)) {
		t.Fatal("oversized stat was accepted")
	}
}

func writeNoCTTYStat(t *testing.T, stat string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBrowserhostNoCTTYChildResult(t *testing.T) {
	const target = "TestTarget"
	for _, tc := range []struct {
		name   string
		output string
		want   bool
	}{
		{"exact target pass", "=== RUN   TestTarget\n--- PASS: TestTarget (0.01s)\nPASS\n", true},
		{"pass without run marker", "--- PASS: TestTarget (0.01s)\nPASS\n", false},
		{"missing pass marker", "=== RUN   TestTarget\nPASS\n", false},
		{"no match", "testing: warning: no tests to run\nPASS\n", false},
		{"target skip", "=== RUN   TestTarget\n--- SKIP: TestTarget (0.00s)\nPASS\n", false},
		{"subtest skip", "=== RUN   TestTarget\n--- PASS: TestTarget (0.01s)\n    --- SKIP: TestTarget/sub (0.00s)\nPASS\n", false},
		{"name prefix only", "=== RUN   TestTarget\n--- PASS: TestTargetExtra (0.01s)\nPASS\n", false},
		{"subtest pass only", "=== RUN   TestTarget\n--- PASS: TestTarget/sub (0.01s)\nPASS\n", false},
		{"tab after target", "=== RUN   TestTarget\n--- PASS: TestTarget\t(0.01s)\n", true},
	} {
		if got := noCTTYChildTargetPassed([]byte(tc.output), target); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
