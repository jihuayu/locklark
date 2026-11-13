//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const browserhostNoCTTYChildEnv = "LOCKLARK_BROWSER_NO_CTTY_CHILD"

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
		if _, _, _, ok := peerControllingTerminal(os.Getpid()); ok {
			t.Fatal("no-CTTY child unexpectedly has a controlling terminal")
		}
		body(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^"+regexp.QuoteMeta(name)+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), browserhostNoCTTYChildEnv+"=1")
	cmd.Stdin = strings.NewReader("")
	var childOutput bytes.Buffer
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Run(); err != nil {
		t.Fatal("no-CTTY child failed the legacy contract")
	}
}
