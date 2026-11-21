//go:build linux

package browserhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/localpath"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/sys/unix"
)

// The peer half of TestLinuxBrokerPeerUnsupportedTTYRefusedBeforeApproval runs
// in the same test binary, re-executed by this test with a real kernel-owned
// controlling terminal. Only the helper switch and one serialized synthetic
// request cross into that process; the private socket is named through the
// production environment variable the client already reads.
const (
	linuxBrokerPeerHelperEnv  = "LOCKLARK_TEST_BROWSERHOST_LINUX_BROKER_PEER_HELPER"
	linuxBrokerPeerFixtureEnv = "LOCKLARK_TEST_BROWSERHOST_LINUX_BROKER_PEER_FIXTURE"
	linuxBrokerPeerTestName   = "TestLinuxBrokerPeerUnsupportedTTYRefusedBeforeApproval"
	linuxBrokerPeerRefused    = "linux-broker-peer-refused"
	linuxBrokerPeerWait       = 20 * time.Second
)

// TestLinuxBrokerPeerUnsupportedTTYRefusedBeforeApproval is the T4_06 live
// broker-peer checkpoint for the documented Linux result: because Linux has no
// kernel proof that a peer's tty_nr names this broker's terminal object,
// AttestCLIRunTTY is unavailable, so every otherwise-valid CLI-run request is
// the ordinary fixed refusal before approval and before any prepared value.
//
// The test does not replace the production terminal gate or the production
// path trust check. A synthetic, owned vault and a short private Unix socket
// under the real localpath.TrustedTemporaryParent feed one normal request from
// a real peer process started on a test-owned PTY. That peer derives its own
// kernel-attested controlling terminal with CurrentTTYIdentity and sends
// through RequestCLIRun. The test-only HandleCLIRun callback would return a
// synthetic prepared success, so reaching it would be an explicit failure; the
// observed refusal must come first.
func TestLinuxBrokerPeerUnsupportedTTYRefusedBeforeApproval(t *testing.T) {
	if os.Getenv(linuxBrokerPeerHelperEnv) == "1" {
		linuxBrokerPeerExchange(t)
		return
	}

	// This is the documented platform fact the live exchange must exercise,
	// not a substituted gate. A future Linux peer association would make this
	// checkpoint obsolete rather than silently pass.
	if cliRunTTYPeerAttestationAvailable() {
		t.Fatal("Linux peer TTY attestation is unexpectedly available")
	}
	if _, e := AttestCLIRunTTY(Peer{PID: uint32(os.Getpid())}); !errors.Is(e, errCLIRunUnavailable) {
		t.Fatalf("Linux peer TTY attestation = %v, want unavailable", e)
	}

	endpoint := linuxBrokerTestTrustedSocket(t)
	session, row := brokerTestSession(t)

	// One correctly formed, normal request against the synthetic session.
	request := freshCLIRunFixtureRequest()
	request.VaultPath = session.VaultPath()
	request.Targets = []personal.CLIBrokerTarget{{
		Slot:     "token",
		ID:       row.ID,
		Revision: row.Revision,
		Field:    "password",
	}}
	fixture, e := json.Marshal(request)
	if e != nil {
		t.Fatal("marshal synthetic peer request")
	}
	defer clear(fixture)

	// Test-only approval/preparation callback. If the refusal did not precede
	// it, the synthetic prepared success and this flag make the failure
	// explicit instead of leaving a value-bearing reply to be classified.
	receipt := cliRunReceiptFromFixture(t)
	synthetic := []byte("linux-peer-callback-prepared-value")
	var callbackRan atomic.Bool
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			callbackRan.Store(true)
			return BrokerCLIResponse{
				V:              1,
				PreparedValues: map[string][]byte{"token": synthetic},
				Receipt:        receipt,
			}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal("start private broker socket")
	}
	t.Cleanup(func() { _ = broker.Close() })

	executable, e := os.Executable()
	if e != nil {
		t.Fatal("test executable unavailable")
	}

	// This native PTY is owned by the test, not by the invoking terminal. The
	// child gets it as fd 0 and as its controlling terminal below.
	_, slave := openLinuxBrokerPeerPTY(t)

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), linuxBrokerPeerWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable,
		"-test.run=^"+linuxBrokerPeerTestName+"$",
		"-test.count=1",
	)
	// Keep the child environment minimal: the helper switch, one serialized
	// synthetic request, and the same private socket variable production reads.
	cmd.Env = []string{
		linuxBrokerPeerHelperEnv + "=1",
		linuxBrokerPeerFixtureEnv + "=" + base64.RawURLEncoding.EncodeToString(fixture),
		"LOCKLARK_BROWSER_SOCKET=" + endpoint,
	}
	cmd.Stdin = slave
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Setsid makes the child a session leader; Setctty with Ctty 0 makes the
	// slave its controlling terminal, which is what CurrentTTYIdentity reads.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	cmd.WaitDelay = 5 * time.Second
	if e := cmd.Start(); e != nil {
		t.Fatalf("real PTY peer did not start: %v", e)
	}
	_ = slave.Close()
	if cmd.Process.Pid == os.Getpid() {
		t.Fatal("PTY peer is not a distinct process")
	}
	runErr := cmd.Wait()
	if callbackRan.Load() {
		t.Fatal("peer terminal refusal did not precede approval")
	}
	if runErr != nil {
		if ctx.Err() != nil {
			t.Fatalf("real PTY peer exceeded %s: %v\n%s%s", linuxBrokerPeerWait, runErr, stdout.String(), stderr.String())
		}
		t.Fatalf("real PTY peer exchange did not complete: %v\n%s%s", runErr, stdout.String(), stderr.String())
	}
	// The peer writes one fixed marker to stderr only after it has observed the
	// exact refusal; the test binary's fixed "PASS" goes to stdout. A skip, an
	// early success, or any unexpected diagnostic cannot pass.
	if got := strings.TrimSpace(stderr.String()); got != linuxBrokerPeerRefused {
		t.Fatalf("real PTY peer did not report the ordinary refusal: %q", got)
	}
	if got := strings.TrimSpace(stdout.String()); got != "PASS" {
		t.Fatalf("real PTY peer wrote unexpected output: %q", got)
	}
}

// linuxBrokerPeerExchange is the peer side of the checkpoint. It runs only in
// the re-executed child, decodes the single synthetic request fixture, derives
// the child's real controlling terminal through the production client helper,
// and sends exactly one normal request through the production client. The
// expected ordinary result is the fixed refusal, never the fallback-eligible
// unavailable reply.
func linuxBrokerPeerExchange(t *testing.T) {
	raw, e := base64.RawURLEncoding.DecodeString(os.Getenv(linuxBrokerPeerFixtureEnv))
	if e != nil {
		t.Fatal("synthetic peer fixture is not valid base64")
	}
	defer clear(raw)
	var request CLIRunBrokerRequest
	if e := json.Unmarshal(raw, &request); e != nil {
		t.Fatal("synthetic peer fixture is not a request")
	}

	name, _, e := CurrentTTYIdentity()
	if e != nil {
		t.Fatal("peer has no kernel-attested controlling terminal")
	}
	request.Scope.TTY = name
	request.Scope.TTYPlatform = CLIRunTTYPlatform()
	request.Scope.TTYPeerID = ""

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, e := RequestCLIRun(ctx, request)
	if !errors.Is(e, ErrCLIRunRefused) {
		if errors.Is(e, ErrBrokerUnavailable) {
			t.Fatal("Linux unsupported peer terminal was treated as unavailable")
		}
		t.Fatalf("Linux unsupported peer terminal was not the ordinary refusal: %v", e)
	}
	if response.PreparedValues != nil || response.Values != nil ||
		response.Receipt != (personal.RunBundlePreparationReceipt{}) {
		t.Fatal("peer terminal refusal carried prepared data")
	}
	if _, e := os.Stderr.WriteString(linuxBrokerPeerRefused + "\n"); e != nil {
		t.Fatal("peer could not record the ordinary refusal")
	}
}

// openLinuxBrokerPeerPTY creates the test's own PTY pair. The master stays
// open in the parent for the pair's lifetime; the slave is passed to the child
// as its stdin and controlling terminal. There is no skip: a Linux container
// without a usable devpts PTY fails this strict checkpoint.
func openLinuxBrokerPeerPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, e := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if e != nil {
		t.Fatalf("pty master unavailable: %v", e)
	}
	t.Cleanup(func() { _ = master.Close() })
	if e := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); e != nil {
		t.Fatalf("pty unlock unavailable: %v", e)
	}
	unit, e := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if e != nil {
		t.Fatalf("pty unit unavailable: %v", e)
	}
	slave, e = os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(unit)), os.O_RDWR|unix.O_NOCTTY, 0)
	if e != nil {
		t.Fatalf("pty slave unavailable: %v", e)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

// linuxBrokerTestTrustedSocket returns a short, private socket path under the
// real temporary-parent trust check. It deliberately does not use
// brokerTestSocket, which swaps trustedBrokerParent for an untrusted fixture
// directory; the live peer must exercise the same path validation production
// uses.
func linuxBrokerTestTrustedSocket(t *testing.T) string {
	t.Helper()
	parent, e := localpath.TrustedTemporaryParent(os.TempDir())
	if e != nil {
		t.Fatalf("real trusted temporary parent: %v", e)
	}
	dir, e := os.MkdirTemp(parent, "llb-")
	if e != nil {
		t.Fatal("private broker directory unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal("private broker directory mode unavailable")
	}
	canonical, e := localpath.TrustedTemporaryParent(dir)
	if e != nil || canonical != dir {
		t.Fatalf("private broker directory is not trusted: %v", e)
	}
	endpoint := filepath.Join(canonical, "b.sock")
	if len(endpoint) > 100 {
		t.Fatalf("private broker socket path is %d bytes, want at most 100", len(endpoint))
	}
	return endpoint
}
