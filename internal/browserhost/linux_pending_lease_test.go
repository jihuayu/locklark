//go:build linux

package browserhost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

const (
	linuxPendingModeEnv   = "LOCKLARK_LINUX_PENDING_MODE"
	linuxPendingSocketEnv = "LOCKLARK_LINUX_PENDING_SOCKET"
	linuxPendingNonceEnv  = "LOCKLARK_LINUX_PENDING_NONCE"
	linuxPendingResultFD  = 4
	linuxPendingResultOK  = "1\n"
	linuxPendingBroker    = "broker"
	linuxPendingClient    = "client"
)

// The outer broker helper owns a private PTY. Two independent low-level CLI
// processes inherit the session/CTTY with pipe stdio and fresh nonces; the
// first proof is closed before the second matches the independent anchor.
func TestLinuxPendingLeaseAnchorSameTerminal(t *testing.T) {
	master, slave, _, _ := linuxPeerProofPTY(t)
	_ = master
	defer slave.Close()

	dir, err := os.MkdirTemp("", linuxPeerProofSocketPrefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "s")
	resultR, resultW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultR.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxPendingLeaseBrokerHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxPendingModeEnv+"="+linuxPendingBroker,
		linuxPendingSocketEnv+"="+endpoint,
	)
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{slave, resultW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	if err := cmd.Start(); err != nil {
		_ = resultW.Close()
		t.Fatal(err)
	}
	_ = resultW.Close()
	waitErr := cmd.Wait()
	result, err := io.ReadAll(resultR)
	if err != nil || waitErr != nil || string(result) != linuxPendingResultOK {
		t.Fatal("pending lease anchor minimum failed")
	}
}

func TestLinuxPendingLeaseBrokerHelper(t *testing.T) {
	if os.Getenv(linuxPendingModeEnv) != linuxPendingBroker {
		return
	}
	result := os.NewFile(linuxPendingResultFD, "locklark-linux-pending-result")
	if result == nil {
		os.Exit(2)
	}
	fail := func() {
		_ = result.Close()
		os.Exit(2)
	}
	endpoint := os.Getenv(linuxPendingSocketEnv)
	sessionDir, err := os.MkdirTemp("", "lllease-")
	if err != nil {
		fail()
	}
	sessionPath := filepath.Join(sessionDir, "fixture.ll")
	key := []byte("0123456789abcdef")
	if err := personal.Create(sessionPath, "fixture", key); err != nil {
		fail()
	}
	session, err := personal.UnlockSession(sessionPath, []byte("fixture"), key, time.Minute)
	if err != nil {
		fail()
	}
	store := newLinuxPendingLeaseStore(4)
	var index atomic.Int32
	var added, matched, closedMatched atomic.Bool
	b := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, peer Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			switch index.Add(1) {
			case 1:
				added.Store(store.Add(req, peer, req.VaultPath, session, 7, session.AuthorityDeadline()))
			case 2:
				matched.Store(store.Match(req, peer, req.VaultPath, session, 7))
				store.Clear()
				store.Close()
			case 3:
				closedMatched.Store(store.Match(req, peer, req.VaultPath, session, 7))
			}
			return BrokerCLIResponse{}, ErrCLIRunRefused
		},
	})
	if err := b.Start(endpoint); err != nil {
		fail()
	}
	run := func(nonce string) {
		cli := exec.Command(os.Args[0], "-test.run=^TestLinuxPendingLeaseClientHelper$", "-test.count=1")
		cli.Env = append(os.Environ(),
			linuxPendingModeEnv+"="+linuxPendingClient,
			linuxPendingSocketEnv+"="+endpoint,
			linuxPendingNonceEnv+"="+nonce,
			"LOCKLARK_BROWSER_SOCKET="+endpoint,
		)
		cli.Stdin = strings.NewReader("")
		cli.Stdout = io.Discard
		cli.Stderr = io.Discard
		if err := cli.Start(); err != nil {
			fail()
		}
		if err := cli.Wait(); err != nil {
			fail()
		}
	}
	run(strings.Repeat("a1", 32))
	run(strings.Repeat("b2", 32))
	run(strings.Repeat("c3", 32))
	_ = b.Close()
	if !added.Load() || !matched.Load() || closedMatched.Load() {
		fail()
	}
	if _, err := result.WriteString(linuxPendingResultOK); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func TestLinuxPendingScopeDigestExcludesNonceAndTempRoot(t *testing.T) {
	scope := cliRunFixtureScope()
	targets := cliRunFixtureRequest().Targets
	first, ok := linuxPendingScopeDigest(scope, targets)
	if !ok {
		t.Fatal("initial scope digest failed")
	}
	scope.Nonce = strings.Repeat("f1", 32)
	scope.TempRoot = "/another/private/root"
	second, ok := linuxPendingScopeDigest(scope, targets)
	if !ok || first != second {
		t.Fatal("nonce/temp root changed the pending key")
	}
	scope.Args[0] = "different-argument"
	third, ok := linuxPendingScopeDigest(scope, targets)
	if !ok || third == second {
		t.Fatal("scope change was not bound")
	}
	targets[0].Revision = strings.Repeat("0", 64)
	fourth, ok := linuxPendingScopeDigest(scope, targets)
	if !ok || fourth == third {
		t.Fatal("target revision change was not bound")
	}
}

func TestLinuxPendingLeaseClientHelper(t *testing.T) {
	if os.Getenv(linuxPendingModeEnv) != linuxPendingClient {
		return
	}
	endpoint := os.Getenv(linuxPendingSocketEnv)
	_ = os.Setenv("LOCKLARK_BROWSER_SOCKET", endpoint)
	tty, _, err := CurrentTTYIdentity()
	if err != nil {
		os.Exit(2)
	}
	req := cliRunFixtureRequest()
	req.Scope.TTY = tty
	req.Scope.TTYPlatform = CLIRunTTYPlatform()
	req.Scope.TTYPeerID = ""
	req.Scope.Nonce = os.Getenv(linuxPendingNonceEnv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := RequestCLIRun(ctx, req)
	if !errors.Is(err, ErrCLIRunRefused) || len(resp.PreparedValues) != 0 {
		os.Exit(2)
	}
	os.Exit(0)
}
