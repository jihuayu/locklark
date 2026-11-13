//go:build linux

package browserhost

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/sys/unix"
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
		stage := strings.TrimSpace(string(result))
		if stage == "" {
			stage = "unknown"
		}
		t.Fatalf("pending lease anchor minimum failed at %s", stage)
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
	stage := "S-session"
	fail := func() {
		_, _ = result.WriteString(stage + "\n")
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
	stage = "S-store"
	store := newLinuxPendingLeaseStore(4)
	var index atomic.Int32
	var added, ttlOK, duplicateNoRenew, anchorLive, matched, oldEpochCleaned atomic.Bool
	var clearClosed, closeClosed, capacityOK, newerPreserved, closedMatched atomic.Bool
	var anchorFD, clearFD, closeFD, capacityFD atomic.Int32
	b := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, peer Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			switch index.Add(1) {
			case 1:
				deadline := session.AuthorityDeadline()
				now := time.Now()
				added.Store(store.Add(req, peer, req.VaultPath, session, 7, deadline))
				store.mu.Lock()
				if len(store.records) == 1 {
					record := store.records[0]
					anchorFD.Store(int32(record.anchor.file.Fd()))
					ttlOK.Store(record.expiry.After(now) &&
						!record.expiry.After(now.Add(linuxPendingLeaseTTL)) &&
						(deadline.IsZero() || !record.expiry.After(deadline)))
					expiry := record.expiry
					store.mu.Unlock()
					duplicate := !store.Add(req, peer, req.VaultPath, session, 7, deadline)
					store.mu.Lock()
					duplicateNoRenew.Store(duplicate && len(store.records) == 1 && store.records[0].expiry.Equal(expiry))
				}
				store.mu.Unlock()
			case 2:
				matched.Store(store.Match(req, peer, req.VaultPath, session, 7))
				oldEpoch := store.Match(req, peer, req.VaultPath, session, 8)
				store.mu.Lock()
				oldRecords := len(store.records)
				store.mu.Unlock()
				oldEpochCleaned.Store(!oldEpoch && oldRecords == 0 && linuxPendingFDClosed(anchorFD.Load()))
				store.Clear()
				store.Close()
			case 3:
				closedMatched.Store(store.Match(req, peer, req.VaultPath, session, 7))
				deadline := session.AuthorityDeadline()
				clearStore := newLinuxPendingLeaseStore(2)
				if clearStore.Add(req, peer, "clear-vault", session, 7, deadline) {
					clearFD.Store(linuxPendingFD(clearStore))
					clearStore.Clear()
					clearClosed.Store(linuxPendingFDClosed(clearFD.Load()))
				}
				closeStore := newLinuxPendingLeaseStore(2)
				if closeStore.Add(req, peer, "close-vault", session, 7, deadline) {
					closeFD.Store(linuxPendingFD(closeStore))
					closeStore.Close()
					closeClosed.Store(linuxPendingFDClosed(closeFD.Load()))
				}
				capacityStore := newLinuxPendingLeaseStore(1)
				capacityA := capacityStore.Add(req, peer, "capacity-a", session, 7, deadline)
				if capacityA {
					capacityFD.Store(linuxPendingFD(capacityStore))
				}
				capacityB := capacityStore.Add(req, peer, "capacity-b", session, 7, deadline)
				capacityStore.mu.Lock()
				capacityRecords := len(capacityStore.records)
				capacityStore.mu.Unlock()
				capacityStore.Clear()
				capacityOK.Store(capacityA && !capacityB && capacityRecords == 1 && linuxPendingFDClosed(capacityFD.Load()))

				newerStore := newLinuxPendingLeaseStore(2)
				if newerStore.Add(req, peer, "newer-vault", session, 8, deadline) {
					newerFD := linuxPendingFD(newerStore)
					stale := newerStore.Match(req, peer, "newer-vault", session, 7)
					newerStore.mu.Lock()
					newerRecords := len(newerStore.records)
					newerLive := newerRecords == 1 && newerStore.records[0].anchor.live()
					newerStore.mu.Unlock()
					newerPreserved.Store(!stale && newerRecords == 1 && newerLive && !linuxPendingFDClosed(newerFD))
					newerStore.Clear()
				}
			}
			return BrokerCLIResponse{}, ErrCLIRunRefused
		},
	})
	stage = "S-listen"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		fail()
	}
	run := func(nonce string) {
		stage = "S-client"
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
		conn, err := listener.AcceptUnix()
		if err != nil {
			fail()
		}
		b.serve(conn)
		if err := cli.Wait(); err != nil {
			fail()
		}
	}
	run(strings.Repeat("a1", 32))
	stage = "S-anchor"
	store.mu.Lock()
	records := len(store.records)
	if records == 1 {
		anchorLive.Store(store.records[0].anchor.live() && !linuxPendingFDClosed(anchorFD.Load()))
	}
	store.mu.Unlock()
	switch {
	case !added.Load():
		stage = "S-anchor-add"
		fail()
	case records != 1:
		stage = "S-anchor-record"
		fail()
	case !anchorLive.Load():
		stage = "S-anchor-live"
		fail()
	}
	run(strings.Repeat("b2", 32))
	run(strings.Repeat("c3", 32))
	_ = listener.Close()
	stage = "S-assert"
	switch {
	case !added.Load():
		stage = "S-assert-add"
		fail()
	case !ttlOK.Load():
		stage = "S-assert-ttl"
		fail()
	case !duplicateNoRenew.Load():
		stage = "S-assert-renew"
		fail()
	case !matched.Load():
		stage = "S-assert-match"
		fail()
	case !oldEpochCleaned.Load():
		stage = "S-assert-oldepoch"
		fail()
	case !clearClosed.Load():
		stage = "S-assert-clearfd"
		fail()
	case !closeClosed.Load():
		stage = "S-assert-closefd"
		fail()
	case !capacityOK.Load():
		stage = "S-assert-capacity"
		fail()
	case !newerPreserved.Load():
		stage = "S-assert-newer"
		fail()
	case closedMatched.Load():
		stage = "S-assert-closed"
		fail()
	}
	if _, err := result.WriteString(linuxPendingResultOK); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func linuxPendingFD(store *linuxPendingLeaseStore) int32 {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.records) != 1 {
		return 0
	}
	return int32(store.records[0].anchor.file.Fd())
}

func linuxPendingFDClosed(fd int32) bool {
	if fd <= 0 {
		return false
	}
	var stat unix.Stat_t
	return errors.Is(unix.Fstat(int(fd), &stat), unix.EBADF)
}

func TestLinuxPendingLeaseCapacityBound(t *testing.T) {
	for _, capacity := range []int{-1, 0, 17, 1000} {
		if got := newLinuxPendingLeaseStore(capacity).capacity; got != linuxPendingLeaseCapacity {
			t.Fatalf("capacity %d was not clamped to %d", capacity, linuxPendingLeaseCapacity)
		}
	}
	if got := newLinuxPendingLeaseStore(1).capacity; got != 1 {
		t.Fatalf("small capacity changed to %d", got)
	}
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
