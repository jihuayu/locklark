//go:build linux

package browserhost

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	linuxPeerAssocModeEnv             = "LOCKLARK_LINUX_PEER_ASSOC_MODE"
	linuxPeerAssocSocketEnv           = "LOCKLARK_LINUX_PEER_ASSOC_SOCKET"
	linuxPeerAssocNonceEnv            = "LOCKLARK_LINUX_PEER_ASSOC_NONCE"
	linuxPeerAssocBroker              = "broker"
	linuxPeerAssocPeer                = "peer"
	linuxPeerAssocDifferentCTTYBroker = "broker-different-ctty"
	linuxPeerAssocDifferentCTTYPeer   = "peer-own-ctty"
	linuxPeerAssocDetachBroker        = "broker-detach"
	linuxPeerAssocDetachPeer          = "peer-detach"
	linuxPeerAssocResultFD            = 4
	linuxPeerAssocResultGood          = "1\n"
	linuxPeerAssocDetachByte          = 'D'
)

func TestLinuxPeerCTTYAssociationRealSameSession(t *testing.T) {
	linuxPeerAssocOuter(t, linuxPeerAssocBroker)
}

func TestLinuxPeerCTTYAssociationRejectsDifferentPeerCTTY(t *testing.T) {
	linuxPeerAssocOuter(t, linuxPeerAssocDifferentCTTYBroker)
}

func TestLinuxPeerCTTYAssociationGoesStaleAfterPeerSetsid(t *testing.T) {
	linuxPeerAssocOuter(t, linuxPeerAssocDetachBroker)
}

// linuxPeerAssocOuter starts one broker helper with a private PTY as its
// controlling terminal and a fixed result pipe. The broker helper owns the
// actual peer process and socket; this outer process only checks the fixed
// success byte.
func linuxPeerAssocOuter(t *testing.T, brokerMode string) {
	t.Helper()
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

	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxPeerCTTYAssociationBrokerHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxPeerAssocModeEnv+"="+brokerMode,
		linuxPeerAssocSocketEnv+"="+endpoint,
		linuxPeerAssocNonceEnv+"="+linuxPeerProofFixedNonce,
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
	if err != nil || waitErr != nil || string(result) != linuxPeerAssocResultGood {
		t.Fatal("peer CTTY association fixture failed")
	}
}

func TestLinuxPeerCTTYAssociationBrokerHelper(t *testing.T) {
	brokerMode := os.Getenv(linuxPeerAssocModeEnv)
	switch brokerMode {
	case linuxPeerAssocBroker, linuxPeerAssocDifferentCTTYBroker, linuxPeerAssocDetachBroker:
	default:
		return
	}
	result := os.NewFile(linuxPeerAssocResultFD, "locklark-linux-peer-assoc-result")
	if result == nil {
		os.Exit(2)
	}
	fail := func() {
		_ = result.Close()
		os.Exit(2)
	}
	endpoint := os.Getenv(linuxPeerAssocSocketEnv)
	nonce := os.Getenv(linuxPeerAssocNonceEnv)
	path, dev, _, ok := peerControllingTerminal(os.Getpid())
	if !ok {
		fail()
	}
	held, ok := openLinuxPeerTTY(path, dev, uint32(os.Geteuid()))
	if !ok {
		fail()
	}
	heldDev := held.identity.dev
	brokerSID, err := unix.Getsid(os.Getpid())
	if err != nil || brokerSID <= 0 || !held.valid() {
		_ = held.Close()
		fail()
	}
	heldSID, ok := held.sessionID()
	if !ok || heldSID != brokerSID {
		_ = held.Close()
		fail()
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		_ = held.Close()
		fail()
	}
	if err := listener.SetDeadline(time.Now().Add(linuxPeerProofHelperWait)); err != nil {
		_ = held.Close()
		_ = listener.Close()
		fail()
	}
	peerMode := linuxPeerAssocPeer
	switch brokerMode {
	case linuxPeerAssocDifferentCTTYBroker:
		peerMode = linuxPeerAssocDifferentCTTYPeer
	case linuxPeerAssocDetachBroker:
		peerMode = linuxPeerAssocDetachPeer
	}
	peer := exec.Command(os.Args[0], "-test.run=^TestLinuxPeerCTTYAssociationPeerHelper$", "-test.count=1")
	peer.Env = append(os.Environ(),
		linuxPeerAssocModeEnv+"="+peerMode,
		linuxPeerAssocSocketEnv+"="+endpoint,
		linuxPeerAssocNonceEnv+"="+nonce,
	)
	peer.Stdin = strings.NewReader("")
	peer.Stdout = io.Discard
	peer.Stderr = io.Discard
	if err := peer.Start(); err != nil {
		_ = held.Close()
		_ = listener.Close()
		fail()
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		_ = held.Close()
		_ = listener.Close()
		_ = peer.Wait()
		fail()
	}
	_ = listener.Close()
	_ = conn.SetDeadline(time.Now().Add(linuxPeerProofHelperWait))
	nonceBuf := make([]byte, len(nonce))
	if _, err := io.ReadFull(conn, nonceBuf); err != nil || string(nonceBuf) != nonce {
		_ = held.Close()
		_ = conn.Close()
		_ = peer.Wait()
		fail()
	}
	if got := linuxPeerStdioPipeCount(peer.Process.Pid); got != 3 {
		_ = held.Close()
		_ = conn.Close()
		_ = peer.Wait()
		fail()
	}
	assoc, assocErr := newLinuxPeerCTTYAssociation(conn, held)
	ack := func(b byte) bool {
		_, err := conn.Write([]byte{b})
		return err == nil
	}
	switch brokerMode {
	case linuxPeerAssocBroker:
		if assocErr != nil || assoc == nil || assoc.proof.pid != peer.Process.Pid || !assoc.live() {
			if assoc != nil {
				_ = assoc.Close()
			}
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		peerIdentity := Peer{
			User: "UID " + strconv.FormatUint(uint64(assoc.proof.uid), 10),
			PID:  uint32(assoc.proof.pid), Process: assoc.proof.exe.path,
		}
		scope := cliRunFixtureScope()
		digest, ok := cliRunScopeDigest(scope)
		if !ok {
			_ = assoc.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		bound := &clirunCTTYProof{
			owner: assoc, peerUser: peerIdentity.User, peerPID: peerIdentity.PID,
			peerProcess: peerIdentity.Process, scopeDigest: digest,
		}
		req := CLIRunBrokerRequest{V: 1, Scope: scope, cttyProof: bound}
		binding, ok := req.CLIRunCTTYBinding(peerIdentity)
		if !ok || binding.Equal(CLIRunTerminalBinding{}) {
			_ = bound.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if err := bound.Close(); err != nil {
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if _, ok := req.CLIRunCTTYBinding(peerIdentity); ok {
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if !ack(1) {
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
	case linuxPeerAssocDifferentCTTYBroker:
		if assoc != nil || !errors.Is(assocErr, errLinuxPeerCTTYUnavailable) {
			if assoc != nil {
				_ = assoc.Close()
			}
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		peerSID, err := unix.Getsid(peer.Process.Pid)
		_, peerDev, _, peerTTY := peerControllingTerminal(peer.Process.Pid)
		if err != nil || peerSID <= 0 || peerSID == brokerSID || !peerTTY || peerDev == heldDev {
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if !ack(1) {
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
	case linuxPeerAssocDetachBroker:
		if assocErr != nil || assoc == nil || assoc.proof.pid != peer.Process.Pid || !assoc.live() {
			if assoc != nil {
				_ = assoc.Close()
			}
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if !ack(1) {
			_ = assoc.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		var detached [1]byte
		if _, err := io.ReadFull(conn, detached[:]); err != nil || detached[0] != linuxPeerAssocDetachByte {
			_ = assoc.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		peerSID, sidErr := unix.Getsid(peer.Process.Pid)
		_, _, _, peerTTY := peerControllingTerminal(peer.Process.Pid)
		if sidErr != nil || peerSID <= 0 || peerSID == brokerSID || assoc.live() || !assoc.proof.pidfd.live() || !assoc.held.valid() || peerTTY {
			_ = assoc.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
		if !ack(2) {
			_ = assoc.Close()
			_ = conn.Close()
			_ = peer.Wait()
			fail()
		}
	}
	_ = conn.Close()
	if err := peer.Wait(); err != nil {
		if assoc != nil {
			_ = assoc.Close()
		}
		fail()
	}
	if _, err := result.WriteString(linuxPeerAssocResultGood); err != nil {
		if assoc != nil {
			_ = assoc.Close()
		}
		fail()
	}
	_ = result.Close()
	if assoc != nil {
		_ = assoc.Close()
	}
	os.Exit(0)
}

func TestLinuxPeerCTTYAssociationPeerHelper(t *testing.T) {
	peerMode := os.Getenv(linuxPeerAssocModeEnv)
	switch peerMode {
	case linuxPeerAssocPeer, linuxPeerAssocDifferentCTTYPeer, linuxPeerAssocDetachPeer:
	default:
		return
	}
	if peerMode == linuxPeerAssocDifferentCTTYPeer {
		master, slave, _, _ := linuxPeerProofPTY(t)
		_ = master
		if _, err := unix.Setsid(); err != nil {
			os.Exit(2)
		}
		if err := unix.IoctlSetInt(int(slave.Fd()), unix.TIOCSCTTY, 0); err != nil {
			os.Exit(2)
		}
	}
	endpoint := os.Getenv(linuxPeerAssocSocketEnv)
	nonce := os.Getenv(linuxPeerAssocNonceEnv)
	conn, err := net.DialTimeout("unix", endpoint, linuxPeerProofHelperWait)
	if err != nil {
		os.Exit(2)
	}
	_ = conn.SetDeadline(time.Now().Add(linuxPeerProofHelperWait))
	if _, err := io.WriteString(conn, nonce); err != nil {
		_ = conn.Close()
		os.Exit(2)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		_ = conn.Close()
		os.Exit(2)
	}
	if peerMode == linuxPeerAssocDetachPeer {
		if _, err := unix.Setsid(); err != nil {
			_ = conn.Close()
			os.Exit(2)
		}
		if _, err := conn.Write([]byte{linuxPeerAssocDetachByte}); err != nil {
			_ = conn.Close()
			os.Exit(2)
		}
		if _, err := io.ReadFull(conn, ack[:]); err != nil {
			_ = conn.Close()
			os.Exit(2)
		}
	}
	_ = conn.Close()
	os.Exit(0)
}
