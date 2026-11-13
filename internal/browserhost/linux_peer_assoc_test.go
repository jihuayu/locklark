//go:build linux

package browserhost

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	linuxPeerAssocModeEnv    = "LOCKLARK_LINUX_PEER_ASSOC_MODE"
	linuxPeerAssocSocketEnv  = "LOCKLARK_LINUX_PEER_ASSOC_SOCKET"
	linuxPeerAssocNonceEnv   = "LOCKLARK_LINUX_PEER_ASSOC_NONCE"
	linuxPeerAssocBroker     = "broker"
	linuxPeerAssocPeer       = "peer"
	linuxPeerAssocResultFD   = 4
	linuxPeerAssocResultGood = "1\n"
)

// TestLinuxPeerCTTYAssociationRealSameSession is the single positive CP2b
// fixture. The outer test gives the broker helper a private PTY as its
// controlling terminal. The broker helper then starts a same-session peer with
// pipe stdio, accepts its real Unix-socket credentials, and runs the qualified
// association. It does not use a SID/PID/TTY seam or a callback.
func TestLinuxPeerCTTYAssociationRealSameSession(t *testing.T) {
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
		linuxPeerAssocModeEnv+"="+linuxPeerAssocBroker,
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
		t.Fatal("same-session association positive failed")
	}
}

func TestLinuxPeerCTTYAssociationBrokerHelper(t *testing.T) {
	if os.Getenv(linuxPeerAssocModeEnv) != linuxPeerAssocBroker {
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
	peer := exec.Command(os.Args[0], "-test.run=^TestLinuxPeerCTTYAssociationPeerHelper$", "-test.count=1")
	peer.Env = append(os.Environ(),
		linuxPeerAssocModeEnv+"="+linuxPeerAssocPeer,
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
	assoc, err := newLinuxPeerCTTYAssociation(conn, held)
	if err != nil {
		_ = conn.Close()
		_ = peer.Wait()
		fail()
	}
	if assoc.proof.pid != peer.Process.Pid || !assoc.live() {
		_ = assoc.Close()
		_ = conn.Close()
		_ = peer.Wait()
		fail()
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		_ = assoc.Close()
		_ = conn.Close()
		_ = peer.Wait()
		fail()
	}
	_ = conn.Close()
	if err := peer.Wait(); err != nil {
		_ = assoc.Close()
		fail()
	}
	if _, err := result.WriteString(linuxPeerAssocResultGood); err != nil {
		_ = assoc.Close()
		fail()
	}
	_ = result.Close()
	_ = assoc.Close()
	os.Exit(0)
}

func TestLinuxPeerCTTYAssociationPeerHelper(t *testing.T) {
	if os.Getenv(linuxPeerAssocModeEnv) != linuxPeerAssocPeer {
		return
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
	_ = conn.Close()
	os.Exit(0)
}
