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
	"syscall"
	"testing"
	"time"
)

const (
	linuxCLIBrokerModeEnv    = "LOCKLARK_LINUX_CLI_BROKER_MODE"
	linuxCLIBrokerSocketEnv  = "LOCKLARK_LINUX_CLI_BROKER_SOCKET"
	linuxCLIBrokerResultFD   = 4
	linuxCLIBrokerResultGood = "1\n"
	linuxCLIBrokerBrokerMode = "broker"
	linuxCLIBrokerPeerMode   = "peer"
)

// TestLinuxCLIRunBrokerTransportCTTYProof is the real broker transport
// minimum. The broker helper owns a private PTY, the peer inherits the same
// session/CTTY with pipe stdio, and an observational callback refuses without
// approval or values.
func TestLinuxCLIRunBrokerTransportCTTYProof(t *testing.T) {
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunBrokerTransportHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxCLIBrokerModeEnv+"="+linuxCLIBrokerBrokerMode,
		linuxCLIBrokerSocketEnv+"="+endpoint,
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
	if err != nil || waitErr != nil || string(result) != linuxCLIBrokerResultGood {
		t.Fatal("broker transport proof minimum failed")
	}
}

func TestLinuxCLIRunBrokerTransportHelper(t *testing.T) {
	if os.Getenv(linuxCLIBrokerModeEnv) != linuxCLIBrokerBrokerMode {
		return
	}
	result := os.NewFile(linuxCLIBrokerResultFD, "locklark-linux-cli-broker-result")
	if result == nil {
		os.Exit(2)
	}
	fail := func() {
		_ = result.Close()
		os.Exit(2)
	}
	endpoint := os.Getenv(linuxCLIBrokerSocketEnv)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		fail()
	}
	if err := listener.SetDeadline(time.Now().Add(linuxPeerProofHelperWait)); err != nil {
		_ = listener.Close()
		fail()
	}
	peer := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunBrokerTransportPeerHelper$", "-test.count=1")
	peer.Env = append(os.Environ(),
		linuxCLIBrokerModeEnv+"="+linuxCLIBrokerPeerMode,
		linuxCLIBrokerSocketEnv+"="+endpoint,
	)
	peer.Stdin = strings.NewReader("")
	peer.Stdout = io.Discard
	peer.Stderr = io.Discard
	if err := peer.Start(); err != nil {
		_ = listener.Close()
		fail()
	}
	if got := linuxPeerStdioPipeCount(peer.Process.Pid); got != 3 {
		_ = listener.Close()
		_ = peer.Wait()
		fail()
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		_ = listener.Close()
		_ = peer.Wait()
		fail()
	}
	_ = listener.Close()
	_ = conn.SetDeadline(time.Now().Add(linuxPeerProofHelperWait))
	verified := false
	b := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, peer Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			verified = req.VerifyCLIRunCTTY(peer)
			return BrokerCLIResponse{}, ErrCLIRunRefused
		},
	})
	b.serve(conn)
	if err := peer.Wait(); err != nil || !verified {
		fail()
	}
	if _, err := result.WriteString(linuxCLIBrokerResultGood); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func TestLinuxCLIRunBrokerTransportPeerHelper(t *testing.T) {
	if os.Getenv(linuxCLIBrokerModeEnv) != linuxCLIBrokerPeerMode {
		return
	}
	endpoint := os.Getenv(linuxCLIBrokerSocketEnv)
	_ = os.Setenv("LOCKLARK_BROWSER_SOCKET", endpoint)
	tty, _, err := CurrentTTYIdentity()
	if err != nil {
		os.Exit(2)
	}
	req := cliRunFixtureRequest()
	req.Scope.TTY = tty
	req.Scope.TTYPlatform = CLIRunTTYPlatform()
	req.Scope.TTYPeerID = ""
	req.Scope.Nonce = strings.Repeat("d1", 32)
	ctx, cancel := context.WithTimeout(context.Background(), linuxPeerProofHelperWait)
	defer cancel()
	resp, err := RequestCLIRun(ctx, req)
	if !errors.Is(err, ErrCLIRunRefused) || len(resp.PreparedValues) != 0 {
		os.Exit(2)
	}
	os.Exit(0)
}
