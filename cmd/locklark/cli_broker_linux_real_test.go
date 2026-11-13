//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"golang.org/x/sys/unix"
)

const (
	linuxCLIRealModeEnv   = "LOCKLARK_LINUX_CLI_REAL_MODE"
	linuxCLIRealSocketEnv = "LOCKLARK_LINUX_CLI_REAL_SOCKET"
	linuxCLIRealResultFD  = 4
	linuxCLIRealResultOK  = "1\n"
	linuxCLIRealBroker    = "broker"
	linuxCLIRealClient    = "client"
	linuxCLIRealOwnCTTY   = "own-ctty"
)

// TestLinuxCLIRunProductionBrokerTransport is the real minimum: one broker
// helper owns a private PTY; two independent production CLI processes inherit
// that session/CTTY with pipe stdio and fresh nonces. A third CLI process
// creates its own CTTY and must be refused before the callback. The callback
// only observes the sealed binding and refuses.
func TestLinuxCLIRunProductionBrokerTransport(t *testing.T) {
	master, slave := openTestPTY(t)
	_ = master
	defer slave.Close()

	dir, err := os.MkdirTemp("/tmp", "llcli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "b.sock")
	resultR, resultW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resultR.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunRealBrokerHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxCLIRealModeEnv+"="+linuxCLIRealBroker,
		linuxCLIRealSocketEnv+"="+endpoint,
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
	if err != nil || waitErr != nil || string(result) != linuxCLIRealResultOK {
		t.Fatal("production CLI broker transport minimum failed")
	}
}

type linuxCLIRealObservation struct {
	binding browserhost.CLIRunTerminalBinding
	ok      bool
	req     browserhost.BrokerCLIRequest
	peer    browserhost.Peer
}

func TestLinuxCLIRunRealBrokerHelper(t *testing.T) {
	if os.Getenv(linuxCLIRealModeEnv) != linuxCLIRealBroker {
		return
	}
	result := os.NewFile(linuxCLIRealResultFD, "locklark-linux-cli-real-result")
	if result == nil {
		os.Exit(2)
	}
	fail := func() {
		_ = result.Close()
		os.Exit(2)
	}
	endpoint := os.Getenv(linuxCLIRealSocketEnv)
	observed := make(chan linuxCLIRealObservation, 4)
	b := browserhost.NewBroker(browserhost.BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
			binding, ok := req.CLIRunCTTYBinding(peer)
			observed <- linuxCLIRealObservation{binding: binding, ok: ok, req: req, peer: peer}
			return browserhost.BrokerCLIResponse{}, browserhost.ErrCLIRunRefused
		},
	})
	if err := b.Start(endpoint); err != nil {
		fail()
	}
	run := func(mode string) (int, error) {
		cli := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunRealClientHelper$", "-test.count=1")
		cli.Env = append(os.Environ(),
			linuxCLIRealModeEnv+"="+mode,
			linuxCLIRealSocketEnv+"="+endpoint,
			"LOCKLARK_BROWSER_SOCKET="+endpoint,
		)
		cli.Stdin = strings.NewReader("")
		cli.Stdout = io.Discard
		cli.Stderr = io.Discard
		if err := cli.Start(); err != nil {
			return 0, err
		}
		return cli.Process.Pid, cli.Wait()
	}
	firstPID, err := run(linuxCLIRealClient)
	if err != nil {
		_ = b.Close()
		fail()
	}
	secondPID, err := run(linuxCLIRealClient)
	if err != nil || firstPID == secondPID {
		_ = b.Close()
		fail()
	}
	read := func() (linuxCLIRealObservation, bool) {
		select {
		case obs := <-observed:
			return obs, true
		case <-time.After(2 * time.Second):
			return linuxCLIRealObservation{}, false
		}
	}
	first, ok := read()
	if !ok {
		_ = b.Close()
		fail()
	}
	second, ok := read()
	if !ok || !first.ok || !second.ok || !first.binding.Equal(second.binding) {
		_ = b.Close()
		fail()
	}
	if _, err := run(linuxCLIRealOwnCTTY); err != nil {
		_ = b.Close()
		fail()
	}
	select {
	case <-observed:
		_ = b.Close()
		fail()
	default:
	}
	_ = b.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := first.req.CLIRunCTTYBinding(first.peer); !ok {
			break
		}
		if time.Now().After(deadline) {
			fail()
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := result.WriteString(linuxCLIRealResultOK); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func TestLinuxCLIRunRealClientHelper(t *testing.T) {
	mode := os.Getenv(linuxCLIRealModeEnv)
	if mode != linuxCLIRealClient && mode != linuxCLIRealOwnCTTY {
		return
	}
	if mode == linuxCLIRealOwnCTTY {
		master, slave := openTestPTY(t)
		_ = master
		if _, err := unix.Setsid(); err != nil {
			os.Exit(2)
		}
		if err := unix.IoctlSetInt(int(slave.Fd()), unix.TIOCSCTTY, 0); err != nil {
			os.Exit(2)
		}
	}
	fixture := newCLIBrokerFixture(t)
	err := dispatchCLIRunWithBroker(fixture)
	if _, ok := err.(cliRunBrokerRefusedError); !ok {
		os.Exit(2)
	}
	os.Exit(0)
}
