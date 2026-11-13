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

	"github.com/jihuayu/locklark/internal/browserhost"
)

const (
	linuxCLIRealModeEnv   = "LOCKLARK_LINUX_CLI_REAL_MODE"
	linuxCLIRealSocketEnv = "LOCKLARK_LINUX_CLI_REAL_SOCKET"
	linuxCLIRealResultFD  = 4
	linuxCLIRealResultOK  = "1\n"
	linuxCLIRealBroker    = "broker"
	linuxCLIRealClient    = "client"
)

// TestLinuxCLIRunProductionBrokerTransport is the real minimum: the broker
// helper owns a private PTY, the CLI child inherits that session/CTTY with pipe
// stdio, and the production client prepare/request branch reaches a real broker
// Unix connection/PIDFD. The callback observes the proof and refuses without
// approval or values.
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
	verified := false
	b := browserhost.NewBroker(browserhost.BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
			verified = req.VerifyCLIRunCTTY(peer)
			return browserhost.BrokerCLIResponse{}, browserhost.ErrCLIRunRefused
		},
	})
	if err := b.Start(endpoint); err != nil {
		fail()
	}
	cli := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunRealClientHelper$", "-test.count=1")
	cli.Env = append(os.Environ(),
		linuxCLIRealModeEnv+"="+linuxCLIRealClient,
		linuxCLIRealSocketEnv+"="+endpoint,
		"LOCKLARK_BROWSER_SOCKET="+endpoint,
	)
	cli.Stdin = strings.NewReader("")
	cli.Stdout = io.Discard
	cli.Stderr = io.Discard
	if err := cli.Start(); err != nil {
		_ = b.Close()
		fail()
	}
	waitErr := cli.Wait()
	_ = b.Close()
	if waitErr != nil || !verified {
		fail()
	}
	if _, err := result.WriteString(linuxCLIRealResultOK); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func TestLinuxCLIRunRealClientHelper(t *testing.T) {
	if os.Getenv(linuxCLIRealModeEnv) != linuxCLIRealClient {
		return
	}
	fixture := newCLIBrokerFixture(t)
	err := dispatchCLIRunWithBroker(fixture)
	if _, ok := err.(cliRunBrokerRefusedError); !ok {
		os.Exit(2)
	}
	os.Exit(0)
}
