//go:build linux

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
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
)

const (
	linuxCLIControlModeEnv   = "LOCKLARK_LINUX_CLI_CONTROL_MODE"
	linuxCLIControlSocketEnv = "LOCKLARK_LINUX_CLI_CONTROL_SOCKET"
	linuxCLIControlNonceEnv  = "LOCKLARK_LINUX_CLI_CONTROL_NONCE"
	linuxCLIControlResultFD  = 4
	linuxCLIControlOK        = "1\n"
	linuxCLIControlBroker    = "broker"
	linuxCLIControlClient    = "client"
)

// The prepared success below is a transport-only fixture: it proves the
// control-ready frame and socket retention, not native approval or product
// acceptance. Real peer/proof/nonce/scope checks still run.
func TestLinuxCLIRunControlTransport(t *testing.T) {
	master, slave, _, _ := linuxPeerProofPTY(t)
	_ = master
	defer slave.Close()
	dir, err := os.MkdirTemp("", "llctl-")
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
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxCLIRunControlBrokerHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxCLIControlModeEnv+"="+linuxCLIControlBroker,
		linuxCLIControlSocketEnv+"="+endpoint,
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
	if err != nil || waitErr != nil || string(result) != linuxCLIControlOK {
		stage := strings.TrimSpace(string(result))
		if stage == "" {
			stage = "unknown"
		}
		t.Fatalf("CLI delivery-control transport failed at %s", stage)
	}
}

func TestLinuxCLIRunControlBrokerHelper(t *testing.T) {
	if os.Getenv(linuxCLIControlModeEnv) != linuxCLIControlBroker {
		return
	}
	result := os.NewFile(linuxCLIControlResultFD, "locklark-linux-cli-control-result")
	if result == nil {
		os.Exit(2)
	}
	stage := "S-start"
	fail := func() {
		_, _ = result.WriteString(stage + "\n")
		_ = result.Close()
		os.Exit(2)
	}
	endpoint := os.Getenv(linuxCLIControlSocketEnv)
	stage = "S-receipt"
	receipt := cliRunReceiptFromFixture(t)
	var seenControl, seenDefault, hardCapOK, deadlineOK atomic.Bool
	var count atomic.Int32
	b := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(_ context.Context, _ Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			n := count.Add(1)
			if n == 3 {
				return BrokerCLIResponse{}, ErrCLIRunRefused
			}
			if n == 5 {
				time.Sleep(60 * time.Millisecond)
			}
			if req.DeliveryControl {
				seenControl.Store(true)
			} else {
				seenDefault.Store(true)
			}
			return BrokerCLIResponse{V: 1, PreparedValues: map[string][]byte{"token": []byte("transport-only")}, Receipt: receipt}, nil
		},
	})
	b.cliRunControlLifetime = 120 * time.Millisecond
	stage = "S-listen"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		fail()
	}
	run := func(mode, nonce string) {
		stage = "S-client-" + mode
		cli := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunControlClientHelper$", "-test.count=1")
		cli.Env = append(os.Environ(),
			linuxCLIControlModeEnv+"="+linuxCLIControlClient,
			linuxCLIControlSocketEnv+"="+endpoint,
			linuxCLIControlNonceEnv+"="+nonce,
			"LOCKLARK_BROWSER_SOCKET="+endpoint,
			"LOCKLARK_LINUX_CLI_CONTROL_CLIENT_MODE="+mode,
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
		start := time.Now()
		b.serve(conn)
		elapsed := time.Since(start)
		if mode == "control-deadline" {
			deadlineOK.Store(elapsed < 110*time.Millisecond)
		}
		if err := cli.Wait(); err != nil {
			fail()
		}
	}
	runHold := func(mode, nonce string) {
		stage = "S-client-" + mode
		cli := exec.Command(os.Args[0], "-test.run=^TestLinuxCLIRunControlClientHelper$", "-test.count=1")
		cli.Env = append(os.Environ(),
			linuxCLIControlModeEnv+"="+linuxCLIControlClient,
			linuxCLIControlSocketEnv+"="+endpoint,
			linuxCLIControlNonceEnv+"="+nonce,
			"LOCKLARK_BROWSER_SOCKET="+endpoint,
			"LOCKLARK_LINUX_CLI_CONTROL_CLIENT_MODE="+mode,
		)
		stdin, err := cli.StdinPipe()
		if err != nil {
			fail()
		}
		cli.Stdout = io.Discard
		cli.Stderr = io.Discard
		if err := cli.Start(); err != nil {
			fail()
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			fail()
		}
		start := time.Now()
		b.serve(conn)
		elapsed := time.Since(start)
		_ = stdin.Close()
		if err := cli.Wait(); err != nil {
			fail()
		}
		hardCapOK.Store(elapsed < 160*time.Millisecond)
	}
	run("control", strings.Repeat("a1", 32))
	run("default", strings.Repeat("b2", 32))
	run("control-refused", strings.Repeat("c3", 32))
	run("control-deadline", strings.Repeat("d4", 32))
	runHold("control-hold", strings.Repeat("e5", 32))
	_ = listener.Close()
	stage = "S-assert"
	if !seenControl.Load() {
		stage = "S-assert-control"
		fail()
	}
	if !seenDefault.Load() {
		stage = "S-assert-default"
		fail()
	}
	if !hardCapOK.Load() {
		stage = "S-assert-hardcap"
		fail()
	}
	if !deadlineOK.Load() {
		stage = "S-assert-deadline"
		fail()
	}
	if _, err := result.WriteString(linuxCLIControlOK); err != nil {
		fail()
	}
	_ = result.Close()
	os.Exit(0)
}

func TestLinuxCLIRunControlClientHelper(t *testing.T) {
	if os.Getenv(linuxCLIControlModeEnv) != linuxCLIControlClient {
		return
	}
	req := cliRunFixtureRequest()
	tty, _, err := CurrentTTYIdentity()
	if err != nil {
		os.Exit(2)
	}
	req.Scope.TTY = tty
	req.Scope.TTYPlatform = CLIRunTTYPlatform()
	req.Scope.TTYPeerID = ""
	req.Scope.Nonce = os.Getenv(linuxCLIControlNonceEnv)
	mode := os.Getenv("LOCKLARK_LINUX_CLI_CONTROL_CLIENT_MODE")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch mode {
	case "default":
		resp, err := RequestCLIRun(ctx, req)
		if err != nil || len(resp.PreparedValues) == 0 {
			os.Exit(2)
		}
	case "control":
		resp, control, err := RequestCLIRunControl(ctx, req)
		if err != nil || control == nil || len(resp.PreparedValues) == 0 {
			os.Exit(2)
		}
		_ = control.Close()
	case "control-refused":
		_, control, err := RequestCLIRunControl(ctx, req)
		if !errors.Is(err, ErrCLIRunRefused) || control != nil {
			os.Exit(2)
		}
	case "control-deadline":
		deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer deadlineCancel()
		_, control, err := RequestCLIRunControl(deadlineCtx, req)
		if err != nil || control == nil {
			os.Exit(2)
		}
		<-deadlineCtx.Done()
	case "control-hold":
		_, control, err := RequestCLIRunControl(ctx, req)
		if err != nil || control == nil {
			os.Exit(2)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = control.Close()
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestCLIRunControlReadyContract(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"ready", string(cliRunControlReady), true},
		{"wrong-v", `{"v":2,"delivery_control":true}`, false},
		{"missing", `{"v":1}`, false},
		{"false", `{"v":1,"delivery_control":false}`, false},
		{"extra", `{"v":1,"delivery_control":true,"x":1}`, false},
		{"trailing", string(cliRunControlReady) + "x", false},
		{"empty", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				_ = writeFrame(server, []byte(tc.raw))
			}()
			err := readCLIRunControlReady(client)
			if (err == nil) != tc.ok {
				t.Fatalf("contract result mismatch for %s", tc.name)
			}
		})
	}
}

func TestCLIRunControlRejectsNoDeadline(t *testing.T) {
	t.Setenv("LOCKLARK_BROWSER_SOCKET", filepath.Join(t.TempDir(), "absent"))
	_, control, err := RequestCLIRunControl(context.Background(), cliRunFixtureRequest())
	if !errors.Is(err, errCLIRunControlDeadline) || control != nil {
		t.Fatal("no-deadline control request was not rejected before dial")
	}
}

func TestCLIRunControlDefaultRequestHasNoCapability(t *testing.T) {
	raw, err := json.Marshal(cliRunFixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("delivery_control")) {
		t.Fatal("default request opted into delivery control")
	}
}
