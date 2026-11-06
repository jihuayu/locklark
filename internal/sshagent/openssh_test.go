//go:build linux || darwin || windows

package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// This is a transport/runtime gate using the platform's actual OpenSSH client.
// It does not replace encrypted-vault/native-approval product acceptance.
func TestNativeOpenSSHCustomEndpoint(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_OPENSSH") != "1" {
		t.Skip("explicit native OpenSSH runtime gate disabled")
	}
	executable := os.Getenv("LOCKLARK_TEST_OPENSSH_BIN")
	if executable == "" {
		if runtime.GOOS == "windows" {
			executable = filepath.Join(os.Getenv("WINDIR"), "System32", "OpenSSH", "ssh-add.exe")
		} else {
			executable = "/usr/bin/ssh-add"
		}
	}
	if !filepath.IsAbs(executable) {
		t.Fatal("OpenSSH test requires an absolute executable")
	}
	endpoint := nativeTestEndpoint(t)
	h := newTestHandler(t)
	service, e := Start(endpoint, h)
	if e != nil {
		t.Fatal("native SSH agent endpoint unavailable")
	}
	defer service.Close()
	clientState, clientExit := "NOT_RUN", 0
	diagnostic := func() string {
		service.mu.Lock()
		accepted, refused := service.accepted, service.peerRefusal
		service.mu.Unlock()
		if refused == "" {
			refused = "NONE"
		}
		return fmt.Sprintf("client=%s exit=%d accepted=%d peer=%s lists=%d", clientState, clientExit, accepted, refused, h.lists.Load())
	}
	runProgram := func(program string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Env = nativeOpenSSHEnvironment(runtime.GOOS, program, service.Endpoint(), os.Getenv)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, e := cmd.Output()
		defer clear(stderr.Bytes())
		clientState, clientExit = openSSHFailureCategory(e, stderr.Bytes())
		return out, e
	}
	run := func(args ...string) ([]byte, error) { return runProgram(executable, args...) }
	listing, e := run("-L")
	defer clear(listing)
	if e != nil {
		t.Fatal("native OpenSSH could not enumerate the private custom endpoint: " + diagnostic())
	}
	public, comment, options, rest, e := ssh.ParseAuthorizedKey(listing)
	if e != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || comment != "Locklark fixture" || !bytes.Equal(public.Marshal(), h.signer.PublicKey().Marshal()) {
		t.Fatal("native OpenSSH enumerated an unexpected key or endpoint")
	}
	publicFile := filepath.Join(t.TempDir(), "probe.pub")
	if os.WriteFile(publicFile, ssh.MarshalAuthorizedKey(public), 0600) != nil {
		t.Fatal("public probe file failed")
	}
	output, e := run("-T", publicFile)
	clear(output)
	if e != nil || h.calls.Load() < 1 {
		t.Fatal("native OpenSSH signature self-test failed: " + diagnostic())
	}
	if strings.Contains(strings.ToLower(service.Endpoint()), "openssh-ssh-agent") {
		t.Fatal("test took over the system agent endpoint")
	}
	sshExecutable := filepath.Join(filepath.Dir(executable), "ssh")
	if runtime.GOOS == "windows" {
		sshExecutable += ".exe"
	}
	testNativeSSHConnection(t, sshExecutable, publicFile, h, runProgram, diagnostic)
}

func nativeOpenSSHEnvironment(goos, program, endpoint string, getenv func(string) string) []string {
	env := []string{"SSH_AUTH_SOCK=" + endpoint, "LC_ALL=C", "PATH=" + filepath.Dir(program)}
	if goos == "windows" {
		// Microsoft v9.5.0.0 win32compat/w32fd.c init_prog_paths() fatals
		// before any pipe connection if ProgramData is absent. The observed
		// system clients report file version 9.5.6.4; keep the OS startup
		// environment explicit instead of inheriting parent credentials.
		// https://github.com/PowerShell/openssh-portable/blob/v9.5.0.0/contrib/win32/win32compat/w32fd.c
		for _, name := range []string{"SystemRoot", "WINDIR", "ProgramData"} {
			env = append(env, name+"="+getenv(name))
		}
	}
	return env
}

func TestWindowsNativeOpenSSHStartupEnvironmentIsExplicit(t *testing.T) {
	values := map[string]string{"SystemRoot": `C:\Windows`, "WINDIR": `C:\Windows`, "ProgramData": `C:\ProgramData`}
	getenv := func(name string) string {
		if value, ok := values[name]; ok {
			return value
		}
		return "private-parent-token-not-for-child"
	}
	env := nativeOpenSSHEnvironment("windows", filepath.Join("native", "ssh-add.exe"), "private-custom-endpoint", getenv)
	found := false
	for _, entry := range env {
		if entry == `ProgramData=C:\ProgramData` {
			found = true
		}
		if strings.Contains(entry, "private-parent-token-not-for-child") {
			t.Fatal("unreviewed parent environment inherited")
		}
	}
	if !found {
		t.Fatal("native Windows OpenSSH startup requires explicit ProgramData")
	}
}

// Never return child error text, executable paths, usernames, or arbitrary
// stderr. Even test fixture data stays out of public CI failure reports.
func openSSHFailureCategory(err error, stderr []byte) (string, int) {
	if err == nil {
		return "SUCCESS", 0
	}
	var child *exec.ExitError
	if !errors.As(err, &child) {
		if errors.Is(err, os.ErrNotExist) {
			return "START_NOT_FOUND", -1
		}
		if errors.Is(err, os.ErrPermission) {
			return "START_DENIED", -1
		}
		return "START_OTHER", -1
	}
	category := "PROCESS_EXIT"
	for _, known := range []struct{ marker, category string }{
		{"couldn't find ProgramData environment variable", "MISSING_PROGRAMDATA"},
		{"Error connecting to agent: No such file or directory", "NO_ENDPOINT"},
		{"Error connecting to agent: Permission denied", "ACCESS_DENIED"},
		{"Error connecting to agent: Invalid argument", "INVALID_ADDRESS"},
		{"Could not open a connection to your authentication agent", "NO_AGENT"},
		{"communication with agent failed", "WIRE_FAILURE"},
		{"The agent has no identities", "NO_IDENTITIES"},
	} {
		if bytes.Contains(stderr, []byte(known.marker)) {
			category = known.category
			break
		}
	}
	return category, child.ExitCode()
}

func TestOpenSSHDiagnosticsNeverExposeArbitraryErrorBodies(t *testing.T) {
	private := "fixture-private-path-key-body"
	category, exit := openSSHFailureCategory(errors.New(private), []byte(private))
	if category != "START_OTHER" || exit != -1 {
		t.Fatal("arbitrary process failure escaped fixed classification")
	}
	category, _ = openSSHFailureCategory(&exec.ExitError{}, []byte(private))
	if category != "PROCESS_EXIT" {
		t.Fatal("arbitrary stderr escaped fixed classification")
	}
	category, _ = openSSHFailureCategory(&exec.ExitError{}, []byte("Error connecting to agent: Permission denied: "+private))
	if category != "ACCESS_DENIED" {
		t.Fatal("known stderr did not use fixed classification")
	}
	if peerRefusalCategory(errors.New(private)) != "OTHER" || peerRefusalCategory(peerRefusal(private)) != "OTHER" {
		t.Fatal("arbitrary peer error escaped fixed classification")
	}
}

func testNativeSSHConnection(t *testing.T, executable, publicFile string, h *testHandler, run func(string, ...string) ([]byte, error), diagnostic func() string) {
	t.Helper()
	_, hostKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("SSH host fixture failed")
	}
	host, e := ssh.NewSignerFromKey(hostKey)
	if e != nil {
		t.Fatal("SSH host signer fixture failed")
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "locklark-probe" || !bytes.Equal(key.Marshal(), h.signer.PublicKey().Marshal()) {
			return nil, errors.New("unrecognized test identity")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(host)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal("loopback SSH fixture failed")
	}
	defer listener.Close()
	done := make(chan bool, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- false
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		server, channels, requests, e := ssh.NewServerConn(conn, config)
		if e != nil {
			done <- false
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "unsupported fixture channel")
				continue
			}
			channel, requests, e := incoming.Accept()
			if e != nil {
				done <- false
				return
			}
			for request := range requests {
				var command struct{ Command string }
				if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "locklark-agent-probe" {
					if request.WantReply {
						_ = request.Reply(false, nil)
					}
					continue
				}
				if request.WantReply {
					_ = request.Reply(true, nil)
				}
				_, _ = channel.Write([]byte("local-agent-ok\n"))
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				_ = channel.Close()
				// Do not close the SSH transport until the client has consumed
				// the command result and disconnected. Closing immediately can
				// race the client's exit-status receive under the race detector.
				_ = server.Wait()
				done <- true
				return
			}
			_ = channel.Close()
		}
		done <- false
	}()
	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	empty := filepath.Join(dir, "empty_config")
	if os.WriteFile(known, []byte(knownhosts.Line([]string{listener.Addr().String()}, host.PublicKey())+"\n"), 0600) != nil || os.WriteFile(empty, nil, 0600) != nil {
		t.Fatal("public SSH configuration fixture failed")
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	output, e := run(executable, "-F", empty, "-T", "-a", "-x", "-p", port, "-oBatchMode=yes", "-oIdentitiesOnly=yes", "-oPreferredAuthentications=publickey", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=5", "-oUserKnownHostsFile="+strconv.Quote(filepath.ToSlash(known)), "-oGlobalKnownHostsFile="+strconv.Quote(filepath.ToSlash(empty)), "-i", publicFile, "locklark-probe@127.0.0.1", "locklark-agent-probe")
	defer clear(output)
	if e != nil {
		t.Fatal("actual native OpenSSH connection did not authenticate through the private custom agent: " + diagnostic())
	}
	if string(output) != "local-agent-ok\n" {
		t.Fatal("actual native OpenSSH command result did not match the controlled fixture")
	}
	if h.calls.Load() < 2 {
		t.Fatal("actual native OpenSSH connection bypassed the private custom agent")
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("controlled SSH service did not finish the exact public command")
		}
	case <-time.After(time.Second):
		t.Fatal("controlled SSH service did not close")
	}
}
