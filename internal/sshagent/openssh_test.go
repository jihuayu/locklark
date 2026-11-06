//go:build linux || darwin || windows

package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	runProgram := func(program string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Env = []string{"SSH_AUTH_SOCK=" + service.Endpoint(), "LC_ALL=C", "PATH=" + filepath.Dir(program)}
		if runtime.GOOS == "windows" {
			cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"), "WINDIR="+os.Getenv("WINDIR"))
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, e := cmd.Output()
		defer clear(stderr.Bytes())
		return out, e
	}
	run := func(args ...string) ([]byte, error) { return runProgram(executable, args...) }
	listing, e := run("-L")
	defer clear(listing)
	if e != nil {
		t.Fatal("native OpenSSH could not enumerate the private custom endpoint")
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
		t.Fatal("native OpenSSH signature self-test failed")
	}
	if strings.Contains(strings.ToLower(service.Endpoint()), "openssh-ssh-agent") {
		t.Fatal("test took over the system agent endpoint")
	}
	sshExecutable := filepath.Join(filepath.Dir(executable), "ssh")
	if runtime.GOOS == "windows" {
		sshExecutable += ".exe"
	}
	testNativeSSHConnection(t, sshExecutable, publicFile, h, runProgram)
}

func testNativeSSHConnection(t *testing.T, executable, publicFile string, h *testHandler, run func(string, ...string) ([]byte, error)) {
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
		t.Fatal("actual native OpenSSH connection did not authenticate through the private custom agent")
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
