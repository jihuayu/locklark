//go:build linux || darwin

package browserhost

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// rawCLIRunServer is a bare private UNIX socket that records whether a client
// connected and whether any hello/request byte was written before it closed.
type rawCLIRunServer struct {
	sock      string
	connected atomic.Bool
	wrote     atomic.Bool
}

func listenRawCLIRun(t *testing.T) *rawCLIRunServer {
	t.Helper()
	sock := brokerTestSocket(t)
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(sock, 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &rawCLIRunServer{sock: sock}
	go func() {
		_ = ln.(*net.UnixListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		srv.connected.Store(true)
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		if _, e := conn.Read(b[:]); e == nil {
			srv.wrote.Store(true)
		}
	}()
	return srv
}

// noHelloOrRequest waits past the client dial timeout and asserts the server
// observed no hello frame or secret request bytes.
func (s *rawCLIRunServer) noHelloOrRequest(t *testing.T) {
	t.Helper()
	time.Sleep(350 * time.Millisecond)
	if s.wrote.Load() {
		t.Fatal("client wrote to an untrusted endpoint before verification")
	}
}

func TestRequestCLIRunRefusesUntrustedSocketBeforeWrite(t *testing.T) {
	t.Run("bad socket mode", func(t *testing.T) {
		srv := listenRawCLIRun(t)
		if e := os.Chmod(srv.sock, 0644); e != nil {
			t.Fatal(e)
		}
		_, e := RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused for group-readable socket", e)
		}
		if errors.Is(e, ErrBrokerUnavailable) {
			t.Fatal("untrusted socket reported fallback-safe unavailable")
		}
		srv.noHelloOrRequest(t)
	})

	t.Run("final symlink", func(t *testing.T) {
		real := listenRawCLIRun(t)
		link := filepath.Join(filepath.Dir(real.sock), "link.sock")
		if e := os.Symlink(real.sock, link); e != nil {
			t.Fatal(e)
		}
		t.Setenv("LOCKLARK_BROWSER_SOCKET", link)
		_, e := RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused for a symlinked endpoint", e)
		}
		real.noHelloOrRequest(t)
	})

	t.Run("untrusted parent directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "shared")
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(dir, 0777); e != nil {
			t.Fatal(e)
		}
		sock := filepath.Join(dir, "b.sock")
		ln, e := net.Listen("unix", sock)
		if e != nil {
			t.Fatal(e)
		}
		defer ln.Close()
		srv := &rawCLIRunServer{sock: sock}
		go func() {
			_ = ln.(*net.UnixListener).SetDeadline(time.Now().Add(2 * time.Second))
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			srv.connected.Store(true)
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var b [1]byte
			if _, e := conn.Read(b[:]); e == nil {
				srv.wrote.Store(true)
			}
		}()
		if e := os.Chmod(sock, 0600); e != nil {
			t.Fatal(e)
		}
		t.Setenv("LOCKLARK_BROWSER_SOCKET", sock)
		_, e = RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused for a publicly writable parent", e)
		}
		srv.noHelloOrRequest(t)
	})

	t.Run("regular file endpoint", func(t *testing.T) {
		sock := brokerTestSocket(t)
		if e := os.WriteFile(sock, []byte("not a socket"), 0600); e != nil {
			t.Fatal(e)
		}
		_, e := RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused for a non-socket endpoint", e)
		}
	})
}

func TestRequestCLIRunRefusesUnverifiablePeerBeforeWrite(t *testing.T) {
	old := authenticatedBrokerPeer
	authenticatedBrokerPeer = func(net.Conn) (Peer, error) { return Peer{}, ErrBrokerUnavailable }
	t.Cleanup(func() { authenticatedBrokerPeer = old })
	srv := listenRawCLIRun(t)
	resp, e := RequestCLIRun(context.Background(), cliRunTestRequest())
	if !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("got %v, want ErrBrokerRefused for an unverifiable server identity", e)
	}
	if errors.Is(e, ErrBrokerUnavailable) {
		t.Fatal("unverifiable peer reported fallback-safe unavailable")
	}
	if len(resp.Values) != 0 {
		t.Fatalf("refused peer returned values: %#v", resp.Values)
	}
	srv.noHelloOrRequest(t)
}

func TestRequestCLIRunAcceptsOwnPrivateSocket(t *testing.T) {
	startCLIRunIPC(t, cliRunRespondBody(`{"v":1,"values":{"PASSWORD":"synthetic-secret"}}`))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, e := RequestCLIRun(ctx, cliRunTestRequest())
	if e != nil {
		t.Fatalf("own 0600 socket refused: %v", e)
	}
	if resp.Values["PASSWORD"] != "synthetic-secret" {
		t.Fatalf("success payload: %#v", resp.Values)
	}
}

func TestRequestCLIRunMissingDefaultSocketUnavailable(t *testing.T) {
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	old := trustedBrokerParent
	trustedBrokerParent = func(string) (string, error) { return base, nil }
	t.Cleanup(func() { trustedBrokerParent = old })
	t.Setenv("LOCKLARK_BROWSER_SOCKET", "")
	_, e := RequestCLIRun(context.Background(), cliRunTestRequest())
	if !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("got %v, want ErrBrokerUnavailable for an absent default socket", e)
	}
	if errors.Is(e, ErrBrokerRefused) {
		t.Fatal("absent default socket reported a refusal")
	}
}

// stubTrustedTemp makes the shipped default endpoint resolve under a private
// test directory while leaving every other trust query on the real validator.
func stubTrustedTemp(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	old := trustedBrokerParent
	trustedBrokerParent = func(p string) (string, error) {
		if p == base || p == os.TempDir() {
			return base, nil
		}
		return old(p)
	}
	t.Cleanup(func() { trustedBrokerParent = old })
	t.Setenv("LOCKLARK_BROWSER_SOCKET", "")
	return base
}

func TestRequestCLIRunAbsentDefaultBrokerDirUnavailable(t *testing.T) {
	base := stubTrustedTemp(t)
	dir := filepath.Join(base, "locklark-brw-"+strconv.Itoa(os.Geteuid()))
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		t.Fatalf("first-run precondition: broker dir should not exist: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, e := RequestCLIRun(ctx, cliRunTestRequest())
	if !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("got %v, want ErrBrokerUnavailable for a never-created default broker dir", e)
	}
	if errors.Is(e, ErrBrokerRefused) {
		t.Fatal("first run without a broker refused instead of falling back")
	}
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		t.Fatal("client created the broker directory")
	}
}

func TestRequestCLIRunUntrustedDefaultBrokerDirRefused(t *testing.T) {
	base := stubTrustedTemp(t)
	dir := filepath.Join(base, "locklark-brw-"+strconv.Itoa(os.Geteuid()))
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	_, e := RequestCLIRun(context.Background(), cliRunTestRequest())
	if !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("got %v, want ErrBrokerRefused for an untrusted default broker dir", e)
	}
	if errors.Is(e, ErrBrokerUnavailable) {
		t.Fatal("untrusted default broker dir reported fallback-safe unavailable")
	}
}
