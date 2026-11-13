//go:build linux || darwin

package browserhost

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCLIRunWriteUnixSocketDelivery is a transport-only contract. It uses a
// fixed refusal frame, not an approval or credential value.
func TestCLIRunWriteUnixSocketDelivery(t *testing.T) {
	dir, err := os.MkdirTemp("", "llw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "s")

	t.Run("complete-read", func(t *testing.T) {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		written := make(chan error, 1)
		go func() {
			conn, err := listener.AcceptUnix()
			if err != nil {
				written <- err
				return
			}
			defer conn.Close()
			written <- writeCLIRunRaw(conn, []byte(`{"v":1,"error":"refused"}`))
		}()
		client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpoint, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := readFrame(client, MaxOutput)
		if err != nil || string(raw) != `{"v":1,"error":"refused"}` {
			t.Fatalf("complete frame read: %v %q", err, raw)
		}
		clear(raw)
		if err := <-written; err != nil {
			t.Fatalf("normal write reported failure: %v", err)
		}
	})

	t.Run("peer-closed", func(t *testing.T) {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpoint, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.AcceptUnix()
		if err != nil {
			_ = client.Close()
			t.Fatal(err)
		}
		defer server.Close()
		_ = client.Close()
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		if n, err := server.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("peer close was not observed: n=%d err=%v", n, err)
		}
		_ = server.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := writeCLIRunRaw(server, []byte(`{"v":1,"error":"refused"}`)); err == nil {
			t.Fatal("write after peer close was reported as delivered")
		}
	})
}
