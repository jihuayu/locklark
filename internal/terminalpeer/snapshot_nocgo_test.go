//go:build darwin && !cgo

package terminalpeer

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserveWithoutCGOIsUnavailable(t *testing.T) {
	dir, err := os.MkdirTemp("", "lltp-")
	if err != nil {
		t.Fatal("private peer directory unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("unix listener unavailable")
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("listener deadline unavailable")
	}

	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("unix dial unavailable")
	}
	defer client.Close()
	var server *net.UnixConn
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("unix accept timed out")
	}
	defer server.Close()

	if _, err := Observe(server); !errors.Is(err, ErrUnavailable) {
		t.Fatal("non-cgo observation did not return ErrUnavailable")
	}
	if err := (Observation{}).Revalidate(server); !errors.Is(err, ErrUnavailable) {
		t.Fatal("non-cgo revalidation did not return ErrUnavailable")
	}
}
