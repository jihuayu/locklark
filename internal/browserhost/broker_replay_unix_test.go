//go:build linux || darwin

package browserhost

import (
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestCLIRunNonceReplayRealUnixPeerRefusedBeforeTTYGate exercises the real
// Unix-socket handshake and authenticatedPeer path for this test process. It
// proves that a consumed nonce is refused on a second connection before the
// TTY gate and before any callback. The TTY gate is injected because this test
// does not own a PTY; it does not attest a kernel CTTY and is not a cross-PID
// or native-approval smoke.
func TestCLIRunNonceReplayRealUnixPeerRefusedBeforeTTYGate(t *testing.T) {
	savedCache := brokerCLIRunNonces
	brokerCLIRunNonces = replayCache(4, time.Minute, newReplayClock())
	t.Cleanup(func() { brokerCLIRunNonces = savedCache })

	var gateCalls atomic.Int32
	oldGate := cliRunTTYGate
	cliRunTTYGate = func(Peer, string, string, string) error {
		gateCalls.Add(1)
		return errCLIRunInvalid
	}
	t.Cleanup(func() { cliRunTTYGate = oldGate })

	endpoint := brokerTestSocket(t)
	b := NewBroker(BrokerCallbacks{})
	if e := b.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = b.Close() })

	send := func(nonce string) string {
		t.Helper()
		req := cliRunFixtureRequest()
		req.Scope.Nonce = nonce
		body, e := json.Marshal(req)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(body)

		conn, e := net.Dial("unix", endpoint)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		if e = conn.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
			t.Fatal(e)
		}
		if e = writeFrame(conn, []byte(`{"v":1,"mode":"cli-run"}`)); e != nil {
			t.Fatal(e)
		}
		if e = writeFrame(conn, body); e != nil {
			t.Fatal(e)
		}
		reply, e := readFrame(conn, MaxOutput)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(reply)
		return string(reply)
	}

	nonce := strings.Repeat("a1", 32)
	for i := 0; i < 2; i++ {
		if got := send(nonce); got != `{"v":1,"error":"refused"}` {
			t.Fatalf("request %d: replay boundary wrote %s", i+1, got)
		}
	}
	if got := gateCalls.Load(); got != 1 {
		t.Fatalf("TTY gate called %d times, want 1: the replay was refused before validation", got)
	}
	if got := send(strings.Repeat("b2", 32)); got != `{"v":1,"error":"refused"}` {
		t.Fatalf("fresh nonce boundary wrote %s", got)
	}
	if got := gateCalls.Load(); got != 2 {
		t.Fatalf("TTY gate called %d times, want 2: the fresh nonce did not reach validation", got)
	}
}
