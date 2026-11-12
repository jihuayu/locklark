//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func brokerTestSocket(t *testing.T) string {
	t.Helper()
	// Keep the absolute socket path short: listenLocal intentionally bounds it
	// at 100 bytes, and t.TempDir includes the long test name.
	dir, e := os.MkdirTemp("", "llb-")
	if e != nil || os.Chmod(dir, 0700) != nil {
		t.Fatal("private test directory")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	old := trustedBrokerParent
	trustedBrokerParent = func(string) (string, error) { return dir, nil }
	t.Cleanup(func() { trustedBrokerParent = old })
	sock := filepath.Join(dir, "b.sock")
	t.Setenv("LOCKLARK_BROWSER_SOCKET", sock)
	return sock
}

func brokerTestSession(t *testing.T) (*personal.Session, personal.Row) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	if _, e := s.AddLogin("Broker login", "broker-user", "broker-password"); e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("fixture rows", e)
	}
	rev, e := s.Edit(personal.Edit{ID: rows[0].ID, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"})
	if e != nil {
		t.Fatal(e)
	}
	rows[0].Revision = rev
	return s, rows[0]
}

type relayClient struct {
	in     *io.PipeWriter
	out    *io.PipeReader
	done   chan error
	closed sync.Once
}

func startRelayClient(t *testing.T) *relayClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &relayClient{in: inW, out: outR, done: make(chan error, 1)}
	go func() {
		c.done <- RelayStdio(Chromium, []string{"chrome-extension://" + ChromiumID + "/"}, inR, outW)
	}()
	t.Cleanup(func() {
		c.closed.Do(func() {
			_ = inW.Close()
			_ = outR.Close()
		})
	})
	return c
}

func (c *relayClient) send(t *testing.T, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e := writeFrame(c.in, raw); e != nil {
		t.Fatal(e)
	}
}

func (c *relayClient) recv(t *testing.T) map[string]any {
	t.Helper()
	raw, e := readFrame(c.out, MaxOutput)
	if e != nil {
		t.Fatal("receive:", e)
	}
	defer clear(raw)
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&out) != nil {
		t.Fatal("decode response")
	}
	return out
}

func (c *relayClient) recvType(t *testing.T, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := c.recv(t)
		if out["type"] == want {
			return out
		}
	}
	t.Fatalf("did not receive %q", want)
	return nil
}

func TestBrokerSharedUnlockAndLockPropagation(t *testing.T) {
	endpoint := brokerTestSocket(t)
	var mu sync.Mutex
	var session *personal.Session
	locked := make(chan struct{}, 4)
	var broker *Broker
	broker = NewBroker(BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) {
			mu.Lock()
			defer mu.Unlock()
			if session == nil || !session.Unlocked() {
				return nil, 0, false
			}
			return session, 1, true
		},
		RequestLock: func() {
			mu.Lock()
			s := session
			mu.Unlock()
			if s != nil {
				s.Lock()
			}
			broker.NotifyLocked(2)
			select {
			case locked <- struct{}{}:
			default:
			}
		},
		ApproveBrowserPair: func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
			if req.Peer.PID == 0 || req.Peer.User == "" {
				t.Errorf("pair request without OS peer: %#v", req)
			}
			return BrowserPairDecision{Approved: true, QuickFill: true}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	client := startRelayClient(t)
	client.send(t, map[string]any{"v": 1, "id": reqID(1), "type": "status"})
	status := client.recvType(t, "status")
	if status["desktop_connected"] != true || status["unlocked"] != false || status["vault_locked"] != true {
		t.Fatalf("locked status: %#v", status)
	}
	// The extension's hello waits for the owner's explicit pairing decision.
	client.send(t, map[string]any{"v": 1, "id": reqID(2), "type": "hello"})

	s, row := brokerTestSession(t)
	mu.Lock()
	session = s
	mu.Unlock()
	broker.NotifyUnlocked(s, 1)
	paired := client.recvType(t, "paired")
	capability, _ := paired["capability"].(string)
	if !token.MatchString(capability) || paired["quick_fill"] != true {
		t.Fatalf("explicit pair: %#v", paired)
	}
	if caps, ok := paired["capabilities"].([]any); !ok || len(caps) != len(SupportedCapabilities()) {
		t.Fatalf("capabilities: %#v", paired["capabilities"])
	}
	for _, key := range []string{"v", "id", "type", "capability", "quick_fill", "capabilities"} {
		if _, ok := paired[key]; !ok {
			t.Fatalf("paired missing %q: %#v", key, paired)
		}
	}
	if len(paired) != 6 {
		t.Fatalf("paired extra keys: %#v", paired)
	}

	client.send(t, map[string]any{"v": 1, "id": reqID(3), "type": "match", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1"})
	candidates := client.recvType(t, "candidates")
	rows, ok := candidates["candidates"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("candidates: %#v", candidates)
	}
	client.send(t, map[string]any{"v": 1, "id": reqID(4), "type": "fill", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "item_id": row.ID, "revision": row.Revision})
	fill := client.recvType(t, "fill")
	if fill["username"] != "broker-user" || fill["password"] != "broker-password" {
		t.Fatalf("quick fill: %#v", fill)
	}

	client.send(t, map[string]any{"v": 1, "id": reqID(5), "type": "lock", "capability": capability})
	client.recvType(t, "locked")
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("desktop lock callback did not fire")
	}
	if s.Unlocked() {
		t.Fatal("session remained unlocked")
	}

	s2, _ := brokerTestSession(t)
	mu.Lock()
	session = s2
	mu.Unlock()
	// Re-unlock does not renew the old capability. The extension must send a
	// fresh hello and the owner must approve that pairing again.
	broker.NotifyUnlocked(s2, 2)
	client.send(t, map[string]any{"v": 1, "id": reqID(9), "type": "hello"})
	repaired := client.recvType(t, "paired")
	capability, _ = repaired["capability"].(string)
	if !token.MatchString(capability) || repaired["quick_fill"] != true {
		t.Fatalf("re-pair capability: %#v", repaired)
	}
	client.send(t, map[string]any{"v": 1, "id": reqID(6), "type": "vault-lock", "capability": capability})
	client.recvType(t, "locked")
	if s2.Unlocked() {
		t.Fatal("vault-lock alias did not revoke the session")
	}
}

func TestBrokerCLIRunApprovalAndFallback(t *testing.T) {
	// The unit terminal gate substitutes only the kernel peer attestation; the
	// broker still runs it before the callback and each exchange below is a
	// real RequestCLIRun over the broker socket.
	installCLIRunPassingGate(t)
	endpoint := brokerTestSocket(t)
	var mu sync.Mutex
	var session *personal.Session
	approved := true
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(ctx context.Context, peer Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			mu.Lock()
			s, ok := session, approved
			mu.Unlock()
			if s == nil || !s.Unlocked() || s.VaultPath() != req.VaultPath {
				return BrokerCLIResponse{}, ErrBrokerUnavailable
			}
			if !ok {
				return BrokerCLIResponse{}, errors.New("refused")
			}
			// The disclosure is the audited preparation of the exact canonical
			// request the scope names, committed through the real session; the
			// legacy ExtractCLIBrokerTargets path is never read here.
			request, e := CanonicalCLIRunRequest(req.Scope, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			receipt, values, e := s.PrepareBrokeredRun(ctx, CanonicalCLIRunTargets(req.Targets), request, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			return BrokerCLIResponse{V: 1, PreparedValues: values, Receipt: receipt}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	req := freshCLIRunFixtureRequest()
	// A valid absolute path that no session under test uses: it passes the
	// client's scope check, so the callback sees it with no session yet and
	// answers with the explicit, non-fallback unavailable.
	req.VaultPath = "/fixture/no-session-vault.ll"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := RequestCLIRun(ctx, req); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("locked broker: %v", e)
	}

	s, row := brokerTestSession(t)
	mu.Lock()
	session = s
	mu.Unlock()
	req = freshCLIRunFixtureRequest()
	req.VaultPath = s.VaultPath()
	req.Targets = []personal.CLIBrokerTarget{{Slot: "token", ID: row.ID, Revision: row.Revision, Field: "password"}}
	resp, e := RequestCLIRun(ctx, req)
	if e != nil || string(resp.PreparedValues["token"]) != "broker-password" || resp.Values != nil {
		t.Fatalf("approved CLI run: %v %#v", e, resp)
	}
	// The receipt must be the session transaction's own committed intent for
	// the exact requested slot.
	if resp.Receipt.Status != personal.RunBundlePreparationStatus || !lowerHex(resp.Receipt.Session, 32) ||
		!lowerHex(resp.Receipt.Intent, 64) || !lowerHex(resp.Receipt.TargetDigest, 64) {
		t.Fatalf("approved CLI run receipt not committed: %#v", resp.Receipt)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.run.bundle" && event.Item == row.ID && event.Result == "intent" &&
			event.Session == resp.Receipt.Session && event.Link == resp.Receipt.TargetDigest {
			found = true
		}
	}
	if !found {
		t.Fatal("CLI disclosed values without a committed audit event")
	}

	mu.Lock()
	approved = false
	mu.Unlock()
	req = freshCLIRunFixtureRequest()
	req.VaultPath = s.VaultPath()
	req.Targets = []personal.CLIBrokerTarget{{Slot: "token", ID: row.ID, Revision: row.Revision, Field: "password"}}
	if _, e := RequestCLIRun(ctx, req); !errors.Is(e, ErrCLIRunRefused) || errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("rejected CLI run must be an explicit, non-fallback refusal: %v", e)
	}
	mu.Lock()
	approved = true
	mu.Unlock()
	bad := freshCLIRunFixtureRequest()
	bad.VaultPath = s.VaultPath()
	bad.Targets = []personal.CLIBrokerTarget{{Slot: "token", ID: row.ID, Revision: reqID(9) + reqID(10), Field: "password"}}
	// The preparation refuses the stale revision in the callback, after
	// approval and the terminal gate: no data, and never fallback-eligible.
	if resp, e := RequestCLIRun(ctx, bad); !errors.Is(e, ErrCLIRunRefused) || resp.PreparedValues != nil {
		t.Fatalf("stale revision disclosed values: %v %#v", e, resp)
	}

	if e := broker.Close(); e != nil {
		t.Fatal(e)
	}
	// A fresh exchange, so the stopped broker itself is the only reason this
	// request is not served.
	stopped := freshCLIRunFixtureRequest()
	stopped.VaultPath = s.VaultPath()
	stopped.Targets = req.Targets
	if _, e := RequestCLIRun(ctx, stopped); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("stopped broker: %v", e)
	}
}

func TestBrokerCLIRunClientCancelCancelsApproval(t *testing.T) {
	// The unit terminal gate only substitutes the kernel peer attestation, so
	// this exchange reaches the callback that is pending native approval.
	installCLIRunPassingGate(t)
	endpoint := brokerTestSocket(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan error)
	broker := NewBroker(BrokerCallbacks{
		// A pending native approval waits on its context; the release also
		// lets it finish if cancellation never arrives.
		HandleCLIRun: func(ctx context.Context, peer Peer, req CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			close(entered)
			select {
			case <-ctx.Done():
			case <-release:
			}
			canceled <- ctx.Err()
			return BrokerCLIResponse{}, ctx.Err()
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, e := RequestCLIRun(ctx, freshCLIRunFixtureRequest())
		result <- e
	}()
	t.Cleanup(func() { close(release) })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("HandleCLIRun did not start")
	}
	cancel()
	select {
	case e := <-canceled:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("callback context after client cancellation: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not cancel the callback context")
	}
	select {
	case e := <-result:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("client return after cancellation: %v", e)
		}
		if errors.Is(e, ErrBrokerUnavailable) {
			t.Fatal("cancellation must never be classified as fallback-eligible")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCLIRun did not return after cancellation")
	}
	// Close the broker on failure paths too; closing twice is a no-op.
	if e := broker.Close(); e != nil {
		t.Fatal(e)
	}
}

// scriptedTimeout is a read timeout observable only through net.Error
// Timeout, like the Windows named-pipe deadline of go-winio.
type scriptedTimeout struct{}

func (scriptedTimeout) Error() string   { return "i/o timeout" }
func (scriptedTimeout) Timeout() bool   { return true }
func (scriptedTimeout) Temporary() bool { return true }

// scriptedDrop is a transport failure that is not an idle deadline.
var scriptedDrop = errors.New("scripted transport drop")

// cliRunScriptedConn is a net.Conn with scripted reads: the first reads return
// the timeout, then the tail decides the last read. It never blocks. The tail
// "extra-with-timeout" reports input and a timeout together.
type cliRunScriptedConn struct {
	net.Conn
	mu      sync.Mutex
	lim     int
	timeout error
	tail    string
	reads   int
}

func (c *cliRunScriptedConn) SetReadDeadline(time.Time) error { return nil }
func (c *cliRunScriptedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.reads < c.lim {
		return 0, c.timeout
	}
	switch c.tail {
	case "disconnect":
		return 0, io.EOF
	case "extra":
		b[0] = '{'
		return 1, nil
	case "extra-with-timeout":
		b[0] = '{'
		return 1, c.timeout
	default:
		return 0, scriptedDrop
	}
}

func (c *cliRunScriptedConn) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// TestWatchCLIRunConnMonitorsPastIdleTimeouts pins the monitor to a scripted
// connection so no real idle deadline is waited. Timeouts of either portable
// shape never cancel on their own, but the monitor must keep reading past
// them: a later disconnect or extra byte still cancels the callback. The
// test's stop is only closed after the monitor exits, so it is never the
// cause of a cancel.
func TestWatchCLIRunConnMonitorsPastIdleTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout error
		tail    string
		cancel  bool
	}{
		{"disconnect after deadline exceeded", os.ErrDeadlineExceeded, "disconnect", true},
		{"extra byte after deadline exceeded", os.ErrDeadlineExceeded, "extra", true},
		{"disconnect after net timeout", scriptedTimeout{}, "disconnect", true},
		{"extra byte after net timeout", scriptedTimeout{}, "extra", true},
		{"input with a timeout error still cancels", scriptedTimeout{}, "extra-with-timeout", true},
		{"transport drop is not a timeout", scriptedTimeout{}, "drop", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &cliRunScriptedConn{lim: 3, timeout: tc.timeout, tail: tc.tail}
			stop := make(chan struct{})
			canceled := make(chan struct{})
			cancels := 0
			done := make(chan struct{})
			go func() {
				defer close(done)
				watchCLIRunConn(conn, func() { cancels++; close(canceled) }, stop, time.Hour)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("monitor neither canceled nor stopped after the scripted reads")
			}
			close(stop)
			cancelled := false
			select {
			case <-canceled:
				cancelled = true
			default:
			}
			if n := conn.readCount(); n < 3 || cancelled != tc.cancel || cancels > 1 {
				t.Fatalf("reads=%d canceled=%v (want %v) after idle timeouts", n, cancelled, tc.cancel)
			}
		})
	}
}

// TestWatchCLIRunConnIdleTimeoutsDoNotCancel keeps the monitor on timeouts
// indefinitely, then releases it through the handler's stop: an idle timeout
// must neither cancel nor end the watch.
func TestWatchCLIRunConnIdleTimeoutsDoNotCancel(t *testing.T) {
	for _, timeout := range []error{os.ErrDeadlineExceeded, scriptedTimeout{}} {
		conn := &cliRunScriptedConn{lim: 1 << 30, timeout: timeout}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchCLIRunConn(conn, func() { t.Errorf("%T canceled on idle timeout", timeout) }, stop, time.Hour)
		}()
		for conn.readCount() < 5 {
			time.Sleep(time.Millisecond)
		}
		close(stop)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("stop did not release the monitor")
		}
	}
}

// cliRunFixtureScope sits in broker_fixture_test.go, which has no build tag.

// cliRunFixtureRequest is a valid CLI-run request for outcome classification.
func cliRunFixtureRequest() CLIRunBrokerRequest {
	return CLIRunBrokerRequest{
		V:         1,
		VaultPath: "/fixture/vault.ll",
		Scope:     cliRunFixtureScope(),
		Targets:   []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "password"}},
	}
}

// cliRunScriptedServer listens on a fresh broker socket and answers one CLI-run
// connection with the supplied reply. It reports whether the client's request
// frame was actually received before any reply behaviour.
func cliRunScriptedServer(t *testing.T, reply func(net.Conn)) <-chan bool {
	t.Helper()
	endpoint := brokerTestSocket(t)
	l, e := net.Listen("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	sent := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := l.Accept()
		if e != nil {
			sent <- false
			return
		}
		defer conn.Close()
		// hello frame, then the request frame, both exactly as the client writes.
		if _, e := readFrame(conn, MaxInput); e != nil {
			sent <- false
			return
		}
		if _, e := readFrame(conn, MaxInput); e != nil {
			sent <- false
			return
		}
		sent <- true
		reply(conn)
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
	})
	return sent
}

func cliRunReplyPayload(raw string) func(net.Conn) {
	return func(conn net.Conn) { _ = writeFrame(conn, []byte(raw)) }
}

func TestCLIRunNoListenerIsUnavailable(t *testing.T) {
	brokerTestSocket(t) // endpoint configured, but nothing listens on it
	if _, e := RequestCLIRun(context.Background(), cliRunFixtureRequest()); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("no listener: %v", e)
	}
}

func TestCLIRunExplicitUnavailableIsUnavailable(t *testing.T) {
	sent := cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"error":"unavailable"}`))
	if _, e := RequestCLIRun(context.Background(), cliRunFixtureRequest()); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("explicit unavailable: %v", e)
	}
	if !<-sent {
		t.Fatal("server did not receive the request frame")
	}
}

func TestCLIRunRefusalIsNonUnavailableWithoutLeakage(t *testing.T) {
	req := cliRunFixtureRequest()
	// A distinct, canonical 32-hex target ID that still passes client-side
	// validation, so the scripted server is actually reached.
	req.Targets[0].ID = "1ea7c0de000000000000000000000003"
	// The exact protocol refusal maps to the stable generic error and never
	// echoes request material.
	sent := cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"error":"refused"}`))
	_, e := RequestCLIRun(context.Background(), req)
	if !<-sent {
		t.Fatal("server did not receive the request frame")
	}
	if e == nil || errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("refusal classified as unavailable: %v", e)
	}
	if !errors.Is(e, ErrCLIRunRefused) {
		t.Fatalf("refusal did not map to ErrCLIRunRefused: %v", e)
	}
	assertNoCLIRunLeak(t, e, req)

	// A reply mixing a refusal with values is malformed: generic error, no
	// values, and no broker payload echoed back.
	sent = cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"error":"refused","values":{"LOGIN_PASSWORD":"leak-masked-value"}}`))
	resp, e := RequestCLIRun(context.Background(), req)
	if !<-sent {
		t.Fatal("server did not receive the request frame")
	}
	if e == nil || errors.Is(e, ErrBrokerUnavailable) || errors.Is(e, ErrCLIRunRefused) {
		t.Fatalf("refusal with values classification: %v", e)
	}
	if len(resp.Values) != 0 {
		t.Fatal("malformed refusal returned response values")
	}
	assertNoCLIRunLeak(t, e, req)

	// Unknown error tokens are never surfaced verbatim either.
	sent = cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"error":"token-secret-xyz"}`))
	_, e = RequestCLIRun(context.Background(), req)
	if !<-sent {
		t.Fatal("server did not receive the request frame")
	}
	if e == nil || errors.Is(e, ErrBrokerUnavailable) || errors.Is(e, ErrCLIRunRefused) {
		t.Fatalf("unknown error token classification: %v", e)
	}
	assertNoCLIRunLeak(t, e, req)
}

// assertNoCLIRunLeak rejects any error text carrying broker payloads, opaque
// error tokens, or request material.
func assertNoCLIRunLeak(t *testing.T, e error, req CLIRunBrokerRequest) {
	t.Helper()
	if e == nil {
		t.Fatal("expected an error")
	}
	msg := e.Error()
	for _, secret := range []string{"leak-masked-value", "token-secret-xyz", "LOGIN_PASSWORD", req.Targets[0].ID, req.Targets[0].Revision, req.VaultPath} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error leaked %q: %q", secret, msg)
		}
	}
}

func TestCLIRunBadResponsesAfterTransmissionAreNonUnavailable(t *testing.T) {
	cases := []struct {
		name  string
		reply func(net.Conn)
	}{
		{"malformed json", cliRunReplyPayload(`{"v":1,"values":`)},
		{"empty object", cliRunReplyPayload(`{}`)},
		{"empty error", cliRunReplyPayload(`{"v":1,"error":""}`)},
		{"bad version", cliRunReplyPayload(`{"v":2,"error":"refused"}`)},
		{"missing version", cliRunReplyPayload(`{"error":"refused"}`)},
		{"second document", cliRunReplyPayload(`{"v":1,"error":"refused"}{}`)},
		{"duplicate keys unavailable", cliRunReplyPayload(`{"v":1,"error":"unavailable","error":"unavailable"}`)},
		{"duplicate version unavailable", cliRunReplyPayload(`{"v":1,"v":1,"error":"unavailable"}`)},
		{"trailing document after unavailable", cliRunReplyPayload(`{"v":1,"error":"unavailable"}{"v":1}`)},
		{"trailing whitespace value", cliRunReplyPayload(`{"v":1,"error":"unavailable"} null`)},
		{"unavailable with empty values", cliRunReplyPayload(`{"v":1,"error":"unavailable","values":{}}`)},
		{"unavailable with extra field", cliRunReplyPayload(`{"v":1,"error":"unavailable","extra":true}`)},
		{"duplicate keys refused", cliRunReplyPayload(`{"v":1,"error":"refused","error":"refused"}`)},
		{"trailing document after values", cliRunReplyPayload(`{"v":1,"values":{"LOGIN_PASSWORD":"x"}}{}`)},
		{"duplicate values key", cliRunReplyPayload(`{"v":1,"values":{"LOGIN_PASSWORD":"x"},"values":{"LOGIN_PASSWORD":"y"}}`)},
		{"unknown response field", cliRunReplyPayload(`{"v":1,"values":{"LOGIN_PASSWORD":"x"},"extra":true}`)},
		{"values with error", cliRunReplyPayload(`{"v":1,"error":"refused","values":{"LOGIN_PASSWORD":"x"}}`)},
		{"success without values", cliRunReplyPayload(`{"v":1}`)},
		{"oversized frame header", func(conn net.Conn) {
			_, _ = conn.Write([]byte{0xff, 0xff, 0xff, 0xff})
		}},
		{"wrong field type", cliRunReplyPayload(`{"v":1,"values":"nope","error":"refused"}`)},
		{"disconnect after request", func(conn net.Conn) {}},
		{"partial frame then disconnect", func(conn net.Conn) {
			_, _ = conn.Write([]byte{4, 0, 0, 0, '{'})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sent := cliRunScriptedServer(t, tc.reply)
			_, e := RequestCLIRun(context.Background(), cliRunFixtureRequest())
			if !<-sent {
				t.Fatal("server did not receive the request frame")
			}
			if e == nil || errors.Is(e, ErrBrokerUnavailable) {
				t.Fatalf("%s classified as available/unavailable: %v", tc.name, e)
			}
		})
	}
}

func TestCLIRunCancellationWhileAwaitingResponse(t *testing.T) {
	requestSeen := make(chan struct{})
	sent := cliRunScriptedServer(t, func(conn net.Conn) {
		close(requestSeen)
		// Never reply: the client must be interrupted by cancellation.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		_, _ = conn.Read(b[:])
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, e := RequestCLIRun(ctx, cliRunFixtureRequest())
		result <- e
	}()
	select {
	case <-requestSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the request frame")
	}
	cancel()
	select {
	case e := <-result:
		if !<-sent {
			t.Fatal("server did not receive the request frame")
		}
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancellation error: %v", e)
		}
		if errors.Is(e, ErrBrokerUnavailable) {
			t.Fatal("cancellation must never be classified as fallback-eligible")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCLIRun did not return after cancellation")
	}
}

func TestCLIRunDeadlineWhileAwaitingResponse(t *testing.T) {
	requestSeen := make(chan struct{})
	release := make(chan struct{})
	cliRunScriptedServer(t, func(conn net.Conn) {
		close(requestSeen)
		<-release // hold the response until the client's deadline fires
	})
	// Registered after the helper's cleanup, so LIFO runs this first and the
	// blocked callback is released even if the test fails early.
	t.Cleanup(func() { close(release) })
	// The hello and request are already delivered before this short real
	// timeout fires; the server never replies, so the client must be
	// interrupted by the deadline (never by an explicit cancel).
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, e := RequestCLIRun(ctx, cliRunFixtureRequest())
		result <- e
	}()
	select {
	case <-requestSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the request frame")
	}
	var e error
	select {
	case <-ctx.Done():
		select {
		case e = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("RequestCLIRun did not return after the deadline")
		}
	case e = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCLIRun did not return after the deadline")
	}
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("deadline error: %v", e)
	}
	if errors.Is(e, ErrBrokerUnavailable) {
		t.Fatal("deadline must never be classified as fallback-eligible")
	}

	// A context that is already done never classifies as unavailability.
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, e := RequestCLIRun(expired, cliRunFixtureRequest()); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("pre-expired context: %v", e)
	}
	canceled, stopCanceled := context.WithCancel(context.Background())
	stopCanceled()
	if _, e := RequestCLIRun(canceled, cliRunFixtureRequest()); !errors.Is(e, context.Canceled) || errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("pre-canceled context: %v", e)
	}
}

func TestCLIRunInvalidRequestIsNotFallbackEligible(t *testing.T) {
	brokerTestSocket(t) // even a reachable endpoint must not turn bad input into unavailability
	valid := cliRunFixtureRequest()
	cases := []CLIRunBrokerRequest{
		{V: 2, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: valid.Targets},
		{V: 1, Scope: valid.Scope, Targets: valid.Targets},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: make([]personal.CLIBrokerTarget, 17)},
		// The scope is mandatory and must validate on the client too.
		{V: 1, VaultPath: valid.VaultPath, Targets: valid.Targets},
		{V: 1, VaultPath: valid.VaultPath, Scope: CLIRunScope{}, Targets: valid.Targets},
		{V: 1, VaultPath: "relative/vault.ll", Scope: valid.Scope, Targets: valid.Targets},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: []personal.CLIBrokerTarget{{Slot: "", ID: reqID(1), Revision: reqRevision(2), Field: "password"}}},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "password"}, {Slot: "token", ID: reqID(3), Revision: reqRevision(4), Field: "password"}}},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: []personal.CLIBrokerTarget{{Slot: "elsewhere", ID: reqID(1), Revision: reqRevision(2), Field: "password"}}},
		{V: 1, VaultPath: valid.VaultPath, Scope: valid.Scope, Targets: []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "username"}}},
	}
	for i, req := range cases {
		_, e := RequestCLIRun(context.Background(), req)
		if e == nil || errors.Is(e, ErrBrokerUnavailable) {
			t.Fatalf("case %d: invalid request classified as fallback-eligible: %v", i, e)
		}
	}
	if _, e := RequestCLIRun(nil, cliRunFixtureRequest()); e == nil || errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("nil context classified as fallback-eligible: %v", e)
	}
}

func TestDialAbsentOnlyForClearlyAbsentBroker(t *testing.T) {
	if dialAbsent(errors.New("unknown")) {
		t.Fatal("unknown dial error classified as absence")
	}
	if dialAbsent(nil) {
		t.Fatal("nil dial error classified as absence")
	}
	if dialAbsent(context.DeadlineExceeded) || dialAbsent(context.Canceled) {
		t.Fatal("context errors classified as absence")
	}
}

// A brokered browser gets no capability unless the native pairing callback
// explicitly approves. A refused hello must fail closed, not auto-pair.
func TestBrokerBrowserPairingIsExplicitAndRefusable(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, _ := brokerTestSession(t)
	requests := make(chan BrowserPairRequest, 1)
	broker := NewBroker(BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) { return s, 7, true },
		ApproveBrowserPair: func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
			requests <- req
			return BrowserPairDecision{Approved: false}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	client := startRelayClient(t)
	client.send(t, map[string]any{"v": 1, "id": reqID(80), "type": "hello"})
	out := client.recvType(t, "error")
	if out["error"] != "refused" {
		t.Fatalf("refused pairing: %#v", out)
	}
	select {
	case req := <-requests:
		if req.Peer.PID == 0 || req.Peer.User == "" || req.Origin == "" {
			t.Fatalf("pair review lacked authenticated peer or extension identity: %#v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("pairing callback was not invoked")
	}
}

// The peer must be the desktop's own canonical executable or an exact Locklark
// host basename at any absolute install directory, provided the file is a
// trusted regular executable owned by the authenticated user. Prefixes, bare
// names, arbitrary executables and writable/unowned/non-executable files are
// refused; neither the declared browser nor origin participates.
func TestPeerProcessAllowedUsesExactHostNamesAndInstallLocation(t *testing.T) {
	dir := t.TempDir()
	write := func(path string, perm os.FileMode) string {
		t.Helper()
		if perm == 0 {
			perm = 0700
		}
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte("fixture"), perm); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(path, perm); e != nil {
			t.Fatal(e)
		}
		return path
	}
	self := write(filepath.Join(dir, "bin", "locklark-desktop"), 0)
	host := write(filepath.Join(dir, "bin", "locklark-browser-chromium"), 0)
	installed := write(filepath.Join(dir, "Library Application Support", "Locklark Browser Host", "locklark-browser-chromium"), 0)
	firefox := write(filepath.Join(dir, "opt", "locklark", "locklark-browser-firefox"), 0)
	evilPrefix := write(filepath.Join(dir, "opt", "locklark", "locklark-browser-chromium-evil"), 0)
	shortPrefix := write(filepath.Join(dir, "opt", "locklark", "locklark-browser"), 0)
	arbitrary := write(filepath.Join(dir, "opt", "locklark", "evil"), 0)
	groupWritable := write(filepath.Join(dir, "rw", "locklark-browser-chromium"), 0770)
	otherWritable := write(filepath.Join(dir, "rw", "locklark-browser-firefox"), 0702)
	notExecutable := write(filepath.Join(dir, "rx", "locklark-browser-chromium"), 0600)
	directory := filepath.Join(dir, "a-directory", "locklark-browser-chromium")
	if e := os.MkdirAll(directory, 0700); e != nil {
		t.Fatal(e)
	}
	// Give the file an owner uid other than the broker's. Unprivileged
	// processes cannot chown, so this check is skipped when refused.
	unowned := write(filepath.Join(dir, "unowned", "locklark-browser-chromium"), 0)
	chowned := os.Chown(unowned, 12345, 12345) == nil
	peerUser := "UID " + strconv.Itoa(os.Geteuid())
	otherUser := "UID " + strconv.Itoa(os.Geteuid()+1)
	type tc struct {
		name, path, user, goos string
		want                   bool
	}
	cases := []tc{
		{"exact executable", self, peerUser, "linux", true},
		{"installed host beside desktop", host, peerUser, "linux", true},
		{"exact host in another absolute directory", installed, peerUser, "linux", true},
		{"exact firefox host in another directory", firefox, peerUser, "darwin", true},
		{"longer prefix", evilPrefix, peerUser, "linux", false},
		{"short prefix", shortPrefix, peerUser, "linux", false},
		{"arbitrary executable", arbitrary, peerUser, "linux", false},
		{"group writable", groupWritable, peerUser, "linux", false},
		{"other writable", otherWritable, peerUser, "linux", false},
		{"non executable", notExecutable, peerUser, "linux", false},
		{"directory", directory, peerUser, "linux", false},
		{"bare basename", "locklark-browser-chromium", peerUser, "linux", false},
		{"unauthenticated PID", installed, peerUser, "linux", false},
	}
	if chowned {
		cases = append(cases, tc{"unowned host", unowned, peerUser, "linux", false})
	}
	// Unless a case names the desktop itself, the broker runs from another
	// absolute desktop path so install-directory equality cannot help.
	broker := write(filepath.Join(dir, "unrelated", "locklark-desktop"), 0)
	against := make(map[string]string, len(cases))
	for _, c := range cases {
		against[c.path] = broker
	}
	against[self] = self
	for _, c := range cases {
		peer := Peer{User: c.user, PID: 2, Process: c.path}
		if c.name == "unauthenticated PID" {
			peer.PID = 0
		}
		if got := peerProcessAllowedFor(peer, against[c.path], c.goos); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// Ownership names the authenticated peer user, not just any user string.
	if peerProcessAllowedFor(Peer{User: otherUser, PID: 2, Process: installed}, self, "linux") {
		t.Fatal("host owned by this broker accepted for a foreign peer user")
	}

	// macOS Safari follows the same exact-basename policy at any directory; the
	// sibling app-bundle requirement is gone.
	apps := filepath.Join(dir, "Applications")
	desktop := write(filepath.Join(apps, "Locklark.app", "Contents", "MacOS", "locklark-desktop"), 0)
	safari := write(filepath.Join(apps, "Locklark Safari.app", "Contents", "MacOS", "locklark-browser-safari"), 0)
	if !peerProcessAllowedFor(Peer{User: peerUser, PID: 3, Process: safari}, desktop, "darwin") {
		t.Fatal("exact Safari helper rejected")
	}
	looseSafari := write(filepath.Join(dir, "safari elsewhere", "locklark-browser-safari"), 0)
	if !peerProcessAllowedFor(Peer{User: peerUser, PID: 3, Process: looseSafari}, desktop, "darwin") {
		t.Fatal("Safari helper outside an app bundle rejected")
	}
	writableSafari := write(filepath.Join(dir, "safari elsewhere", "locklark-browser-chromium"), 0o702)
	if e := os.Chmod(writableSafari, 0702); e != nil {
		t.Fatal(e)
	}
	if peerProcessAllowedFor(Peer{User: peerUser, PID: 3, Process: writableSafari}, desktop, "darwin") {
		t.Fatal("writable Darwin host accepted")
	}
}

func pairingTestConnection(t *testing.T) (*Connection, *memoryPipe, *personal.Session, *Broker) {
	t.Helper()
	s, _ := brokerTestSession(t)
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	return c, out, s, NewBroker(BrokerCallbacks{})
}

func TestBrokerPairingCloseCancelsNativeReview(t *testing.T) {
	c, out, s, b := pairingTestConnection(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	b.callbacks.ApproveBrowserPair = func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return BrowserPairDecision{}, ctx.Err()
	}
	c.SetBroker(b)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.mu.Lock()
	c.hello, c.pairUntil = reqID(90), now.Add(time.Minute)
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.reviewBrowserHello(s, 1); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("pairing review did not start")
	}
	c.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("connection close did not cancel the pairing context")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pairing review did not return after close")
	}
	if c.PairAuthorized() || c.Snapshot().Paired {
		t.Fatal("closed connection obtained pairing authority")
	}
	for _, frame := range out.responses(t) {
		if frame.Type == "paired" || frame.Type == "unlocked" {
			t.Fatalf("closed pairing wrote %q", frame.Type)
		}
	}
}

func TestBrokerPairingExpiryRejectsLateApproval(t *testing.T) {
	c, out, s, b := pairingTestConnection(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	b.callbacks.ApproveBrowserPair = func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 61*time.Second || time.Until(deadline) <= 0 {
			t.Errorf("pairing context deadline: %v %v", deadline, ok)
		}
		close(entered)
		<-release
		return BrowserPairDecision{Approved: true, QuickFill: true}, nil
	}
	c.SetBroker(b)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.mu.Lock()
	c.hello, c.pairUntil = reqID(91), now.Add(time.Minute)
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.reviewBrowserHello(s, 1); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("pairing review did not start")
	}
	now = now.Add(61 * time.Second)
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pairing review did not return after expiry")
	}
	if c.PairAuthorized() || c.Snapshot().Paired {
		t.Fatal("expired pairing bound a late approval")
	}
	for _, frame := range out.responses(t) {
		if frame.Type == "paired" || frame.Type == "unlocked" {
			t.Fatalf("expired pairing wrote %q", frame.Type)
		}
	}
}

func TestClearCLIRunRawMessagesZeroesEverySlice(t *testing.T) {
	first := json.RawMessage(`"s3cret-one"`)
	second := json.RawMessage(`{"nested":"s3cret-two"}`)
	raws := map[string]json.RawMessage{"a": first, "b": second}
	clearCLIRunRawMessages(raws)
	for name, raw := range raws {
		for i, b := range raw {
			if b != 0 {
				t.Fatalf("%s: byte %d not cleared: %q", name, i, raw)
			}
		}
	}
	// The backing bytes of each slice are zeroed in place.
	for _, raw := range [][]byte{first, second} {
		for i, b := range raw {
			if b != 0 {
				t.Fatalf("backing byte %d not cleared: %q", i, raw)
			}
		}
	}
	clearCLIRunRawMessages(nil)
	clearCLIRunRawMessages(map[string]json.RawMessage{})
}

func TestClearCLIRunRawMessagesOnParseFailure(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"duplicate-key", `{"a":"s3cret-a","b":"s3cret-b","a":"s3cret-dup"}`},
		{"truncated-value", `{"a":"s3cret-a","b":{"x":"s3cret-b"`},
		{"not-object", `["s3cret-a"]`},
		{"trailing-data", `{"a":"s3cret-a"} {"b":"s3cret-b"}`},
		{"unterminated", `{"a":"s3cret-a"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys, values, ok := strictJSONObject([]byte(tc.raw))
			if ok || keys != nil || values != nil {
				t.Fatalf("accepted %q: keys=%v values=%q", tc.raw, keys, values)
			}
		})
	}
	// A well-formed object is still returned with raw values intact.
	_, values, ok := strictJSONObject([]byte(`{"v":1,"x":"keep"}`))
	if !ok || string(values["x"]) != `"keep"` || string(values["v"]) != `1` {
		t.Fatalf("valid object not preserved: ok=%v values=%q", ok, values)
	}
}

func TestClearCLIRunRawMessagesRejectPathsZeroNamedCollection(t *testing.T) {
	// Every rejection path must return nil/nil/false and must run cleanup over
	// the local collection the deferred closure captures, not a nil shadow of
	// it (a named result would be set to nil by the return statement first).
	for _, raw := range []string{
		`{"v":1,"a":"s3cret-a","b":"s3cret-b","a":"s3cret-dup"}`,
		`{"a":"s3cret-a","b":{"x":"s3cret-b"`,
		`{"a":"s3cret-a"} {"b":"s3cret-b"}`,
		`{"a":"s3cret-a"`,
		`{"a":"s3cret-a",1:true}`,
		``,
	} {
		keys, values, ok := strictJSONObject([]byte(raw))
		if ok || keys != nil || values != nil {
			t.Fatalf("accepted %q: keys=%v values=%q", raw, keys, values)
		}
	}
}

func TestCLIRunResponsesClearRawCopiesWithoutAlteringValues(t *testing.T) {
	// A legacy map[string]string success is unaudited: it is refused with no
	// value returned.
	sent := cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"values":{"slot-7":"pw-exact"}}`))
	resp, e := RequestCLIRun(context.Background(), cliRunFixtureRequest())
	if !errors.Is(e, errCLIRunResponse) || resp.Values != nil || resp.PreparedValues != nil {
		t.Fatalf("legacy values reply: %v %#v", e, resp)
	}
	if !<-sent {
		t.Fatal("server did not receive the request frame")
	}
	// Partially invalid nested values and error replies stay generic.
	for name, reply := range map[string]string{
		"nested-unknown-field": `{"v":1,"values":{"slot-1":"p","x":1}}`,
		"nested-empty-slot":    `{"v":1,"values":{"":"p"}}`,
		"nested-empty-value":   `{"v":1,"values":{"slot-1":"","slot-2":"q"}}`,
		"unknown-error":        `{"v":1,"error":"s3cret-token"}`,
	} {
		t.Run(name, func(t *testing.T) {
			sent := cliRunScriptedServer(t, cliRunReplyPayload(reply))
			if _, e := RequestCLIRun(context.Background(), cliRunFixtureRequest()); !errors.Is(e, errCLIRunResponse) {
				t.Fatalf("%s: %v", reply, e)
			}
			<-sent
		})
	}
}

// cliRunReceiptJSON is a canonical receipt for the fixture request: a 32-hex
// session and two 64-hex digests.
func cliRunReceiptJSON() string {
	return `{"status":"` + personal.RunBundlePreparationStatus + `","session":"` + reqID(70) + `","intent":"` + reqRevision(71) + `","target_digest":"` + reqRevision(72) + `"}`
}

// cliRunReceiptFromFixture decodes cliRunReceiptJSON into the receipt value.
func cliRunReceiptFromFixture(t *testing.T) personal.RunBundlePreparationReceipt {
	t.Helper()
	receipt, ok := decodeCLIRunReceipt(json.RawMessage(cliRunReceiptJSON()))
	if !ok {
		t.Fatal("receipt fixture is not canonical")
	}
	return receipt
}

// cliRunAuditedReply is the exact audited success frame: raw base64 slot
// values plus the canonical receipt.
func cliRunAuditedReply(slot, b64 string) string {
	return `{"v":1,"values_b64":{"` + slot + `":"` + b64 + `"},"receipt":` + cliRunReceiptJSON() + `}`
}

// TestCLIRunWireExactBytesAndReceipt proves the audited reply is canonical on
// the wire, round-trips byte-exact in both directions, accepts empty bytes,
// and refuses every malformed, null, partial, non-canonical or escaped base64
// value and every non-canonical raw receipt without returning a value.
func TestCLIRunWireExactBytesAndReceipt(t *testing.T) {
	slot := "token"
	exact := []byte("line\nwith\t\x00 and \xff bytes")
	values := map[string][]byte{slot: exact}
	raw, e := marshalCLIRunResponse(CLIRunBrokerResponse{V: 1, PreparedValues: values, Receipt: cliRunReceiptFromFixture(t)})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	want := cliRunAuditedReply(slot, base64.StdEncoding.EncodeToString(exact))
	if string(raw) != want {
		t.Fatalf("wire %q, want %q", raw, want)
	}
	if bytes.Contains(raw, []byte(`"values"`)) {
		t.Fatal("legacy values member on the wire")
	}
	resp, e := decodeCLIRunResponse(raw, cliRunFixtureRequest().Targets)
	if e != nil {
		t.Fatalf("canonical reply refused: %v", e)
	}
	defer clearCLIRunResponse(&resp)
	if !bytes.Equal(resp.PreparedValues[slot], exact) || len(resp.PreparedValues) != 1 {
		t.Fatalf("round trip altered the bytes: %q", resp.PreparedValues)
	}
	if resp.Receipt != cliRunReceiptFromFixture(t) {
		t.Fatalf("round trip altered the receipt: %#v", resp.Receipt)
	}
	// Empty bytes are exact bytes: accepted, non-nil, and encoded as "".
	empty, e := marshalCLIRunResponse(CLIRunBrokerResponse{V: 1, PreparedValues: map[string][]byte{slot: {}}, Receipt: cliRunReceiptFromFixture(t)})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(empty)
	if decoded, e := decodeCLIRunResponse(empty, cliRunFixtureRequest().Targets); e != nil || decoded.PreparedValues[slot] == nil || len(decoded.PreparedValues[slot]) != 0 {
		t.Fatalf("empty bytes: %q %v", decoded.PreparedValues, e)
	}
	// The writer refuses a legacy map, values with an error, values without a
	// canonical receipt, and a nil buffer instead of writing them.
	for name, bad := range map[string]CLIRunBrokerResponse{
		"legacy-values":    {V: 1, Values: map[string]string{slot: "legacy"}},
		"values-and-error": {V: 1, PreparedValues: values, Receipt: cliRunReceiptFromFixture(t), Error: "refused"},
		"no-receipt":       {V: 1, PreparedValues: values},
		"nil-value":        {V: 1, PreparedValues: map[string][]byte{slot: nil}, Receipt: cliRunReceiptFromFixture(t)},
	} {
		if got, e := marshalCLIRunResponse(bad); e == nil {
			t.Fatalf("%s: wrote %q", name, got)
		}
	}
	// Every malformed reply is a generic, non-fallback error with no value.
	receipt := cliRunReceiptJSON()
	withValues := func(v string) string { return `{"v":1,"values_b64":` + v + `,"receipt":` + receipt + `}` }
	for name, reply := range map[string]string{
		"null-value":            withValues(`{"token":null}`),
		"values-null":           withValues(`null`),
		"invalid-partial-b64":   withValues(`{"token":"cHctc2VjcmV0*"}`),
		"invalid-partial-b64-2": withValues(`{"token":"cHctc2VjcmV0AB"}`),
		// eB== and eHh= decode to x and xx but carry non-zero pad bits, so
		// only the exact re-encode check refuses them.
		"noncanonical-pad-bits":   withValues(`{"token":"eB=="}`),
		"noncanonical-pad-bits-2": withValues(`{"token":"eHh="}`),
		"noncanonical-space":      withValues(`{"token":"cHctc2VjcmV0 "}`),
		"noncanonical-extra-pad":  withValues(`{"token":"cHctc2VjcmV0=="}`),
		"noncanonical-url":        withValues(`{"token":"___="}`),
		"noncanonical-alphabet":   withValues(`{"token":"cHctc2VjcmV0-_"}`),
		"noncanonical-receipt":    `{"v":1,"values_b64":{"token":"cA=="},"receipt":{"session":"` + reqID(70) + `","status":"intent-recorded","intent":"` + reqRevision(71) + `","target_digest":"` + reqRevision(72) + `"}}`,
		"receipt-null":            `{"v":1,"values_b64":{"token":"cA=="},"receipt":null}`,
		"legacy-values":           `{"v":1,"values":{"token":"pw"}}`,
	} {
		resp, e := decodeCLIRunResponse([]byte(reply), cliRunFixtureRequest().Targets)
		if !errors.Is(e, errCLIRunResponse) || errors.Is(e, ErrBrokerUnavailable) || errors.Is(e, ErrCLIRunRefused) {
			t.Fatalf("%s: %v", name, e)
		}
		if resp.PreparedValues != nil || resp.Receipt != (personal.RunBundlePreparationReceipt{}) {
			t.Fatalf("%s returned a partial response: %#v", name, resp)
		}
	}
}

// TestCLIRunBrokerRefusalAndCleanup proves the broker's own write path never
// emits a legacy, unaudited, wrapped-unavailable or malformed reply, that an
// unsupported peer TTY is a fixed refusal, and that callback-owned buffers are
// zeroed on error.
func TestCLIRunBrokerRefusalAndCleanup(t *testing.T) {
	receipt := cliRunReceiptFromFixture(t)
	own := []byte("callback-owned-secret")
	wrote := func(reply func() (BrokerCLIResponse, error)) string {
		t.Helper()
		server, client := net.Pipe()
		defer client.Close()
		b := NewBroker(BrokerCallbacks{HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			return reply()
		}})
		got := make(chan []byte, 1)
		go func() { raw, _ := readFrame(client, MaxOutput); got <- raw }()
		b.handleCLIRunConn(server, Peer{User: "UID 501"}, cliRunFixtureRequest(), &CLIRunBrokerResponse{V: 1})
		raw := <-got
		if raw == nil {
			t.Fatal("no broker reply")
		}
		defer clear(raw)
		return string(raw)
	}
	if got := wrote(func() (BrokerCLIResponse, error) {
		return BrokerCLIResponse{V: 1, Values: map[string]string{"token": "legacy-secret"}}, nil
	}); got != `{"v":1,"error":"refused"}` {
		t.Fatalf("legacy reply wrote %s", got)
	}
	// A partial byte map with a callback error is refused, its bytes are
	// zeroed, and nothing of it is written.
	if got := wrote(func() (BrokerCLIResponse, error) {
		return BrokerCLIResponse{V: 1, PreparedValues: map[string][]byte{"token": own}}, errors.New("refused")
	}); got != `{"v":1,"error":"refused"}` || !bytes.Equal(own, make([]byte, len(own))) {
		t.Fatalf("error reply wrote %s, buffer %q", got, own)
	}
	// Only the exact sentinel is unavailable; a wrapped copy is a refusal.
	if got := wrote(func() (BrokerCLIResponse, error) { return BrokerCLIResponse{}, ErrBrokerUnavailable }); got != `{"v":1,"error":"unavailable"}` {
		t.Fatalf("exact sentinel wrote %s", got)
	}
	if got := wrote(func() (BrokerCLIResponse, error) {
		return BrokerCLIResponse{}, fmt.Errorf("wrapped: %w", ErrBrokerUnavailable)
	}); got != `{"v":1,"error":"refused"}` {
		t.Fatalf("wrapped sentinel wrote %s", got)
	}
	// The audited pair is the only success written.
	if got := wrote(func() (BrokerCLIResponse, error) {
		return BrokerCLIResponse{V: 1, PreparedValues: map[string][]byte{"token": []byte("x")}, Receipt: receipt}, nil
	}); got != cliRunAuditedReply("token", "eA==") {
		t.Fatalf("audited reply wrote %s", got)
	}
	// An unsupported peer TTY attestation is the fixed refusal, and the
	// callback never runs.
	oldGate := cliRunTTYGate
	cliRunTTYGate = func(Peer, string, string, string) error { return errCLIRunUnavailable }
	t.Cleanup(func() { cliRunTTYGate = oldGate })
	endpoint := brokerTestSocket(t)
	ran := false
	b := NewBroker(BrokerCallbacks{HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
		ran = true
		return BrokerCLIResponse{}, nil
	}})
	if e := b.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = b.Close() })
	conn, e := net.Dial("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	req := cliRunFixtureRequest()
	req.Scope.Nonce = reqID(73)
	body, _ := json.Marshal(req)
	_ = writeFrame(conn, []byte(`{"v":1,"mode":"cli-run"}`))
	_ = writeFrame(conn, body)
	reply, e := readFrame(conn, MaxOutput)
	if e != nil {
		t.Fatal(e)
	}
	if string(reply) != `{"v":1,"error":"refused"}` || ran {
		t.Fatalf("unsupported TTY wrote %s, callback ran=%v", reply, ran)
	}
}
