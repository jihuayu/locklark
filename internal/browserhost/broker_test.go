//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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
			values, e := s.ExtractCLIBrokerTargets(req.Targets)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			return BrokerCLIResponse{V: 1, Values: values}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	req := cliRunFixtureRequest()
	req.VaultPath = "placeholder"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := RequestCLIRun(ctx, req); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("locked broker: %v", e)
	}

	s, row := brokerTestSession(t)
	mu.Lock()
	session = s
	mu.Unlock()
	req.VaultPath = s.VaultPath()
	req.Targets = []personal.CLIBrokerTarget{{Slot: "LOGIN_PASSWORD", ID: row.ID, Revision: row.Revision, Field: "password"}}
	resp, e := RequestCLIRun(ctx, req)
	if e != nil || resp.Values["LOGIN_PASSWORD"] != "broker-password" {
		t.Fatalf("approved CLI run: %v %#v", e, resp)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.desktop.show.password" && event.Item == row.ID && event.Result == "intent" {
			found = true
		}
	}
	if !found {
		t.Fatal("CLI disclosed values without a committed audit event")
	}

	mu.Lock()
	approved = false
	mu.Unlock()
	if _, e := RequestCLIRun(ctx, req); !errors.Is(e, ErrCLIRunRefused) || errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("rejected CLI run must be an explicit, non-fallback refusal: %v", e)
	}
	mu.Lock()
	approved = true
	mu.Unlock()
	bad := req
	bad.Targets = []personal.CLIBrokerTarget{{Slot: "LOGIN_PASSWORD", ID: row.ID, Revision: reqID(9) + reqID(10), Field: "password"}}
	if _, e := RequestCLIRun(ctx, bad); e == nil {
		t.Fatal("stale revision disclosed values")
	}

	if e := broker.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := RequestCLIRun(ctx, req); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("stopped broker: %v", e)
	}
}

// cliRunFixtureRequest is a valid CLI-run request for outcome classification.
func cliRunFixtureRequest() CLIRunBrokerRequest {
	return CLIRunBrokerRequest{
		V:         1,
		VaultPath: "/fixture/vault.ll",
		Targets:   []personal.CLIBrokerTarget{{Slot: "LOGIN_PASSWORD", ID: reqID(1), Revision: reqID(2), Field: "password"}},
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
	req.Targets[0].ID = "leak-target-" + reqID(3)
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
	cases := []CLIRunBrokerRequest{
		{V: 2, VaultPath: "/fixture/vault.ll", Targets: cliRunFixtureRequest().Targets},
		{V: 1, Targets: cliRunFixtureRequest().Targets},
		{V: 1, VaultPath: "/fixture/vault.ll"},
		{V: 1, VaultPath: "/fixture/vault.ll", Targets: make([]personal.CLIBrokerTarget, 17)},
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

func TestPeerProcessAllowedUsesExactHostNamesAndInstallLocation(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, []byte("fixture"), 0700); e != nil {
			t.Fatal(e)
		}
		return path
	}
	self := write("locklark-desktop")
	host := write("locklark-browser-chromium")
	evilPrefix := write("locklark-browser-chromium-evil")
	shortPrefix := write("locklark-browser")
	otherDir := filepath.Join(dir, "other")
	if e := os.Mkdir(otherDir, 0700); e != nil {
		t.Fatal(e)
	}
	otherHost := filepath.Join(otherDir, "locklark-browser-chromium")
	if e := os.WriteFile(otherHost, []byte("fixture"), 0700); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name string
		path string
		goos string
		want bool
	}{
		{"exact executable", self, "linux", true},
		{"installed host beside desktop", host, "linux", true},
		{"longer prefix", evilPrefix, "linux", false},
		{"short prefix", shortPrefix, "linux", false},
		{"same basename in another directory", otherHost, "linux", false},
		{"bare basename", "locklark-browser-chromium", "linux", false},
		{"arbitrary executable", "/tmp/evil", "linux", false},
	}
	for _, tc := range cases {
		peer := Peer{User: "UID 501", PID: 2, Process: tc.path}
		if got := peerProcessAllowedFor(peer, self, tc.goos); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}

	apps := filepath.Join(dir, "Applications")
	desktop := filepath.Join(apps, "Locklark.app", "Contents", "MacOS", "locklark-desktop")
	safari := filepath.Join(apps, "Locklark Safari.app", "Contents", "MacOS", "locklark-browser-safari")
	for _, path := range []string{desktop, safari} {
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte("fixture"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if !peerProcessAllowedFor(Peer{User: "UID 501", PID: 3, Process: safari}, desktop, "darwin") {
		t.Fatal("sibling Safari helper rejected")
	}
	if peerProcessAllowedFor(Peer{User: "UID 501", PID: 3, Process: safari}, desktop, "linux") {
		t.Fatal("Safari sibling location accepted off macOS")
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
	// Success: the decoded map[string]string reaches the caller intact and is
	// the exact value the reply carried.
	sent := cliRunScriptedServer(t, cliRunReplyPayload(`{"v":1,"values":{"slot-7":"pw-exact"}}`))
	resp, e := RequestCLIRun(context.Background(), cliRunFixtureRequest())
	if e != nil {
		t.Fatal(e)
	}
	if len(resp.Values) != 1 || resp.Values["slot-7"] != "pw-exact" {
		t.Fatalf("values altered: %q", resp.Values)
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
