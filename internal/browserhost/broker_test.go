//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	broker.NotifyUnlocked(s, 1, true)
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
	broker.NotifyUnlocked(s2, 2, true)
	unlocked := client.recvType(t, "unlocked")
	capability, _ = unlocked["capability"].(string)
	if !token.MatchString(capability) {
		t.Fatalf("re-unlock capability: %#v", unlocked)
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

	req := CLIRunBrokerRequest{V: 1, VaultPath: "placeholder"}
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
	if _, e := RequestCLIRun(ctx, req); e == nil {
		t.Fatal("rejected CLI run disclosed values")
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

func TestPeerProcessAllowedRejectsArbitrarySameUIDProcess(t *testing.T) {
	if peerProcessAllowed(Peer{User: "UID 501", PID: 1, Process: "/tmp/evil"}) {
		t.Fatal("arbitrary process accepted as a browser host")
	}
	if !peerProcessAllowed(Peer{User: "UID 501", PID: 2, Process: "/opt/locklark-browser-chromium"}) {
		t.Fatal("browser host rejected")
	}
}
