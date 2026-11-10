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
	"strconv"
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
