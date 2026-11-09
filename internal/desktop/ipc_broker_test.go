package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/localpath"
	"github.com/jihuayu/locklark/internal/personal"
)

func desktopFrame(raw []byte) []byte {
	out := binary.NativeEndian.AppendUint32(nil, uint32(len(raw)))
	return append(out, raw...)
}

func desktopReadFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.NativeEndian.Uint32(h[:])
	if n == 0 || n > browserhost.MaxOutput {
		return nil, errors.New("bad frame")
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return nil, e
	}
	return raw, nil
}

type desktopRelay struct {
	in  *io.PipeWriter
	out *io.PipeReader
}

func (c *desktopRelay) send(t *testing.T, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := c.in.Write(desktopFrame(raw)); e != nil {
		t.Fatal(e)
	}
}

func (c *desktopRelay) recv(t *testing.T) map[string]any {
	t.Helper()
	raw, e := desktopReadFrame(c.out)
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("decode")
	}
	return out
}

func (c *desktopRelay) recvType(t *testing.T, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := c.recv(t)
		if out["type"] == want {
			return out
		}
	}
	t.Fatalf("no %s", want)
	return nil
}

func desktopFixture(t *testing.T) (string, []byte, string, personal.Row) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "desktop.ll")
	key := bytes.Repeat([]byte{3}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.AddLogin("Desktop login", "desktop-user", "desktop-password"); e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	s.Lock()
	return path, key, personal.FormatSecret(key), rows[0]
}

type desktopCLIRunV2Outcome struct {
	result browserhost.CLIRunV2Result
	err    error
}

func TestDesktopIPCBrokerUnlockLockAndCLIRun(t *testing.T) {
	path, key, secret, row := desktopFixture(t)
	a := New()
	// This fixture runs its UI dispatcher synchronously on the test goroutine;
	// only broker I/O runs concurrently, as in the real serialized UI loop.
	a.launch = func(fn func()) { fn() }
	a.path = path
	a.secret = secret
	a.password = "fixture"
	var mu sync.Mutex
	approved := true
	hookCalls := 0
	a.cliApprover = func(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		hookCalls++
		return approved, nil
	}
	defer a.stopBrowserBroker()

	dir := t.TempDir()
	if _, e := localpath.TrustedTemporaryParent(dir); e == nil {
		t.Setenv("LOCKLARK_BROWSER_SOCKET", filepath.Join(dir, "b.sock"))
		// The relay dials once; start its listener before launching the client.
		a.startBrowserBroker()
		if a.broker == nil {
			t.Fatal("broker did not start")
		}
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		go func() {
			defer inR.Close()
			defer outW.Close()
			_ = browserhost.RelayStdio(browserhost.Chromium, []string{"chrome-extension://" + browserhost.ChromiumID + "/"}, inR, outW)
		}()
		defer inW.Close()
		defer outR.Close()
		client := &desktopRelay{in: inW, out: outR}
		client.send(t, map[string]any{"v": 1, "id": reqIDDesktop(1), "type": "status"})
		status := client.recvType(t, "status")
		if status["desktop_connected"] != true || status["unlocked"] != false || status["vault_locked"] != true {
			t.Fatalf("locked status: %#v", status)
		}
		a.password = "fixture"
		a.secret = secret
		a.unlock()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			a.brokerMu.Lock()
			ready := a.session != nil && a.broker != nil
			a.brokerMu.Unlock()
			if ready {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if a.session == nil {
			t.Fatal("desktop did not unlock")
		}
		unlocked := client.recvType(t, "unlocked")
		capability, _ := unlocked["capability"].(string)
		if !desktopCapabilityOK(capability) || unlocked["quick_fill"] != true {
			t.Fatalf("unlocked push: %#v", unlocked)
		}
		client.send(t, map[string]any{"v": 1, "id": reqIDDesktop(2), "type": "hello"})
		paired := client.recvType(t, "paired")
		if paired["capability"] != capability {
			t.Fatalf("pair: %#v", paired)
		}
		a.Lock()
		client.recvType(t, "locked")
		if a.session != nil {
			t.Fatal("desktop session survived lock")
		}
		a.password = "fixture"
		a.secret = secret
		a.unlock()
		deadline = time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && a.session == nil {
			time.Sleep(5 * time.Millisecond)
		}
		if a.session == nil {
			t.Fatal("desktop did not re-unlock")
		}
		client.recvType(t, "unlocked")
		rows, e := a.session.List("active")
		if e != nil {
			t.Fatal(e)
		}

		// The legacy per-field v1 cli-run product path is disabled: a v1
		// request is refused by the broker before any approval callback, even
		// when the historical test hook would approve it.
		mu.Lock()
		callsBefore := hookCalls
		mu.Unlock()
		legacyReq := browserhost.BrokerCLIRequest{V: 1, VaultPath: a.session.VaultPath(), Targets: []personal.CLIBrokerTarget{{Slot: "TOKEN", ID: rows[0].ID, Revision: rows[0].Revision, Field: "password"}}}
		if _, e := browserhost.RequestCLIRun(context.Background(), legacyReq); !errors.Is(e, browserhost.ErrBrokerRefused) {
			t.Fatalf("legacy v1 CLI run: %v", e)
		}
		mu.Lock()
		legacyHookCalls := hookCalls - callsBefore
		mu.Unlock()
		if legacyHookCalls != 0 {
			t.Fatal("legacy v1 hook decided a request the product refuses")
		}

		// The v2 path is the only product flow: one authenticated socket
		// exchange, one real native pending approval decided through the
		// product method, then the exact requested slot and canonical receipt.
		profile, ok := cliprofile.Lookup("deepseek")
		if !ok {
			t.Fatal("missing deepseek profile")
		}
		params := browserhost.CLIRunV2Params{
			VaultPath:      a.session.VaultPath(),
			Root:           filepath.Join(t.TempDir(), "client-root"),
			ProfileID:      "deepseek",
			Program:        "/usr/bin/env",
			Args:           []string{"deepseek", "run"},
			Directory:      t.TempDir(),
			TimeoutSeconds: 30,
			HelperPath:     []string{"/usr/bin"},
			Passthrough:    map[string]string{"DEEPSEEK_MODEL": "deepseek-chat", "NO_COLOR": "1"},
			Targets:        []browserhost.CLIRunV2Target{{Slot: "token", ID: rows[0].ID, Revision: rows[0].Revision, Field: "password"}},
		}
		v2ctx, v2cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer v2cancel()
		v2done := make(chan desktopCLIRunV2Outcome, 1)
		go func() {
			result, err := browserhost.RequestCLIRunV2(v2ctx, params)
			v2done <- desktopCLIRunV2Outcome{result: result, err: err}
		}()

		pending := waitCLIRunV2Pending(t, a)
		if pending.session != a.session {
			t.Fatal("v2 pending approval is not bound to the unlocked desktop session")
		}
		scope := pending.scope
		if scope.VaultPath != params.VaultPath || scope.Root != params.Root || scope.ProfileID != params.ProfileID || scope.SpecID != profile.Spec().ID {
			t.Fatalf("v2 pending scope identity: %#v", scope)
		}
		if !cliV2TestHex(scope.SpecDigest, 32) || !cliV2TestHex(scope.ScopeDigest, 32) {
			t.Fatalf("v2 pending scope digest: %#v", scope)
		}
		if scope.Request.Program != params.Program || scope.Request.Directory != params.Directory ||
			scope.Request.TimeoutSeconds != params.TimeoutSeconds || len(scope.Request.Args) != len(params.Args) ||
			scope.Request.Args[0] != params.Args[0] || scope.Request.Args[1] != params.Args[1] ||
			len(scope.Request.HelperPath) != 1 || scope.Request.HelperPath[0] != params.HelperPath[0] ||
			scope.Request.Passthrough["DEEPSEEK_MODEL"] != params.Passthrough["DEEPSEEK_MODEL"] ||
			scope.Request.Passthrough["NO_COLOR"] != params.Passthrough["NO_COLOR"] {
			t.Fatalf("v2 pending scope request: %#v", scope.Request)
		}
		if len(scope.Targets) != 1 || scope.Targets[0].Slot != params.Targets[0].Slot ||
			scope.Targets[0].ID != params.Targets[0].ID || scope.Targets[0].Revision != params.Targets[0].Revision ||
			scope.Targets[0].Field != params.Targets[0].Field {
			t.Fatalf("v2 pending scope targets: %#v", scope.Targets)
		}
		if scope.Peer.PID == 0 || scope.Peer.User == "" || scope.Peer.Process == "" {
			t.Fatalf("v2 pending scope has no authenticated OS peer: %#v", scope.Peer)
		}
		if runtime.GOOS == "linux" && scope.Peer.PID != uint32(os.Getpid()) {
			t.Fatalf("v2 peer PID = %d, want the real client PID %d", scope.Peer.PID, os.Getpid())
		}
		if pendingDecided(a, pending) {
			t.Fatal("v2 approval was decided without an owner action")
		}
		a.decideCLIRunV2(pending.id, true)

		var v2 desktopCLIRunV2Outcome
		select {
		case v2 = <-v2done:
		case <-time.After(20 * time.Second):
			t.Fatal("v2 CLI run did not return")
		}
		if v2.err != nil {
			t.Fatalf("approved v2 CLI: %v", v2.err)
		}
		if len(v2.result.Values) != 1 || string(v2.result.Values["token"]) != "desktop-password" {
			t.Fatalf("v2 values: %#v", v2.result.Values)
		}
		if !cliV2TestHex(v2.result.Receipt.Session, 16) || !cliV2TestHex(v2.result.Receipt.Intent, 32) ||
			!cliV2TestHex(v2.result.Receipt.TargetDigest, 32) || !cliV2TestHex(v2.result.ScopeDigest, 32) {
			t.Fatalf("v2 receipt: %#v", v2.result)
		}
		if v2.result.Epoch != scope.Epoch {
			t.Fatalf("v2 epoch = %d, want %d", v2.result.Epoch, scope.Epoch)
		}
		if currentCLIRunV2Pending(a) != nil {
			t.Fatal("v2 pending approval survived the owner decision")
		}

		// A lock that lands while a real v2 approval is pending refuses that
		// request, clears only the owned pending approval and still pushes
		// "locked" to the paired browser connection.
		lockCtx, lockCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer lockCancel()
		lockDone := make(chan desktopCLIRunV2Outcome, 1)
		go func() {
			result, err := browserhost.RequestCLIRunV2(lockCtx, params)
			lockDone <- desktopCLIRunV2Outcome{result: result, err: err}
		}()
		lockPending := waitCLIRunV2Pending(t, a)
		a.Lock()
		client.recvType(t, "locked")
		if lockPending.id == pending.id {
			t.Fatal("pending approval ids were reused")
		}
		if currentCLIRunV2Pending(a) != nil {
			t.Fatal("lock left a pending v2 approval")
		}
		select {
		case out := <-lockDone:
			if !errors.Is(out.err, browserhost.ErrBrokerRefused) || len(out.result.Values) != 0 {
				t.Fatalf("lock pending v2 CLI run: %v %#v", out.err, out.result.Values)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("lock pending v2 CLI run did not return")
		}
		return
	}

	// This environment lacks a trusted temporary ancestor (for example /home is
	// owned by another UID). Exercise the historical v1 approval/disclosure path
	// directly; the product no longer exports it to the broker.
	t.Log("trusted temporary directory unavailable; exercising CLI approval without the socket relay")
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	a.brokerMu.Lock()
	a.session = s
	a.brokerSession = s
	a.brokerMu.Unlock()
	req := browserhost.BrokerCLIRequest{V: 1, VaultPath: s.VaultPath(), Targets: []personal.CLIBrokerTarget{{Slot: "TOKEN", ID: row.ID, Revision: row.Revision, Field: "password"}}}
	resp, e := a.handleCLIRun(context.Background(), browserhost.Peer{User: "fixture"}, req)
	if e != nil || resp.Values["TOKEN"] != "desktop-password" {
		t.Fatalf("direct approved CLI: %v %#v", e, resp)
	}
	mu.Lock()
	approved = false
	mu.Unlock()
	if _, e := a.handleCLIRun(context.Background(), browserhost.Peer{User: "fixture"}, req); e == nil {
		t.Fatal("direct rejected CLI disclosed a value")
	}
	a.brokerMu.Lock()
	a.session = nil
	a.brokerSession = nil
	a.brokerMu.Unlock()
	if _, e := a.handleCLIRun(context.Background(), browserhost.Peer{User: "fixture"}, req); !errors.Is(e, browserhost.ErrBrokerUnavailable) {
		t.Fatalf("direct locked CLI: %v", e)
	}
}

func desktopCapabilityOK(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}

func reqIDDesktop(n int) string {
	var out [32]byte
	for i := range out {
		out[i] = '0'
	}
	hex := "0123456789abcdef"
	for i := 31; n > 0; i-- {
		out[i] = hex[n%16]
		n /= 16
	}
	return string(out[:])
}
