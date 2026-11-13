package desktop

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
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

func TestDesktopIPCBrokerUnlockLockAndCLIRun(t *testing.T) {
	path, key, secret, _ := desktopFixture(t)
	a := New()
	// This fixture runs its UI dispatcher synchronously on the test goroutine;
	// only broker I/O runs concurrently, as in the real serialized UI loop.
	a.launch = func(fn func()) { fn() }
	a.path = path
	a.secret = secret
	a.password = "fixture"
	var mu sync.Mutex
	approved := true
	a.cliApprover = func(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		return approved, nil
	}
	a.browserPairApprover = func(ctx context.Context, req browserhost.BrowserPairRequest) (browserhost.BrowserPairDecision, error) {
		if req.Peer.PID == 0 || req.Peer.User == "" {
			t.Errorf("browser pair request without OS peer: %#v", req)
		}
		return browserhost.BrowserPairDecision{Approved: true, QuickFill: true}, nil
	}
	defer a.stopBrowserBroker()

	// The endpoint is the platform's real broker socket: an absolute socket
	// path under the private /tmp on Unix, and a unique safe token driving the
	// per-user named pipe on Windows. Windows never applies the Unix temporary
	// root guard to a token, so it is always trusted and must exercise the real
	// named pipe; there is no skip or fallback there.
	endpoint := desktopBrokerSocket(t)
	if e := desktopBrokerTrusted(endpoint); e == nil {
		t.Setenv("LOCKLARK_BROWSER_SOCKET", endpoint)
		// On Unix the trusted endpoint is also the listening path. On Windows
		// it is only the safe token: DefaultBrokerEndpoint appends it to the
		// per-user pipe name, so the two differ by design. Both the broker and
		// the relay derive that name from the same env token, and the real
		// start/dial below proves they agree; do not compare them directly.
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
		client.send(t, map[string]any{"v": 1, "id": reqIDDesktop(2), "type": "hello"})
		paired := client.recvType(t, "paired")
		capability, _ := paired["capability"].(string)
		if !desktopCapabilityOK(capability) || paired["quick_fill"] != true {
			t.Fatalf("explicit pair: %#v", paired)
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
		// Lock revokes the existing browser consent, so re-unlock must not
		// revive the old connection's capability. The extension has to send a
		// fresh hello and pass native pairing review again.
		client.send(t, map[string]any{"v": 1, "id": reqIDDesktop(3), "type": "hello"})
		repaired := client.recvType(t, "paired")
		capability, _ = repaired["capability"].(string)
		if !desktopCapabilityOK(capability) || repaired["quick_fill"] != true {
			t.Fatalf("re-pair after unlock: %#v", repaired)
		}
		rows, e := a.session.List("active")
		if e != nil {
			t.Fatal(e)
		}
		// The production gate attests the peer's controlling terminal, so the
		// request declares this process's own terminal. A process without one
		// has no positive broker case to run: under the PTY smoke run that is a
		// failure, never a fallback or a skipped success.
		scope := desktopSelfTTYScope(t, desktopCLIScopeFixture())
		scope.TempRoot = t.TempDir()
		// Each live request carries its own single-use nonce: the broker
		// consumes it for this peer, so a replayed one is refused before the
		// terminal check and could never prove the positive path.
		vaultPath := a.session.VaultPath()
		liveReq := func() browserhost.BrokerCLIRequest {
			live := scope
			live.Nonce = desktopFreshNonce(t)
			req := browserhost.BrokerCLIRequest{V: 1, VaultPath: vaultPath, Scope: live, Targets: desktopCLITargetsFixture()}
			req.Targets[0].ID, req.Targets[0].Revision = rows[0].ID, rows[0].Revision
			return req
		}
		resp, e := browserhost.RequestCLIRun(context.Background(), liveReq())
		desktopAssertCLIPrepared(t, "socket", resp, e, desktopCLITargetsFixture())
		desktopReleaseCLIPrepared(resp)
		mu.Lock()
		approved = false
		mu.Unlock()
		refused, e := browserhost.RequestCLIRun(context.Background(), liveReq())
		if e != browserhost.ErrCLIRunRefused || desktopHasCLIPrepared(refused) {
			t.Fatalf("refused CLI: %v %#v", e, refused)
		}
		// The direct matrix owns its own unlocked session and runs while the
		// broker is still live.
		desktopCLIRunRefusalMatrix(t, a, path, key)
		// Locking stops the desktop broker listener and the session, so the
		// next request begins with no usable unlocked broker session: that is
		// the exact unavailable entry state, with a fresh nonce, and it never
		// discloses a value.
		a.Lock()
		locked, e := browserhost.RequestCLIRun(context.Background(), liveReq())
		if e != browserhost.ErrBrokerUnavailable || desktopHasCLIPrepared(locked) {
			t.Fatalf("starting-locked entry CLI: %v %#v", e, locked)
		}
		return
	}

	// This environment lacks a trusted temporary ancestor (for example /home is
	// owned by another UID). Exercise the same approval/disclosure path directly.
	t.Log("trusted temporary directory unavailable; exercising CLI approval without the socket relay")
	desktopCLIRunRefusalMatrix(t, a, path, key)
}

// desktopCLIRunRefusalMatrix exercises the direct handler path on the app's
// own unlocked session: one approved disclosure, then the refusal states, each
// on a fresh request. A denial is the fixed refusal; a session that is locked
// synchronously inside the approver callback, after the handler captured its
// exact session and epoch, is also the fixed refusal with no prepared bytes.
// No test here simulates a lock with idle timers or sleeps.
func desktopCLIRunRefusalMatrix(t *testing.T, a *App, path string, key []byte) {
	t.Helper()
	s, e := personal.UnlockSession(path, []byte("fixture"), key, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	a.brokerMu.Lock()
	a.session = s
	a.brokerSession = s
	a.brokerMu.Unlock()
	// The handler zeroes the caller's target elements in place, so every call
	// builds a fresh request.
	directReq := func() browserhost.BrokerCLIRequest {
		scope := desktopCLIScopeFixture()
		scope.TempRoot = t.TempDir()
		req := browserhost.BrokerCLIRequest{V: 1, VaultPath: s.VaultPath(), Scope: scope, Targets: desktopCLITargetsFixture()}
		req.Targets[0].ID, req.Targets[0].Revision = rows[0].ID, rows[0].Revision
		return req
	}
	previous := a.cliApprover
	t.Cleanup(func() { a.cliApprover = previous })
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return true, nil }
	resp, e := a.handleCLIRunUnit(context.Background(), browserhost.Peer{User: "fixture"}, directReq())
	desktopAssertCLIPrepared(t, "direct", resp, e, desktopCLITargetsFixture())
	desktopReleaseCLIPrepared(resp)
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) { return false, nil }
	if refused, e := a.handleCLIRunUnit(context.Background(), browserhost.Peer{User: "fixture"}, directReq()); e != errCLIRunRefused || desktopHasCLIPrepared(refused) {
		t.Fatalf("direct denied CLI: %v %#v", e, refused)
	}
	// The pending-lock case keeps the original request and captured session:
	// the approver locks that exact session synchronously, so the recheck after
	// approval must refuse rather than disclose.
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		a.Lock()
		return true, nil
	}
	if refused, e := a.handleCLIRunUnit(context.Background(), browserhost.Peer{User: "fixture"}, directReq()); e != errCLIRunRefused || desktopHasCLIPrepared(refused) {
		t.Fatalf("direct pending-lock CLI: %v %#v", e, refused)
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

// desktopVaultPassword reads the expected target value straight from the
// unlocked fixture session. The audited handler must never take this path, so
// only tests use it, to know the exact bytes preparation should disclose. The
// legacy string map is blanked before returning; Go strings cannot be wiped, so
// the caller's copy of want is the only one left to clear.
func desktopVaultPassword(t *testing.T, s *personal.Session, targets []personal.CLIBrokerTarget) string {
	t.Helper()
	values, e := s.ExtractCLIBrokerTargets(targets)
	defer clearDesktopCLILegacyValues(values)
	if e != nil {
		t.Fatal("fixture vault read:", e)
	}
	return values[targets[0].Slot]
}

// desktopAssertCLIPrepared asserts one successful broker reply: the audited V=1
// pair of the exact prepared bytes, one non-nil buffer per requested slot, and
// the canonical RunBundlePreparationReceipt, with no legacy Values payload. It
// copies the buffers into a temporary comparison (cleared before returning) so
// the caller keeps ownership of the returned map.
func desktopAssertCLIPrepared(t *testing.T, label string, resp browserhost.BrokerCLIResponse, err error, targets []personal.CLIBrokerTarget) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: approved CLI failed: %v", label, err)
	}
	if resp.V != 1 || len(resp.Values) != 0 || resp.Error != "" {
		t.Fatalf("%s: reply is not the audited V=1 pair: %#v", label, resp)
	}
	if len(resp.PreparedValues) != len(targets) {
		t.Fatalf("%s: %d prepared slots for %d targets", label, len(resp.PreparedValues), len(targets))
	}
	for _, target := range targets {
		value, ok := resp.PreparedValues[target.Slot]
		if !ok || value == nil || len(value) == 0 {
			t.Fatalf("%s: prepared slot %q missing or empty", label, target.Slot)
		}
	}
	receipt := resp.Receipt
	if receipt.Status != personal.RunBundlePreparationStatus ||
		!desktopLowerHex(receipt.Session, 32) || !desktopLowerHex(receipt.Intent, 64) || !desktopLowerHex(receipt.TargetDigest, 64) {
		t.Fatalf("%s: receipt is not a canonical preparation receipt: %+v", label, receipt)
	}
}

// desktopAssertCLIPreparedBytes asserts the prepared slot holds exactly want.
func desktopAssertCLIPreparedBytes(t *testing.T, label string, resp browserhost.BrokerCLIResponse, slot string, want string) {
	t.Helper()
	value := resp.PreparedValues[slot]
	if len(value) == 0 || !bytes.Equal(value, []byte(want)) {
		t.Fatalf("%s: prepared slot %q is not the exact vault bytes (got %d bytes, zeroed=%v)", label, slot, len(value), desktopAllZero(value))
	}
}

// desktopAllZero reports whether every byte of value is zero.
func desktopAllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// desktopHasCLIPrepared reports whether a reply still carries any value buffer.
func desktopHasCLIPrepared(resp browserhost.BrokerCLIResponse) bool {
	return len(resp.PreparedValues) != 0 || len(resp.Values) != 0
}

// desktopReleaseCLIPrepared zeroes the test-owned buffers of a reply and drops
// the map, mirroring the broker callback's cleanup after encoding.
func desktopReleaseCLIPrepared(resp browserhost.BrokerCLIResponse) {
	clearDesktopCLIPrepared(resp.PreparedValues)
}

// desktopAssertCallerTargetsCleared asserts what a caller can observe after a
// direct handleCLIRun call. What is observable is the shared backing memory the handler zeroes in place:
// every target element of the caller's slice. The scope's own element blanking
// happens in the handler's restored copy, so the caller's view of Args, Helper
// and Passthru headers and elements is unchanged; no test claims otherwise. A
// refusal is proven by the returned reply (no prepared bytes, no receipt).
// Production's handleCLIRunConn additionally clears its own callback-owned
// copy of the scope and targets after the callback returns.
func desktopAssertCallerTargetsCleared(t *testing.T, label string, req browserhost.BrokerCLIRequest) {
	t.Helper()
	for i, target := range req.Targets {
		if target != (personal.CLIBrokerTarget{}) {
			t.Fatalf("%s: caller target %d survived the call: %+v", label, i, target)
		}
	}
}

// desktopFreshNonce returns a fresh 32-byte crypto-random lowercase hex nonce
// for one live broker request. The broker consumes a nonce at most once per
// authenticated peer for the whole process, so every live request in a test
// must carry its own. Summary-only fixtures keep their static nonce because
// they never reach the broker.
func desktopFreshNonce(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		t.Fatal("nonce:", e)
	}
	return hex.EncodeToString(raw[:])
}
