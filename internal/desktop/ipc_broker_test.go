package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
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

func TestDesktopIPCBrokerUnlockLockAndCLIRun(t *testing.T) {
	path, key, secret, row := desktopFixture(t)
	a := New()
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
	defer a.stopBrowserBroker()

	dir := t.TempDir()
	if _, e := localpath.TrustedTemporaryParent(dir); e == nil {
		t.Setenv("LOCKLARK_BROWSER_SOCKET", filepath.Join(dir, "b.sock"))
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		go func() {
			_ = browserhost.RelayStdio(browserhost.Chromium, []string{"chrome-extension://" + browserhost.ChromiumID + "/"}, inR, outW)
		}()
		defer inW.Close()
		defer outR.Close()
		client := &desktopRelay{in: inW, out: outR}
		a.startBrowserBroker()
		if a.broker == nil {
			t.Fatal("broker did not start")
		}
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
		cliReq := browserhost.BrokerCLIRequest{V: 1, VaultPath: a.session.VaultPath(), Targets: []personal.CLIBrokerTarget{{Slot: "TOKEN", ID: rows[0].ID, Revision: rows[0].Revision, Field: "password"}}}
		resp, e := browserhost.RequestCLIRun(context.Background(), cliReq)
		if e != nil || resp.Values["TOKEN"] != "desktop-password" {
			t.Fatalf("approved CLI: %v %#v", e, resp)
		}
		mu.Lock()
		approved = false
		mu.Unlock()
		if _, e := browserhost.RequestCLIRun(context.Background(), cliReq); e == nil {
			t.Fatal("rejected CLI disclosed a value")
		}
		a.Lock()
		if _, e := browserhost.RequestCLIRun(context.Background(), cliReq); !errors.Is(e, browserhost.ErrBrokerUnavailable) {
			t.Fatalf("locked CLI: %v", e)
		}
		return
	}

	// This environment lacks a trusted temporary ancestor (for example /home is
	// owned by another UID). Exercise the same approval/disclosure path directly.
	t.Log("trusted temporary directory unavailable; exercising CLI approval without the socket relay")
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	a.brokerMu.Lock()
	a.session = s
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
