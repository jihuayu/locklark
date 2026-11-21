//go:build darwin

package desktop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

// TestDarwinBrowserSaveRevisionPinsBrokerPreparation joins one synthetic owned
// item across the real browser save API and the real local broker: approve and
// read R0, update that same item to R1 through Session.SaveBrowser, refuse the
// now-stale R0 target without any prepared value, then approve current R1 and
// disclose only the new value.
//
// The approval callback is the test-only explicit decision seam and is counted
// per approved request. This test makes no claim about the visual approval UI,
// child processes, or network activity; its scope is product broker
// preparation over a private local socket.
func TestDarwinBrowserSaveRevisionPinsBrokerPreparation(t *testing.T) {
	const origin = "https://example.test"
	wantR0 := []byte("synthetic-owned-r0-value")
	wantR1 := []byte("synthetic-owned-r1-value")
	defer clear(wantR0)
	defer clear(wantR1)

	a, req := desktopCLIRunFixture(t)
	defer clearDesktopCLITargets(req.Targets)
	// Keep every credential-store access in this synthetic fixture in memory.
	store := newFakeDeviceSecretStore()
	a.deviceSecrets = store
	defer func() {
		for key, value := range store.values {
			clear(value)
			delete(store.values, key)
		}
	}()
	// The fixture replaces the asynchronous worker launcher with inline
	// dispatch: launched work runs on the calling broker goroutine, not on the
	// test goroutine or the actual UI event loop. Broker I/O remains concurrent.
	a.launch = func(fn func()) { fn() }
	defer a.stopBrowserBroker()

	rows, err := a.session.List("active")
	if err != nil || len(rows) != 1 {
		t.Fatal("synthetic fixture is not one active item")
	}
	itemID := rows[0].ID
	// The browser update path binds the exact item ID, current revision and
	// origin, so prepare that same item with both before the first read.
	rev, err := a.session.Edit(personal.Edit{ID: itemID, Revision: rows[0].Revision, Field: "url", Value: origin})
	if err != nil {
		t.Fatal("synthetic item origin edit failed")
	}
	r0, err := a.session.Edit(personal.Edit{ID: itemID, Revision: rev, Field: "password", Value: string(wantR0)})
	if err != nil {
		t.Fatal("synthetic item R0 password edit failed")
	}
	req.Targets[0].ID = itemID
	req.Targets[0].Revision = r0
	req.Scope = desktopSelfTTYScope(t, req.Scope)

	var mu sync.Mutex
	approvals := 0
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		mu.Lock()
		approvals++
		mu.Unlock()
		// Every request here receives an explicit approve decision. The product
		// still decides whether the approved target is current.
		return true, nil
	}
	approved := func() int {
		mu.Lock()
		defer mu.Unlock()
		return approvals
	}

	if _, ok := desktopStartBrokerEndpoint(t, a, a.browserBrokerCallbacks()); !ok {
		desktopSkipOrFailWithoutTTY(t, "trusted temporary directory unavailable")
	}

	// 1. The real socket client approves and reads the synthetic R0 value.
	req.Scope.Nonce = desktopFreshNonce(t)
	r0Resp, err := browserhost.RequestCLIRun(context.Background(), req)
	// Register cleanup now so a failed assertion below cannot leave the
	// returned buffers live through Goexit; the successful R0 reply is cleared
	// before progressing to the write and later requests.
	defer desktopReleaseCLIPrepared(r0Resp)
	desktopAssertCLIPrepared(t, "R0 broker preparation", r0Resp, err, req.Targets)
	desktopAssertCLIPreparedBytes(t, "R0 broker preparation", r0Resp, "token", string(wantR0))
	if got := approved(); got != 1 {
		t.Fatalf("approved test-only decisions after R0 = %d, want 1", got)
	}
	desktopReleaseCLIPrepared(r0Resp)

	// 2. A legitimate same-item browser save commits R0 -> R1.
	target := personal.BrowserSaveTarget{
		Context: personal.BrowserSaveContext{
			BrowserContext: personal.BrowserContext{
				RequestID:  "11111111111111111111111111111111",
				Origin:     origin,
				TabID:      1,
				DocumentID: "doc-1",
			},
			WindowID: 1,
		},
		ID:       itemID,
		Revision: r0,
	}
	gate := personal.NewBrowserSaveGate(time.Now().Add(time.Minute))
	if err := a.session.RegisterBrowserSave(gate); err != nil {
		t.Fatal("browser save gate was not registered")
	}
	saved, err := a.session.SaveBrowser(target, []byte("synthetic-owned-user"), append([]byte(nil), wantR1...), gate)
	if err != nil {
		t.Fatal("same-item browser save update was refused")
	}
	if saved.ID != itemID || saved.Revision == r0 || !desktopLowerHex(saved.Revision, 64) {
		t.Fatal("browser save did not commit a new revision for the same item")
	}
	rows, err = a.session.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != itemID || rows[0].Revision != saved.Revision {
		t.Fatal("saved revision is not the committed revision of the same item")
	}

	// 3. The approved stale R0 target is refused by preparation, not disclosed.
	stale := req
	stale.Scope = req.Scope.Clone()
	stale.Scope.Nonce = desktopFreshNonce(t)
	stale.Targets = append([]personal.CLIBrokerTarget(nil), req.Targets...)
	defer clearDesktopCLITargets(stale.Targets)
	stale.Targets[0].ID, stale.Targets[0].Revision = itemID, r0
	staleResp, err := browserhost.RequestCLIRun(context.Background(), stale)
	// The refused reply must carry no prepared values, but release whatever
	// arrived before asserting so an unexpected buffer is cleared on failure.
	defer desktopReleaseCLIPrepared(staleResp)
	if !errors.Is(err, browserhost.ErrCLIRunRefused) || desktopHasCLIPrepared(staleResp) {
		t.Fatalf("stale R0 target was not the fixed denial without prepared values (refused=%v, prepared=%v)",
			errors.Is(err, browserhost.ErrCLIRunRefused), desktopHasCLIPrepared(staleResp))
	}
	if got := approved(); got != 2 {
		t.Fatalf("approved test-only decisions after stale R0 = %d, want 2", got)
	}

	// 4. Only the explicitly approved current R1 discloses its new value.
	current := req
	current.Scope = req.Scope.Clone()
	current.Scope.Nonce = desktopFreshNonce(t)
	current.Targets = append([]personal.CLIBrokerTarget(nil), req.Targets...)
	defer clearDesktopCLITargets(current.Targets)
	current.Targets[0].ID, current.Targets[0].Revision = itemID, saved.Revision
	currentResp, err := browserhost.RequestCLIRun(context.Background(), current)
	defer desktopReleaseCLIPrepared(currentResp)
	desktopAssertCLIPrepared(t, "R1 broker preparation", currentResp, err, current.Targets)
	desktopAssertCLIPreparedBytes(t, "R1 broker preparation", currentResp, "token", string(wantR1))
	if got := approved(); got != 3 {
		t.Fatalf("approved test-only decisions after R1 = %d, want 3", got)
	}
}
