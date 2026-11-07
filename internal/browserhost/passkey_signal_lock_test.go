package browserhost

import (
	"strings"
	"testing"
	"time"
)

// RejectPasskeySignal must revoke authorization without waiting for the
// connection mutex. A read-only passkey list can hold c.mu while it waits for
// Session.mu during a blocked owner confirmation, so the owner's cancel click
// has to return and clear the cancellation flag before that mutex is released.
func TestPasskeySignalRejectReturnsWhileConnectionMutexHeld(t *testing.T) {
	c, out, s, capability, itemID, credential, _ := signalConnectionFixture(t)
	defer c.Close()
	epoch := s.PasskeyRevocationEpoch()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(400), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	if view := waitSignal(t, c); view.ID != reqID(400) {
		t.Fatalf("review: %#v", view)
	}

	c.mu.Lock()
	held := true
	unlock := func() {
		if held {
			held = false
			c.mu.Unlock()
		}
	}
	defer unlock()
	p := c.signal
	if p == nil || p.id != reqID(400) {
		unlock()
		t.Fatal("pending signal vanished before the lock test")
	}
	done := make(chan error, 1)
	go func() { done <- c.RejectPasskeySignal(reqID(400)) }()
	select {
	case err := <-done:
		if err != nil {
			unlock()
			t.Fatalf("reject while c.mu held: %v", err)
		}
	case <-time.After(2 * time.Second):
		unlock()
		t.Fatal("RejectPasskeySignal waited for the connection mutex")
	}
	if !p.cancelled.Load() {
		unlock()
		t.Fatal("reject did not revoke authorization before the connection mutex was released")
	}
	if gate := p.gate.Load(); gate != nil {
		unlock()
		t.Fatal("idle reject retained a mutation gate")
	}
	unlock()

	// Once the mutex is available the cancelled idle proposal must disappear.
	var reaped View
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		reaped = c.Snapshot()
		if reaped.Signal == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if reaped.Signal != nil {
		t.Fatalf("cancelled idle signal was not reaped: %#v", reaped.Signal)
	}
	if !strings.Contains(reaped.SignalStatus, "已忽略") {
		t.Fatalf("cancelled idle status: %q", reaped.SignalStatus)
	}
	if err := c.ApprovePasskeySignal(reqID(400)); err == nil {
		t.Fatal("revoked signal was approved after cancellation")
	}
	if s.PasskeyRevocationEpoch() != epoch {
		t.Fatal("rejected signal advanced the revocation epoch")
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("reject wrote a page frame: %d", len(frames)-before)
	}
	_ = itemID
}

// A stale native request id must not revoke the newer signal that currently
// owns the authorization surface.
func TestPasskeySignalStaleIDCannotCancelNewSignal(t *testing.T) {
	c, out, s, capability, itemID, credential, _ := signalConnectionFixture(t)
	defer c.Close()
	epoch := s.PasskeyRevocationEpoch()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(410), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c)
	c.mu.Lock()
	p := c.signal
	c.mu.Unlock()
	if p == nil || p.id != reqID(410) {
		t.Fatal("pending signal missing before stale reject")
	}
	if err := c.RejectPasskeySignal(reqID(411)); err == nil {
		t.Fatal("stale request id revoked a newer signal")
	}
	if p.cancelled.Load() {
		t.Fatal("stale request id set the cancellation flag")
	}
	if gate := p.gate.Load(); gate != nil {
		t.Fatal("stale request id touched a mutation gate")
	}
	view := c.Snapshot()
	if view.Signal == nil || view.Signal.ID != reqID(410) {
		t.Fatalf("new signal vanished after stale reject: %#v", view.Signal)
	}
	// The exact signal is still fully confirmable, so the stale reject changed
	// no authorization state and no session slot ownership.
	if err := c.ApprovePasskeySignal(reqID(410)); err != nil {
		t.Fatalf("stale reject prevented the real approval: %v", err)
	}
	metadata, err := s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadata[itemID]; ok {
		t.Fatal("approved removal did not remove the credential")
	}
	if s.PasskeyRevocationEpoch() != epoch+1 {
		t.Fatal("approved removal did not advance the revocation epoch")
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("stale reject/approval wrote extra frames: %d", len(frames)-before)
	}
}

// The interleaving that motivated the fix: the owner confirmation holds
// Session.mu while its database writer is blocked, and an unrelated read-only
// passkey list holds c.mu. RejectPasskeySignal must still return and cancel the
// already published gate before c.mu is released; resuming the blocked Apply
// must then persist nothing at all.
func TestPasskeySignalRejectWhileConnectionMutexHeldCancelsBlockedCommit(t *testing.T) {
	c, out, _, capability, itemID, credential, path := signalConnectionFixture(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(420), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	if view := waitSignal(t, c); len(view.Changes) != 1 || view.Changes[0].Action != "remove" {
		t.Fatalf("review: %#v", view)
	}
	release := blockVaultWrites(t, path)
	released := false
	releaseDB := func() {
		if !released {
			released = true
			release()
		}
	}
	defer releaseDB()
	done := make(chan error, 1)
	go func() { done <- c.ApprovePasskeySignal(reqID(420)) }()
	waitApplyBlocked(t)

	c.mu.Lock()
	held := true
	unlock := func() {
		if held {
			held = false
			c.mu.Unlock()
		}
	}
	defer unlock()
	p := c.signal
	if p == nil || p.id != reqID(420) {
		unlock()
		t.Fatal("blocked approval lost its signal")
	}
	gate := p.gate.Load()
	if gate == nil {
		unlock()
		t.Fatal("blocked approval published no gate")
	}
	rejected := make(chan error, 1)
	go func() { rejected <- c.RejectPasskeySignal(reqID(420)) }()
	select {
	case err := <-rejected:
		if err != nil {
			unlock()
			t.Fatalf("reject while c.mu held during a blocked commit: %v", err)
		}
	case <-time.After(2 * time.Second):
		unlock()
		t.Fatal("RejectPasskeySignal waited for the connection mutex while a commit was blocked")
	}
	// Both checks happen before the connection mutex is released: the gate is
	// already cancelled and the authorization flag is already set.
	if !p.cancelled.Load() || gate.Pending() {
		unlock()
		t.Fatal("reject did not cancel the published gate before the connection mutex was released")
	}
	unlock()
	releaseDB()
	if err := <-done; err == nil {
		t.Fatal("cancelled commit reported success")
	}
	view := c.Snapshot()
	if view.Signal != nil || !strings.Contains(view.SignalStatus, "未应用") {
		t.Fatalf("owner status after cancelled blocked commit: %#v %q", view.Signal, view.SignalStatus)
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("cancelled blocked commit wrote a page frame: %d", len(frames)-before)
	}
	assertSignalWroteNothing(t, path, itemID)
}
