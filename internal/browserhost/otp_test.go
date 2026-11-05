package browserhost

import (
	"fmt"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func pendingOTPFixture(t *testing.T) (*Connection, *personal.Session, *memoryPipe, Request) {
	return pendingOTPFixtureDigits(t, 6)
}
func pendingOTPFixtureDigits(t *testing.T, digits int) (*Connection, *personal.Session, *memoryPipe, Request) {
	t.Helper()
	c, s, out, r := paired(t)
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	period := int64(3600)
	for time.Now().Unix()%period > period-15 {
		period--
	}
	_, err = s.Edit(personal.Edit{ID: rows[0].ID, Revision: rows[0].Revision, Field: "otp", Value: fmt.Sprintf("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d&digits=%d", period, digits)})
	if err != nil {
		t.Fatal(err)
	}
	r.Revision = ""
	if c.Handle(r) != nil {
		t.Fatal("match")
	}
	all := out.responses(t)
	rows = all[len(all)-1].Candidates
	if len(rows) != 1 {
		t.Fatal("candidate")
	}
	r.ID, r.Type, r.WindowID, r.ItemID, r.Revision = reqID(20), "otp", 1, rows[0].ID, rows[0].Revision
	if c.Handle(r) != nil {
		t.Fatal("OTP pending")
	}
	t.Cleanup(c.Close)
	return c, s, out, r
}

func TestOTPSlotDoesNotWaitForConnectionLock(t *testing.T) {
	out := &memoryPipe{}
	w := NewWriter(out, time.Second)
	c := NewConnection(w, nil)
	p := &pendingOTP{}
	c.otp = p
	release, err := w.acquire(time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, finished := make(chan struct{}), make(chan struct{})
	go func() {
		c.mu.Lock()
		close(entered)
		_, _ = c.saveMessage(Request{ID: reqID(31), Type: "save-new"})
		c.mu.Unlock()
		close(finished)
	}()
	<-entered
	grant := make(chan struct{})
	go func() { _, _ = c.grantOTP(p, nil); close(grant) }()
	select {
	case <-grant:
		release()
	case <-time.After(100 * time.Millisecond):
		release()
		<-finished
		<-grant
		t.Fatal("OTP slot waited for a connection lock held by another writer")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("legacy writer remained blocked")
	}
	all := out.responses(t)
	if len(all) != 1 || all[0].ID != reqID(31) || all[0].Type != "error" || p.ackClaimed || w.failed.Load() {
		t.Fatal("save refusal and OTP rejection did not complete independently")
	}
}

func TestOTPNoResponseUntilNativeApproval(t *testing.T) {
	_, _, out, r := pendingOTPFixture(t)
	for _, response := range out.responses(t) {
		if response.ID == r.ID {
			t.Fatal("OTP did not wait for explicit native approval")
		}
	}
}

func TestOTPChallengeAckDedicatedCodeAndRetiredCancel(t *testing.T) {
	c, s, out, r := pendingOTPFixture(t)
	if err := c.ApproveOTP(r.ID); err != nil {
		t.Fatal(err)
	}
	all := out.responses(t)
	ready := all[len(all)-1]
	if ready.ID != r.ID || ready.Type != "otp-ready" || !revision.MatchString(ready.Nonce) || ready.Code != "" {
		t.Fatal("invalid challenge")
	}
	ack := Request{V: 1, ID: reqID(21), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: ready.Nonce}
	if err := c.Handle(ack); err != nil {
		t.Fatal(err)
	}
	response := awaitTerminal(t, out, ack.ID)
	if response.Type != "otp-fill" || len(response.Code) != 6 || response.Username != "" || response.Password != "" || len(response.Candidates) != 0 {
		t.Fatal("OTP did not use its dedicated value response")
	}
	if c.Handle(Request{V: 1, ID: reqID(22), Type: "cancel-otp", Capability: r.Capability, RequestID: r.ID}) != nil {
		t.Fatal("retired cancel")
	}
	if awaitTerminal(t, out, reqID(22)).Type != "unknown" {
		t.Fatal("grant-won cancellation was definite")
	}
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.browser.fill.otp-code" && event.Result == "intent" {
			found = true
		}
	}
	if !found {
		t.Fatal("dedicated OTP audit missing")
	}
}

func TestOTPEightDigitDedicatedWriter(t *testing.T) {
	c, _, out, r := pendingOTPFixtureDigits(t, 8)
	if c.ApproveOTP(r.ID) != nil {
		t.Fatal("challenge")
	}
	all := out.responses(t)
	nonce := all[len(all)-1].Nonce
	ack := Request{V: 1, ID: reqID(21), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: nonce}
	if c.Handle(ack) != nil {
		t.Fatal("ack")
	}
	response := awaitTerminal(t, out, ack.ID)
	if response.Type != "otp-fill" || len(response.Code) != 8 {
		t.Fatal("eight-digit code was not delivered")
	}
}
