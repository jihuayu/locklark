package browserhost

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("OTP lifecycle barrier timed out")
	}
}
func lifecycleCancel(r Request, n int) Request {
	return Request{V: 1, ID: reqID(n), Type: "cancel-otp", Capability: r.Capability, RequestID: r.ID}
}
func lifecycleAck(t *testing.T, c *Connection, out *memoryPipe, r Request, n int) Request {
	t.Helper()
	if err := c.ApproveOTP(r.ID); err != nil {
		t.Fatal("OTP approval failed")
	}
	ready := awaitTerminal(t, out, r.ID)
	if ready.Type != "otp-ready" || !revision.MatchString(ready.Nonce) {
		t.Fatal("OTP challenge absent")
	}
	return Request{V: 1, ID: reqID(n), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: ready.Nonce}
}
func lifecycleTerminals(t *testing.T, out *memoryPipe, expected map[string]string) {
	t.Helper()
	counts := map[string]int{}
	for _, response := range out.responses(t) {
		kind, ok := expected[response.ID]
		if !ok {
			continue
		}
		counts[response.ID]++
		if response.Type != kind || response.Type != "otp-fill" && response.Code != "" || response.Username != "" || response.Password != "" || len(response.Candidates) != 0 {
			t.Fatal("OTP terminal type or value isolation failed")
		}
		if kind == "error" && response.Error != "refused" || kind != "otp-ready" && response.Nonce != "" {
			t.Fatal("OTP terminal did not use its fixed response fields")
		}
	}
	for id := range expected {
		if counts[id] != 1 {
			t.Fatal("OTP logical request did not have exactly one terminal")
		}
	}
}

func TestOTPLifecycleCancelBeforeChallenge(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	p := c.otp
	cancel := lifecycleCancel(r, 30)
	if c.Handle(cancel) != nil {
		t.Fatal("OTP cancel failed")
	}
	if c.ApproveOTP(r.ID) == nil || p.control.Pending() || p.control.Granted() {
		t.Fatal("cancelled OTP reopened approval")
	}
	// A fresh cancellation of the retired operation is idempotent, not a new O.
	again := lifecycleCancel(r, 31)
	if c.Handle(again) != nil {
		t.Fatal("retired cancel failed")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "error", cancel.ID: "cancelled", again.ID: "cancelled"})
}

func TestOTPLifecycleNativeRejectIsExplicitCancellation(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		name := "before-challenge"
		if challenge {
			name = "after-challenge"
		}
		t.Run(name, func(t *testing.T) {
			c, _, out, r := pendingOTPFixture(t)
			p := c.otp
			expected := map[string]string{r.ID: "error"}
			if challenge {
				_ = lifecycleAck(t, c, out, r, 21)
				expected[r.ID] = "otp-ready"
			}
			if c.RejectOTP(r.ID) != nil || p.control.Pending() || p.control.Granted() {
				t.Fatal("native rejection retained approval")
			}
			cancel := lifecycleCancel(r, 30)
			if c.Handle(cancel) != nil {
				t.Fatal("late cancellation failed after native rejection")
			}
			expected[cancel.ID] = "cancelled"
			lifecycleTerminals(t, out, expected)
		})
	}
}

func TestOTPLifecycleChallengeClaimThenCancelBeforeAck(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	claimed, release := make(chan struct{}), make(chan struct{})
	var claimedOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	c.notify = func() {
		c.mu.Lock()
		ready := c.otp != nil && c.otp.originalClaimed
		c.mu.Unlock()
		if ready {
			claimedOnce.Do(func() { close(claimed); <-release })
		}
	}
	approved := make(chan struct{})
	go func() { _ = c.ApproveOTP(r.ID); close(approved) }()
	lifecycleWait(t, claimed) // O sending right claimed, pipe write has not begun.
	cancel := lifecycleCancel(r, 30)
	if c.Handle(cancel) != nil {
		t.Fatal("claimed challenge cancel failed")
	}
	for _, response := range out.responses(t) {
		if response.ID == r.ID {
			t.Fatal("challenge escaped controlled barrier")
		}
	}
	unblock()
	lifecycleWait(t, approved)
	ready := awaitTerminal(t, out, r.ID)
	ack := Request{V: 1, ID: reqID(31), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: ready.Nonce}
	if c.Handle(ack) != nil {
		t.Fatal("late ack refused transport")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", cancel.ID: "cancelled", ack.ID: "error"})
}

func TestOTPLifecycleCancelIngressBeforeSlowWorkerFinish(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	release, err := c.writer.acquire(time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal("writer slot barrier failed")
	}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(release) }
	t.Cleanup(unblock)
	retired := make(chan struct{})
	var retiredOnce sync.Once
	var retiredObserved atomic.Bool
	c.notify = func() {
		if retiredObserved.Load() {
			return
		}
		c.mu.Lock()
		gone := c.otp != p
		c.mu.Unlock()
		if gone {
			retiredOnce.Do(func() { retiredObserved.Store(true); close(retired) })
		}
	}
	if c.Handle(ack) != nil {
		t.Fatal("ack registration failed")
	}
	cancel := lifecycleCancel(r, 30)
	allowed, err := c.registerRequest(cancel)
	if err != nil || !allowed || p.control.Pending() || p.control.Granted() {
		t.Fatal("fresh cancel did not revoke at ingress")
	}
	// This is the real Handle decomposition. A cancelled worker can finish after
	// ingress revocation but before the C handler obtains Connection.mu.
	finished := make(chan struct{})
	go func() { c.finishOTP(p, personal.ErrBrowserOTP); close(finished) }()
	lifecycleWait(t, retired)
	cancelled := make(chan struct{})
	go func() { _ = c.handleOTP(cancel, allowed); close(cancelled) }()
	unblock()
	lifecycleWait(t, finished)
	lifecycleWait(t, cancelled)
	_ = awaitTerminal(t, out, ack.ID)
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "error", cancel.ID: "cancelled"})
	// Any later result of that same worker must leave a new operation untouched.
	match := Request{V: 1, ID: reqID(60), Type: "match", Capability: r.Capability, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
	if c.Handle(match) != nil {
		t.Fatal("new match failed")
	}
	next := r
	next.ID = reqID(61)
	if c.Handle(next) != nil {
		t.Fatal("new OTP failed")
	}
	c.mu.Lock()
	current := c.otp
	c.mu.Unlock()
	c.finishOTP(p, personal.ErrBrowserOTP)
	c.mu.Lock()
	unchanged := c.otp == current && current != nil && current.control.Pending()
	c.mu.Unlock()
	if !unchanged {
		t.Fatal("late worker changed a newer operation")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "error", cancel.ID: "cancelled"})
}

type lifecycleBlockingPipe struct {
	out              *memoryPipe
	armed            atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (p *lifecycleBlockingPipe) Write(raw []byte) (int, error) {
	if p.armed.Swap(false) {
		close(p.entered)
		<-p.release
	}
	return p.out.Write(raw)
}
func (p *lifecycleBlockingPipe) unblock()     { p.once.Do(func() { close(p.release) }) }
func (p *lifecycleBlockingPipe) Close() error { p.unblock(); return nil }

func TestOTPLifecycleGrantBeforeCancelIsUnknown(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	pipe := &lifecycleBlockingPipe{out: out, entered: make(chan struct{}), release: make(chan struct{})}
	pipe.armed.Store(true)
	c.writer.out = pipe
	t.Cleanup(pipe.unblock)
	cancelObserved := make(chan struct{})
	var once sync.Once
	c.notify = func() {
		if c.OTPUnknown() {
			once.Do(func() { close(cancelObserved) })
		}
	}
	if c.Handle(ack) != nil {
		t.Fatal("ack failed")
	}
	lifecycleWait(t, pipe.entered) // The dedicated writer obtained the real grant.
	if !p.control.Granted() {
		t.Fatal("pipe write preceded output grant")
	}
	cancel := lifecycleCancel(r, 30)
	done := make(chan struct{})
	go func() { _ = c.Handle(cancel); close(done) }()
	lifecycleWait(t, cancelObserved)
	pipe.unblock()
	lifecycleWait(t, done)
	response := awaitTerminal(t, out, ack.ID)
	if len(response.Code) != 6 {
		t.Fatal("granted output absent")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "otp-fill", cancel.ID: "unknown"})
	again := lifecycleCancel(r, 31)
	if c.Handle(again) != nil {
		t.Fatal("retired granted cancel failed")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "otp-fill", cancel.ID: "unknown", again.ID: "unknown"})
}

func TestOTPLifecycleLegacyCancellationAndMutualExclusion(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	p := c.otp
	fill := r
	fill.ID = reqID(40)
	fill.Type = "fill"
	fill.WindowID = 0
	save := r
	save.ID = reqID(41)
	save.Type = "save-new"
	save.ItemID = ""
	save.Revision = ""
	save.payload = &savePayload{[]byte("test-user"), []byte("test-password")}
	second := r
	second.ID = reqID(42)
	attempts := []Request{
		{V: 1, ID: reqID(43), Type: "cancel", Capability: r.Capability},
		{V: 1, ID: reqID(44), Type: "cancel-save", Capability: r.Capability, RequestID: r.ID},
		{V: 1, ID: reqID(45), Type: "cancel-otp", Capability: r.Capability, RequestID: reqID(90)},
		fill, save, second,
	}
	expected := map[string]string{}
	for _, request := range attempts {
		if c.Handle(request) != nil {
			t.Fatal("valid mutually exclusive request failed transport")
		}
		expected[request.ID] = "error"
		if c.otp != p || !p.control.Pending() || c.pending != nil || c.save != nil {
			t.Fatal("another purpose changed OTP control")
		}
	}
	lifecycleTerminals(t, out, expected)
	if c.RejectOTP(r.ID) != nil {
		t.Fatal("native reject failed")
	}
	expected[r.ID] = "error"
	lifecycleTerminals(t, out, expected)
}

func TestOTPLifecycleCannotStartDuringLegacyFillOrSave(t *testing.T) {
	t.Run("fill", func(t *testing.T) {
		c, _, out, r := paired(t)
		r = matchAndFill(t, c, out, r)
		otp := r
		otp.ID = reqID(40)
		otp.Type = "otp"
		otp.WindowID = 1
		if c.Handle(otp) != nil || c.otp != nil || c.pending == nil {
			t.Fatal("OTP interrupted pending legacy fill")
		}
		lifecycleTerminals(t, out, map[string]string{otp.ID: "error"})
	})
	t.Run("save", func(t *testing.T) {
		c, s, out, r, p := pendingSaveFixture(t)
		rows, err := s.List("active")
		if err != nil || len(rows) != 1 {
			t.Fatal("fixture rows unavailable")
		}
		otp := Request{V: 1, ID: reqID(40), Type: "otp", Capability: r.Capability, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID, WindowID: 1, ItemID: rows[0].ID, Revision: rows[0].Revision}
		if c.Handle(otp) != nil || c.otp != nil || c.save != p || !p.gate.Pending() {
			t.Fatal("OTP interrupted pending legacy save")
		}
		lifecycleTerminals(t, out, map[string]string{otp.ID: "error"})
	})
}

func TestOTPLifecycleCancelBetweenAckIngressAndRegistration(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	allowed, err := c.registerRequest(ack)
	if err != nil || !allowed {
		t.Fatal("ACK ingress failed")
	}
	// The frame was authenticated, but its handler has not registered A yet.
	cancel := lifecycleCancel(r, 30)
	if c.Handle(cancel) != nil || c.handleOTP(ack, allowed) != nil {
		t.Fatal("cancel and late ACK handlers failed")
	}
	if p.control.Pending() || p.control.Granted() || c.Snapshot().OTP != nil {
		t.Fatal("late ACK reopened a cancelled operation")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "error", cancel.ID: "cancelled"})
}

func TestOTPLifecycleCancelAfterAckBeforeWriterGrant(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	release, err := c.writer.acquire(time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal("writer slot barrier failed")
	}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(release) }
	t.Cleanup(unblock)
	retired := make(chan struct{})
	var retiredOnce sync.Once
	c.notify = func() {
		c.mu.Lock()
		gone := c.otp != p
		c.mu.Unlock()
		if gone {
			retiredOnce.Do(func() { close(retired) })
		}
	}
	if c.Handle(ack) != nil {
		t.Fatal("ACK registration failed")
	}
	c.mu.Lock()
	registered := p.ackID == ack.ID
	c.mu.Unlock()
	if !registered {
		t.Fatal("ACK was not registered before cancellation")
	}
	cancel := lifecycleCancel(r, 30)
	done := make(chan struct{})
	go func() { _ = c.Handle(cancel); close(done) }()
	lifecycleWait(t, p.control.Done())
	lifecycleWait(t, retired)
	if p.control.Granted() {
		t.Fatal("cancelled operation obtained output grant")
	}
	// Both the worker and cancellation reply may wait for the occupied slot.
	// Neither may retain Connection.mu while waiting for the transport.
	if view := c.Snapshot(); view.Busy || !view.Paired || view.OTP != nil {
		t.Fatal("cancelled output kept connection state locked")
	}
	unblock()
	lifecycleWait(t, done)
	_ = awaitTerminal(t, out, ack.ID)
	c.finishOTP(p, personal.ErrBrowserOTP)
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "error", cancel.ID: "cancelled"})
}

func TestOTPLifecycleNaturalRetirementRefusesLateCancel(t *testing.T) {
	for _, stage := range []string{"approval-expiry", "challenge-expiry", "ACK-expiry", "worker-refusal"} {
		t.Run(stage, func(t *testing.T) {
			c, s, out, r := pendingOTPFixture(t)
			p := c.otp
			expected := map[string]string{r.ID: "error"}
			var ack Request
			if stage != "approval-expiry" {
				ack = lifecycleAck(t, c, out, r, 21)
				expected[r.ID] = "otp-ready"
			}
			if stage == "worker-refusal" {
				if _, err := s.Edit(personal.Edit{ID: r.ItemID, Revision: r.Revision, Field: "title", Value: "Updated fixture"}); err != nil {
					t.Fatal("revision change failed")
				}
				if c.Handle(ack) != nil {
					t.Fatal("stale revision ACK failed transport")
				}
				_ = awaitTerminal(t, out, ack.ID)
				expected[ack.ID] = "error"
			} else {
				var unblock func()
				if stage == "ACK-expiry" {
					release, err := c.writer.acquire(time.Now().Add(time.Second), nil)
					if err != nil {
						t.Fatal("writer slot barrier failed")
					}
					var once sync.Once
					unblock = func() { once.Do(release) }
					t.Cleanup(unblock)
					if c.Handle(ack) != nil {
						t.Fatal("ACK registration failed")
					}
					expected[ack.ID] = "error"
				}
				c.mu.Lock()
				expired := p.until.Add(time.Nanosecond)
				c.now = func() time.Time { return expired }
				c.mu.Unlock()
				if c.Snapshot().OTP != nil {
					t.Fatal("expired operation remained pending")
				}
				if unblock != nil {
					unblock()
				}
				if ack.ID != "" && stage == "ACK-expiry" {
					_ = awaitTerminal(t, out, ack.ID)
				} else if stage == "approval-expiry" {
					_ = awaitTerminal(t, out, r.ID)
				}
			}
			cancel := lifecycleCancel(r, 30)
			if c.Handle(cancel) != nil || p.control.Pending() || p.control.Granted() {
				t.Fatal("natural retirement cancellation failed")
			}
			expected[cancel.ID] = "error"
			lifecycleTerminals(t, out, expected)
		})
	}
}

func TestOTPLifecycleLateCancelCannotWinBeforeExpiryCallback(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		name := "approval"
		if challenge {
			name = "challenge"
		}
		t.Run(name, func(t *testing.T) {
			c, _, out, r := pendingOTPFixture(t)
			expected := map[string]string{r.ID: "error"}
			if challenge {
				_ = lifecycleAck(t, c, out, r, 21)
				expected[r.ID] = "otp-ready"
			}
			c.mu.Lock()
			p := c.otp
			// Advance only the connection clock. Its actual timer has not run,
			// and the control's real-time status is still pending at ingress.
			expired := p.until.Add(time.Nanosecond)
			c.now = func() time.Time { return expired }
			c.mu.Unlock()
			if !p.control.Pending() {
				t.Fatal("expiry callback was not isolated")
			}
			cancel := lifecycleCancel(r, 30)
			if c.Handle(cancel) != nil {
				t.Fatal("late cancellation failed transport")
			}
			if !challenge {
				_ = awaitTerminal(t, out, r.ID)
			}
			expected[cancel.ID] = "error"
			lifecycleTerminals(t, out, expected)
		})
	}
}

func TestOTPLifecycleEarlyCancelRemainsCancelledAfterDeadline(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	p := c.otp
	cancel := lifecycleCancel(r, 30)
	allowed, err := c.registerRequest(cancel)
	if err != nil || !allowed || p.control.Pending() {
		t.Fatal("early cancellation did not revoke at ingress")
	}
	c.mu.Lock()
	expired := p.until.Add(time.Nanosecond)
	c.now = func() time.Time { return expired }
	c.mu.Unlock()
	c.finishOTP(p, personal.ErrBrowserOTP)
	if c.handleOTP(cancel, allowed) != nil {
		t.Fatal("early cancellation failed after deadline")
	}
	lifecycleTerminals(t, out, map[string]string{r.ID: "error", cancel.ID: "cancelled"})
}

func lifecycleDifferentHex(value string) string {
	first := byte('0')
	if value[0] == first {
		first = '1'
	}
	return string(first) + value[1:]
}

func TestOTPLifecycleWrongNonceAndForeignAuthorityDoNotConsumeChallenge(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	badNonce := ack
	badNonce.ID, badNonce.Nonce = reqID(40), lifecycleDifferentHex(ack.Nonce)
	wrongTarget := ack
	wrongTarget.ID, wrongTarget.RequestID = reqID(41), reqID(90)
	wrongCancel := lifecycleCancel(r, 42)
	wrongCancel.RequestID = reqID(90)
	wrongCapability := lifecycleCancel(r, 43)
	wrongCapability.Capability = lifecycleDifferentHex(r.Capability)
	expected := map[string]string{r.ID: "otp-ready", ack.ID: "otp-fill"}
	for _, bad := range []Request{badNonce, wrongTarget, wrongCancel, wrongCapability} {
		if c.Handle(bad) != nil || !p.control.Pending() || c.Snapshot().OTP == nil {
			t.Fatal("foreign request changed the approved operation")
		}
		expected[bad.ID] = "error"
	}
	if c.Handle(ack) != nil {
		t.Fatal("valid ACK failed after rejected requests")
	}
	_ = awaitTerminal(t, out, ack.ID)
	lifecycleTerminals(t, out, expected)
}

func lifecycleRematch(t *testing.T, c *Connection, out *memoryPipe, r Request, id int) {
	t.Helper()
	match := Request{V: 1, ID: reqID(id), Type: "match", Capability: r.Capability, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
	if c.Handle(match) != nil || awaitTerminal(t, out, match.ID).Type != "candidates" {
		t.Fatal("new match failed")
	}
}

func TestOTPLifecycleMismatchedInitialContextCannotCreatePending(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	cancel := lifecycleCancel(r, 30)
	if c.Handle(cancel) != nil {
		t.Fatal("fixture cancel failed")
	}
	lifecycleRematch(t, c, out, r, 40)
	expected := map[string]string{r.ID: "error", cancel.ID: "cancelled"}
	changes := []func(*Request){
		func(q *Request) { q.Origin = "https://other.test" },
		func(q *Request) { q.TabID++ },
		func(q *Request) { q.DocumentID = "different-document" },
		func(q *Request) { q.ItemID = reqID(90) },
		func(q *Request) { q.Revision = lifecycleDifferentHex(q.Revision) },
	}
	for i, change := range changes {
		bad := r
		bad.ID = reqID(50 + i)
		change(&bad)
		if c.Handle(bad) != nil || c.Snapshot().OTP != nil {
			t.Fatal("mismatched initial context created an operation")
		}
		expected[bad.ID] = "error"
	}
	next := r
	next.ID = reqID(60)
	if c.Handle(next) != nil || c.Snapshot().OTP == nil {
		t.Fatal("valid context failed after rejected requests")
	}
	stop := lifecycleCancel(next, 61)
	if c.Handle(stop) != nil {
		t.Fatal("new operation cancel failed")
	}
	expected[next.ID], expected[stop.ID] = "error", "cancelled"
	lifecycleTerminals(t, out, expected)
}

func TestOTPLifecycleOldOperationCannotAffectNewOTP(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	oldAck := lifecycleAck(t, c, out, r, 21)
	old := c.otp
	stop := lifecycleCancel(r, 30)
	if c.Handle(stop) != nil {
		t.Fatal("old operation cancel failed")
	}
	lifecycleRematch(t, c, out, r, 40)
	next := r
	next.ID = reqID(41)
	if c.Handle(next) != nil {
		t.Fatal("new operation failed")
	}
	current := c.otp
	if current == nil || current == old {
		t.Fatal("new operation was not isolated")
	}
	lateCancel := lifecycleCancel(r, 42)
	if c.Handle(oldAck) != nil || c.Handle(lateCancel) != nil {
		t.Fatal("late old request failed transport")
	}
	c.finishOTP(old, personal.ErrBrowserOTP)
	c.expireOTP(old)
	c.mu.Lock()
	unchanged := c.otp == current && current.control.Pending()
	c.mu.Unlock()
	if !unchanged {
		t.Fatal("old callback changed the newer operation")
	}
	newAck := lifecycleAck(t, c, out, next, 43)
	if c.Handle(newAck) != nil {
		t.Fatal("new ACK failed")
	}
	_ = awaitTerminal(t, out, newAck.ID)
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", stop.ID: "cancelled", oldAck.ID: "error", lateCancel.ID: "cancelled", next.ID: "otp-ready", newAck.ID: "otp-fill"})
}

func TestOTPLifecycleLockOrDisconnectRevokesBeforeGrant(t *testing.T) {
	for _, stage := range []string{"pending", "challenge", "ACK"} {
		for _, action := range []string{"lock", "disconnect"} {
			t.Run(stage+"/"+action, func(t *testing.T) {
				c, s, out, r := pendingOTPFixture(t)
				p := c.otp
				var ack Request
				if stage != "pending" {
					ack = lifecycleAck(t, c, out, r, 21)
				}
				var unblock func()
				if stage == "ACK" {
					release, err := c.writer.acquire(time.Now().Add(time.Second), nil)
					if err != nil {
						t.Fatal("writer slot barrier failed")
					}
					var once sync.Once
					unblock = func() { once.Do(release) }
					t.Cleanup(unblock)
					if c.Handle(ack) != nil {
						t.Fatal("ACK registration failed")
					}
				}
				if action == "lock" {
					c.Invalidate()
				} else {
					c.Close()
				}
				if p.control.Pending() || p.control.Granted() || s.Unlocked() || c.ApproveOTP(r.ID) == nil {
					t.Fatal("revoked operation retained approval or grant")
				}
				if view := c.Snapshot(); view.Busy || view.OTP != nil || view.Paired {
					t.Fatal("revocation retained connection state")
				}
				if unblock != nil {
					unblock()
				}
				if action == "lock" && stage != "challenge" {
					id := r.ID
					if stage == "ACK" {
						id = ack.ID
					}
					_ = awaitTerminal(t, out, id)
				}
				c.finishOTP(p, personal.ErrBrowserOTP)
				counts := map[string]int{}
				for _, response := range out.responses(t) {
					if response.ID == r.ID || response.ID == ack.ID && ack.ID != "" {
						counts[response.ID]++
						if response.Code != "" || response.Type == "otp-fill" || counts[response.ID] > 1 {
							t.Fatal("revoked operation emitted a value or second terminal")
						}
					}
				}
			})
		}
	}
}

func TestOTPLifecycleNativeLockAfterGrantKeepsUnknown(t *testing.T) {
	c, s, out, r := pendingOTPFixture(t)
	ack := lifecycleAck(t, c, out, r, 21)
	p := c.otp
	pipe := &lifecycleBlockingPipe{out: out, entered: make(chan struct{}), release: make(chan struct{})}
	pipe.armed.Store(true)
	c.writer.out = pipe
	t.Cleanup(pipe.unblock)
	if c.Handle(ack) != nil {
		t.Fatal("ACK failed")
	}
	lifecycleWait(t, pipe.entered)
	if !p.control.Granted() {
		t.Fatal("pipe barrier did not follow grant")
	}
	c.Invalidate()
	if s.Unlocked() || !c.OTPUnknown() || c.Snapshot().OTP != nil {
		t.Fatal("native lock erased the granted delivery outcome")
	}
	pipe.unblock()
	_ = awaitTerminal(t, out, ack.ID)
	c.finishOTP(p, personal.ErrBrowserOTP)
	lifecycleTerminals(t, out, map[string]string{r.ID: "otp-ready", ack.ID: "otp-fill"})
	if !c.OTPUnknown() {
		t.Fatal("late worker erased the unknown outcome")
	}
}
