package browserhost

import (
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// waitForStack waits (bounded) until one goroutine's stack contains every
// fragment. It replaces blind sleeps with an observed wait point.
func waitForStack(t *testing.T, fragments ...string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		for _, g := range strings.Split(string(stack[:n]), "\n\n") {
			matched := true
			for _, fragment := range fragments {
				if !strings.Contains(g, fragment) {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// waitFillQueued waits until ApproveFill is parked acquiring the writer slot
// it cannot get while the test holds the slot.
func waitFillQueued(t *testing.T) {
	t.Helper()
	if !waitForStack(t, "(*Connection).ApproveFill", "(*Writer).acquire") {
		t.Fatal("approval did not reach writer acquisition")
	}
}

// waitCancelRegistered waits until an authenticated cancel has completed
// registration (including its epoch bump) and is parked on the vault mutex
// held by the queued approval.
func waitCancelRegistered(t *testing.T) {
	t.Helper()
	if !waitForStack(t, "(*Connection).Handle", "sync.(*Mutex).Lock") {
		t.Fatal("cancel did not reach the vault mutex")
	}
}

func fillFrameCount(responses []Response) int {
	count := 0
	for _, response := range responses {
		if response.Type == "fill" {
			count++
		}
	}
	return count
}

func TestFillQueuedForWriterRefusesAfterLock(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	// Reserve the serializer slot, as another in-flight response would.
	release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.ApproveFill(r.ID) }()
	waitFillQueued(t)
	c.Invalidate()
	if s.Unlocked() {
		release()
		t.Fatal("session still unlocked")
	}
	before := len(out.responses(t))
	release()
	err := <-done
	for _, response := range out.responses(t)[before:] {
		if response.Type == "fill" {
			t.Fatalf("fill containing credentials emitted after native lock while no fill bytes had previously been written; approval error=%v", err)
		}
	}
}

// TestFillQueuedAuthenticatedCancelRevokesGrant covers open #36: a fresh
// authenticated cancel must revoke the queued approval before the grant runs,
// even though Handle cannot take the vault mutex until ApproveFill returns.
func TestFillQueuedAuthenticatedCancelRevokesGrant(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	pendingEpoch := c.pendingEpoch
	release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.ApproveFill(r.ID) }()
	waitFillQueued(t)
	cancelID := reqID(40)
	cancelled := make(chan error, 1)
	go func() {
		cancelled <- c.Handle(Request{V: 1, ID: cancelID, Type: "cancel", Capability: r.Capability})
	}()
	waitCancelRegistered(t)
	// Registration authenticated and bumped the epoch before waiting on c.mu.
	if got := c.cancelEpoch.Load(); got != pendingEpoch+1 {
		release()
		t.Fatalf("authenticated cancel epoch = %d, want %d before the grant", got, pendingEpoch+1)
	}
	before := len(out.responses(t))
	release()
	if err := <-done; err == nil {
		t.Fatal("queued approval succeeded after authenticated cancel")
	}
	if err := <-cancelled; err != nil {
		t.Fatal(err)
	}
	after := out.responses(t)[before:]
	if fillFrameCount(after) != 0 {
		t.Fatal("credential fill frame emitted after authenticated cancel while queued")
	}
	if fillFrameCount(out.responses(t)) != 0 {
		t.Fatal("credential fill frame emitted anywhere")
	}
	if c.Snapshot().Pending != nil {
		t.Fatal("pending fill survived cancellation")
	}
	if !s.Unlocked() {
		t.Fatal("cancel must not lock the vault")
	}
}

// TestFillQueuedExpiryRevokesGrant covers the expiry half of open #36: an
// approval queued past its deadline (or past the pairing deadline) must refuse
// inside the grant instead of disclosing credentials.
func TestFillQueuedExpiryRevokesGrant(t *testing.T) {
	for _, kind := range []string{"pending", "capability"} {
		t.Run(kind, func(t *testing.T) {
			c, _, out, r := paired(t)
			r = matchAndFill(t, c, out, r)
			var offset atomic.Int64
			base := time.Now()
			// Install the clock before any goroutine reads it; only the
			// atomic offset moves afterwards, so -race stays clean.
			c.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
			if kind == "capability" {
				// Keep the request alive while the pairing window lapses.
				c.mu.Lock()
				c.until = base.Add(time.Minute)
				c.pendingUntil = base.Add(10 * time.Minute)
				c.mu.Unlock()
			}
			release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- c.ApproveFill(r.ID) }()
			waitFillQueued(t)
			if kind == "pending" {
				offset.Add(int64(31 * time.Second))
			} else {
				offset.Add(int64(2 * time.Minute))
			}
			before := len(out.responses(t))
			release()
			if err := <-done; err == nil {
				t.Fatal("queued approval succeeded after expiry")
			}
			after := out.responses(t)[before:]
			if fillFrameCount(after) != 0 {
				t.Fatalf("%s expiry emitted a credential fill frame", kind)
			}
			refused := false
			for _, response := range after {
				if response.Type == "error" && response.ID == r.ID {
					refused = true
				}
			}
			if !refused {
				t.Fatalf("%s expiry did not refuse request %q", kind, r.ID)
			}
			if c.Snapshot().Pending != nil {
				t.Fatalf("%s expiry left pending fill", kind)
			}
		})
	}
}

// TestFillQueuedInvalidCancelCannotRevoke pins that an unauthenticated cancel
// neither revokes the queued approval nor touches the cancellation epoch.
func TestFillQueuedInvalidCancelCannotRevoke(t *testing.T) {
	c, _, out, r := paired(t)
	// Pin the paired capability to a known "f" prefix before any request is
	// handled. The historical invalid-capability construction copied the real
	// capability and replaced only its first byte with "f", so it collapsed
	// onto the genuine capability whenever the random fixture capability
	// already began with "f" (1/16 of runs). With this prefix the collapse is
	// unconditional, so a regression back to that construction fails here
	// every time instead of intermittently in CI.
	c.mu.Lock()
	c.authMu.Lock()
	r.Capability = "f" + r.Capability[1:]
	c.capability = r.Capability
	c.authCapability = r.Capability
	c.authMu.Unlock()
	c.mu.Unlock()
	r = matchAndFill(t, c, out, r)
	pendingEpoch := c.pendingEpoch
	// Derive invalid capabilities from the real one by flipping a single low
	// hex bit at distinct positions: each result stays a well-formed 32-hex
	// token that differs from the paired capability by exactly one digit.
	const hexDigits = "0123456789abcdef"
	for i, position := range []int{0, 15, 31} {
		digit := strings.IndexByte(hexDigits, r.Capability[position])
		if digit < 0 {
			t.Fatalf("paired capability has non-hex byte at position %d", position)
		}
		flipped := []byte(r.Capability)
		flipped[position] = hexDigits[digit^1]
		capability := string(flipped)
		if capability == r.Capability {
			t.Fatalf("capability with bit flipped at %d equals the paired capability", position)
		}
		allowed, err := c.registerRequest(Request{V: 1, ID: reqID(50 + i), Type: "cancel", Capability: capability})
		if allowed || err != nil {
			t.Fatalf("unauthenticated cancel allowed=%v err=%v", allowed, err)
		}
		if got := c.cancelEpoch.Load(); got != pendingEpoch {
			t.Fatalf("unauthenticated cancel advanced epoch to %d, want %d", got, pendingEpoch)
		}
	}
	if e := c.ApproveFill(r.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "fill" || last.ID != r.ID || last.Username != "fixture-user" || last.Password != "fixture-password" {
		t.Fatal("invalid cancel blocked or corrupted the approved fill")
	}
}

// TestFillQueuedReplayedCancelCannotRevokeNewerFill pins that a replayed
// cancel frame is counted and ignored: after the first authenticated cancel
// revokes one queued approval, its replay must not revoke a newer fill.
func TestFillQueuedReplayedCancelCannotRevokeNewerFill(t *testing.T) {
	c, _, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	pendingEpoch := c.pendingEpoch
	release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.ApproveFill(r.ID) }()
	waitFillQueued(t)
	cancelID := reqID(41)
	cancelled := make(chan error, 1)
	go func() {
		cancelled <- c.Handle(Request{V: 1, ID: cancelID, Type: "cancel", Capability: r.Capability})
	}()
	waitCancelRegistered(t)
	before := len(out.responses(t))
	release()
	if err := <-done; err == nil {
		t.Fatal("queued approval succeeded after authenticated cancel")
	}
	if err := <-cancelled; err != nil {
		t.Fatal(err)
	}
	after := out.responses(t)[before:]
	if fillFrameCount(after) != 0 {
		t.Fatal("credential fill frame emitted after authenticated cancel while queued")
	}
	epoch := c.cancelEpoch.Load()
	if epoch != pendingEpoch+1 {
		t.Fatalf("cancel epoch = %d, want %d", epoch, pendingEpoch+1)
	}
	// A newer legitimate fill is already pending when the old cancel replays.
	match := r
	match.ID = reqID(42)
	match.Type = "match"
	match.ItemID = ""
	match.Revision = ""
	if e := c.Handle(match); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	rows := all[len(all)-1].Candidates
	if len(rows) != 1 {
		t.Fatal("missing match for newer fill")
	}
	fill := match
	fill.ID = reqID(43)
	fill.Type = "fill"
	fill.ItemID = rows[0].ID
	fill.Revision = rows[0].Revision
	if e := c.Handle(fill); e != nil {
		t.Fatal(e)
	}
	if c.Snapshot().Pending == nil {
		t.Fatal("newer fill not pending")
	}
	if e := c.Handle(Request{V: 1, ID: cancelID, Type: "cancel", Capability: r.Capability}); e != nil {
		t.Fatal(e)
	}
	if got := c.cancelEpoch.Load(); got != epoch {
		t.Fatalf("replayed cancel advanced epoch to %d, want %d", got, epoch)
	}
	if c.Snapshot().Pending == nil {
		t.Fatal("replayed cancel revoked the newer fill")
	}
	responses := out.responses(t)
	cancelledFrames := 0
	for _, response := range responses {
		if response.Type == "cancelled" {
			cancelledFrames++
		}
	}
	if cancelledFrames != 1 {
		t.Fatalf("cancelled responses = %d, want 1", cancelledFrames)
	}
	if e := c.ApproveFill(fill.ID); e != nil {
		t.Fatal(e)
	}
	responses = out.responses(t)
	last := responses[len(responses)-1]
	if last.Type != "fill" || last.ID != fill.ID || last.Username != "fixture-user" || last.Password != "fixture-password" {
		t.Fatal("replayed cancel prevented the newer authenticated fill")
	}
}
