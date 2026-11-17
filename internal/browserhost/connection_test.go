package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestConnectionMetadataRefusalKeepsPairing(t *testing.T) {
	c, s, out, r := paired(t)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Edit(personal.Edit{ID: rows[0].ID, Revision: rows[0].Revision, Field: "title", Value: strings.Repeat("<", 1025)}); e != nil {
		t.Fatal(e)
	}
	r.Revision = ""
	if c.Handle(r) != nil || c.closed.Load() || !c.Snapshot().Paired {
		t.Fatal("metadata business refusal closed connection")
	}
	all := out.responses(t)
	if all[len(all)-1].Type != "error" {
		t.Fatal("missing fixed metadata refusal")
	}
}

type memoryPipe struct {
	sync.Mutex
	bytes.Buffer
}

func (b *memoryPipe) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *memoryPipe) Close() error { return nil }
func (b *memoryPipe) responses(t *testing.T) []Response {
	t.Helper()
	b.Lock()
	raw := bytes.Clone(b.Bytes())
	b.Unlock()
	var out []Response
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatal("short frame")
		}
		n := int(binary.NativeEndian.Uint32(raw))
		raw = raw[4:]
		if n > len(raw) {
			t.Fatal("bad frame")
		}
		var r Response
		if json.Unmarshal(raw[:n], &r) != nil {
			t.Fatal("bad response")
		}
		out = append(out, r)
		raw = raw[n:]
	}
	return out
}
func reqID(n int) string { return fmt.Sprintf("%032x", n) }
func paired(t *testing.T) (*Connection, *personal.Session, *memoryPipe, Request) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Host login", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"})
	if e != nil {
		t.Fatal(e)
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e = c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if len(out.responses(t)) != 0 {
		t.Fatal("pair did not require native consent")
	}
	if e = c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	cap := out.responses(t)[0].Capability
	return c, s, out, Request{V: 1, ID: reqID(2), Type: "match", Capability: cap, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", ItemID: "", Revision: rev}
}
func matchAndFill(t *testing.T, c *Connection, out *memoryPipe, r Request) Request {
	t.Helper()
	r.Revision = ""
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	rows := all[len(all)-1].Candidates
	if len(rows) != 1 {
		t.Fatal("missing match")
	}
	r.ID = reqID(3)
	r.Type = "fill"
	r.ItemID = rows[0].ID
	r.Revision = rows[0].Revision
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestConnectionNativePairFillRejectAndReplay(t *testing.T) {
	c, _, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	for _, response := range out.responses(t) {
		if response.Type == "fill" {
			t.Fatal("values before approval")
		}
	}
	if c.Snapshot().Pending == nil {
		t.Fatal("no native intent")
	}
	if e := c.ApproveFill(r.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "fill" || last.Username != "fixture-user" || last.Password != "fixture-password" {
		t.Fatal("wrong fill response")
	}
	if c.ApproveFill(r.ID) == nil || c.Handle(r) != nil {
		t.Fatal("fill replay")
	}
}
func TestConnectionLockAndLateConfirmation(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	c.Invalidate()
	if s.Unlocked() || c.ApproveFill(r.ID) == nil || c.Snapshot().Pending != nil {
		t.Fatal("late approval survived lock")
	}
	for _, response := range out.responses(t) {
		if response.Type == "fill" {
			t.Fatal("locked delivery")
		}
	}
}
func TestConnectionExpiryAndHelloRetry(t *testing.T) {
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	now := time.Now()
	c.now = func() time.Time { return now }
	if c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}) != nil {
		t.Fatal("hello")
	}
	now = now.Add(61 * time.Second)
	if c.Handle(Request{V: 1, ID: reqID(2), Type: "hello"}) != nil || !c.Snapshot().Pair {
		t.Fatal("expired hello blocked retry")
	}
}

func TestCancelRevokesBeforeWaitingForTransaction(t *testing.T) {
	c, _, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	before := c.cancelEpoch.Load()
	c.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- c.Handle(Request{V: 1, ID: reqID(4), Type: "cancel", Capability: r.Capability}) }()
	deadline := time.Now().Add(time.Second)
	for c.cancelEpoch.Load() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	changed := c.cancelEpoch.Load() != before
	c.mu.Unlock()
	<-done
	if !changed || c.ApproveFill(r.ID) == nil {
		t.Fatal("cancel waited behind transaction")
	}
}

func TestConnectionStaleRevisionAndRequestExpiry(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	if _, e := s.Edit(personal.Edit{ID: r.ItemID, Revision: r.Revision, Field: "password", Value: "changed"}); e != nil {
		t.Fatal(e)
	}
	if c.ApproveFill(r.ID) == nil {
		t.Fatal("stale confirmation reported success")
	}
	for _, response := range out.responses(t) {
		if response.Type == "fill" {
			t.Fatal("stale revision disclosed")
		}
	}
}

func TestConnectionIntentAndCapabilityDeadline(t *testing.T) {
	c, _, out, r := paired(t)
	now := time.Now()
	c.now = func() time.Time { return now }
	r = matchAndFill(t, c, out, r)
	now = now.Add(31 * time.Second)
	if c.Snapshot().Pending != nil || c.ApproveFill(r.ID) == nil {
		t.Fatal("expired native intent")
	}
	now = now.Add(16 * time.Minute)
	r.ID = reqID(5)
	r.Type = "match"
	r.ItemID = ""
	r.Revision = ""
	if c.Handle(r) != nil || c.Snapshot().Paired {
		t.Fatal("expired capability")
	}
}

func TestWrongCapabilityAndReplayCannotCancelCurrentIntent(t *testing.T) {
	c, _, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	before := c.cancelEpoch.Load()
	bad := Request{V: 1, ID: reqID(10), Type: "cancel", Capability: reqID(99)}
	if c.Handle(bad) != nil || c.cancelEpoch.Load() != before || c.Snapshot().Pending == nil {
		t.Fatal("wrong cap cancelled current request")
	}
	if c.Handle(bad) != nil || c.cancelEpoch.Load() != before {
		t.Fatal("replayed cancel changed epoch")
	}
}
func TestNativeLockNotifiesPendingHello(t *testing.T) {
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}) != nil {
		t.Fatal("hello")
	}
	c.Invalidate()
	deadline := time.Now().Add(time.Second)
	notified := false
	for !notified && time.Now().Before(deadline) {
		for _, r := range out.responses(t) {
			if r.Type == "locked" {
				notified = true
			}
		}
		if !notified {
			time.Sleep(time.Millisecond)
		}
	}
	if !notified || c.Snapshot().Pair {
		t.Fatal("pending hello hung after native lock")
	}
}

type blockingPipe struct {
	*memoryPipe
	block bool
	start chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (b *blockingPipe) Write(p []byte) (int, error) {
	if !b.block {
		return b.memoryPipe.Write(p)
	}
	b.once.Do(func() { close(b.start) })
	<-b.done
	return 0, io.ErrClosedPipe
}
func (b *blockingPipe) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	return nil
}
func TestConnectionSlowWriteLockIsImmediate(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	slow := &blockingPipe{memoryPipe: out, block: true, start: make(chan struct{}), done: make(chan struct{})}
	c.writer = NewWriter(slow, 30*time.Millisecond)
	finished := make(chan error, 1)
	go func() { finished <- c.ApproveFill(r.ID) }()
	<-slow.start
	start := time.Now()
	c.Invalidate()
	if time.Since(start) > 20*time.Millisecond || s.Unlocked() {
		t.Fatal("lock waited for pipe")
	}
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("broken delivery succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write hung")
	}
}

// A shared desktop capability is per-browser-window authority. Closing it or
// losing its pipe must revoke only that connection, never request a lock on the
// owner's shared *personal.Session.
func TestSharedConnectionCloseDoesNotLockDesktopSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-close.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	if e := c.BindDesktopSession(s, 3, true); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if !s.Unlocked() {
		t.Fatal("shared connection close locked the desktop session")
	}
	if !c.Snapshot().Closed {
		t.Fatal("closed connection still reported open")
	}
}

type failingPipe struct{}

func (failingPipe) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (failingPipe) Close() error              { return nil }

func TestSharedPipeFailureDoesNotLockDesktopSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-write.ll")
	key := bytes.Repeat([]byte{8}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	if e := c.BindDesktopSession(s, 4, false); e != nil {
		t.Fatal(e)
	}
	c.writer = NewWriter(failingPipe{}, time.Second)
	if e := c.response(Response{Type: "status"}); e == nil {
		t.Fatal("broken pipe response succeeded")
	}
	if !s.Unlocked() {
		t.Fatal("shared pipe failure locked the desktop session")
	}
}

// A lock request is a vault mutation and therefore needs the current
// capability. An unauthenticated frame must not even reach the native lock
// callback.
func TestUnauthenticatedLockIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock-cap.ll")
	key := bytes.Repeat([]byte{10}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	locks := 0
	b := NewBroker(BrokerCallbacks{RequestLock: func() { locks++ }})
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	// A brokered connection can never be bound directly; this fixture binds the
	// direct desktop session first, then attaches the broker callbacks it
	// exercises.
	if e := c.BindDesktopSession(s, 5, false); e != nil {
		t.Fatal(e)
	}
	c.SetBroker(b)
	if e := c.Handle(Request{V: 1, ID: reqID(70), Type: "lock"}); e != nil {
		t.Fatal(e)
	}
	if locks != 0 || !s.Unlocked() {
		t.Fatal("unauthenticated lock reached the desktop")
	}
	all := out.responses(t)
	if all[len(all)-1].Type != "error" {
		t.Fatal("unauthenticated lock was not refused")
	}
	if e := c.Handle(Request{V: 1, ID: reqID(71), Type: "lock", Capability: c.capability}); e != nil {
		t.Fatal(e)
	}
	if locks != 1 {
		t.Fatal("authenticated lock did not reach the desktop")
	}
}

// A valid capability lock must block every other shared connection before the
// asynchronous App/UI lock dispatch runs. Disconnect and pipe failure paths
// remain per-connection and are covered separately.
func TestAuthenticatedLockBlocksOtherSharedConnectionsBeforeDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-lock.ll")
	key := bytes.Repeat([]byte{12}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Shared lock login", "shared-user", "shared-secret")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	b := NewBroker(BrokerCallbacks{RequestLock: func() {
		close(entered)
		<-release
	}})
	out1, out2 := &memoryPipe{}, &memoryPipe{}
	c1 := NewDesktopConnection(NewWriter(out1, time.Second), nil)
	if e := c1.BindDesktopSession(s, 3, true); e != nil {
		t.Fatal(e)
	}
	c1.SetBroker(b)
	c2 := NewDesktopConnection(NewWriter(out2, time.Second), nil)
	if e := c2.BindDesktopSession(s, 3, true); e != nil {
		t.Fatal(e)
	}
	c2.SetBroker(b)
	cap1 := out1.responses(t)[0].Capability
	cap2 := out2.responses(t)[0].Capability
	finished := make(chan error, 1)
	go func() {
		finished <- c1.Handle(Request{V: 1, ID: reqID(500), Type: "lock", Capability: cap1})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lock callback was not reached")
	}
	if s.Unlocked() {
		t.Fatal("lock did not synchronously block the shared session")
	}
	if e := c2.Handle(Request{V: 1, ID: reqID(501), Type: "item-get", Capability: cap2, ItemID: id, Revision: rows[0].Revision}); e != nil {
		t.Fatal(e)
	}
	all := out2.responses(t)
	if all[len(all)-1].Type != "error" {
		t.Fatal("another paired connection disclosed after lock but before UI dispatch")
	}
	close(release)
	select {
	case e := <-finished:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("lock request did not finish")
	}
}

// Lock or expiry revokes the native pairing consent. A later unlock on the same
// connection must not silently reissue a quick capability; only a fresh native
// approval can do that.
func TestBrokeredLockRevokesPairingConsentUntilFreshApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consent.ll")
	key := bytes.Repeat([]byte{14}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	unlock := func() *personal.Session {
		s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Lock)
		return s
	}
	s := unlock()
	// The broker reports the session exactly as the desktop does: locked while
	// locked, then the freshly unlocked session and its new epoch. The current
	// session and epoch are read under the broker lock so the hello review never
	// races the desktop switching them below.
	var epoch atomic.Uint64
	epoch.Store(1)
	var curMu sync.Mutex
	cur := s
	reviews := make(chan struct{}, 4)
	b := NewBroker(BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) {
			curMu.Lock()
			defer curMu.Unlock()
			n := epoch.Load()
			if cur.Unlocked() {
				return cur, n, true
			}
			return nil, 0, false
		},
		ApproveBrowserPair: func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
			reviews <- struct{}{}
			return BrowserPairDecision{Approved: true, QuickFill: true}, nil
		},
	})
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	// Only a connection the broker knows receives NotifyLocked and
	// NotifyUnlocked; drop it from the broker when the fixture ends.
	if !b.addConn(c) {
		t.Fatal("broker refused the fixture connection")
	}
	t.Cleanup(func() { b.dropConn(c); c.Close() })
	c.SetBroker(b)
	// Handle serves the frame directly: it takes the connection mutex itself
	// and must not reenter it through its own hello review.
	hello := func(id int) {
		t.Helper()
		if e := c.Handle(Request{V: 1, ID: reqID(id), Type: "hello"}); e != nil {
			t.Fatal(e)
		}
	}
	hello(80)
	// The review runs off the caller and commits after its callback returns.
	select {
	case <-reviews:
	case <-time.After(time.Second):
		t.Fatal("native review was not requested")
	}
	waitPaired(t, c)
	if !c.PairAuthorized() || !c.Snapshot().QuickFill {
		t.Fatal("explicit approval did not pair the connection")
	}
	// The successful bind answered the hello and released its review slot.
	c.mu.Lock()
	cleared := c.hello == "" && !c.pairing
	c.mu.Unlock()
	if !cleared {
		t.Fatal("pairing review did not clear the hello it answered")
	}
	b.NotifyLocked(1)
	if c.PairAuthorized() || c.Snapshot().QuickFill || c.Snapshot().Paired {
		t.Fatal("lock kept pairing consent")
	}
	// The lock revoked the vault key, so unlocking opens a new session.
	if e := c.BindDesktopSession(s, 2, true); e == nil {
		t.Fatal("direct bind bypassed the pairing review")
	}
	// Lock already blocked the session; take the lock and switch the fixture
	// to the freshly unlocked session and epoch before announcing it. Both move
	// together under curMu, as they do on the desktop.
	s.Lock()
	fresh := unlock()
	curMu.Lock()
	cur = fresh
	epoch.Store(2)
	curMu.Unlock()
	if c.PairAuthorized() || c.Snapshot().QuickFill || c.Snapshot().Paired {
		t.Fatal("unlock silently reissued a capability")
	}
	select {
	case <-reviews:
		t.Fatal("unlock without a pending hello started a review")
	default:
	}
	// Only a hello sent after the unlock starts the explicit review.
	hello(81)
	select {
	case <-reviews:
	case <-time.After(time.Second):
		t.Fatal("new hello did not request a fresh native review")
	}
	// The review callback returns before the approval is committed; wait for
	// it to give the connection mutex back before reading the consent.
	waitPaired(t, c)
	deadline := time.Now().Add(time.Second)
	for !c.Snapshot().QuickFill && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !c.PairAuthorized() || !c.Snapshot().QuickFill {
		t.Fatal("fresh approval did not restore the capability")
	}
}

// waitPaired waits a bounded time for the pairing goroutine to commit the
// native approval and its capability and release the connection mutex.
func waitPaired(t *testing.T, c *Connection) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.mu.TryLock() {
			paired := c.pairAuthorized && !c.pairing
			c.mu.Unlock()
			if paired {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("native approval was not committed")
}

// pairFixture starts a brokered connection on a fake clock frozen at base. The
// broker reports the unlocked session and epoch exactly as the desktop does, so
// only a deadline or phase check can refuse a late approval. It leaves the
// hello slot empty: the test sends the hello through Handle so the pending
// slot and its deadline are created by production code alone.
func pairFixture(t *testing.T, b *Broker, now *time.Time) (*Connection, *memoryPipe, *personal.Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "late-pair.ll")
	key := bytes.Repeat([]byte{16}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	b.callbacks.CurrentSession = func() (*personal.Session, uint64, bool) {
		if s.Unlocked() {
			return s, 1, true
		}
		return nil, 0, false
	}
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	c.desktopShared = true
	c.SetBroker(b)
	c.mu.Lock()
	c.now = func() time.Time { return *now }
	c.mu.Unlock()
	return c, out, s
}

// noGrant asserts the hello obtained no capability, quick-fill or consent.
func noGrant(t *testing.T, c *Connection, out *memoryPipe) {
	t.Helper()
	if c.PairAuthorized() {
		t.Fatal("late approval granted pairing consent")
	}
	if v := c.Snapshot(); v.Paired || v.QuickFill {
		t.Fatal("late approval issued a capability")
	}
	c.mu.Lock()
	cap, quick := c.capability, c.quickFill
	c.mu.Unlock()
	if cap != "" || quick {
		t.Fatal("late approval issued a capability")
	}
	for _, r := range out.responses(t) {
		if r.Type == "paired" || r.Capability != "" {
			t.Fatal("late approval answered with a capability")
		}
	}
}

// A native callback that ignores the canceled ctx and returns Approved=true
// after the hello deadline grants nothing: no capability, no quick-fill, no
// consent. The pending hello, its deadline and the review all come from real
// Handle production code on a matching broker session, and nothing touches the
// connection between the review entering and the late decision. So with only
// the deadline check removed from the commit the approval lands on the live
// hello slot and pairs: this is the minimal regression that falsifies that code.
func TestBrokeredLateApprovalAfterHelloDeadlineGrantsNothing(t *testing.T) {
	id := reqID(82)
	base := time.Now()
	now := base
	entered, release := make(chan struct{}), make(chan struct{})
	b := NewBroker(BrokerCallbacks{ApproveBrowserPair: func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
		close(entered)
		// A late click: ignore the canceled ctx and approve regardless.
		<-release
		return BrowserPairDecision{Approved: true, QuickFill: true}, nil
	}})
	c, out, _ := pairFixture(t, b, &now)
	// Handle creates the pending hello slot and its deadline itself and starts
	// the review off the caller.
	if e := c.Handle(Request{V: 1, ID: id, Type: "hello"}); e != nil {
		t.Fatalf("hello was refused: %v", e)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native pairing review was not requested")
	}
	c.mu.Lock()
	live, till, phase := c.hello, c.pairUntil, c.pairing
	c.mu.Unlock()
	if live != id || !phase || till.IsZero() {
		t.Fatalf("hello did not leave a live review slot: hello=%q pairing=%v until=%v", live, phase, till)
	}
	// Advance only the clock past the deadline. No Handle or Snapshot runs
	// before the approval is released: those expire the hello and would let the
	// old commit succeed by refusing a missing slot rather than by its own
	// deadline check.
	now = till.Add(time.Second)
	c.mu.Lock()
	still := c.hello
	c.mu.Unlock()
	if still != id {
		t.Fatalf("hello vanished before the late approval: %q", still)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		released := !c.pairing
		c.mu.Unlock()
		if released {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late review never finished")
		}
		time.Sleep(time.Millisecond)
	}
	noGrant(t, c, out)
}

// Closing one brokered connection revokes only that connection; the other
// Closing one brokered connection revokes only that connection; the other
// paired connection and the desktop session stay usable.
func TestBrokeredCloseDoesNotRevokeOtherPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "close-peer.ll")
	key := bytes.Repeat([]byte{15}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	b := NewBroker(BrokerCallbacks{
		ApproveBrowserPair: func(ctx context.Context, req BrowserPairRequest) (BrowserPairDecision, error) {
			return BrowserPairDecision{Approved: true, QuickFill: true}, nil
		},
	})
	pair := func(id int) *Connection {
		out := &memoryPipe{}
		c := NewDesktopConnection(NewWriter(out, time.Second), nil)
		c.SetBroker(b)
		c.mu.Lock()
		c.hello, c.pairUntil = reqID(id), time.Now().Add(time.Minute)
		c.mu.Unlock()
		c.reviewBrowserHello(s, 1)
		waitPaired(t, c)
		c.mu.Lock()
		paired := c.pairAuthorized && c.capability != ""
		c.mu.Unlock()
		if !paired {
			t.Fatal("pairing failed")
		}
		return c
	}
	first, second := pair(60), pair(61)
	first.Close()
	second.mu.Lock()
	paired := second.pairAuthorized && second.capability != "" && !second.closed.Load()
	second.mu.Unlock()
	if !s.Unlocked() || !paired || second.Snapshot().Closed {
		t.Fatal("closing one connection affected the other pairing or session")
	}
}
