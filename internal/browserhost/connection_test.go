package browserhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
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
	if c.ApproveFill(r.ID) == nil || c.Handle(r) == nil {
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
	if c.Handle(bad) == nil || c.cancelEpoch.Load() != before {
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
