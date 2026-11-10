package vaultfilebackend

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func memoryOpen(t *testing.T) Backend { return NewMemory() }

func TestMemoryConformance(t *testing.T) {
	RunConformance(t, memoryOpen, nil)
}

func TestMemoryRevisionsAreInstanceScoped(t *testing.T) {
	ctx := context.Background()
	a := NewMemory()
	b := NewMemory()
	if err := a.CreateIfAbsent(ctx, "x", []byte("same")); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateIfAbsent(ctx, "x", []byte("same")); err != nil {
		t.Fatal(err)
	}
	ra, err := a.Read(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Read(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if ra.Revision.Zero() || rb.Revision.Zero() {
		t.Fatal("Memory must mint non-zero revisions")
	}
	// Two fresh instances committing identical bytes as their first version
	// must still mint distinct revisions.
	if string(ra.Bytes) != "same" || string(rb.Bytes) != "same" {
		t.Fatalf("bytes = %q, %q", ra.Bytes, rb.Bytes)
	}
	if ra.Revision == rb.Revision {
		t.Fatalf("first revisions of distinct instances collided: %q", ra.Revision)
	}
	if len(ra.Revision) > MaxRevisionSize || len(rb.Revision) > MaxRevisionSize {
		t.Fatalf("revision length over MaxRevisionSize: %d, %d", len(ra.Revision), len(rb.Revision))
	}
	// A revision from one store must not authorize a write in another.
	if err := b.ReplaceIfVersion(ctx, "x", ra.Revision, []byte("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign revision = %v, want ErrConflict", err)
	}
	if got, err := b.Read(ctx, "x"); err != nil || string(got.Bytes) != "same" || got.Revision != rb.Revision {
		t.Fatalf("foreign revision wrote state: %q %v", got.Bytes, err)
	}
	// Committed versions in one instance have distinct revisions even with
	// identical bytes.
	if err := a.CreateIfAbsent(ctx, "x2", []byte("same")); err != nil {
		t.Fatal(err)
	}
	ra2, _ := a.Read(ctx, "x2")
	if ra2.Revision == ra.Revision {
		t.Fatal("distinct committed versions must have distinct revisions")
	}
}

// etagMemory models a backend that passes provider ETags through verbatim.
type etagMemory struct {
	*Memory
	next int
	etag string
}

func (e *etagMemory) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	if err := e.Memory.CreateIfAbsent(ctx, name, value); err != nil {
		return err
	}
	e.next++
	e.Memory.mu.lock(ctx)
	v := e.Memory.values[name]
	v.revision = Revision(e.etag)
	e.Memory.values[name] = v
	e.Memory.mu.unlock()
	return nil
}

func TestMemoryPreservesQuotedETagRevision(t *testing.T) {
	ctx := context.Background()
	b := &etagMemory{Memory: NewMemory(), etag: `"0x8D9F1A2B3C4D5E6:W/opaque+EtAg="`}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err := b.Read(ctx, "n")
	if err != nil || string(got.Revision) != b.etag {
		t.Fatalf("revision = %q, %v, want verbatim %q", got.Revision, err, b.etag)
	}
	if err := b.ReplaceIfVersion(ctx, "n", got.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace with quoted ETag: %v", err)
	}
	if err := b.ReplaceIfVersion(ctx, "n", got.Revision, []byte("v3")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale quoted ETag = %v, want ErrConflict", err)
	}
}

// TestMemoryCancelReturnsWhileLockHeld proves every operation gives up waiting
// for the internal lock as soon as ctx is cancelled: the holder never unlocks
// before the cancelled calls have returned.
func TestMemoryCancelReturnsWhileLockHeld(t *testing.T) {
	m := NewMemory()
	if err := m.mu.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	locked := true
	unlock := sync.OnceFunc(func() {
		locked = false
		m.mu.unlock()
	})
	t.Cleanup(func() {
		if locked {
			unlock()
		}
	})
	m.values["n"] = memoryVersion{bytes: []byte("v1"), revision: Revision("seed")}

	ops := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"read", func(ctx context.Context) error {
			_, err := m.Read(ctx, "n")
			return err
		}},
		{"create", func(ctx context.Context) error {
			return m.CreateIfAbsent(ctx, "n2", []byte("new"))
		}},
		{"replace", func(ctx context.Context) error {
			return m.ReplaceIfVersion(ctx, "n", Revision("seed"), []byte("v2"))
		}},
		{"list", func(ctx context.Context) error {
			_, err := m.List(ctx)
			return err
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			res := make(chan error, 1)
			go func() {
				close(started)
				res <- op.call(ctx)
			}()
			<-started
			// Give the goroutine a chance to block on the held lock.
			time.Sleep(10 * time.Millisecond)
			select {
			case err := <-res:
				t.Fatalf("%s returned before cancel: %v", op.name, err)
			default:
			}
			cancel()
			select {
			case err := <-res:
				if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled %s = %v, want ErrDenied wrapping context.Canceled", op.name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s still blocked on the held lock after cancel", op.name)
			}
			if !locked {
				t.Fatalf("%s observed the lock released before returning", op.name)
			}
		})
	}
	unlock()

	// Cancelled writers must not have committed anything.
	ctx := context.Background()
	if _, err := m.Read(ctx, "n2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled create wrote state: %v", err)
	}
	if got, err := m.Read(ctx, "n"); err != nil || string(got.Bytes) != "v1" || got.Revision != Revision("seed") {
		t.Fatalf("cancelled replace wrote state: %q %v", got.Bytes, err)
	}
	// The lock is usable again after the holder releases it.
	if err := m.CreateIfAbsent(ctx, "n3", []byte("ok")); err != nil {
		t.Fatalf("create after unlock: %v", err)
	}
}

func TestMemoryCloseListDenied(t *testing.T) {
	m := NewMemory()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.List(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatalf("list after close = %v, want ErrDenied", err)
	}
}

func TestMemoryCancellationKeepsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewMemory().CreateIfAbsent(ctx, "n", []byte("v"))
	if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v, want ErrDenied wrapping context.Canceled", err)
	}
}

// hookContext is a test-only context whose Err reports a non-nil cause from
// the begin-th call onward while Done and Deadline stay inert. It lets tests
// cancel at an exact internal point of an operation without touching
// production code; it implements only what Memory's ctx.Err checks use.
type hookContext struct {
	armed atomic.Bool
	calls atomic.Int32
	begin int32
}

func (c *hookContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *hookContext) Done() <-chan struct{}       { return nil }
func (c *hookContext) Value(any) any               { return nil }
func (c *hookContext) Err() error {
	if !c.armed.Load() {
		return nil
	}
	if c.calls.Add(1) >= c.begin {
		return context.Canceled
	}
	return nil
}

// idleHookContext is a context that is already cancelled but reports it only
// from its begin-th Err call, so the pre-lock fast paths pass and the next
// check observes the cancellation.
func idleHookContext(begin int32) *hookContext {
	c := &hookContext{begin: begin}
	c.armed.Store(true)
	return c
}

// TestMemoryCancelledAfterLockIsDenied covers the race where ctx is cancelled
// after the pre-lock check but a lock fast path still succeeds: every operation
// must re-check under the lock and refuse, writing nothing.
func TestMemoryCancelledAfterLockIsDenied(t *testing.T) {
	m := NewMemory()
	m.values["n"] = memoryVersion{bytes: []byte("v1"), revision: Revision("seed")}

	// Pre-lock check is call 1, memoryLock.lock's own check is call 2, and the
	// check after lock acquisition is call 3.
	ctx := idleHookContext(3)
	if _, err := m.Read(ctx, "n"); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("read = %v, want ErrDenied wrapping context.Canceled", err)
	}
	ctx = idleHookContext(3)
	if err := m.CreateIfAbsent(ctx, "n2", []byte("new")); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("create = %v, want ErrDenied wrapping context.Canceled", err)
	}
	ctx = idleHookContext(3)
	if err := m.ReplaceIfVersion(ctx, "n", Revision("seed"), []byte("v2")); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("replace = %v, want ErrDenied wrapping context.Canceled", err)
	}

	bg := context.Background()
	if _, err := m.Read(bg, "n2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled create wrote state: %v", err)
	}
	if got, err := m.Read(bg, "n"); err != nil || string(got.Bytes) != "v1" || got.Revision != Revision("seed") {
		t.Fatalf("cancelled replace wrote state: %q %v", got.Bytes, err)
	}
}

// TestMemoryReadMissingKeyCancelledAfterLock covers the post-lock check on
// Read's missing-name path: a cancelled caller must see the cancellation, not
// ErrNotFound, and must not mutate state.
func TestMemoryReadMissingKeyCancelledAfterLock(t *testing.T) {
	m := NewMemory()
	// Read checks Err before locking (1), memoryLock.lock checks it before
	// waiting (2), and Read checks again right after locking (3). Cancelling at
	// call 3 proves the named post-lock phase ran.
	ctx := idleHookContext(3)
	if _, err := m.Read(ctx, "missing"); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("read missing = %v, want ErrDenied wrapping context.Canceled", err)
	}
	if got := ctx.calls.Load(); got != 3 {
		t.Fatalf("read made %d Err calls, want 3 (post-lock)", got)
	}
	if m.seq != 0 {
		t.Fatalf("cancelled read advanced seq to %d", m.seq)
	}
	if m.closed {
		t.Fatal("cancelled read closed the backend")
	}
	if len(m.values) != 0 {
		t.Fatalf("cancelled read changed state: %v", m.values)
	}
}

// TestMemoryListCancelledAfterLock covers the post-lock check on List's
// unsupported path: a cancelled caller must see the cancellation, not
// ErrUnsupported, and must not mutate state.
func TestMemoryListCancelledAfterLock(t *testing.T) {
	m := NewMemory()
	// List has no pre-lock check of its own; memoryLock.lock checks Err before
	// waiting (1) and List checks again right after locking (2). Cancelling at
	// call 2 proves the named post-lock phase ran.
	ctx := idleHookContext(2)
	if _, err := m.List(ctx); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("list = %v, want ErrDenied wrapping context.Canceled", err)
	}
	if got := ctx.calls.Load(); got != 2 {
		t.Fatalf("list made %d Err calls, want 2 (post-lock)", got)
	}
	if m.seq != 0 {
		t.Fatalf("cancelled list advanced seq to %d", m.seq)
	}
	if m.closed {
		t.Fatal("cancelled list closed the backend")
	}
	if len(m.values) != 0 {
		t.Fatalf("cancelled list changed state: %v", m.values)
	}
}

// TestMemoryReadCancelledAfterCopyIsDenied covers cancellation after the
// stored bytes were copied: Read must return nothing.
func TestMemoryReadCancelledAfterCopyIsDenied(t *testing.T) {
	m := NewMemory()
	m.values["n"] = memoryVersion{bytes: []byte("v1"), revision: Revision("seed")}

	// Pre-lock check 1, memoryLock.lock's check 2, post-lock check 3,
	// post-copy check 4.
	ctx := idleHookContext(4)
	got, err := m.Read(ctx, "n")
	if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("read = %v, want ErrDenied wrapping context.Canceled", err)
	}
	if got.Bytes != nil || got.Revision != "" {
		t.Fatalf("cancelled read returned %q %q", got.Bytes, got.Revision)
	}
}

// TestMemoryWriteCancelledAfterCopyNotCommitted covers cancellation after
// commit copied value but before installing it: the write must not commit, the
// revision counter must not advance, and a later write succeeds normally.
func TestMemoryWriteCancelledAfterCopyNotCommitted(t *testing.T) {
	for _, tc := range []struct {
		name string
		// begin is the Err call that first reports cancellation.
		begin int32
		call  func(ctx context.Context, m *Memory) error
	}{
		// Create: pre-lock 1, memoryLock.lock's check 2, post-lock 3,
		// commit post-copy 4.
		{"create", 4, func(ctx context.Context, m *Memory) error {
			return m.CreateIfAbsent(ctx, "new", []byte("new"))
		}},
		// Replace: pre-lock 1, memoryLock.lock's check 2, post-lock 3,
		// commit post-copy 4.
		{"replace", 4, func(ctx context.Context, m *Memory) error {
			return m.ReplaceIfVersion(ctx, "n", Revision("seed"), []byte("v2"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMemory()
			m.values["n"] = memoryVersion{bytes: []byte("v1"), revision: Revision("seed")}
			err := tc.call(idleHookContext(tc.begin), m)
			if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
				t.Fatalf("%s = %v, want ErrDenied wrapping context.Canceled", tc.name, err)
			}
			if m.seq != 0 {
				t.Fatalf("cancelled %s advanced seq to %d", tc.name, m.seq)
			}
			if _, ok := m.values["new"]; ok {
				t.Fatal("cancelled create installed a version")
			}
			if cur := m.values["n"]; string(cur.bytes) != "v1" || cur.revision != Revision("seed") {
				t.Fatalf("cancelled %s changed n: %q %q", tc.name, cur.bytes, cur.revision)
			}
			if err := m.CreateIfAbsent(context.Background(), "n3", []byte("ok")); err != nil {
				t.Fatalf("write after cancelled %s: %v", tc.name, err)
			}
		})
	}
}
