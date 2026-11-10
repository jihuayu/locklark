package vaultfilebackend

import (
	"context"
	"errors"
	"sync"
	"testing"
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
	if err := b.CreateIfAbsent(ctx, "y", []byte("same")); err != nil {
		t.Fatal(err)
	}
	ra, _ := a.Read(ctx, "x")
	rb, _ := b.Read(ctx, "y")
	if ra.Revision.Zero() || rb.Revision.Zero() {
		t.Fatal("Memory must mint non-zero revisions")
	}
	// Revisions are opaque: not required to be equal across instances or
	// derivable from bytes, and a revision from one store must not authorize a
	// write in another.
	if err := b.CreateIfAbsent(ctx, "x", []byte("same")); err != nil {
		t.Fatal(err)
	}
	if err := b.ReplaceIfVersion(ctx, "x", ra.Revision, []byte("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign revision = %v, want ErrConflict", err)
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
	e.Memory.mu.Lock()
	v := e.Memory.values[name]
	v.revision = Revision(e.etag)
	e.Memory.values[name] = v
	e.Memory.mu.Unlock()
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

func TestMemoryCancelWhileWaitingForLockDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	t.Cleanup(func() { _ = m.Close() })
	if err := m.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	cur, err := m.Read(ctx, "n")
	if err != nil {
		t.Fatal(err)
	}
	// Hold the lock: the writers below must queue on it.
	m.mu.Lock()
	locked := true
	unlock := sync.OnceFunc(func() {
		locked = false
		m.mu.Unlock()
	})
	t.Cleanup(func() {
		if locked {
			unlock()
		}
	})

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var started, done sync.WaitGroup
	var createErr, replaceErr error
	started.Add(2)
	done.Add(2)
	go func() {
		defer done.Done()
		started.Done()
		createErr = m.CreateIfAbsent(wctx, "n2", []byte("new"))
	}()
	go func() {
		defer done.Done()
		started.Done()
		replaceErr = m.ReplaceIfVersion(wctx, "n", cur.Revision, []byte("v2"))
	}()
	started.Wait()

	// Cancel while both writers are queued on the held lock.
	cancel()
	unlock()
	done.Wait()

	if !errors.Is(createErr, ErrDenied) || !errors.Is(createErr, context.Canceled) {
		t.Fatalf("cancelled create = %v, want ErrDenied wrapping context.Canceled", createErr)
	}
	if !errors.Is(replaceErr, ErrDenied) || !errors.Is(replaceErr, context.Canceled) {
		t.Fatalf("cancelled replace = %v, want ErrDenied wrapping context.Canceled", replaceErr)
	}
	if _, err := m.Read(ctx, "n2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled create wrote state: %v", err)
	}
	if got, err := m.Read(ctx, "n"); err != nil || string(got.Bytes) != "v1" || got.Revision != cur.Revision {
		t.Fatalf("cancelled replace wrote state: %q %v", got.Bytes, err)
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
