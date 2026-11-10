package vaultfilebackend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// openFunc opens one backend for a conformance run.
type openFunc func(t *testing.T) Backend

// RunConformance runs the shared contract suite. Every driver must pass it with
// its own backend, and must not special-case subtests by name.
//
// The suite pins the contract, not the revision scheme: it requires revisions
// to be opaque, non-zero, bounded, and to change whenever bytes change, but it
// never requires them to be derived from the bytes or shared across backends
// or stores.
//
// open is called for each subtest and the backend is closed afterwards. reopen
// returns a fresh backend over the same durable state (a new instance rooted at
// the same directory); pass nil only for non-durable backends such as Memory,
// which skips the durability subtests.
func RunConformance(t *testing.T, open openFunc, reopen openFunc) {
	t.Helper()
	ctx := context.Background()
	f := func(t *testing.T) Backend {
		b := open(t)
		t.Cleanup(func() { _ = b.Close() })
		return b
	}

	t.Run("create_read_roundtrip", func(t *testing.T) {
		b := f(t)
		value := []byte("opaque encrypted payload")
		if err := b.CreateIfAbsent(ctx, "vault.db", value); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := b.Read(ctx, "vault.db")
		if err != nil || !bytes.Equal(got.Bytes, value) || got.Revision.Zero() {
			t.Fatalf("read after create = %q, %v, zero revision=%v", got.Bytes, err, got.Revision.Zero())
		}
		if len(got.Revision) > MaxRevisionSize {
			t.Fatalf("revision length %d exceeds MaxRevisionSize", len(got.Revision))
		}
		// Mutating the caller's buffer must not change stored state.
		value[0] = 'X'
		again, err := b.Read(ctx, "vault.db")
		if err != nil || again.Revision != got.Revision || bytes.Equal(again.Bytes, value) {
			t.Fatal("stored value aliased or revision changed without a write")
		}
		value[0] = 'o'
		if err := b.CreateIfAbsent(ctx, "vault.db", []byte("second")); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate create = %v, want ErrConflict", err)
		}
	})

	t.Run("read_missing", func(t *testing.T) {
		b := f(t)
		if _, err := b.Read(ctx, "absent"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("read missing = %v, want ErrNotFound", err)
		}
	})

	t.Run("replace_if_version", func(t *testing.T) {
		b := f(t)
		if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
			t.Fatal(err)
		}
		first, err := b.Read(ctx, "n")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", first.Revision, []byte("v2")); err != nil {
			t.Fatalf("replace: %v", err)
		}
		second, err := b.Read(ctx, "n")
		if err != nil || string(second.Bytes) != "v2" || second.Revision == first.Revision {
			t.Fatalf("after replace = %q, %v", second.Bytes, err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", first.Revision, []byte("stale")); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale replace = %v, want ErrConflict", err)
		}
		if cur, err := b.Read(ctx, "n"); err != nil || string(cur.Bytes) != "v2" || cur.Revision != second.Revision {
			t.Fatal("conflicting replace changed the stored version")
		}
		if err := b.ReplaceIfVersion(ctx, "missing", second.Revision, []byte("x")); !errors.Is(err, ErrConflict) {
			t.Fatalf("replace missing = %v, want ErrConflict", err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", Revision(""), []byte("x")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace with zero revision = %v, want ErrDenied", err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", Revision(strings.Repeat("r", MaxRevisionSize+1)), []byte("x")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace with oversize revision = %v, want ErrDenied", err)
		}
		if cur, err := b.Read(ctx, "n"); err != nil || string(cur.Bytes) != "v2" || cur.Revision != second.Revision {
			t.Fatal("malformed revision changed the stored version")
		}
	})

	t.Run("same_token_retry", func(t *testing.T) {
		b := f(t)
		if err := b.CreateIfAbsent(ctx, "n", []byte("v1")); err != nil {
			t.Fatal(err)
		}
		cur, err := b.Read(ctx, "n")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("done")); err != nil {
			t.Fatal(err)
		}
		after, err := b.Read(ctx, "n")
		if err != nil {
			t.Fatal(err)
		}
		// A write whose outcome was unknown is resolved by observing the
		// current revision; retrying with the pre-write revision conflicts.
		if after.Revision == cur.Revision {
			t.Fatal("a committed replace must change the revision")
		}
		if got, _ := b.Read(ctx, "n"); string(got.Bytes) != "done" {
			t.Fatal("retry changed bytes")
		}
		if err := b.ReplaceIfVersion(ctx, "n", cur.Revision, []byte("stale")); !errors.Is(err, ErrConflict) {
			t.Fatalf("retry with pre-write revision = %v, want ErrConflict", err)
		}
	})

	// Of concurrent writers racing on one token, exactly one commits.
	t.Run("concurrent_same_token_single_winner", func(t *testing.T) {
		for round := range 20 {
			name := "race"
			b := f(t)
			if err := b.CreateIfAbsent(ctx, name, []byte("base")); err != nil {
				t.Fatal(err)
			}
			base, err := b.Read(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			const writers = 8
			var wins, conflicts atomic.Int32
			var otherMu sync.Mutex
			var other []error
			var start, done sync.WaitGroup
			start.Add(1)
			for i := range writers {
				done.Add(1)
				go func(i int) {
					defer done.Done()
					start.Wait()
					err := b.ReplaceIfVersion(ctx, name, base.Revision, []byte{byte(i), byte(round)})
					switch {
					case err == nil:
						wins.Add(1)
					case errors.Is(err, ErrConflict):
						conflicts.Add(1)
					default:
						otherMu.Lock()
						other = append(other, err)
						otherMu.Unlock()
					}
				}(i)
			}
			start.Done()
			done.Wait()
			if len(other) != 0 {
				t.Fatalf("round %d unexpected errors: %v", round, other)
			}
			if wins.Load() != 1 || conflicts.Load() != writers-1 {
				t.Fatalf("round %d wins=%d conflicts=%d, want 1/%d", round, wins.Load(), conflicts.Load(), writers-1)
			}
		}
	})

	t.Run("concurrent_create_single_winner", func(t *testing.T) {
		b := f(t)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				err := b.CreateIfAbsent(ctx, "once", []byte{byte(i)})
				if err == nil {
					wins.Add(1)
				} else if !errors.Is(err, ErrConflict) {
					t.Errorf("create race: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("wins = %d, want 1", wins.Load())
		}
	})

	t.Run("validation", func(t *testing.T) {
		b := f(t)
		for _, name := range []string{"", ".", "..", "a/b", `a\b`, "../x", ".hidden", "trail.", "trail ", "nul\x00", "\xff", string(make([]byte, MaxNameSize+1))} {
			if err := b.CreateIfAbsent(ctx, name, []byte("v")); !errors.Is(err, ErrDenied) {
				t.Fatalf("create %q = %v, want ErrDenied", name, err)
			}
			if _, err := b.Read(ctx, name); !errors.Is(err, ErrDenied) {
				t.Fatalf("read %q = %v, want ErrDenied", name, err)
			}
		}
		if err := b.CreateIfAbsent(ctx, "ok", nil); !errors.Is(err, ErrDenied) {
			t.Fatalf("empty value = %v, want ErrDenied", err)
		}
		if err := b.CreateIfAbsent(ctx, "ok", make([]byte, MaxValueSize+1)); !errors.Is(err, ErrDenied) {
			t.Fatalf("oversize value = %v, want ErrDenied", err)
		}
	})

	t.Run("full_file_budget", func(t *testing.T) {
		b := f(t)
		if MaxValueSize != 32<<20 {
			t.Fatalf("MaxValueSize = %d, want 32 MiB for the complete file", MaxValueSize)
		}
		if err := b.CreateIfAbsent(ctx, "full", make([]byte, MaxValueSize)); err != nil {
			t.Fatalf("max value = %v", err)
		}
		got, err := b.Read(ctx, "full")
		if err != nil || len(got.Bytes) != MaxValueSize {
			t.Fatalf("read max value = %d bytes, %v", len(got.Bytes), err)
		}
		cur, err := b.Read(ctx, "full")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ReplaceIfVersion(ctx, "full", cur.Revision, make([]byte, MaxValueSize+1)); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace oversize value = %v, want ErrDenied", err)
		}
		if err := b.ReplaceIfVersion(ctx, "full", cur.Revision, make([]byte, MaxValueSize)); err != nil {
			t.Fatalf("replace at max value = %v", err)
		}
	})

	// A revision is compared verbatim: no trimming, no quote folding.
	t.Run("revision_compared_verbatim", func(t *testing.T) {
		b := f(t)
		if err := b.CreateIfAbsent(ctx, "etag", []byte("v1")); err != nil {
			t.Fatal(err)
		}
		first, err := b.Read(ctx, "etag")
		if err != nil {
			t.Fatal(err)
		}
		again, err := b.Read(ctx, "etag")
		if err != nil || again.Revision != first.Revision {
			t.Fatalf("revision round trip = %q, %v", again.Revision, err)
		}
		if len([]byte(first.Revision)) > MaxRevisionSize {
			t.Fatalf("revision length %d exceeds MaxRevisionSize", len(first.Revision))
		}
		if err := b.ReplaceIfVersion(ctx, "etag", Revision(`"`+string(first.Revision)+`"`), []byte("v2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("revision wrapped in quotes = %v, want ErrConflict", err)
		}
		if err := b.ReplaceIfVersion(ctx, "etag", first.Revision+" ", []byte("v2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("revision with trailing space = %v, want ErrConflict", err)
		}
		if cur, err := b.Read(ctx, "etag"); err != nil || string(cur.Bytes) != "v1" {
			t.Fatal("non-matching revision changed the stored version")
		}
	})

	t.Run("cancelled_before_start", func(t *testing.T) {
		b := f(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := b.CreateIfAbsent(cctx, "c", []byte("v")); !errors.Is(err, ErrDenied) {
			t.Fatalf("cancelled create = %v, want ErrDenied", err)
		}
		if _, err := b.Read(cctx, "c"); !errors.Is(err, ErrDenied) {
			t.Fatalf("cancelled read = %v, want ErrDenied", err)
		}
		if _, err := b.Read(ctx, "c"); !errors.Is(err, ErrNotFound) {
			t.Fatal("cancelled create wrote state")
		}
	})

	if reopen == nil {
		t.Run("list_unsupported", func(t *testing.T) {
			b := f(t)
			if _, err := b.List(ctx); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("list = %v, want ErrUnsupported", err)
			}
		})
	}

	t.Run("close", func(t *testing.T) {
		b := open(t)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("second close = %v", err)
		}
		if err := b.CreateIfAbsent(ctx, "after", []byte("v")); !errors.Is(err, ErrDenied) {
			t.Fatalf("create after close = %v, want ErrDenied", err)
		}
		if _, err := b.Read(ctx, "after"); !errors.Is(err, ErrDenied) {
			t.Fatalf("read after close = %v, want ErrDenied", err)
		}
		if err := b.ReplaceIfVersion(ctx, "after", Revision("1"), []byte("v")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace after close = %v, want ErrDenied", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrDenied) {
			t.Fatalf("list after close = %v, want ErrDenied", err)
		}
	})

	if reopen != nil {
		t.Run("durable_across_reopen", func(t *testing.T) {
			b := open(t)
			if err := b.CreateIfAbsent(ctx, "d", []byte("v1")); err != nil {
				t.Fatal(err)
			}
			first, err := b.Read(ctx, "d")
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			b2 := reopen(t)
			defer b2.Close()
			again, err := b2.Read(ctx, "d")
			if err != nil || !bytes.Equal(again.Bytes, []byte("v1")) || again.Revision != first.Revision {
				t.Fatalf("reopen read = %q %v, revision equal=%v", again.Bytes, err, again.Revision == first.Revision)
			}
			if err := b2.ReplaceIfVersion(ctx, "d", first.Revision, []byte("v2")); err != nil {
				t.Fatalf("reopen replace: %v", err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			b3 := reopen(t)
			defer b3.Close()
			if got, err := b3.Read(ctx, "d"); err != nil || string(got.Bytes) != "v2" {
				t.Fatalf("after reopen replace = %q %v", got.Bytes, err)
			}
			if err := b3.CreateIfAbsent(ctx, "d", []byte("v3")); !errors.Is(err, ErrConflict) {
				t.Fatal("reopen duplicate create must conflict")
			}
		})
	}
}
