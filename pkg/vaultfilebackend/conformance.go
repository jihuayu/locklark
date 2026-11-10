package vaultfilebackend

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// openFunc opens one backend for a conformance run.
type openFunc func(t *testing.T) Backend

// RunConformance runs the shared contract suite. Every driver must pass it with
// its own backend, and must not special-case subtests by name.
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
		if err != nil || !bytes.Equal(got.Bytes, value) || got.Token.Zero() {
			t.Fatalf("read after create = %q, %v, token zero=%v", got.Bytes, err, got.Token.Zero())
		}
		// Mutating the caller's buffer must not change stored state.
		value[0] = 'X'
		again, err := b.Read(ctx, "vault.db")
		if err != nil || again.Token != got.Token || bytes.Equal(again.Bytes, value) {
			t.Fatal("stored value aliased or token changed without a write")
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
		if err := b.ReplaceIfVersion(ctx, "n", first.Token, []byte("v2")); err != nil {
			t.Fatalf("replace: %v", err)
		}
		second, err := b.Read(ctx, "n")
		if err != nil || string(second.Bytes) != "v2" || second.Token == first.Token {
			t.Fatalf("after replace = %q, %v", second.Bytes, err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", first.Token, []byte("stale")); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale replace = %v, want ErrConflict", err)
		}
		if cur, err := b.Read(ctx, "n"); err != nil || string(cur.Bytes) != "v2" || cur.Token != second.Token {
			t.Fatal("conflicting replace changed the stored version")
		}
		if err := b.ReplaceIfVersion(ctx, "missing", second.Token, []byte("x")); !errors.Is(err, ErrConflict) {
			t.Fatalf("replace missing = %v, want ErrConflict", err)
		}
		if err := b.ReplaceIfVersion(ctx, "n", Token{}, []byte("x")); !errors.Is(err, ErrDenied) {
			t.Fatalf("replace with zero token = %v, want ErrDenied", err)
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
		if err := b.ReplaceIfVersion(ctx, "n", cur.Token, []byte("done")); err != nil {
			t.Fatal(err)
		}
		after, err := b.Read(ctx, "n")
		if err != nil {
			t.Fatal(err)
		}
		// An unknown outcome is resolved by retrying the identical write with
		// the observed token, which leaves the committed bytes in place.
		if err := b.ReplaceIfVersion(ctx, "n", after.Token, []byte("done")); err != nil {
			t.Fatalf("idempotent retry = %v", err)
		}
		if got, _ := b.Read(ctx, "n"); string(got.Bytes) != "done" {
			t.Fatal("retry changed bytes")
		}
		if err := b.ReplaceIfVersion(ctx, "n", cur.Token, []byte("stale")); !errors.Is(err, ErrConflict) {
			t.Fatalf("retry with pre-write token = %v, want ErrConflict", err)
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
					err := b.ReplaceIfVersion(ctx, name, base.Token, []byte{byte(i), byte(round)})
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
		if err := b.CreateIfAbsent(ctx, "ok", make([]byte, MaxValueSize)); err != nil {
			t.Fatalf("max value = %v", err)
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

	t.Run("list_unsupported", func(t *testing.T) {
		b := f(t)
		if _, err := b.List(ctx); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("list = %v, want ErrUnsupported", err)
		}
	})

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
			if err != nil || !bytes.Equal(again.Bytes, []byte("v1")) || again.Token != first.Token {
				t.Fatalf("reopen read = %q %v, token equal=%v", again.Bytes, err, again.Token == first.Token)
			}
			if err := b2.ReplaceIfVersion(ctx, "d", first.Token, []byte("v2")); err != nil {
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
