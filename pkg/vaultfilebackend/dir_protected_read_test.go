//go:build darwin || linux

package vaultfilebackend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openProtectedReadTestDir(t *testing.T, root string) *Dir {
	t.Helper()
	d, err := OpenExistingDir(root)
	if err != nil {
		t.Fatalf("open existing dir: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

type protectedReadTestFixture struct {
	root     string
	reader   *Dir
	writer   *Dir
	revision Revision
	value    []byte
}

func newProtectedReadTestFixtureAt(t *testing.T, root string) protectedReadTestFixture {
	t.Helper()
	setup := openAt(t, root).(*Dir)
	value := []byte("alpha-value")
	if err := setup.CreateIfAbsent(context.Background(), "alpha", value); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, setup, "alpha")
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}
	return protectedReadTestFixture{
		root:     root,
		reader:   openProtectedReadTestDir(t, root),
		writer:   openProtectedReadTestDir(t, root),
		revision: got.Revision,
		value:    append([]byte(nil), got.Bytes...),
	}
}

func newProtectedReadTestFixture(t *testing.T) protectedReadTestFixture {
	t.Helper()
	return newProtectedReadTestFixtureAt(t, filepath.Join(t.TempDir(), "root"))
}

func assertProtectedReadTestTreeUnchanged(t *testing.T, root string, before map[string]existingTreeEntry) {
	t.Helper()
	if !maps.Equal(before, existingTree(t, root)) {
		t.Fatal("protected read scope mutated the backend tree")
	}
}

// The protected view serves exact bytes and opaque revisions for two names from
// the same store while the normal writers block on the same in-process and OS
// lock. After the callback returns, both writers commit normally.
func TestIssue120LocalDirProtectedReadExactRecordsAndWriterFence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	setup := openAt(t, root).(*Dir)
	if err := setup.CreateIfAbsent(ctx, "alpha", []byte("alpha-value")); err != nil {
		t.Fatal(err)
	}
	if err := setup.CreateIfAbsent(ctx, "beta", []byte("beta-value")); err != nil {
		t.Fatal(err)
	}
	alpha := mustRead(t, setup, "alpha")
	beta := mustRead(t, setup, "beta")
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	reader := openProtectedReadTestDir(t, root)
	creator := openProtectedReadTestDir(t, root)
	replacer := openProtectedReadTestDir(t, root)
	// A short deadline keeps the contending writers deterministic and proves
	// the scope reports the same bounded conflict as any other operation.
	creator.timeout = 80 * time.Millisecond
	replacer.timeout = 80 * time.Millisecond

	var saved *ProtectedReadView
	err := reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
		saved = view

		gotAlpha, err := view.Read(ctx, "alpha")
		if err != nil {
			return fmt.Errorf("scope read alpha: %w", err)
		}
		if !bytes.Equal(gotAlpha.Bytes, alpha.Bytes) || gotAlpha.Revision != alpha.Revision {
			return fmt.Errorf("scope alpha = %q/%q, want %q/%q", gotAlpha.Bytes, gotAlpha.Revision, alpha.Bytes, alpha.Revision)
		}
		gotBeta, err := view.Read(ctx, "beta")
		if err != nil {
			return fmt.Errorf("scope read beta: %w", err)
		}
		if !bytes.Equal(gotBeta.Bytes, beta.Bytes) || gotBeta.Revision != beta.Revision {
			return fmt.Errorf("scope beta = %q/%q, want %q/%q", gotBeta.Bytes, gotBeta.Revision, beta.Bytes, beta.Revision)
		}
		if _, err := view.Read(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("scope read missing = %v, want ErrNotFound", err)
		}
		if _, err := view.Read(ctx, "bad/name"); !errors.Is(err, ErrDenied) {
			return fmt.Errorf("scope read invalid name = %v, want ErrDenied", err)
		}

		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- creator.CreateIfAbsent(ctx, "gamma", []byte("gamma-value"))
		}()
		go func() {
			defer wg.Done()
			errs <- replacer.ReplaceIfVersion(ctx, "alpha", alpha.Revision, []byte("alpha-new"))
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknown) {
				return fmt.Errorf("writer under held scope = %v, want definite ErrConflict", err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A saved view is not reusable authority.
	if got, err := saved.Read(ctx, "alpha"); !errors.Is(err, ErrDenied) || len(got.Bytes) != 0 {
		t.Fatalf("escaped view read = %v/%v, want ErrDenied and no bytes", got, err)
	}

	// The failed writers left the store untouched.
	if _, err := reader.Read(ctx, "gamma"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed create wrote gamma: %v", err)
	}
	if got := mustRead(t, reader, "alpha"); !bytes.Equal(got.Bytes, alpha.Bytes) || got.Revision != alpha.Revision {
		t.Fatal("failed replace changed alpha")
	}

	// The same writer handles now succeed with their original revisions.
	if err := creator.CreateIfAbsent(ctx, "gamma", []byte("gamma-value")); err != nil {
		t.Fatalf("create after scope release: %v", err)
	}
	if err := replacer.ReplaceIfVersion(ctx, "alpha", alpha.Revision, []byte("alpha-new")); err != nil {
		t.Fatalf("replace after scope release: %v", err)
	}
	gotAlpha := mustRead(t, reader, "alpha")
	if !bytes.Equal(gotAlpha.Bytes, []byte("alpha-new")) || gotAlpha.Revision == alpha.Revision {
		t.Fatalf("alpha after release = %q/%q", gotAlpha.Bytes, gotAlpha.Revision)
	}
	gotBeta := mustRead(t, reader, "beta")
	if !bytes.Equal(gotBeta.Bytes, beta.Bytes) || gotBeta.Revision != beta.Revision {
		t.Fatal("beta changed without a write")
	}
	gotGamma := mustRead(t, reader, "gamma")
	if !bytes.Equal(gotGamma.Bytes, []byte("gamma-value")) {
		t.Fatalf("gamma after release = %q", gotGamma.Bytes)
	}
}

func TestIssue120LocalDirProtectedReadEscapedViewRefuses(t *testing.T) {
	ctx := context.Background()
	f := newProtectedReadTestFixture(t)

	var saved *ProtectedReadView
	if err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
		saved = view
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	copied := *saved
	for name, view := range map[string]*ProtectedReadView{
		"saved":  saved,
		"copied": &copied,
		"nil":    nil,
		"zero":   {},
	} {
		got, err := view.Read(ctx, "alpha")
		if !errors.Is(err, ErrDenied) || len(got.Bytes) != 0 || got.Revision != "" {
			t.Fatalf("%s view read = %v/%q, want ErrDenied and no result", name, err, got.Bytes)
		}
	}

	// An old view stays invalid even while the same Dir holds a new scope; the
	// new view is the only live authority.
	if err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
		if _, err := saved.Read(ctx, "alpha"); !errors.Is(err, ErrDenied) {
			return fmt.Errorf("old view during new scope = %v, want ErrDenied", err)
		}
		if got, err := view.Read(ctx, "alpha"); err != nil || !bytes.Equal(got.Bytes, f.value) {
			return fmt.Errorf("new view read = %q/%v", got.Bytes, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Reads that start while the scope is live may finish, but every read that
// reaches the saved view after the scope is withdrawn is refused, including the
// contenders that race the callback's return and the physical lock release.
func TestIssue120LocalDirProtectedReadViewRaceWithRelease(t *testing.T) {
	ctx := context.Background()
	f := newProtectedReadTestFixture(t)

	var saved *ProtectedReadView
	start := make(chan struct{})
	var startOnce sync.Once
	beginStart := func() { startOnce.Do(func() { close(start) }) }
	stop := make(chan struct{})
	firstSuccess := make(chan struct{})
	var first sync.Once
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad error
	successes := 0

	recordBad := func(err error) {
		mu.Lock()
		if bad == nil {
			bad = err
		}
		mu.Unlock()
	}
	stopReaders := func() { close(stop) }

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case <-stop:
					// The final read always begins after the scope and its OS
					// lock were released, so it must not retain any authority.
					got, err := saved.Read(ctx, "alpha")
					if !errors.Is(err, ErrDenied) || len(got.Bytes) != 0 || got.Revision != "" {
						recordBad(fmt.Errorf("read after release = %v/%q, want ErrDenied and no result", err, got.Bytes))
					}
					return
				default:
				}
				_, err := saved.Read(ctx, "alpha")
				if err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
					first.Do(func() { close(firstSuccess) })
					continue
				}
				if !errors.Is(err, ErrDenied) {
					recordBad(fmt.Errorf("live scope read = %v, want nil or ErrDenied", err))
					return
				}
			}
		}()
	}

	err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
		saved = view
		beginStart()
		select {
		case <-firstSuccess:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("no reader completed a read under the scope")
		}
	})
	// If entry was refused before the callback, release the readers with the
	// zero capability; they must still refuse every read.
	beginStart()
	stopReaders()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if bad != nil {
		t.Fatal(bad)
	}
	if successes == 0 {
		t.Fatal("no read completed while the scope was live")
	}
}

func TestIssue120LocalDirProtectedReadReleasesOnErrorAndPanic(t *testing.T) {
	ctx := context.Background()
	f := newProtectedReadTestFixture(t)

	before := existingTree(t, f.root)
	callbackErr := errors.New("callback stopped")
	if err := f.reader.WithProtectedRead(ctx, func(*ProtectedReadView) error {
		return callbackErr
	}); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error = %v, want the callback error", err)
	}
	assertProtectedReadTestTreeUnchanged(t, f.root, before)
	if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-error")); err != nil {
		t.Fatalf("write after callback error: %v", err)
	}

	afterError := mustRead(t, f.reader, "alpha")
	before = existingTree(t, f.root)
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_ = f.reader.WithProtectedRead(ctx, func(*ProtectedReadView) error {
			panic("scope panic")
		})
	}()
	if !panicked {
		t.Fatal("scope did not propagate the callback panic")
	}
	assertProtectedReadTestTreeUnchanged(t, f.root, before)
	if err := f.writer.ReplaceIfVersion(ctx, "alpha", afterError.Revision, []byte("after-panic")); err != nil {
		t.Fatalf("write after callback panic: %v", err)
	}
	if got := mustRead(t, f.reader, "alpha"); !bytes.Equal(got.Bytes, []byte("after-panic")) {
		t.Fatalf("alpha after panic = %q", got.Bytes)
	}
}

func TestIssue120LocalDirProtectedReadRefusesEntry(t *testing.T) {
	ctx := context.Background()
	f := newProtectedReadTestFixture(t)
	before := existingTree(t, f.root)
	ran := false

	if err := f.reader.WithProtectedRead(ctx, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("nil callback = %v, want ErrDenied", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.reader.WithProtectedRead(cctx, func(*ProtectedReadView) error {
		ran = true
		return nil
	}); !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled entry = %v, want ErrDenied wrapping context.Canceled", err)
	}
	if ran {
		t.Fatal("pre-canceled entry ran the callback")
	}
	if err := f.reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.reader.WithProtectedRead(ctx, func(*ProtectedReadView) error {
		ran = true
		return nil
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("closed backend entry = %v, want ErrDenied", err)
	}
	if ran {
		t.Fatal("closed backend entry ran the callback")
	}
	assertProtectedReadTestTreeUnchanged(t, f.root, before)
	if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-refusal")); err != nil {
		t.Fatalf("write after refused entries: %v", err)
	}
}

func TestIssue120LocalDirProtectedReadCancellationAndClose(t *testing.T) {
	t.Run("acquire_canceled", func(t *testing.T) {
		ctx := context.Background()
		f := newProtectedReadTestFixture(t)
		before := existingTree(t, f.root)

		if err := f.reader.inProc.acquire(ctx, time.Time{}); err != nil {
			t.Fatal(err)
		}
		held := true
		defer func() {
			if held {
				f.reader.inProc.release()
			}
		}()

		cctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		callbackRan := make(chan struct{}, 1)
		go func() {
			done <- f.reader.WithProtectedRead(cctx, func(*ProtectedReadView) error {
				callbackRan <- struct{}{}
				return nil
			})
		}()
		time.Sleep(10 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnknown) {
				t.Fatalf("canceled acquisition = %v, want ErrDenied wrapping context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled acquisition did not return")
		}
		select {
		case <-callbackRan:
			t.Fatal("canceled acquisition ran the callback")
		default:
		}
		assertProtectedReadTestTreeUnchanged(t, f.root, before)
		f.reader.inProc.release()
		held = false
		if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-cancel")); err != nil {
			t.Fatalf("write after canceled acquisition: %v", err)
		}
	})

	t.Run("acquire_timeout", func(t *testing.T) {
		ctx := context.Background()
		f := newProtectedReadTestFixture(t)
		before := existingTree(t, f.root)
		f.reader.timeout = 40 * time.Millisecond

		if err := f.reader.inProc.acquire(ctx, time.Time{}); err != nil {
			t.Fatal(err)
		}
		held := true
		defer func() {
			if held {
				f.reader.inProc.release()
			}
		}()
		err := f.reader.WithProtectedRead(ctx, func(*ProtectedReadView) error {
			t.Error("timed-out scope ran the callback")
			return nil
		})
		if !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknown) {
			t.Fatalf("timed-out acquisition = %v, want definite ErrConflict", err)
		}
		assertProtectedReadTestTreeUnchanged(t, f.root, before)
		f.reader.inProc.release()
		held = false
		if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-timeout")); err != nil {
			t.Fatalf("write after timed-out acquisition: %v", err)
		}
	})

	t.Run("per_read_cancel_live_scope", func(t *testing.T) {
		ctx := context.Background()
		f := newProtectedReadTestFixture(t)
		before := existingTree(t, f.root)

		err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
			if got, err := view.Read(ctx, "alpha"); err != nil || !bytes.Equal(got.Bytes, f.value) {
				return fmt.Errorf("read before cancellation = %q/%v", got.Bytes, err)
			}
			readCtx, cancel := context.WithCancel(ctx)
			cancel()
			got, err := view.Read(readCtx, "alpha")
			if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) ||
				len(got.Bytes) != 0 || got.Revision != "" {
				return fmt.Errorf("read with canceled per-read context = %v/%q/%q, want ErrDenied wrapping context.Canceled and no result", err, got.Bytes, got.Revision)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("live scope with canceled per-read context = %v, want nil", err)
		}
		assertProtectedReadTestTreeUnchanged(t, f.root, before)
		if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-per-read-cancel")); err != nil {
			t.Fatalf("write after per-read cancellation: %v", err)
		}
	})

	t.Run("outer_cancel_live_per_read", func(t *testing.T) {
		ctx := context.Background()
		f := newProtectedReadTestFixture(t)
		before := existingTree(t, f.root)
		outerCtx, cancelOuter := context.WithCancel(ctx)

		err := f.reader.WithProtectedRead(outerCtx, func(view *ProtectedReadView) error {
			if got, err := view.Read(ctx, "alpha"); err != nil || !bytes.Equal(got.Bytes, f.value) {
				return fmt.Errorf("read before outer cancellation = %q/%v", got.Bytes, err)
			}
			cancelOuter()
			// The per-read context is still live; the retained outer context
			// must still deny the read and release no record bytes or revision.
			got, err := view.Read(context.Background(), "alpha")
			if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) ||
				len(got.Bytes) != 0 || got.Revision != "" {
				return fmt.Errorf("read after outer cancellation with live per-read context = %v/%q/%q, want ErrDenied wrapping context.Canceled and no result", err, got.Bytes, got.Revision)
			}
			return nil
		})
		if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
			t.Fatalf("scope with canceled outer context = %v, want ErrDenied wrapping context.Canceled", err)
		}
		assertProtectedReadTestTreeUnchanged(t, f.root, before)
		if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-outer-cancel")); err != nil {
			t.Fatalf("write after outer cancellation: %v", err)
		}
	})

	t.Run("closed_during_scope", func(t *testing.T) {
		ctx := context.Background()
		f := newProtectedReadTestFixture(t)
		before := existingTree(t, f.root)

		err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
			if err := f.reader.Close(); err != nil {
				return err
			}
			got, err := view.Read(ctx, "alpha")
			if !errors.Is(err, ErrDenied) || len(got.Bytes) != 0 {
				return fmt.Errorf("read after close = %v/%q, want ErrDenied and no bytes", err, got.Bytes)
			}
			return nil
		})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("scope closed during callback = %v, want ErrDenied", err)
		}
		assertProtectedReadTestTreeUnchanged(t, f.root, before)
		if err := f.writer.ReplaceIfVersion(ctx, "alpha", f.revision, []byte("after-close")); err != nil {
			t.Fatalf("write after close released the scope: %v", err)
		}
	})
}

func TestIssue120LocalDirProtectedReadIdentityDrift(t *testing.T) {
	drift := map[string]func(*testing.T, *Dir){
		"root_replaced": func(t *testing.T, d *Dir) {
			t.Helper()
			if err := os.Rename(d.cfgRoot, d.cfgRoot+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(d.cfgRoot, 0700); err != nil {
				t.Fatal(err)
			}
		},
		"data_replaced": func(t *testing.T, d *Dir) {
			t.Helper()
			data := filepath.Join(d.root, dataName)
			if err := os.Rename(data, data+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
		},
		"lock_replaced": func(t *testing.T, d *Dir) {
			t.Helper()
			lock := filepath.Join(d.root, lockName)
			if err := os.Rename(lock, lock+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"lock_missing": func(t *testing.T, d *Dir) {
			t.Helper()
			lock := filepath.Join(d.root, lockName)
			if err := os.Rename(lock, lock+"-moved"); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, replace := range drift {
		t.Run(name, func(t *testing.T) {
			f := newProtectedReadTestFixture(t)
			var saved *ProtectedReadView
			err := f.reader.WithProtectedRead(context.Background(), func(view *ProtectedReadView) error {
				saved = view
				replace(t, f.reader)
				got, err := view.Read(context.Background(), "alpha")
				if !errors.Is(err, ErrDenied) || len(got.Bytes) != 0 {
					return fmt.Errorf("read after %s = %v/%q, want ErrDenied and no bytes", name, err, got.Bytes)
				}
				return nil
			})
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("scope after %s = %v, want ErrDenied", name, err)
			}
			if _, err := saved.Read(context.Background(), "alpha"); !errors.Is(err, ErrDenied) {
				t.Fatalf("escaped view after %s = %v, want ErrDenied", name, err)
			}
		})
	}

	t.Run("drift_after_successful_read", func(t *testing.T) {
		f := newProtectedReadTestFixture(t)
		err := f.reader.WithProtectedRead(context.Background(), func(view *ProtectedReadView) error {
			if got, err := view.Read(context.Background(), "alpha"); err != nil || !bytes.Equal(got.Bytes, f.value) {
				return fmt.Errorf("read before drift = %q/%v", got.Bytes, err)
			}
			data := filepath.Join(f.reader.root, dataName)
			if err := os.Rename(data, data+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			return nil
		})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("scope with identity drift after a read = %v, want ErrDenied", err)
		}
	})
}

// The scope holds the real OS lock across processes, and a live cross-process
// holder blocks acquisition with the normal bounded ErrConflict result.
func TestIssue120LocalDirProtectedReadCrossProcessFence(t *testing.T) {
	ctx := context.Background()
	f := newProtectedReadTestFixture(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
			if got, err := view.Read(ctx, "alpha"); err != nil || !bytes.Equal(got.Bytes, f.value) {
				return fmt.Errorf("scope read = %q/%v", got.Bytes, err)
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("scope did not enter: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("scope did not enter")
	}

	probe := startTryLockHelper(t, f.root)
	if line := probe.lineWithin(t, 5*time.Second); line != "busy" {
		t.Fatalf("child lock attempt during scope = %q, want busy", line)
	}
	probe.kill()

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("scope after child probe: %v", err)
	}
	after := startTryLockHelper(t, f.root)
	if line := after.lineWithin(t, 5*time.Second); line != "locked" {
		t.Fatalf("child lock attempt after scope = %q, want locked", line)
	}
	after.kill()

	// A real child writer also succeeds once the scope has released the lock.
	created := startDirHelper(t, "create", f.root, "beta", "", "beta-value")
	if line := created.line(t); line != "win:beta-value" {
		t.Fatalf("child create after scope = %q, want win:beta-value", line)
	}
	created.finish(t)
	if got := mustRead(t, f.reader, "beta"); !bytes.Equal(got.Bytes, []byte("beta-value")) {
		t.Fatalf("child create after scope stored %q", got.Bytes)
	}

	// Reverse direction: an actual child process holds the OS lock, so opening
	// the scope reports the established bounded conflict without running fn.
	f.reader.timeout = 50 * time.Millisecond
	holder := startDirHelper(t, "hold-lock", f.root, "", "", "")
	if line := holder.line(t); line != "ready" {
		t.Fatalf("holder line = %q, want ready", line)
	}
	err := f.reader.WithProtectedRead(ctx, func(*ProtectedReadView) error {
		t.Error("scope ran while a child held the lock")
		return nil
	})
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknown) {
		t.Fatalf("scope against a child lock holder = %v, want definite ErrConflict", err)
	}
	holder.kill()

	if err := f.reader.WithProtectedRead(ctx, func(view *ProtectedReadView) error {
		got, err := view.Read(ctx, "alpha")
		if err != nil || !bytes.Equal(got.Bytes, f.value) {
			return fmt.Errorf("scope after holder exit = %q/%v", got.Bytes, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("scope after child holder exit: %v", err)
	}
}
