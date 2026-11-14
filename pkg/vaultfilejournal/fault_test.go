package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestTransactionFaultAfterPutKeepsOldRecord injects a failure inside the Save
// transaction after the bucket Put and before the Bolt commit. The bbolt
// transaction must roll back: after close and reopen, the old record survives
// and the attempted generation was never stored.
func TestTransactionFaultAfterPutKeepsOldRecord(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	old := baseProposal()
	mustSave(t, j, old)

	next := baseProposal()
	next.Generation = old.Generation + 1
	next.OperationID = "next-op"
	next.Bytes = opaque(4096, 5)

	fault := errors.New("injected fault after bucket Put")
	hookRan := false
	err := j.save(next, func() error {
		hookRan = true
		return fault
	})
	if !hookRan {
		t.Fatal("fault hook never ran")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("Save = %v, want the injected fault", err)
	}

	// Within the still-open handle nothing was published.
	assertProposal(t, mustLoad(t, j), old)

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j2 := openAt(t, dir)
	assertProposal(t, mustLoad(t, j2), old)

	// The rolled-back generation is free: saving it now must succeed and must
	// not be mistaken for a same-generation replay.
	next.Bytes = opaque(4096, 5)
	mustSave(t, j2, next)
	if err := j2.Close(); err != nil {
		t.Fatal(err)
	}
	assertProposal(t, mustLoad(t, openAt(t, dir)), next)
}

// commitResultWrite is a test-only wrapper that performs one committed local
// Save and then throws away its success result, as if the calling goroutine or
// process lost the completion observation (panic, cancellation, crash after
// the syscall returned) after the commit had already become durable. It
// deliberately reports no error: Save itself returned nil.
func commitResultWrite(j *Journal, p Proposal) {
	if err := j.Save(p); err != nil {
		panic("commitResultWrite: unexpected Save error: " + err.Error())
	}
	// The success result is discarded here.
}

// TestRecoveryAfterLostCompletionObservation covers the only recovery story
// this local-only package owns: a local commit succeeded, but the caller no
// longer has its result. After close and reopen, Load shows the exact new
// proposal, so the caller resolves the unknown by exact comparison instead of
// inventing an outcome or signing a new proposal. No remote CAS is involved.
func TestRecoveryAfterLostCompletionObservation(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	old := baseProposal()
	mustSave(t, j, old)

	newer := baseProposal()
	newer.Generation = old.Generation + 1
	newer.OperationID = "committed-but-unobserved"
	newer.ExpectedRevision = ""
	newer.Bytes = opaque(32<<10+7, 11)

	// The commit succeeds; the caller never records the success.
	commitResultWrite(j, newer)

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	// All the caller can do is observe: reopen and Load.
	j2 := openAt(t, dir)
	got := mustLoad(t, j2)
	assertProposal(t, got, newer)
	if !sameProposal(got, newer) {
		t.Fatal("exact-record comparison does not recognise the committed proposal")
	}

	// Rebuilding the same proposal and replaying it is an idempotent no-op.
	mustSave(t, j2, Proposal{
		Generation:       newer.Generation,
		OperationID:      newer.OperationID,
		ExpectedRevision: newer.ExpectedRevision,
		Bytes:            opaque(32<<10+7, 11),
	})

	// A different proposal for the same generation is a conflict, not a
	// replay, and does not replace the committed record.
	other := newer
	other.Bytes = opaque(len(newer.Bytes), 12)
	var conflict *SavedGenerationConflictError
	if err := j2.Save(other); !errors.As(err, &conflict) {
		t.Fatalf("Save(different, same gen) = %v, want conflict", err)
	}
	if err := j2.Close(); err != nil {
		t.Fatal(err)
	}
	assertProposal(t, mustLoad(t, openAt(t, dir)), newer)
}

// openBounded runs Open on a goroutine and fails the test promptly when it
// overruns the deadline, so a lock regression cannot hang the package. It
// asserts that a non-nil Journal is always returned with a nil error.
func openBounded(t *testing.T, path string, limit time.Duration) (*Journal, error) {
	t.Helper()
	type result struct {
		j   *Journal
		err error
	}
	c := make(chan result, 1)
	go func() {
		j, err := Open(path)
		c <- result{j, err}
	}()
	select {
	case r := <-c:
		if (r.j == nil) != (r.err != nil) {
			t.Fatalf("Open returned journal=%p err=%v; want exactly one", r.j, r.err)
		}
		return r.j, r.err
	case <-time.After(limit):
		t.Fatalf("Open did not return within %v", limit)
		return nil, nil
	}
}

// TestOpenLocked proves a second writer of an existing journal fails promptly
// with ErrLocked and does not disturb the first handle or the file.
func TestOpenLocked(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	j := openAt(t, dir)
	want := baseProposal()
	mustSave(t, j, want)

	start := time.Now()
	j2, err := openBounded(t, path, lockTimeout+3*time.Second)
	if j2 != nil {
		_ = j2.Close()
	}
	if !errors.Is(err, ErrLocked) || !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second Open = %v, want ErrLocked", err)
	}
	if elapsed := time.Since(start); elapsed >= lockTimeout+3*time.Second {
		t.Fatalf("second Open took %v", elapsed)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("locked second Open removed the database: %v", statErr)
	}
	if err := j.Save(want); err != nil {
		t.Fatalf("first handle Save after refused second Open: %v", err)
	}
	assertProposal(t, mustLoad(t, j), want)
}

// TestOpenStaleMissingHintDoesNotRemoveOwnedJournal models the race where
// Open's existence check observes a missing path (missing=true) and another
// opener then creates, locks and writes it before this call reaches bbolt. The
// stale hint is passed directly to the same internal helper to keep the
// regression deterministic and free of global state: it must fail promptly
// with ErrLocked, must not remove the competing database, and the owning
// handle must keep working.
func TestOpenStaleMissingHintDoesNotRemoveOwnedJournal(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")
	owner := openAt(t, dir)
	want := baseProposal()
	mustSave(t, owner, want)

	start := time.Now()
	j, err := openDatabase(path, dir, true)
	if j != nil {
		_ = j.Close()
		t.Fatalf("stale-hint open unexpectedly succeeded")
	}
	if !errors.Is(err, ErrLocked) || !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("stale-hint open = %v, want ErrLocked", err)
	}
	if elapsed := time.Since(start); elapsed > lockTimeout+3*time.Second {
		t.Fatalf("stale-hint open took %v, want prompt ErrLocked", elapsed)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("stale-hint open removed the owned database: %v, %v", info, err)
	}

	// The owning handle is intact and usable.
	assertProposal(t, mustLoad(t, owner), want)
	next := baseProposal()
	next.Generation++
	mustSave(t, owner, next)
	assertProposal(t, mustLoad(t, owner), next)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	assertProposal(t, mustLoad(t, openAt(t, dir)), next)
}

// TestOpenFailuresPreserveUnknownFile proves failed Opens preserve the path
// in its current state and report an explicit error instead of removing it.
func TestOpenFailuresPreserveUnknownFile(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")

	// Empty file: platform-defined, but whatever the outcome the file is
	// never removed.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	makeDBPrivate(t, path)
	emptyBytes := mustReadFile(t, path)
	j, err := openBounded(t, path, 10*time.Second)
	switch {
	case err == nil:
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
	case errors.Is(err, ErrInvalid):
		if got := mustReadFile(t, path); !bytes.Equal(got, emptyBytes) {
			t.Fatal("rejecting an empty database changed its bytes")
		}
	default:
		t.Fatalf("Open(empty) = %v, want success or ErrInvalid", err)
	}

	// Foreign file: preserved byte for byte.
	foreign := []byte(strings.Repeat("not a bbolt database\n", 8))
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	makeDBPrivate(t, path)
	if j, err := openBounded(t, path, 10*time.Second); j != nil || err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("Open(foreign) = %v, %v; want explicit non-lock error", j, err)
	}
	if got := mustReadFile(t, path); string(got) != string(foreign) {
		t.Fatal("Open(foreign) modified the file")
	}
}

// TestClosedJournal checks every method after Close, and Close idempotence.
func TestClosedJournal(t *testing.T) {
	j, err := Open(filepath.Join(privateDir(t), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := j.Load(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Load = %v, want ErrClosed", err)
	}
	if err := j.Save(baseProposal()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Save = %v, want ErrClosed", err)
	}
}
