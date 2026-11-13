package vaultfilejournal

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// reconcileFixture is one real journal holding the input state S and the
// matching target R, Rrev and P.
type reconcileFixture struct {
	dir  string
	j    *Journal
	old  State
	base []byte
	rev  vaultfilebackend.Revision
	p    Proposal
}

func newReconcileFixture(t *testing.T) *reconcileFixture {
	t.Helper()
	f := &reconcileFixture{dir: privateDir(t)}
	f.j = openAt(t, f.dir)
	f.old = baseState()
	mustInitialize(t, f.j, f.old)
	f.base = opaque(2048, 241)
	f.rev = vaultfilebackend.Revision(`"reconcile-target-rev"`)
	f.p = baseProposal()
	f.p.Generation = 4242
	f.p.OperationID = "op-reconcile:target.1"
	f.p.ExpectedRevision = f.rev
	f.p.Bytes = opaque(3111, 242)
	return f
}

func (f *reconcileFixture) reconcile() (ReconcileOutcome, error) {
	return f.j.ReconcileRebaseAndPrepare(f.old, f.base, f.rev, f.p)
}

func (f *reconcileFixture) mustRebase(t *testing.T) {
	t.Helper()
	mustRebase(t, f.j, f.old, f.base, f.rev, f.p)
}

func (f *reconcileFixture) targetState() State {
	return State{BaseBytes: f.base, RemoteRevision: f.rev, WorkingBytes: f.p.Bytes, Generation: f.old.Generation + 1}
}

func (f *reconcileFixture) targetPrepared() PreparedProposal {
	return PreparedProposal{WorkingGeneration: f.old.Generation + 1, Proposal: f.p}
}

func (f *reconcileFixture) targetAudit() RebaseAudit {
	return RebaseAudit{OldState: f.old, RemoteBase: f.base, RemoteRevision: f.rev, NewGeneration: f.old.Generation + 1, Proposal: f.p}
}

func wantOutcome(t *testing.T, got ReconcileOutcome, err error, want ReconcileOutcome) {
	t.Helper()
	if got != want {
		t.Fatalf("outcome = %v (err %v), want %v", got, err, want)
	}
}

// TestReconcileRebaseAppliedAfterLostResult performs a real, bbolt-synced
// RebaseAndPrepare and then has the caller forget only the returned nil: the
// same handle reconciles it as Applied. This is a lost caller result, not a
// simulated I/O failure.
func TestReconcileRebaseAppliedAfterLostResult(t *testing.T) {
	f := newReconcileFixture(t)
	f.mustRebase(t)

	got, err := f.reconcile()
	wantOutcome(t, got, err, ReconcileApplied)
	if err != nil {
		t.Fatalf("Applied carries error %v", err)
	}
	// Reconciliation is read-only.
	assertState(t, mustLoadState(t, f.j), f.targetState())
	assertPrepared(t, mustLoadPrepared(t, f.j), f.targetPrepared())
	assertAudit(t, mustLoadAudit(t, f.j, f.old.Generation+1), f.targetAudit())

	// A clean restart and a repeated reconciliation agree.
	mustClose(t, f.j)
	f.j = openAt(t, f.dir)
	got, err = f.reconcile()
	wantOutcome(t, got, err, ReconcileApplied)
}

// TestReconcileRebaseFaultRollsBackNotApplied commits one earlier rebase, acks
// it, then fails the next rebase after all Puts. The prior audit sits at the
// current state generation S, so the target-generation lookup must not mistake
// it for the failed attempt's audit.
func TestReconcileRebaseFaultRollsBackNotApplied(t *testing.T) {
	f := newReconcileFixture(t)
	f.mustRebase(t)
	next := f.old.Generation + 1

	ackRev := vaultfilebackend.Revision(`"reconcile-acked"`)
	if err := f.j.Ack(f.p.OperationID, f.p.Bytes, ackRev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	s := mustLoadState(t, f.j)
	if s.Generation != next {
		t.Fatalf("acked state generation %d, want %d", s.Generation, next)
	}
	mustLoadAudit(t, f.j, next)

	r := opaque(1500, 243)
	rev := vaultfilebackend.Revision(`"reconcile-second-rev"`)
	p := rebaseProposal(rev)
	fault := errors.New("injected rebase fault")
	err := f.j.rebaseAndPrepareWithHook(s, r, rev, p, func() error { return fault })
	if !errors.Is(err, fault) {
		t.Fatalf("rebase under fault = %v", err)
	}

	got, err := f.j.ReconcileRebaseAndPrepare(s, r, rev, p)
	wantOutcome(t, got, err, ReconcileNotApplied)
	if err != nil {
		t.Fatalf("NotApplied carries error %v", err)
	}
	// The result is stable after reopen.
	mustClose(t, f.j)
	f.j = openAt(t, f.dir)
	got, err = f.j.ReconcileRebaseAndPrepare(s, r, rev, p)
	wantOutcome(t, got, err, ReconcileNotApplied)
}

// TestReconcileRebaseSyncErrorUnknown injects a private Sync failure while a
// deliberately corrupt state record is on disk: the result must be Unknown with
// the sync error before any snapshot read, never Review/Corrupt and never
// NotApplied.
func TestReconcileRebaseSyncErrorUnknown(t *testing.T) {
	f := newReconcileFixture(t)
	writeRawState(t, f.j, []byte("corrupt-marker-state"))
	f.j.syncFn = func() error { return errTestReconcileSync }

	got, err := f.reconcile()
	wantOutcome(t, got, err, ReconcileUnknown)
	if !errors.Is(err, errTestReconcileSync) {
		t.Fatalf("sync failure = %v, want the injected error", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatalf("sync failure surfaced a record classification: %v", err)
	}

	// With Sync restored the same corrupt marker is classified by the read.
	f.j.syncFn = nil
	got, err = f.reconcile()
	wantOutcome(t, got, err, ReconcileReview)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt state = %v, want ErrCorrupt", err)
	}
}

var errTestReconcileSync = errors.New("injected reconcile sync fault")

// TestReconcileRebaseChangedStateReview changes the working bytes after a
// committed target and expects Review without a guess.
func TestReconcileRebaseChangedStateReview(t *testing.T) {
	f := newReconcileFixture(t)
	f.mustRebase(t)
	gen := f.old.Generation + 1
	if err := f.j.UpdateWorking(gen, opaque(999, 244)); err != nil {
		t.Fatalf("UpdateWorking: %v", err)
	}
	got, err := f.reconcile()
	wantOutcome(t, got, err, ReconcileReview)
	if !errors.Is(err, ErrReconcileReview) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("changed state = %v, want ErrReconcileReview", err)
	}
}

// TestReconcileRebasePendingRecordReview stores a syntactically valid legacy or
// prepared record while the state still equals S exactly.
func TestReconcileRebasePendingRecordReview(t *testing.T) {
	t.Run("legacy record", func(t *testing.T) {
		f := newReconcileFixture(t)
		legacy := baseProposal()
		legacy.OperationID = "op-reconcile:legacy.1"
		mustSave(t, f.j, legacy)
		got, err := f.reconcile()
		wantOutcome(t, got, err, ReconcileReview)
		if !errors.Is(err, ErrReconcileReview) {
			t.Fatalf("legacy record = %v, want ErrReconcileReview", err)
		}
	})
	t.Run("prepared record", func(t *testing.T) {
		f := newReconcileFixture(t)
		pp := baseProposal()
		pp.ExpectedRevision = f.old.RemoteRevision
		pp.Bytes = bytes.Clone(f.old.WorkingBytes)
		mustPrepare(t, f.j, f.old.Generation, pp)
		got, err := f.reconcile()
		wantOutcome(t, got, err, ReconcileReview)
		if !errors.Is(err, ErrReconcileReview) {
			t.Fatalf("prepared record = %v, want ErrReconcileReview", err)
		}
	})
}

// TestReconcileRebaseUnknownKeysReview plants unknown journal keys after a
// committed target. They are not classified as corruption and never as
// NotApplied; they are a stable review.
func TestReconcileRebaseUnknownKeysReview(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *reconcileFixture)
	}{
		{"unknown key", func(t *testing.T, f *reconcileFixture) {
			writeRawJournalKey(t, f.j, "unknown-key", []byte("x"))
		}},
		{"unknown nested bucket", func(t *testing.T, f *reconcileFixture) {
			writeJournalNestedBucket(t, f.j, "unknown-bucket", "child", []byte("x"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newReconcileFixture(t)
			f.mustRebase(t)
			c.setup(t, f)
			got, err := f.reconcile()
			wantOutcome(t, got, err, ReconcileReview)
			if !errors.Is(err, ErrReconcileReview) || errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s = %v, want ErrReconcileReview", c.name, err)
			}
		})
	}
}

// TestReconcileRebaseMalformedShapesReview plants nested buckets and corrupt
// state, prepared, legacy or audit records after a committed target. Every case
// is Review with ErrCorrupt, never NotApplied: a malformed record is never read
// as absent, whatever key order bbolt returns.
func TestReconcileRebaseMalformedShapesReview(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *reconcileFixture)
	}{
		{"state nested bucket", func(t *testing.T, f *reconcileFixture) {
			replaceWithNestedBucket(t, f.j, bucketName, stateKey)
		}},
		{"prepared nested bucket", func(t *testing.T, f *reconcileFixture) {
			replaceWithNestedBucket(t, f.j, bucketName, preparedKey)
		}},
		{"legacy nested bucket", func(t *testing.T, f *reconcileFixture) {
			writeJournalNestedBucket(t, f.j, recordKey, "child", []byte("x"))
		}},
		{"corrupt legacy record", func(t *testing.T, f *reconcileFixture) {
			writeRawJournalKey(t, f.j, recordKey, []byte("LLVJ-corrupt"))
		}},
		{"corrupt prepared record", func(t *testing.T, f *reconcileFixture) {
			writeRawJournalKey(t, f.j, preparedKey, []byte("LLVP-corrupt"))
		}},
		{"corrupt state record", func(t *testing.T, f *reconcileFixture) {
			writeRawState(t, f.j, []byte("LLVS-corrupt"))
		}},
		{"corrupt target audit", func(t *testing.T, f *reconcileFixture) {
			corruptAudit(t, f.j, f.old.Generation+1, []byte("LLVA-corrupt"))
		}},
		{"nested bucket at target audit", func(t *testing.T, f *reconcileFixture) {
			nestAudit(t, f.j, auditKey(f.old.Generation+1), "child", []byte("x"))
		}},
		{"audit bucket stored as value", func(t *testing.T, f *reconcileFixture) {
			replaceAuditBucketWithValue(t, f.j, []byte("x"))
		}},
		{"malformed audit key", func(t *testing.T, f *reconcileFixture) {
			malformedAuditKey(t, f.j, []byte("short"), rawAudit(t, f.j, f.old.Generation+1))
		}},
		{"corrupt historical audit", func(t *testing.T, f *reconcileFixture) {
			corruptAudit(t, f.j, 0, []byte("LLVA-corrupt"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newReconcileFixture(t)
			f.mustRebase(t)
			c.setup(t, f)
			got, err := f.reconcile()
			wantOutcome(t, got, err, ReconcileReview)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s = %v, want ErrCorrupt", c.name, err)
			}
		})
	}
}

// replaceAuditBucket replaces the journal's audit bucket with one created
// fresh, then calls fill. Tests only.
func replaceAuditBucket(t *testing.T, j *Journal, fill func(ab *bolt.Bucket) error) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb := tx.Bucket([]byte(bucketName))
		if tb.Bucket([]byte(auditBucketName)) != nil {
			if err := tb.DeleteBucket([]byte(auditBucketName)); err != nil {
				return err
			}
		}
		ab, err := tb.CreateBucket([]byte(auditBucketName))
		if err != nil {
			return err
		}
		return fill(ab)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// corruptAudit replaces the audit bucket with one entry at generation holding
// raw, whether or not bbolt reports materialization for that key.
func corruptAudit(t *testing.T, j *Journal, generation uint64, raw []byte) {
	t.Helper()
	replaceAuditBucket(t, j, func(ab *bolt.Bucket) error {
		return ab.Put(auditKey(generation), raw)
	})
}

// replaceAuditBucketWithValue replaces the journal's audit bucket with a plain
// value.
func replaceAuditBucketWithValue(t *testing.T, j *Journal, raw []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb := tx.Bucket([]byte(bucketName))
		if tb.Bucket([]byte(auditBucketName)) != nil {
			if err := tb.DeleteBucket([]byte(auditBucketName)); err != nil {
				return err
			}
		}
		return tb.Put([]byte(auditBucketName), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// nestAudit replaces the audit bucket with a nested bucket at key.
func nestAudit(t *testing.T, j *Journal, key []byte, child string, value []byte) {
	t.Helper()
	replaceAuditBucket(t, j, func(ab *bolt.Bucket) error {
		nb, err := ab.CreateBucket(key)
		if err != nil {
			return err
		}
		return nb.Put([]byte(child), value)
	})
}

// malformedAuditKey replaces the audit bucket with one entry at a non-8-byte
// key holding a valid audit record.
func malformedAuditKey(t *testing.T, j *Journal, key, raw []byte) {
	t.Helper()
	replaceAuditBucket(t, j, func(ab *bolt.Bucket) error { return ab.Put(key, raw) })
}

// replaceWithNestedBucket replaces key's value with an empty nested bucket.
func replaceWithNestedBucket(t *testing.T, j *Journal, bucket, key string) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if err := b.Delete([]byte(key)); err != nil {
			return err
		}
		_, err := b.CreateBucket([]byte(key))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReconcileRebaseTargetAuditWithoutCommitReview leaves state exactly S with
// no legacy or prepared record but plants a syntactically valid audit at the
// target generation that differs from the candidate. The audit's presence alone
// disproves NotApplied, so the result is Review, never NotApplied.
func TestReconcileRebaseTargetAuditWithoutCommitReview(t *testing.T) {
	other := func(t *testing.T, f *reconcileFixture) RebaseAudit {
		t.Helper()
		a := f.targetAudit()
		a.Proposal = rebaseProposal(f.rev)
		return a
	}
	cases := []struct {
		name  string
		audit func(t *testing.T, f *reconcileFixture) RebaseAudit
	}{
		{"other proposal", other},
		{"other remote base", func(t *testing.T, f *reconcileFixture) RebaseAudit {
			a := f.targetAudit()
			a.RemoteBase = opaque(64, 246)
			return a
		}},
		{"other remote revision", func(t *testing.T, f *reconcileFixture) RebaseAudit {
			a := f.targetAudit()
			a.RemoteRevision = vaultfilebackend.Revision(`"other-audit-rev"`)
			a.Proposal.ExpectedRevision = a.RemoteRevision
			return a
		}},
		{"other old state", func(t *testing.T, f *reconcileFixture) RebaseAudit {
			a := f.targetAudit()
			a.OldState = stateWithoutBase()
			a.OldState.Generation = f.old.Generation
			return a
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newReconcileFixture(t)
			a := c.audit(t, f)
			if !validRebaseAudit(a) {
				t.Fatal("fixture audit is not syntactically valid")
			}
			// Plant only the target audit; the journal bucket already exists
			// because the state was initialized.
			writeRawAudit(t, f.j, auditKey(f.old.Generation+1), encodeRebaseAudit(a))
			if s := mustLoadState(t, f.j); !sameState(s, f.old) {
				t.Fatalf("fixture state moved from S: gen %d", s.Generation)
			}
			if _, err := f.j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
				t.Fatalf("fixture prepared record: %v", err)
			}
			if _, err := f.j.Load(); !errors.Is(err, ErrEmpty) {
				t.Fatalf("fixture legacy record: %v", err)
			}
			got, err := f.reconcile()
			wantOutcome(t, got, err, ReconcileReview)
			if !errors.Is(err, ErrReconcileReview) || errors.Is(err, ErrCorrupt) {
				t.Fatalf("target audit without commit = %v, want ErrReconcileReview", err)
			}
		})
	}
}

// TestReconcileRebaseExtraRootBucketReview leaves state exactly S and plants an
// extra top-level bucket beside the journal bucket. The root shape is checked in
// the same View, so the result is Review, never NotApplied.
func TestReconcileRebaseExtraRootBucketReview(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, j *Journal)
	}{
		{"extra bucket", func(t *testing.T, j *Journal) {
			j.mu.Lock()
			defer j.mu.Unlock()
			if err := j.db.Update(func(tx *bolt.Tx) error {
				_, err := tx.CreateBucket([]byte("intruder"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra bucket with child", func(t *testing.T, j *Journal) {
			j.mu.Lock()
			defer j.mu.Unlock()
			if err := j.db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucket([]byte("intruder"))
				if err != nil {
					return err
				}
				return b.Put([]byte("child"), []byte("x"))
			}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newReconcileFixture(t)
			c.plant(t, f.j)
			if s := mustLoadState(t, f.j); !sameState(s, f.old) {
				t.Fatalf("fixture state moved from S: gen %d", s.Generation)
			}
			got, err := f.reconcile()
			wantOutcome(t, got, err, ReconcileReview)
			if !errors.Is(err, ErrReconcileReview) || errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s = %v, want ErrReconcileReview", c.name, err)
			}
			// The extra root bucket must still be present: reconciliation
			// never repairs or deletes.
			j := f.j
			j.mu.Lock()
			defer j.mu.Unlock()
			if err := j.db.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte("intruder")) == nil {
					t.Fatal("reconciliation removed the extra root bucket")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestReconcileRebaseHistoricalAuditsTolerated shows that a well-formed audit at
// the current state generation does not block the NotApplied classification.
func TestReconcileRebaseHistoricalAuditsTolerated(t *testing.T) {
	f := newReconcileFixture(t)
	f.mustRebase(t)
	if err := f.j.Ack(f.p.OperationID, f.p.Bytes, f.rev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	s := mustLoadState(t, f.j)
	if s.Generation != f.old.Generation+1 {
		t.Fatalf("acked generation %d", s.Generation)
	}
	mustLoadAudit(t, f.j, s.Generation)
	r := opaque(10, 245)
	rev := vaultfilebackend.Revision(`"reconcile-third-rev"`)
	p := rebaseProposal(rev)
	got, err := f.j.ReconcileRebaseAndPrepare(s, r, rev, p)
	wantOutcome(t, got, err, ReconcileNotApplied)
}

// TestReconcileRebaseInvalidInput proves invalid inputs are Unknown with
// ErrInvalid before any sync and never echo caller bytes, IDs or revisions.
func TestReconcileRebaseInvalidInput(t *testing.T) {
	f := newReconcileFixture(t)
	badState := cloneState(f.old)
	badState.WorkingBytes = nil
	badProposal := cloneProposal(f.p)
	badProposal.OperationID = "Secret OP ID!"
	badBytes := cloneProposal(f.p)
	badBytes.Bytes = nil
	mismatch := cloneProposal(f.p)
	mismatch.ExpectedRevision = vaultfilebackend.Revision(`"secret-other-rev"`)
	maxed := cloneState(f.old)
	maxed.Generation = math.MaxUint64

	cases := []struct {
		name      string
		old       State
		base      []byte
		rev       vaultfilebackend.Revision
		proposal  Proposal
		sensitive []string
	}{
		{"malformed old state", badState, f.base, f.rev, f.p, nil},
		{"old generation overflow", maxed, f.base, f.rev, f.p, nil},
		{"empty base", f.old, nil, f.rev, f.p, nil},
		{"empty revision", f.old, f.base, "", f.p, nil},
		{"malformed proposal", f.old, f.base, f.rev, badProposal, []string{"Secret OP ID!", "op-reconcile:target.1", string(f.rev), string(f.p.ExpectedRevision)}},
		{"empty proposal bytes", f.old, f.base, f.rev, badBytes, []string{"op-reconcile:target.1"}},
		{"revision mismatch", f.old, f.base, f.rev, mismatch, []string{"secret-other-rev", string(f.rev), "op-reconcile:target.1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synced := false
			f.j.syncFn = func() error { synced = true; return nil }
			got, err := f.j.ReconcileRebaseAndPrepare(c.old, c.base, c.rev, c.proposal)
			wantOutcome(t, got, err, ReconcileUnknown)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s = %v, want ErrInvalid", c.name, err)
			}
			if synced {
				t.Fatal("invalid input reached the sync")
			}
			for _, s := range c.sensitive {
				if strings.Contains(err.Error(), s) {
					t.Fatalf("error echoes caller data %q: %v", s, err)
				}
			}
		})
	}
}
