package vaultfilejournal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// This file adds a read-only reconciliation for a RebaseAndPrepare whose caller
// may have lost the result. It decides strictly from one snapshot of the local
// durable records and never guesses, repairs or writes.
//
// The three outcomes reflect exactly what the journal can prove:
//
//   - ReconcileApplied: the snapshot is precisely the committed target of
//     RebaseAndPrepare(S, R, Rrev, P).
//   - ReconcileNotApplied: the snapshot is precisely the untouched input S.
//     Only the absence of the legacy, prepared and target-generation audit
//     records can prove this.
//   - ReconcileReview: anything else, including valid but different records
//     and malformed records. A malformed shape is never read as "not applied".
//
// The database root may hold only the journal bucket, and the journal bucket
// only its four known positions; anything else is Review, never NotApplied.
//
// Reconciliation is local only. It does not verify a remote publication, decrypt
// bytes or contact a backend.

// ReconcileOutcome is the result of ReconcileRebaseAndPrepare. Its zero value is
// ReconcileUnknown: no outcome was proven.
type ReconcileOutcome int

const (
	// ReconcileUnknown means no outcome was proven: the input was invalid, the
	// journal was closed, or the database could not be synced or read. The
	// accompanying error says why.
	ReconcileUnknown ReconcileOutcome = iota
	// ReconcileApplied means the snapshot is exactly the committed target.
	ReconcileApplied
	// ReconcileNotApplied means the snapshot is exactly the untouched input
	// state with no legacy, prepared or target-generation audit record.
	ReconcileNotApplied
	// ReconcileReview means the snapshot is neither. The caller must not treat
	// the rebase as applied or not applied; it needs review.
	ReconcileReview
)

func (o ReconcileOutcome) String() string {
	switch o {
	case ReconcileApplied:
		return "applied"
	case ReconcileNotApplied:
		return "not-applied"
	case ReconcileReview:
		return "review"
	default:
		return "unknown"
	}
}

// ErrReconcileReview is the stable classification for a ReconcileReview of a
// well-formed snapshot that is neither the committed target nor the untouched
// input state.
var ErrReconcileReview = errors.New("vault file journal: rebase outcome needs review")

// ReconcileRebaseAndPrepare determines whether the rebase of old to remoteBase
// and remoteRevision preparing proposal took effect, without writing anything.
//
// The inputs are the exact old State S, the target base R and revision Rrev,
// and the proposal P that was passed to RebaseAndPrepare. P.Generation is kept
// as the caller's legacy hint; the target working generation is always
// S.Generation+1. Inputs are validated and copied before any lock or I/O, and
// an error never includes their bytes, IDs or revisions.
//
// The call takes j.mu, then syncs the real bbolt database and, only if that
// succeeds, reads one View snapshot covering the database root shape, the
// journal/audit shapes and every record. On a close, sync failure or any error
// returned by db.View, it returns ReconcileUnknown with the cause; record
// defects are carried in the snapshot itself and never surface as a View
// error. The implementation is an unexported seam so tests can inject a sync
// failure. A panic propagates and is never reported as ReconcileNotApplied.
//
// ReconcileApplied and ReconcileNotApplied carry a nil error. ReconcileReview
// carries an error identifying the mismatch: a sentinel (for example
// ErrCorrupt) for malformed records, or an error matching ErrReconcileReview
// for well-formed records that differ.
func (j *Journal) ReconcileRebaseAndPrepare(old State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal Proposal) (ReconcileOutcome, error) {
	return j.reconcileRebaseAndPrepare(old, remoteBase, remoteRevision, proposal)
}

func (j *Journal) reconcileRebaseAndPrepare(old State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal Proposal) (ReconcileOutcome, error) {
	if !validStateGeneration(old) {
		return ReconcileUnknown, fmt.Errorf("%w: malformed old state", ErrInvalid)
	}
	if old.Generation == math.MaxUint64 {
		return ReconcileUnknown, fmt.Errorf("%w: old state generation cannot be incremented", ErrInvalid)
	}
	if len(remoteBase) == 0 || len(remoteBase) > MaxBaseBytes {
		return ReconcileUnknown, fmt.Errorf("%w: remote base must be 1..%d bytes", ErrInvalid, MaxBaseBytes)
	}
	if len(remoteRevision) == 0 || len(remoteRevision) > MaxStateRevisionBytes {
		return ReconcileUnknown, fmt.Errorf("%w: remote revision must be 1..%d bytes", ErrInvalid, MaxStateRevisionBytes)
	}
	if !validProposal(proposal) {
		return ReconcileUnknown, fmt.Errorf("%w: malformed proposal", ErrInvalid)
	}
	if proposal.ExpectedRevision != remoteRevision {
		return ReconcileUnknown, fmt.Errorf("%w: proposal expected revision does not match remote revision", ErrInvalid)
	}
	old = State{
		BaseBytes:      bytes.Clone(old.BaseBytes),
		RemoteRevision: vaultfilebackend.Revision(bytes.Clone([]byte(old.RemoteRevision))),
		WorkingBytes:   bytes.Clone(old.WorkingBytes),
		Generation:     old.Generation,
	}
	remoteBase = bytes.Clone(remoteBase)
	remoteRevision = vaultfilebackend.Revision(bytes.Clone([]byte(remoteRevision)))
	proposal.OperationID = string(bytes.Clone([]byte(proposal.OperationID)))
	proposal.ExpectedRevision = vaultfilebackend.Revision(bytes.Clone([]byte(proposal.ExpectedRevision)))
	proposal.Bytes = bytes.Clone(proposal.Bytes)
	next := old.Generation + 1
	target := reconcileTarget{
		state: State{
			BaseBytes:      remoteBase,
			RemoteRevision: remoteRevision,
			WorkingBytes:   proposal.Bytes,
			Generation:     next,
		},
		prepared: PreparedProposal{WorkingGeneration: next, Proposal: proposal},
		audit: RebaseAudit{
			OldState:       old,
			RemoteBase:     remoteBase,
			RemoteRevision: remoteRevision,
			NewGeneration:  next,
			Proposal:       proposal,
		},
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ReconcileUnknown, ErrClosed
	}
	sync := j.db.Sync
	if j.syncFn != nil {
		sync = j.syncFn
	}
	if err := sync(); err != nil {
		return ReconcileUnknown, fmt.Errorf("vault file journal: reconcile sync: %w", err)
	}
	// Record defects never escape the View as an error: they are stored in
	// the snapshot for classification. Any error db.View itself returns, such
	// as a transaction or iteration failure, leaves the outcome unknown.
	var snap reconcileSnapshot
	if err := j.db.View(func(tx *bolt.Tx) error {
		snap.read(tx, next)
		return nil
	}); err != nil {
		return ReconcileUnknown, fmt.Errorf("vault file journal: reconcile read: %w", err)
	}
	return snap.outcome(old, target)
}

// reconcileTarget is the exact snapshot RebaseAndPrepare(old, R, Rrev, P) commits.
type reconcileTarget struct {
	state    State
	prepared PreparedProposal
	audit    RebaseAudit
}

// reconcileSnapshot is one copied read of the local records. Each present
// record's decodeErr is non-nil exactly when a raw value exists but does not
// decode.
type reconcileSnapshot struct {
	bucket     bool
	state      State
	stateFound bool
	stateErr   error
	prepared   PreparedProposal
	prepFound  bool
	prepErr    error
	legacy     bool
	legacyErr  error
	audit      RebaseAudit
	auditFound bool
	auditErr   error
	// unknownKeys counts journal keys outside the four known positions.
	unknownKeys int
	// rootErr is set when the database has a top-level bucket or key other
	// than the journal bucket.
	rootErr bool
}

// read copies every record the decision needs from tx, a single snapshot. Every
// raw value is decoded before the transaction ends so no returned slice aliases
// transaction memory. It returns no error: every defect is recorded in a field
// so the classification never depends on where a scan stopped.
func (s *reconcileSnapshot) read(tx *bolt.Tx, next uint64) {
	// The database root may hold only the journal bucket; an extra top-level
	// bucket or key is never ignored.
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if !bytes.Equal(name, []byte(bucketName)) {
			s.rootErr = true
		}
		return nil
	}); err != nil {
		s.rootErr = true
	}
	tb := tx.Bucket([]byte(bucketName))
	if tb == nil {
		return
	}
	s.bucket = true
	_ = tb.ForEach(func(k, v []byte) error {
		switch string(k) {
		case stateKey, preparedKey, auditBucketName:
			return nil
		case recordKey:
			s.legacy = true
			if v == nil {
				s.legacyErr = ErrCorrupt
			} else if _, err := decodeRecord(v); err != nil {
				s.legacyErr = ErrCorrupt
			}
		default:
			s.unknownKeys++
		}
		return nil
	})
	// Classify the shaped record positions only after the scan, so a nested
	// bucket at a known key is never counted as an unknown key.
	if s.state, s.stateFound, s.stateErr = readStateTx(tx); !s.stateFound && s.stateErr == nil {
		s.stateErr = recordShapeErr(tb, stateKey)
	}
	if s.prepared, s.prepFound, s.prepErr = readPreparedTx(tx); !s.prepFound && s.prepErr == nil {
		s.prepErr = recordShapeErr(tb, preparedKey)
	}
	s.readAudit(tb, next)
}

// recordShapeErr reports ErrCorrupt when key holds a nested bucket rather than a
// record value, and nil when it holds a value or is absent.
func recordShapeErr(tb *bolt.Bucket, key string) error {
	if tb.Bucket([]byte(key)) != nil {
		return ErrCorrupt
	}
	return nil
}

// readAudit validates the target-generation audit entry and checks that every
// other entry is a well-formed historical record before the new generation.
// Audits after the target generation, malformed or not, are left for review.
func (s *reconcileSnapshot) readAudit(tb *bolt.Bucket, next uint64) {
	if tb.Get([]byte(auditBucketName)) != nil {
		s.auditErr = ErrCorrupt
		return
	}
	ab := tb.Bucket([]byte(auditBucketName))
	if ab == nil {
		return
	}
	targetKey := auditKey(next)
	if ab.Bucket(targetKey) != nil {
		s.auditFound, s.auditErr = true, ErrCorrupt
	} else if raw := ab.Get(targetKey); raw != nil {
		s.auditFound = true
		if err := checkAuditEntry(ab, targetKey, raw, true); err != nil {
			s.auditErr = err
		} else if a, err := decodeRebaseAudit(raw); err != nil {
			s.auditErr = err
		} else {
			s.audit = a
		}
	}
	// Record every defect rather than stopping, so the final classification
	// never depends on key order.
	_ = ab.ForEach(func(k, v []byte) error {
		if len(k) == 8 && bytes.Equal(k, targetKey) {
			return nil
		}
		if len(k) != 8 || v == nil || ab.Bucket(k) != nil || s.auditErr != nil {
			s.auditErr = ErrCorrupt
			return nil
		}
		// A prior audit must be well-formed and strictly older than next.
		if a, err := decodeRebaseAudit(v); err != nil || a.NewGeneration != binary.BigEndian.Uint64(k) || a.OldState.Generation >= next {
			s.auditErr = ErrCorrupt
		}
		return nil
	})
}

// outcome classifies a fully read snapshot without guessing. A malformed record
// is never read as absent.
func (s *reconcileSnapshot) outcome(old State, target reconcileTarget) (ReconcileOutcome, error) {
	// Malformed shapes are Review with a silent ErrCorrupt: bbolt keeps the
	// per-bucket insert order, so the first defect seen is stable but arbitrary.
	if s.stateErr != nil || s.prepErr != nil || s.legacyErr != nil || s.auditErr != nil {
		return ReconcileReview, ErrCorrupt
	}
	if s.rootErr {
		return ReconcileReview, fmt.Errorf("%w: an unknown database root bucket or key is present", ErrReconcileReview)
	}
	if sameState(s.state, target.state) &&
		samePrepared(s.prepared, target.prepared) &&
		sameState(s.audit.OldState, target.audit.OldState) &&
		bytes.Equal(s.audit.RemoteBase, target.audit.RemoteBase) &&
		s.audit.RemoteRevision == target.audit.RemoteRevision &&
		s.audit.NewGeneration == target.audit.NewGeneration &&
		sameProposal(s.audit.Proposal, target.audit.Proposal) &&
		s.auditFound &&
		!s.legacy &&
		s.unknownKeys == 0 {
		return ReconcileApplied, nil
	}
	if sameState(s.state, old) {
		if s.legacy {
			return ReconcileReview, fmt.Errorf("%w: a legacy proposal record is present", ErrReconcileReview)
		}
		if s.prepFound {
			return ReconcileReview, fmt.Errorf("%w: a prepared proposal record is present", ErrReconcileReview)
		}
		if s.unknownKeys != 0 {
			return ReconcileReview, fmt.Errorf("%w: an unknown journal key is present", ErrReconcileReview)
		}
		// An audit already at the target generation, even a well-formed one
		// that differs from the candidate, proves nothing was applied here.
		if s.auditFound {
			return ReconcileReview, fmt.Errorf("%w: an audit record is present at the target generation", ErrReconcileReview)
		}
		return ReconcileNotApplied, nil
	}
	return ReconcileReview, fmt.Errorf("%w: stored records are neither the input state nor the committed target", ErrReconcileReview)
}
