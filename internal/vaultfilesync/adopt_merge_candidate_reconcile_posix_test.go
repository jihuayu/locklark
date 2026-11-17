//go:build darwin || linux

package vaultfilesync

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// These tests cover the one unknown-commit path of AdoptMergeCandidate: an
// unclassified error from Journal.RebaseAndPrepare is resolved in the same call
// by the real Journal.ReconcileRebaseAndPrepare with the exact in-memory state,
// R, Rrev and proposal.
//
// Every case runs against a real file-backed bbolt journal. The only seam is
// the per-call commitFn argument of the private adoptMergeCandidate: each test
// passes a function that performs the real Journal.RebaseAndPrepare transaction
// first and then reports a synthetic unclassified error, exactly the shape of a
// caller that lost the transaction's result. Production passes the real method
// and no test touches shared state. Reconciliation is never overridden, so
// Applied, NotApplied and Review are all decided by the real journal method.

// adoptCommitInputs returns the recorded state S and the proposal P that
// AdoptMergeCandidate derives from the authenticated M.
func adoptCommitInputs(t *testing.T, fx *adoptFixture) (vaultfilejournal.State, vaultfilejournal.Proposal) {
	t.Helper()
	mFile, _, _ := openWorkingState(t, fx.candidate.MergedBytes, fx.f.pin, fx.f.id)
	return fx.recorded, vaultfilejournal.Proposal{
		Generation:       fx.recorded.Generation + 1,
		OperationID:      mFile.Header.OpID,
		ExpectedRevision: fx.candidate.RemoteRevision,
		Bytes:            fx.candidate.MergedBytes,
	}
}

// admitRebaseInputs is one owned snapshot of the inputs the commit function
// observed. Every byte slice is cloned inside the call: AdoptMergeCandidate
// zeroizes its own state and proposal buffers on return, so a shallow copy
// would observe cleared memory afterwards.
type admitRebaseInputs struct {
	old      vaultfilejournal.State
	base     []byte
	rev      vaultfilebackend.Revision
	proposal vaultfilejournal.Proposal
}

// snapshotAdmitInputs clones every input of one commit call.
func snapshotAdmitInputs(old vaultfilejournal.State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal vaultfilejournal.Proposal) admitRebaseInputs {
	return admitRebaseInputs{
		old: vaultfilejournal.State{
			BaseBytes:      bytes.Clone(old.BaseBytes),
			RemoteRevision: vaultfilebackend.Revision(bytes.Clone([]byte(old.RemoteRevision))),
			WorkingBytes:   bytes.Clone(old.WorkingBytes),
			Generation:     old.Generation,
		},
		base: bytes.Clone(remoteBase),
		rev:  vaultfilebackend.Revision(bytes.Clone([]byte(remoteRevision))),
		proposal: vaultfilejournal.Proposal{
			Generation:       proposal.Generation,
			OperationID:      string([]byte(proposal.OperationID)),
			ExpectedRevision: vaultfilebackend.Revision(bytes.Clone([]byte(proposal.ExpectedRevision))),
			Bytes:            bytes.Clone(proposal.Bytes),
		},
	}
}

// adoptAssertExactInputs proves the commit function received exactly S, R, Rrev
// and P of this attempt, compared against owned snapshots taken inside it.
func adoptAssertExactInputs(t *testing.T, got admitRebaseInputs, fx *adoptFixture, candidateBefore MergeCandidate) {
	t.Helper()
	wantState, wantProposal := adoptCommitInputs(t, fx)
	if got.old.Generation != wantState.Generation ||
		got.old.RemoteRevision != wantState.RemoteRevision ||
		wantState.Generation != candidateBefore.ExpectedGeneration ||
		!bytes.Equal(got.old.BaseBytes, wantState.BaseBytes) ||
		!bytes.Equal(got.old.WorkingBytes, wantState.WorkingBytes) ||
		!bytes.Equal(got.base, fx.candidate.RemoteBytes) ||
		got.rev != fx.candidate.RemoteRevision ||
		got.proposal.Generation != wantProposal.Generation ||
		got.proposal.OperationID != wantProposal.OperationID ||
		got.proposal.ExpectedRevision != wantProposal.ExpectedRevision ||
		!bytes.Equal(got.proposal.Bytes, wantProposal.Bytes) {
		t.Fatal("the commit function did not receive this attempt's exact in-memory inputs")
	}
	// The candidate itself must stay untouched.
	if !adoptCandidateEqual(fx.candidate, candidateBefore) {
		t.Fatal("the commit function mutated the caller candidate")
	}
}

// adoptWithCommit runs AdoptMergeCandidate's implementation with commitFn
// injected for this call only, never through shared state.
func adoptWithCommit(fx *adoptFixture, commitFn adoptCommitFunc) error {
	return adoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id, commitFn)
}

// TestAdoptMergeCandidateReconcileAppliedAfterLostResult is the lost-result
// case. The real RebaseAndPrepare commits (real db.Sync, real records on disk)
// and only its result is lost as an unclassified error. The real reconciliation
// of the same in-memory inputs then proves ReconcileApplied, so adoption
// returns nil.
func TestAdoptMergeCandidateReconcileAppliedAfterLostResult(t *testing.T) {
	fx := adoptBuildFixture(t)
	candidateBefore := adoptCloneCandidate(fx.candidate)
	wantState, wantProposal := adoptCommitInputs(t, fx)
	lost := errors.New("synthetic lost rebase result after commit")
	var calls int
	var seen admitRebaseInputs
	adopted := adoptWithCommit(fx, func(journal *vaultfilejournal.Journal, old vaultfilejournal.State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal vaultfilejournal.Proposal) error {
		calls++
		seen = snapshotAdmitInputs(old, remoteBase, remoteRevision, proposal)
		// The real transaction commits, then its result is lost.
		if err := journal.RebaseAndPrepare(old, remoteBase, remoteRevision, proposal); err != nil {
			t.Fatalf("real RebaseAndPrepare: %v", err)
		}
		return lost
	})
	if adopted != nil {
		t.Fatalf("lost-result adoption = %v, want nil after ReconcileApplied", adopted)
	}
	if calls != 1 {
		t.Fatalf("commit function called %d times, want 1 and no retried write", calls)
	}
	adoptAssertExactInputs(t, seen, fx, candidateBefore)

	// The committed records are this attempt's target.
	state, err := fx.journal.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Generation != wantState.Generation+1 ||
		!bytes.Equal(state.BaseBytes, fx.candidate.RemoteBytes) ||
		state.RemoteRevision != fx.candidate.RemoteRevision ||
		!bytes.Equal(state.WorkingBytes, fx.candidate.MergedBytes) {
		t.Fatal("committed state is not R/Rrev with working M at G+1")
	}
	prepared, err := fx.journal.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared: %v", err)
	}
	if prepared.WorkingGeneration != wantState.Generation+1 ||
		prepared.Proposal.OperationID != wantProposal.OperationID ||
		prepared.Proposal.ExpectedRevision != wantProposal.ExpectedRevision ||
		!bytes.Equal(prepared.Proposal.Bytes, wantProposal.Bytes) {
		t.Fatal("committed prepared record is not the exact M proposal over R")
	}
	// The caller's journal is still open and usable.
	if _, err := fx.journal.LoadRebaseAudit(wantState.Generation + 1); err != nil {
		t.Fatalf("LoadRebaseAudit: %v", err)
	}
	outcome, err := fx.journal.ReconcileRebaseAndPrepare(wantState, fx.candidate.RemoteBytes, fx.candidate.RemoteRevision, wantProposal)
	if err != nil || outcome != vaultfilejournal.ReconcileApplied {
		t.Fatalf("reconcile after success = %v, %v, want Applied", outcome, err)
	}
}

// TestAdoptMergeCandidateReconcileNotAppliedNoSecondWrite loses the result
// before the transaction mutates anything: the file still holds S. The real
// reconciliation proves ReconcileNotApplied, adoption returns a definite commit
// failure that keeps the original raw transaction error reachable and does not
// carry the now-obsolete unknown classification, and no write is retried.
func TestAdoptMergeCandidateReconcileNotAppliedNoSecondWrite(t *testing.T) {
	fx := adoptBuildFixture(t)
	candidateBefore := adoptCloneCandidate(fx.candidate)
	before := adoptSnapshot(fx)(t)
	lost := errors.New("synthetic unknown write before commit")
	var calls int
	var seen admitRebaseInputs
	err := adoptWithCommit(fx, func(journal *vaultfilejournal.Journal, old vaultfilejournal.State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal vaultfilejournal.Proposal) error {
		calls++
		seen = snapshotAdmitInputs(old, remoteBase, remoteRevision, proposal)
		// Prove the real journal still holds exactly S, so the real
		// reconciliation will decide NotApplied, then lose the result.
		if outcome, rerr := journal.ReconcileRebaseAndPrepare(old, remoteBase, remoteRevision, proposal); outcome != vaultfilejournal.ReconcileNotApplied || rerr != nil {
			t.Fatalf("journal before mutation = %v, %v, want NotApplied", outcome, rerr)
		}
		return lost
	})
	if calls != 1 {
		t.Fatalf("commit function called %d times, want 1 and no retried write", calls)
	}
	adoptAssertExactInputs(t, seen, fx, candidateBefore)
	if err == nil {
		t.Fatal("not-applied reconciliation returned nil")
	}
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptCommit)
	if !errors.Is(err, lost) {
		t.Fatalf("definite commit failure lost the original transaction error: %v", err)
	}
	if errors.Is(err, ErrMergeCandidateAdoptCommitUnknown) {
		t.Fatalf("not-applied adoption stayed unknown: %v", err)
	}
	adoptAssertUnchanged(t, fx, before)
	adoptAssertNoPreparedOrAudit(t, fx)
}

// TestAdoptMergeCandidateReconcileReviewStaysUnknown commits a well-formed but
// different target at the same generation and then loses the result. The real
// reconciliation sees neither S nor the exact target and returns
// ReconcileReview, so adoption stays unknown while keeping the original
// transaction error and the review classification reachable.
func TestAdoptMergeCandidateReconcileReviewStaysUnknown(t *testing.T) {
	fx := adoptBuildFixture(t)
	candidateBefore := adoptCloneCandidate(fx.candidate)
	lost := errors.New("synthetic lost rebase result")
	var calls int
	var seen admitRebaseInputs
	err := adoptWithCommit(fx, func(journal *vaultfilejournal.Journal, old vaultfilejournal.State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal vaultfilejournal.Proposal) error {
		calls++
		seen = snapshotAdmitInputs(old, remoteBase, remoteRevision, proposal)
		// A different, well-formed rebase of the same S at the same target
		// generation commits, then its result is lost.
		otherRevision := vaultfilebackend.Revision(`"adopt-other-rev"`)
		other := proposal
		other.ExpectedRevision = otherRevision
		other.OperationID = adoptOpID(9)
		other.Bytes = append(bytes.Clone(proposal.Bytes), []byte("\x00synthetic difference")...)
		otherBase := append(bytes.Clone(remoteBase), 0)
		if err := journal.RebaseAndPrepare(old, otherBase, otherRevision, other); err != nil {
			t.Fatalf("real divergent RebaseAndPrepare: %v", err)
		}
		return lost
	})
	if calls != 1 {
		t.Fatalf("commit function called %d times, want 1", calls)
	}
	adoptAssertExactInputs(t, seen, fx, candidateBefore)
	if err == nil {
		t.Fatal("review reconciliation returned nil")
	}
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptCommitUnknown)
	if errors.Is(err, ErrMergeCandidateAdoptCommit) {
		t.Fatalf("review was reported as a definite commit failure: %v", err)
	}
	if !errors.Is(err, lost) {
		t.Fatalf("unknown error lost the original transaction error: %v", err)
	}
	if !errors.Is(err, vaultfilejournal.ErrReconcileReview) {
		t.Fatalf("unknown error lost the review classification: %v", err)
	}
}
