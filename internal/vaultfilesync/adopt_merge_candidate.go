package vaultfilesync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// This file adds the single narrow adoption step for a BuildMergeCandidate
// result: it durably adopts one conflict-free candidate into the local journal
// with one atomic Journal.RebaseAndPrepare. It is one code checkpoint. It adds
// no UI, no generic callback, no state machine, no remote write, no local
// acknowledgement, no clearing of any pending record and no publication. It
// does not implement #111 as a whole.
//
// Trust boundary. The caller-supplied vaultfile.PolicyCheckpoint is the only
// trust input. The candidate is never trusted as a value: it is copied into
// private storage and its bytes are checked against the candidate's own private
// bindings, the exact full journal state it claims to describe, and the exact
// source tuple it was built from. The sealed R and M are then revalidated by the
// existing NewContentProposalVerifier under the caller pin with an exact
// Proposal derived from the authenticated M header. The candidate is an opaque
// function value, so an unknown or forged candidate never verifies.
//
// Durability. The only journal mutation is Journal.RebaseAndPrepare, which
// requires the exact full expected State (same full-state CAS) and rejects any
// legacy or prepared pending record inside the same transaction. One success
// therefore writes the audit, the rebased state and the prepared record
// atomically. A nil return is the sole success signal. Any error, including a
// storage error whose transaction may have committed, is an error and never
// success; recovery is a later exact comparison, never inferred here.

// Sentinel errors classify the definite rejections of AdoptMergeCandidate.
// Callers test them with errors.Is. Every returned error wraps at most one of
// these with %w and keeps the underlying cause reachable. The wrapped
// vaultfilejournal classification (ErrStateMismatch, ErrPendingRecords,
// ErrCorrupt, ErrEmpty, ...) remains matchable as well. A storage error from
// the transaction that does not carry a journal classification is wrapped in
// ErrMergeCandidateAdoptCommitUnknown: the transaction may or may not have
// committed, so the outcome must be reconciled, never assumed.
var (
	// ErrMergeCandidateAdoptRejected reports a definite rejection that wrote
	// nothing: invalid inputs, a nil journal, a nil pin, a nil context, a
	// canceled context, a conflict result, a nil or malformed M/R/revision, an
	// incomplete or inconsistent candidate binding, a candidate whose
	// ExpectedGeneration or source binding does not match the exact journal
	// state, or a journal read that failed before the CAS.
	ErrMergeCandidateAdoptRejected = errors.New("vault file sync: merge candidate adoption rejected")
	// ErrMergeCandidateAdoptPending reports a definite rejection caused by a
	// present legacy Load or LoadPrepared record, or by the transaction's own
	// pending-record recheck. Nothing was written.
	ErrMergeCandidateAdoptPending = errors.New("vault file sync: merge candidate adoption has a pending journal record")
	// ErrMergeCandidateAdoptPendingCorrupt reports a corrupt or unknown error
	// while loading the legacy or prepared record holding a pending proposal.
	// It is propagated, never repaired, and nothing was written.
	ErrMergeCandidateAdoptPendingCorrupt = errors.New("vault file sync: merge candidate adoption could not read a pending journal record")
	// ErrMergeCandidateAdoptVerify reports that the candidate's R or M failed
	// the caller-pinned content proposal verification, or that the candidate's
	// binding tuple is internally inconsistent. Nothing was written.
	ErrMergeCandidateAdoptVerify = errors.New("vault file sync: merge candidate adoption verification failed")
	// ErrMergeCandidateAdoptCommit reports a definite rejection of the
	// RebaseAndPrepare transaction (the exact CAS did not match, a pending
	// record was found inside the transaction, the journal is closed or a
	// classified storage error occurred). The transaction did not commit.
	ErrMergeCandidateAdoptCommit = errors.New("vault file sync: merge candidate adoption transaction failed")
	// ErrMergeCandidateAdoptCommitUnknown reports a storage error from the
	// transaction that did not carry a definite journal classification. The
	// transaction may have committed before the error surfaced; do not claim
	// success or failure, reopen and compare the state, prepared record and
	// audit exactly.
	ErrMergeCandidateAdoptCommitUnknown = errors.New("vault file sync: merge candidate adoption outcome unknown")
)

// AdoptMergeCandidate durably adopts one conflict-free BuildMergeCandidate
// result. It is not generic and exposes no callback.
//
// Inputs. journal is an open local vaultfilejournal.Journal and is read with
// exactly one LoadState call; checkpoint is the caller's trusted pin; candidate
// is the value BuildMergeCandidate returned for this same journal, pin and
// source bytes. candidate is read but never mutated or cleared: its fields are
// copied into private storage for the duration of the call.
//
// Rejections. A nil ctx, journal or checkpoint, a canceled ctx, a nil
// MergedBytes (conflict result or incomplete candidate), a missing or
// oversized RemoteRevision, an absent (zero) source or result binding, a
// RemoteBytes length or nilness that disagrees with the binding, a missing
// journal state, or a source binding that does not match the exact full state
// (an Ack that preserves the generation but changes BaseBytes, WorkingBytes or
// RemoteRevision is rejected) returns ErrMergeCandidateAdoptRejected. A present legacy or prepared record returns
// ErrMergeCandidateAdoptPending and its contents are cleared, never claimed and
// never consumed; a corrupt or unknown error while loading either record is
// propagated (classified as ErrMergeCandidateAdoptPendingCorrupt) and adoption
// is refused. R and M are then revalidated with
// NewContentProposalVerifier under exactly the caller pin and an exact Proposal
// {Generation, OperationID, ExpectedRevision, Bytes} derived from the
// authenticated M header; any rejection returns ErrMergeCandidateAdoptVerify
// without inheriting any claim. A context error observed before the
// transaction returns the context error itself and never success.
//
// Commit. Journal.RebaseAndPrepare is called with the exact full expected
// State, the candidate R and Rrev, and the M proposal. It performs the
// full-state CAS, the pending-record recheck, the audit append, the state
// rebase and the prepared record in one transaction. AdoptMergeCandidate
// returns nil only when that call returns nil. Any error is returned and never
// treated as success.
//
// Errors. No error string contains item values, metadata, plaintext, age
// identity or signing keys.
func AdoptMergeCandidate(ctx context.Context, journal *vaultfilejournal.Journal, candidate MergeCandidate, checkpoint *vaultfile.PolicyCheckpoint) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrMergeCandidateAdoptRejected)
	}
	if journal == nil {
		return fmt.Errorf("%w: nil journal", ErrMergeCandidateAdoptRejected)
	}
	if checkpoint == nil {
		return fmt.Errorf("%w: nil policy checkpoint", ErrMergeCandidateAdoptRejected)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Private snapshot of the exact source tuple. The sealed bytes are owned
	// copies so a concurrent caller mutation of the candidate cannot change
	// what is verified or committed, and the candidate itself is untouched.
	remoteBytes := bytes.Clone(candidate.RemoteBytes)
	defer clearSlice(remoteBytes)
	mergedBytes := bytes.Clone(candidate.MergedBytes)
	defer clearSlice(mergedBytes)
	remoteRevision := candidate.RemoteRevision
	generation := candidate.ExpectedGeneration
	sourceBinding := candidate.sourceBinding
	resultBinding := candidate.resultBinding

	if len(remoteBytes) == 0 || len(remoteBytes) > vaultfilejournal.MaxBaseBytes {
		return fmt.Errorf("%w: candidate remote bytes have an unacceptable length", ErrMergeCandidateAdoptRejected)
	}
	if len(remoteRevision) == 0 || len(remoteRevision) > vaultfilejournal.MaxStateRevisionBytes {
		return fmt.Errorf("%w: candidate remote revision is missing or malformed", ErrMergeCandidateAdoptRejected)
	}
	if sourceBinding == ([32]byte{}) {
		return fmt.Errorf("%w: candidate source binding is absent", ErrMergeCandidateAdoptRejected)
	}
	if resultBinding == ([32]byte{}) {
		return fmt.Errorf("%w: candidate result binding is absent", ErrMergeCandidateAdoptRejected)
	}
	if candidate.Conflicts == nil {
		return fmt.Errorf("%w: candidate is incomplete and carries no conflict result", ErrMergeCandidateAdoptRejected)
	}
	if candidate.MergedBytes == nil {
		return fmt.Errorf("%w: candidate has no merged result (conflict result)", ErrMergeCandidateAdoptRejected)
	}
	if len(mergedBytes) > vaultfilejournal.MaxProposalBytes {
		return fmt.Errorf("%w: candidate merged result is too large", ErrMergeCandidateAdoptVerify)
	}
	if mergedBytes == nil {
		return fmt.Errorf("%w: candidate merged result is empty", ErrMergeCandidateAdoptRejected)
	}
	// The result binding must describe exactly these outputs, not some other
	// candidate's outputs.
	if resultBinding != mergeCandidateResultBinding(sourceBinding, remoteBytes, mergedBytes, remoteRevision, generation) {
		return fmt.Errorf("%w: candidate result binding does not match its outputs", ErrMergeCandidateAdoptRejected)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Any legacy or prepared record makes this candidate non-adoptable. The
	// transaction rechecks this atomically; this pre-check returns the exact
	// pending classification without reading, clearing or consuming anything.
	if err := checkAdoptPendingRecords(journal); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Exactly one full-state read, used both as the binding source and as the
	// exact expected state for the CAS.
	state, err := journal.LoadState()
	if err != nil {
		if errors.Is(err, vaultfilejournal.ErrEmpty) {
			return fmt.Errorf("%w: journal has no state", ErrMergeCandidateAdoptRejected)
		}
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptRejected, err)
	}
	defer clearSlice(state.BaseBytes)
	defer clearSlice(state.WorkingBytes)
	if state.Generation != generation {
		return fmt.Errorf("%w: candidate generation does not match the journal state", ErrMergeCandidateAdoptRejected)
	}
	if !adoptCompleteState(state) {
		return fmt.Errorf("%w: journal state is malformed", ErrMergeCandidateAdoptRejected)
	}
	if state.Generation == math.MaxUint64 {
		return fmt.Errorf("%w: journal generation cannot advance", ErrMergeCandidateAdoptRejected)
	}
	// The source binding covers BaseBytes, WorkingBytes, RemoteRevision and
	// the generation, so an Ack that kept the generation but replaced the base,
	// the working file or the recorded remote revision is rejected here.
	if sourceBinding != mergeCandidateSourceBinding(state) {
		return fmt.Errorf("%w: candidate source binding does not match the journal state", ErrMergeCandidateAdoptRejected)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Revalidate the exact R and M under the caller pin. The proposal is derived
	// from the authenticated M header, so the verifier enforces the R-authorized
	// writer, the same vault/epoch/current policy, M sequence exactly R+1,
	// PrevDigest exactly FileDigest(R) and OperationID exactly M's OpID.
	verify, err := NewContentProposalVerifier(checkpoint)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	// The candidate base file is opaque to this checkpoint; wiring it to a key
	// epoch policy is a later step.
	mergedFile, err := vaultfile.ParseFile(mergedBytes)
	if err != nil {
		return fmt.Errorf("%w: merge candidate does not parse", ErrMergeCandidateAdoptVerify)
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       state.Generation + 1,
		OperationID:      mergedFile.Header.OpID,
		ExpectedRevision: remoteRevision,
		Bytes:            mergedBytes,
	}
	if err := verify(ctx, remoteBytes, remoteRevision, proposal); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := journal.RebaseAndPrepare(state, remoteBytes, remoteRevision, proposal); err != nil {
		return classifyAdoptCommitError(err)
	}
	return nil
}

// adoptCompleteState reports whether a loaded state carries every field a
// candidate binds and the transaction needs. LoadState already validates the
// stored record; this keeps the requirement visible at the adoption boundary.
// The initial recorded generation is 0, so zero itself is not a rejection; a
// zero-value candidate is rejected earlier by its absent bindings.
func adoptCompleteState(s vaultfilejournal.State) bool {
	if len(s.BaseBytes) == 0 || len(s.BaseBytes) > vaultfilejournal.MaxBaseBytes {
		return false
	}
	if len(s.RemoteRevision) == 0 || len(s.RemoteRevision) > vaultfilejournal.MaxStateRevisionBytes {
		return false
	}
	return len(s.WorkingBytes) > 0 && len(s.WorkingBytes) <= vaultfilejournal.MaxWorkingBytes
}

// adoptPendingRecord classifies one proposed pending legacy or prepared record.
// A pending record makes the candidate non-adoptable; its contents are cleared
// and it is never consumed. Any other error is propagated unchanged so a clear
// or unknown Load error stays the underlying error, never an adoption result.
func adoptPendingRecord(record vaultfilejournal.Proposal, err error) (bool, error) {
	if err == nil {
		clearSlice(record.Bytes)
		return true, fmt.Errorf("%w", ErrMergeCandidateAdoptPending)
	}
	if errors.Is(err, vaultfilejournal.ErrEmpty) {
		return false, nil
	}
	return true, fmt.Errorf("%w: %w", ErrMergeCandidateAdoptPendingCorrupt, err)
}

// checkAdoptPendingRecords reports ErrMergeCandidateAdoptPending when either
// the legacy Load record or the prepared LoadPrepared record is present. A
// corrupt record, or any other Load error, is returned as
// ErrMergeCandidateAdoptPendingCorrupt wrapping the cause. Nothing is written
// or consumed in any case.
func checkAdoptPendingRecords(journal *vaultfilejournal.Journal) error {
	legacy, err := journal.Load()
	pending, err := adoptPendingRecord(legacy, err)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("%w: legacy proposal record is present", ErrMergeCandidateAdoptPending)
	}
	prepared, err := journal.LoadPrepared()
	pending, err = adoptPendingRecord(prepared.Proposal, err)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("%w: prepared proposal record is present", ErrMergeCandidateAdoptPending)
	}
	return nil
}

// classifyAdoptCommitError maps the error of Journal.RebaseAndPrepare to a
// definite or unknown adoption error. Only ErrInvalid, ErrEmpty,
// ErrStateMismatch, ErrStateGenerationOverflow, ErrPendingRecords,
// ErrAuditCollision, ErrCorrupt and ErrClosed prove the transaction did not
// commit. Every other error is wrapped in ErrMergeCandidateAdoptCommitUnknown.
// No branch treats an error as success, and none claims the outcome.
func classifyAdoptCommitError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, vaultfilejournal.ErrPendingRecords):
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptPending, err)
	case errors.Is(err, vaultfilejournal.ErrInvalid),
		errors.Is(err, vaultfilejournal.ErrEmpty),
		errors.Is(err, vaultfilejournal.ErrStateMismatch),
		errors.Is(err, vaultfilejournal.ErrStateGenerationOverflow),
		errors.Is(err, vaultfilejournal.ErrAuditCollision),
		errors.Is(err, vaultfilejournal.ErrCorrupt),
		errors.Is(err, vaultfilejournal.ErrClosed):
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptCommit, err)
	default:
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptCommitUnknown, err)
	}
}
