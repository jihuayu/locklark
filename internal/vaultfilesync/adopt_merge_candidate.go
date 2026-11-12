package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// This file adds the single narrow adoption step for a BuildMergeCandidate
// result: it durably adopts one conflict-free candidate into the local journal
// with one atomic Journal.RebaseAndPrepare. It is one code checkpoint. It adds
// no UI, no generic callback, no state machine, no remote write, no local
// acknowledgement, no clearing of any pending record, no publication and no
// transaction-unknown reconciliation. It does not implement #111 as a whole.
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
// Inputs. ctx is checked at entry, after each authenticated open and full read,
// before and after verification, and immediately before the transaction.
// journal is an open
// local vaultfilejournal.Journal and is read with exactly one LoadState call.
// checkpoint is the caller's trusted pin and is snapshotted (including owned
// copies of both byte fields) at entry, so later caller mutation cannot change
// what this call trusts. deviceID and identity select the caller device and
// age key used to open and decrypt R and M. candidate is the value
// BuildMergeCandidate returned for this same journal, pin and source bytes.
// candidate is read but never mutated or cleared: its byte slices are
// snapshotted into owned storage for the duration of the call.
//
// Bindings. The exact existing full-state rule is kept. The single LoadState
// must match the candidate's ExpectedGeneration and its mergeCandidateSourceBinding
// (BaseBytes, WorkingBytes, RemoteRevision, Generation). An initial generation
// of 0 is allowed. R is independent from the journal base: the builder has
// already authenticated R as a descendant of B, so adoption requires only the
// source binding to match the original state, never candidate.RemoteBytes to
// equal state.BaseBytes.
//
// Re-authentication. R and M are fully opened with
// vaultfile.OpenAuthenticatedFile under exactly the caller pin, deviceID and
// identity, then read with vault.ReadItemDatabase so both files are readable
// end to end. Each authenticated current policy is derived with
// workingCurrentPolicy; R and M must share the same vault, key epoch and exact
// current signed policy proof (sameMergeCandidateCurrentPolicy). Their
// same-epoch VUKs are recovered with workingEpochVUK and compared in constant
// time. R's author must hold a current writer, admin or owner role in R's
// policy. M's author authorization is derived only from R's authenticated
// current policy through NewContentProposalVerifier; M's own roster is never
// consulted as authority.
//
// Rejections. A nil ctx, journal, checkpoint, identity, empty deviceID or
// canceled ctx, a non-empty Conflict list, a nil MergedBytes, a missing or
// oversized RemoteRevision, an absent (zero) source or result binding, or a
// journal state that disagrees with the generation or source binding returns
// ErrMergeCandidateAdoptRejected. A present legacy or prepared record returns
// ErrMergeCandidateAdoptPending and is never consumed; a corrupt record is
// ErrMergeCandidateAdoptPendingCorrupt. Any authentication, policy, VUK, author
// or content-proposal failure returns ErrMergeCandidateAdoptVerify. A context
// error observed before the transaction returns the context error itself.
//
// Commit. Journal.RebaseAndPrepare is called with the exact full expected
// State, the candidate R and Rrev, and the M proposal, whose Generation is the
// local G+1 hint and whose OperationID is M's authenticated OpID. It performs
// the full-state CAS, the pending-record recheck, the audit append, the state
// rebase and the prepared record in one transaction. AdoptMergeCandidate
// returns nil only when that call returns nil. Any error is returned and never
// treated as success.
//
// Secret cleanup. Every owned snapshot, opened File, opened database, recovered
// VUK, metadata and item buffer, and the proposal is cleared with the existing
// release helpers on every path, including every rejection.
//
// Errors. No error string contains item values, metadata, plaintext, age
// identity or signing keys.
func AdoptMergeCandidate(
	ctx context.Context,
	journal *vaultfilejournal.Journal,
	candidate MergeCandidate,
	checkpoint *vaultfile.PolicyCheckpoint,
	deviceID string,
	identity *age.X25519Identity,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrMergeCandidateAdoptRejected)
	}
	if journal == nil {
		return fmt.Errorf("%w: nil journal", ErrMergeCandidateAdoptRejected)
	}
	if checkpoint == nil {
		return fmt.Errorf("%w: nil policy checkpoint", ErrMergeCandidateAdoptRejected)
	}
	if identity == nil {
		return fmt.Errorf("%w: nil age identity", ErrMergeCandidateAdoptRejected)
	}
	if deviceID == "" {
		return fmt.Errorf("%w: empty device ID", ErrMergeCandidateAdoptRejected)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Owned snapshots. R and M are copied, and the pin's byte fields are
	// cloned, so neither depends on the caller after this line. The caller's
	// candidate and checkpoint are never mutated or cleared.
	pin := adoptSnapshotCheckpoint(checkpoint)
	defer clearSlice(pin.OwnerRootPublicKey)
	defer clearSlice(pin.PolicyDigest)
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
	if len(candidate.Conflicts) != 0 {
		return fmt.Errorf("%w: candidate carries conflicts", ErrMergeCandidateAdoptRejected)
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
	// the working file or the recorded remote revision is rejected here. R is
	// deliberately independent from B: only the original state is bound.
	if sourceBinding != mergeCandidateSourceBinding(state) {
		return fmt.Errorf("%w: candidate source binding does not match the journal state", ErrMergeCandidateAdoptRejected)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Fully open, decrypt and read both sealed files under the caller pin.
	remoteFile, remoteDB, err := adoptOpenFile(ctx, remoteBytes, &pin, deviceID, identity)
	if err != nil {
		return err
	}
	defer releaseDatabase(remoteDB)
	defer releaseFile(remoteFile)
	mergedFile, mergedDB, err := adoptOpenFile(ctx, mergedBytes, &pin, deviceID, identity)
	if err != nil {
		return err
	}
	defer releaseDatabase(mergedDB)
	defer releaseFile(mergedFile)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Authority and key continuity come only from the authenticated files.
	remoteCurrent, err := adoptCurrentPolicy(remoteFile)
	if err != nil {
		return err
	}
	mergedCurrent, err := adoptCurrentPolicy(mergedFile)
	if err != nil {
		return err
	}
	if remoteFile.Header.VaultID != mergedFile.Header.VaultID ||
		remoteFile.Header.KeyEpoch != mergedFile.Header.KeyEpoch {
		return fmt.Errorf("%w: vault or key epoch differs between R and M", ErrMergeCandidateAdoptVerify)
	}
	if !sameMergeCandidateCurrentPolicy(remoteFile, remoteCurrent, mergedFile, mergedCurrent) {
		return fmt.Errorf("%w: current signed policy proof differs between R and M", ErrMergeCandidateAdoptVerify)
	}
	// R's author is authorized only by R's own authenticated current policy.
	if !mergeCandidateAuthorCanWrite(remoteCurrent, remoteFile.Header.AuthorDeviceID) {
		return fmt.Errorf("%w: remote author is not an authorized current writer", ErrMergeCandidateAdoptVerify)
	}
	// One epoch VUK per vault: equal headers alone do not prove it, so recover
	// both from their authenticated current policies and compare exactly. R's
	// policy is the authority for both recoveries.
	remoteVUK, err := adoptEpochVUK(remoteFile, remoteCurrent, deviceID, identity)
	if err != nil {
		return err
	}
	defer clear(remoteVUK)
	mergedVUK, err := adoptEpochVUK(mergedFile, remoteCurrent, deviceID, identity)
	if err != nil {
		return err
	}
	defer clear(mergedVUK)
	if subtle.ConstantTimeCompare(remoteVUK, mergedVUK) != 1 {
		return fmt.Errorf("%w: R and M do not share one epoch VUK", ErrMergeCandidateAdoptVerify)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// M's author role is authorized only from R's current policy, by the
	// existing caller-pinned verifier. The proposal binds M's own OpID, the
	// target revision and G+1 as a hint.
	verify, err := NewContentProposalVerifier(&pin)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       state.Generation + 1,
		OperationID:      mergedFile.Header.OpID,
		ExpectedRevision: remoteRevision,
		Bytes:            mergedBytes,
	}
	defer clearSlice(proposal.Bytes)
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

// adoptSnapshotCheckpoint copies every trust-relevant field of the caller pin
// into owned storage. The clone never shares a byte slice with the caller, so
// caller mutation after entry cannot change what this call authenticates.
func adoptSnapshotCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) vaultfile.PolicyCheckpoint {
	return vaultfile.PolicyCheckpoint{
		VaultID:            checkpoint.VaultID,
		OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: append(ed25519.PublicKey(nil), checkpoint.OwnerRootPublicKey...),
		PolicySeq:          checkpoint.PolicySeq,
		PolicyDigest:       append([]byte(nil), checkpoint.PolicyDigest...),
	}
}

// adoptOpenFile authenticates, decrypts and fully reads one sealed file under
// exactly the caller pin, device and identity. The returned File and database
// are owned by the caller and must be released; the metadata and items are
// cleared here on every path.
func adoptOpenFile(ctx context.Context, sealed []byte, pin *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*vaultfile.File, *kdbx.Database, error) {
	file, db, err := vaultfile.OpenAuthenticatedFile(sealed, pin, deviceID, identity)
	if err != nil {
		releaseDatabase(db)
		releaseFile(file)
		return nil, nil, fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	if err := ctx.Err(); err != nil {
		releaseDatabase(db)
		releaseFile(file)
		return nil, nil, err
	}
	metadata, items, err := vault.ReadItemDatabase(db)
	releasePlaintext(metadata, items)
	if err != nil {
		releaseDatabase(db)
		releaseFile(file)
		return nil, nil, fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	if err := ctx.Err(); err != nil {
		releaseDatabase(db)
		releaseFile(file)
		return nil, nil, err
	}
	return file, db, nil
}

// adoptCurrentPolicy derives the file's authenticated current policy and
// classifies any failure as a verification rejection.
func adoptCurrentPolicy(file *vaultfile.File) (*vaultfile.Policy, error) {
	current, err := workingCurrentPolicy(file)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	return current, nil
}

// adoptEpochVUK recovers one same-epoch VUK and classifies any failure as a
// verification rejection. The returned key is owned by the caller.
func adoptEpochVUK(file *vaultfile.File, current *vaultfile.Policy, deviceID string, identity *age.X25519Identity) ([]byte, error) {
	vuk, err := workingEpochVUK(file, current, deviceID, identity)
	if err != nil {
		clear(vuk)
		return nil, fmt.Errorf("%w: %w", ErrMergeCandidateAdoptVerify, err)
	}
	return vuk, nil
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
