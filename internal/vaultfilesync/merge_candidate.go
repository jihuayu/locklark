package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"reflect"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/vaultmerge"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// This file adds the local, authenticated three-way merge-candidate builder for
// the current single-file protocol. It is one narrow checkpoint: it reads the
// exact remote tip once, authenticates it together with the local base and
// working files, computes a candidate merged item set, and (only when the merge
// is conflict-free) seals a new candidate working file. It performs no remote
// write, no journal write, no journal proposal/ack/rebase, and no generic
// callback or state-machine integration. It does not implement #111 as a whole.
//
// Trust boundary. The caller-supplied vaultfile.PolicyCheckpoint is the only
// trust input. Nothing read from B, L or R promotes itself into trust: all
// three files are opened with OpenAuthenticatedFile under that pin, the same
// caller device and the same caller age identity, and their current signed
// policy proof is compared exactly. The remote file is an untrusted transport
// value until that open succeeds. The candidate never adopts itself. This
// builder is a pure preview and may run while legacy proposal, prepared
// proposal or other pending remote-outcome records exist; it never reads,
// mutates, resolves or consumes them. The candidate is not adoptable until a
// later same-package RebasePrepare first resolves or rejects every such pending
// outcome, fails closed while any pending state remains, then rechecks both
// private bindings against the exact current journal state and candidate and
// re-authenticates the candidate under its caller pin.
//
// What is merged. Only item values at the authenticated common key epoch are
// passed to internal/vaultmerge.Merge. Policy, roles, members, metadata and file
// controls are never merged: a conflict-free candidate preserves R's
// authenticated policy proofs, metadata and file controls unchanged, and a
// conflict candidate produces no file at all.
//
// History limit. If R is ahead of B, this helper does not fetch a remote DAG,
// does not prove every prev_digest step, and does not establish that R contains
// all prior remote revisions. It authenticates exactly the current R it read and
// uses that authenticated R as the remote branch; B is the local journal's
// recorded base. It also does not require R.ContentSeq to be at least
// L.ContentSeq, because a local offline edit may legitimately have a newer
// sequence than the last remote tip.
//
// Ownership. Every output is owned by the caller: RemoteBytes is a fresh copy
// of the exact read pair's bytes, MergedBytes is freshly sealed, and every
// conflict side is a deep copy made by vaultmerge. No output aliases backend
// bytes, a journal copy, an opened File's bytes, a decoded item, or another
// output. Caller inputs are never mutated. Clear releases the mutable sealed
// and item buffers this result owns. Go strings (including item values,
// identifiers and policy text) are immutable and cannot be overwritten; they
// are dropped, never claimed to be erased. A cancellation or any other error
// returns the zero value and no partial plaintext.

// Sentinel errors classify the definite rejections of BuildMergeCandidate.
// Callers test them with errors.Is. Every returned error wraps at most one of
// these with %w, so the underlying cause (including context.Canceled and
// context.DeadlineExceeded) remains reachable with errors.Is and errors.Unwrap.
// Error messages never contain item values, metadata, plaintext, age identities
// or signing keys.
var (
	// ErrMergeCandidateRejected reports a definite rejection that produced no
	// candidate bytes: invalid inputs, a missing/empty local base, a stale or
	// invalid journal state, or a context cancellation observed at one of the
	// explicit checks. Nothing was written.
	ErrMergeCandidateRejected = errors.New("vault file sync: merge candidate rejected")
	// ErrMergeCandidateRead reports that the single Backend.Read failed or
	// returned an unacceptable pair (empty/oversize bytes or a zero/oversize
	// revision). Nothing was written.
	ErrMergeCandidateRead = errors.New("vault file sync: merge candidate remote read failed")
	// ErrMergeCandidateVerify reports that an authenticated open, item read,
	// header/policy comparison, rollback check or final candidate reopen
	// rejected the input or the produced file. Nothing was written.
	ErrMergeCandidateVerify = errors.New("vault file sync: merge candidate verification failed")
	// ErrMergeCandidateMerge reports that internal/vaultmerge.Merge rejected
	// the authenticated branches. Nothing was written.
	ErrMergeCandidateMerge = errors.New("vault file sync: merge candidate merge failed")
	// ErrMergeCandidateSeal reports that sealing or independently reopening
	// the conflict-free candidate failed. Nothing was written.
	ErrMergeCandidateSeal = errors.New("vault file sync: merge candidate seal failed")
)

// MergeCandidate is one local three-way merge candidate. It is not a
// publication, not a journal proposal and not an adopted state. It is a preview
// that may coexist with pending journal records but is not adoptable until a
// later RebasePrepare has resolved or rejected every legacy/prepared/unknown
// remote outcome, failed closed while anything is still pending, rechecked both
// private bindings against the exact current state/candidate and re-opened the
// candidate under its own caller pin.
//
// On success Conflicts is always non-nil. When it is empty, MergedBytes is
// non-nil and carries a newly sealed candidate working file; when it is
// non-empty, MergedBytes is nil and the caller must inspect every conflict side
// before deciding anything. RemoteBytes and RemoteRevision are always the exact
// pair returned by the one Backend.Read, with the bytes copied into owned
// storage.
type MergeCandidate struct {
	// RemoteBytes is the exact remote file read for this candidate, as an owned
	// copy. It never aliases backend storage.
	RemoteBytes []byte
	// MergedBytes is the newly sealed candidate working file, non-nil exactly
	// when Conflicts is empty. It is nil on a conflict result.
	MergedBytes []byte
	// RemoteRevision is the exact opaque backend revision that was returned
	// together with RemoteBytes.
	RemoteRevision vaultfilebackend.Revision
	// ExpectedGeneration is the local journal generation observed for the
	// source snapshot. It is metadata only; it is not a remote ordering.
	ExpectedGeneration uint64
	// Conflicts is non-nil on success. It is empty on a conflict-free result and
	// carries deep, fully owned Base/Local/Remote sides otherwise. Each side is a
	// complete item or nil when the identifier is absent from that branch.
	//
	// Conflict sides are secret-equivalent plaintext. Their []byte buffers are
	// cleared by Clear; their Go strings cannot be erased and are only dropped.
	Conflicts []vaultmerge.Conflict

	// sourceBinding binds the exact original (BaseBytes, WorkingBytes,
	// RemoteRevision, Generation) tuple. A later same-package RebasePrepare must
	// recompute it from the exact current journal state and reject a mismatch
	// before adoption. The generation alone is deliberately insufficient: Ack
	// may change BaseBytes or RemoteRevision while preserving the working
	// generation.
	sourceBinding [32]byte
	// resultBinding binds sourceBinding, the returned sealed R/M digests, the
	// opaque revision and the observed generation. The source component ties the
	// candidate to the exact journal snapshot it previewed, so a mismatched or
	// replaced candidate is detectable even if its other fields look valid.
	resultBinding [32]byte
}

// Clear releases the mutable output buffers this candidate owns: RemoteBytes,
// MergedBytes and every []byte buffer reachable from a conflict side, then zeroes
// the revision, generation, slices, conflict pointers and both bindings. It is
// safe on a nil receiver and idempotent. Go strings are immutable and are only
// dropped, never overwritten. Journal state, backend storage and caller inputs
// are never touched.
func (c *MergeCandidate) Clear() {
	if c == nil {
		return
	}
	clearSlice(c.RemoteBytes)
	clearSlice(c.MergedBytes)
	for i := range c.Conflicts {
		releaseMergeCandidateConflict(&c.Conflicts[i])
	}
	c.RemoteBytes = nil
	c.MergedBytes = nil
	c.RemoteRevision = ""
	c.ExpectedGeneration = 0
	c.Conflicts = nil
	c.sourceBinding = [32]byte{}
	c.resultBinding = [32]byte{}
}

// BuildMergeCandidate builds one local three-way merge candidate from the
// current single-file protocol state.
//
// Inputs. ctx is checked at entry, after the backend read, after each authored
// open/decrypt, after the merge, after sealing, after the candidate reopen, and
// immediately before the result is returned. backend is read exactly once with
// Read. name is the backend name. journal is the local journal; only LoadState
// is used, exactly once. checkpoint is the caller's already-trusted policy pin
// and the only trust input. deviceID and identity select the caller device and
// age key for opening B, L, R and for authoring M. authorPrivateKey is the
// caller device's Ed25519 content-signing key.
//
// Flow. The journal state is snapshotted; an empty base, an empty working file
// or a zero remote revision is a definite rejection. The exact source tuple is
// bound before any remote read. The remote file is then read once, its bytes
// copied, and the caller-owned Read result buffer cleared on every path. B (the
// journal base), L (the journal working file) and R (the remote read pair) are
// fully opened with OpenAuthenticatedFile and read with vault.ReadItemDatabase.
// All three must authenticate under the caller pin and carry the same VaultID,
// KeyEpoch and exact current signed policy proof (canonical Document, signer,
// algorithm, signature, sequence and digest). R's author is explicitly required
// to be a current writer, admin or owner. After that common current policy is
// authenticated, B's, L's and R's per-epoch VUKs are recovered from their
// authenticated policy device slots and required to compare equal in constant
// time; three same-epoch files encrypted under different VUKs are rejected.
//
// Rollback protection. R.ContentSeq < B.ContentSeq is rejected. Equal sequences
// are accepted only when vaultfile.FileDigest(R) equals vaultfile.FileDigest(B),
// so an equal-sequence fork is rejected. R.ContentSeq == math.MaxUint64 is
// rejected before any increment. R may have a lower sequence than L: local
// offline edits are allowed to be newer. Being ahead of B is not proof of an
// authenticated remote history; see the package note above.
//
// Merge and sealing. Only items are merged, with B as the common base, L as the
// local side and R as the remote side, at the authenticated common KeyEpoch.
// On conflicts the result carries R's exact bytes/revision and the complete deep
// conflicts, with a nil MergedBytes; nothing is chosen or published. On a
// conflict-free result the function seals a new M from R: R's Format, Version,
// ContentEncoding, VaultID, KeyEpoch, current policy sequence/digest and every
// signed policy proof are preserved; ContentSeq is exactly R+1; PrevDigest is
// the raw 32 bytes decoded from vaultfile.FileDigest(R); OpID is a fresh
// "op-" identifier different from R's; AuthorDeviceID is deviceID. M reuses the
// already recovered R VUK; R is never unwrapped a second time and a carried
// DeviceSlot.Recipient is never trusted. The items are sealed with
// vault.SealAuthenticatedItems, whose writer role and key checks authorize
// deviceID. M is then independently reopened under the same pin, device and
// identity with a strict ReadItemDatabase; header/policy continuity, R digest
// linkage, R+1 sequence, operation freshness, author, preserved metadata and
// exact canonical merged item values are all verified before the candidate is
// returned.
//
// Preview and pending records. This builder performs no journal action and may
// run while legacy proposal, prepared proposal or unknown remote-outcome records
// exist. It neither reads nor consumes them, so their presence does not make a
// candidate adoptable. A later same-package RebasePrepare must resolve or reject
// every such pending outcome and fail closed while any remains, then recheck
// both private bindings against the exact current state and candidate and
// re-authenticate the candidate under its caller pin.
//
// No journal or backend mutation. This function never calls journal Load,
// LoadPrepared, Save, Prepare, Ack or UpdateWorking, and it never writes to the
// backend. It allocates every temporary plaintext buffer, sealed buffer, File,
// KDBX database and VUK itself and clears what can be cleared on every path.
//
// Errors. Every error return is the zero MergeCandidate and wraps one of the
// sentinels above. A context cancellation remains matchable with errors.Is. No
// error string includes item values, metadata, plaintext, age identity or
// signing-key bytes.
func BuildMergeCandidate(
	ctx context.Context,
	backend vaultfilebackend.Backend,
	name string,
	journal *vaultfilejournal.Journal,
	checkpoint *vaultfile.PolicyCheckpoint,
	deviceID string,
	identity *age.X25519Identity,
	authorPrivateKey ed25519.PrivateKey,
) (result MergeCandidate, err error) {
	// A single defer guarantees the public contract on every error path: no
	// partial candidate, and every owned buffer this result had acquired is
	// cleared before the zero value is returned.
	defer func() {
		if err != nil {
			result.Clear()
			result = MergeCandidate{}
		}
	}()

	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}
	if err = checkMergeCandidateInputs(backend, journal, name, checkpoint, deviceID, identity, authorPrivateKey); err != nil {
		return MergeCandidate{}, err
	}

	state, stateErr := journal.LoadState()
	if stateErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateRejected, stateErr)
	}
	// LoadState returns deep copies. They are ours; clear them on every path.
	defer clearSlice(state.BaseBytes)
	defer clearSlice(state.WorkingBytes)
	if len(state.BaseBytes) == 0 {
		return MergeCandidate{}, fmt.Errorf("%w: local journal has no remote base", ErrMergeCandidateRejected)
	}
	if len(state.RemoteRevision) == 0 {
		return MergeCandidate{}, fmt.Errorf("%w: local journal has no remote revision", ErrMergeCandidateRejected)
	}
	if len(state.WorkingBytes) == 0 {
		return MergeCandidate{}, fmt.Errorf("%w: local journal has no working file", ErrMergeCandidateRejected)
	}
	sourceBinding := mergeCandidateSourceBinding(state)

	read, readErr := backend.Read(ctx, name)
	// The Read result's bytes are caller-owned by contract. Clear that owned
	// buffer on every path, including an error with a partial result and every
	// length/revision rejection. The candidate keeps only its own clone.
	defer clearSlice(read.Bytes)
	if readErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateRead, readErr)
	}
	if len(read.Bytes) == 0 || len(read.Bytes) > vaultfilebackend.MaxValueSize {
		return MergeCandidate{}, fmt.Errorf("%w: remote bytes have an unacceptable length", ErrMergeCandidateRead)
	}
	if read.Revision.Zero() || len(read.Revision) > vaultfilebackend.MaxRevisionSize {
		return MergeCandidate{}, fmt.Errorf("%w: remote revision is malformed", ErrMergeCandidateRead)
	}
	result.RemoteBytes = bytes.Clone(read.Bytes)
	result.RemoteRevision = read.Revision
	result.ExpectedGeneration = state.Generation
	result.sourceBinding = sourceBinding
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	baseFile, baseDB, openErr := vaultfile.OpenAuthenticatedFile(state.BaseBytes, checkpoint, deviceID, identity)
	if openErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, openErr)
	}
	defer releaseFile(baseFile)
	defer releaseDatabase(baseDB)
	baseMetadata, baseItems, itemsErr := vault.ReadItemDatabase(baseDB)
	if itemsErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, itemsErr)
	}
	defer releasePlaintext(baseMetadata, baseItems)
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	localFile, localDB, openErr := vaultfile.OpenAuthenticatedFile(state.WorkingBytes, checkpoint, deviceID, identity)
	if openErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, openErr)
	}
	defer releaseFile(localFile)
	defer releaseDatabase(localDB)
	localMetadata, localItems, itemsErr := vault.ReadItemDatabase(localDB)
	if itemsErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, itemsErr)
	}
	defer releasePlaintext(localMetadata, localItems)
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	remoteFile, remoteDB, openErr := vaultfile.OpenAuthenticatedFile(result.RemoteBytes, checkpoint, deviceID, identity)
	if openErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, openErr)
	}
	defer releaseFile(remoteFile)
	defer releaseDatabase(remoteDB)
	remoteMetadata, remoteItems, itemsErr := vault.ReadItemDatabase(remoteDB)
	if itemsErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, itemsErr)
	}
	defer releasePlaintext(remoteMetadata, remoteItems)
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	baseCurrent, currentErr := workingCurrentPolicy(baseFile)
	if currentErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, currentErr)
	}
	localCurrent, currentErr := workingCurrentPolicy(localFile)
	if currentErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, currentErr)
	}
	remoteCurrent, currentErr := workingCurrentPolicy(remoteFile)
	if currentErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, currentErr)
	}

	if baseFile.Header.VaultID != localFile.Header.VaultID ||
		baseFile.Header.VaultID != remoteFile.Header.VaultID ||
		baseFile.Header.KeyEpoch != localFile.Header.KeyEpoch ||
		baseFile.Header.KeyEpoch != remoteFile.Header.KeyEpoch {
		return MergeCandidate{}, fmt.Errorf("%w: vault or key epoch differs across B, L and R", ErrMergeCandidateVerify)
	}
	if !sameMergeCandidateCurrentPolicy(baseFile, baseCurrent, localFile, localCurrent) ||
		!sameMergeCandidateCurrentPolicy(baseFile, baseCurrent, remoteFile, remoteCurrent) {
		return MergeCandidate{}, fmt.Errorf("%w: current signed policy proof differs across B, L and R", ErrMergeCandidateVerify)
	}
	if !mergeCandidateAuthorCanWrite(remoteCurrent, remoteFile.Header.AuthorDeviceID) {
		return MergeCandidate{}, fmt.Errorf("%w: remote author is not an authorized current writer", ErrMergeCandidateVerify)
	}

	// The wire contract has exactly one VUK per vault and key epoch. Each file
	// authenticates its own slot, but equal headers alone do not prove the same
	// VUK: recover all three from the authenticated current policy and require
	// constant-time equality. The recovered keys are owned here and cleared on
	// every path. R's key is reused for M; it is never unwrapped a second time.
	baseVUK, vukErr := workingEpochVUK(baseFile, baseCurrent, deviceID, identity)
	if vukErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, vukErr)
	}
	defer clear(baseVUK)
	localVUK, vukErr := workingEpochVUK(localFile, localCurrent, deviceID, identity)
	if vukErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, vukErr)
	}
	defer clear(localVUK)
	remoteVUK, vukErr := workingEpochVUK(remoteFile, remoteCurrent, deviceID, identity)
	if vukErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, vukErr)
	}
	defer clear(remoteVUK)
	baseLocal := subtle.ConstantTimeCompare(baseVUK, localVUK)
	baseRemote := subtle.ConstantTimeCompare(baseVUK, remoteVUK)
	if baseLocal&baseRemote != 1 {
		return MergeCandidate{}, fmt.Errorf("%w: B, L and R do not share one epoch VUK", ErrMergeCandidateVerify)
	}
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	baseSeq := baseFile.Header.ContentSeq
	remoteSeq := remoteFile.Header.ContentSeq
	if remoteSeq < baseSeq {
		return MergeCandidate{}, fmt.Errorf("%w: remote file is a rollback below the local base", ErrMergeCandidateVerify)
	}
	if remoteSeq == baseSeq {
		remoteDigest, digestErr := vaultfile.FileDigest(remoteFile)
		if digestErr != nil {
			return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, digestErr)
		}
		baseDigest, digestErr := vaultfile.FileDigest(baseFile)
		if digestErr != nil {
			return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateVerify, digestErr)
		}
		if remoteDigest != baseDigest {
			return MergeCandidate{}, fmt.Errorf("%w: equal-sequence remote file is not the exact base", ErrMergeCandidateVerify)
		}
	}
	if remoteSeq == math.MaxUint64 {
		return MergeCandidate{}, fmt.Errorf("%w: remote content sequence cannot be incremented", ErrMergeCandidateVerify)
	}
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	// Only items are merged. The authenticated common epoch is R's epoch, which
	// the checks above proved equal to B's and L's.
	epoch := remoteFile.Header.KeyEpoch
	mergeResult, mergeErr := vaultmerge.Merge(
		&vaultmerge.Branch{KeyEpoch: epoch, Items: baseItems},
		vaultmerge.Branch{KeyEpoch: epoch, Items: localItems},
		vaultmerge.Branch{KeyEpoch: epoch, Items: remoteItems},
	)
	if mergeErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateMerge, mergeErr)
	}
	// Non-conflicting items are never returned. They are used to seal M on the
	// clean path and cleared here on every path, including a conflict result.
	defer releasePlaintext(nil, mergeResult.Items)
	if mergeResult.Conflicts == nil {
		mergeResult.Conflicts = []vaultmerge.Conflict{}
	}
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	if len(mergeResult.Conflicts) > 0 {
		result.MergedBytes = nil
		result.Conflicts = mergeResult.Conflicts
		result.resultBinding = mergeCandidateResultBinding(result.sourceBinding, result.RemoteBytes, nil, result.RemoteRevision, result.ExpectedGeneration)
		if err = mergeCandidateContextError(ctx); err != nil {
			return MergeCandidate{}, err
		}
		return result, nil
	}

	result.Conflicts = mergeResult.Conflicts
	expectedItems, canonicalErr := canonicalWorkingItems(remoteMetadata, mergeResult.Items)
	if canonicalErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, canonicalErr)
	}
	defer releasePlaintext(nil, expectedItems)

	prevDigest, digestErr := workingPrevDigest(remoteFile)
	if digestErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, digestErr)
	}
	defer clearSlice(prevDigest)

	opID, idErr := newWorkingOpID(remoteFile.Header.OpID)
	if idErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, idErr)
	}
	draft := mergeCandidateDraft(remoteFile, deviceID, opID, prevDigest)
	defer clear(draft.Header.PolicyDigest)
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	sealed, sealErr := vault.SealAuthenticatedItems(draft, remoteMetadata, mergeResult.Items, checkpoint, remoteVUK, authorPrivateKey)
	if sealErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, sealErr)
	}
	// The candidate now owns the sealed bytes; the deferred error cleanup clears
	// them if any later check fails.
	result.MergedBytes = sealed
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	sealedFile, sealedDB, openErr := vaultfile.OpenAuthenticatedFile(sealed, checkpoint, deviceID, identity)
	if openErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, openErr)
	}
	defer releaseFile(sealedFile)
	defer releaseDatabase(sealedDB)
	sealedMetadata, sealedItems, itemsErr := vault.ReadItemDatabase(sealedDB)
	if itemsErr != nil {
		return MergeCandidate{}, fmt.Errorf("%w: %w", ErrMergeCandidateSeal, itemsErr)
	}
	defer releasePlaintext(sealedMetadata, sealedItems)
	if err = mergeCandidateVerify(remoteFile, sealedFile, deviceID, prevDigest, opID, remoteMetadata, sealedMetadata, expectedItems, sealedItems); err != nil {
		return MergeCandidate{}, err
	}
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}

	result.resultBinding = mergeCandidateResultBinding(result.sourceBinding, result.RemoteBytes, result.MergedBytes, result.RemoteRevision, result.ExpectedGeneration)
	if err = mergeCandidateContextError(ctx); err != nil {
		return MergeCandidate{}, err
	}
	return result, nil
}

// mergeCandidateContextError checks ctx, preserving context.Canceled and
// context.DeadlineExceeded through errors.Is while classifying the failure as a
// definite rejection.
func mergeCandidateContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrMergeCandidateRejected)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrMergeCandidateRejected, err)
	}
	return nil
}

// checkMergeCandidateInputs validates every non-context argument before the
// journal is read. Cryptographic pin shape and device/key validity are checked
// by the vaultfile and vault paths it calls.
func checkMergeCandidateInputs(backend vaultfilebackend.Backend, journal *vaultfilejournal.Journal, name string, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity, authorPrivateKey ed25519.PrivateKey) error {
	if backend == nil || journal == nil {
		return fmt.Errorf("%w: nil backend or journal", ErrMergeCandidateRejected)
	}
	if !vaultfilebackend.ValidName(name) {
		return fmt.Errorf("%w: backend name is not a valid name", ErrMergeCandidateRejected)
	}
	if checkpoint == nil {
		return fmt.Errorf("%w: nil policy checkpoint", ErrMergeCandidateRejected)
	}
	if checkpoint.VaultID == "" || checkpoint.OwnerRootKeyID == "" ||
		len(checkpoint.OwnerRootPublicKey) != 32 || len(checkpoint.PolicyDigest) != sha256.Size {
		return fmt.Errorf("%w: malformed policy checkpoint", ErrMergeCandidateRejected)
	}
	if deviceID == "" {
		return fmt.Errorf("%w: empty device ID", ErrMergeCandidateRejected)
	}
	if identity == nil {
		return fmt.Errorf("%w: nil age identity", ErrMergeCandidateRejected)
	}
	if len(authorPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: malformed author private key", ErrMergeCandidateRejected)
	}
	return nil
}

// sameMergeCandidateCurrentPolicy reports whether two authenticated files carry
// the same exact current signed policy proof: the canonical Document bytes, the
// signer/algorithm/signature, the parsed policy and the header sequence/digest
// binding all agree. Each current policy was itself resolved from the last proof
// and explicitly bound to its header by workingCurrentPolicy.
func sameMergeCandidateCurrentPolicy(aFile *vaultfile.File, aCurrent *vaultfile.Policy, bFile *vaultfile.File, bCurrent *vaultfile.Policy) bool {
	if aFile == nil || bFile == nil || aCurrent == nil || bCurrent == nil ||
		len(aFile.SignedPolicyProofs) == 0 || len(bFile.SignedPolicyProofs) == 0 {
		return false
	}
	a := &aFile.SignedPolicyProofs[len(aFile.SignedPolicyProofs)-1]
	b := &bFile.SignedPolicyProofs[len(bFile.SignedPolicyProofs)-1]
	return a.Policy.PolicySeq == b.Policy.PolicySeq &&
		a.SignerID == b.SignerID &&
		a.Alg == b.Alg &&
		bytes.Equal(a.Document, b.Document) &&
		bytes.Equal(a.Sig, b.Sig) &&
		aCurrent.PolicySeq == aFile.Header.PolicySeq &&
		bCurrent.PolicySeq == bFile.Header.PolicySeq &&
		aCurrent.VaultID == bCurrent.VaultID &&
		reflect.DeepEqual(aCurrent, bCurrent)
}

// mergeCandidateAuthorCanWrite reports whether deviceID is present in the
// authenticated current policy and its principal holds a writer, admin or owner
// role. OpenAuthenticatedFile already enforces content-author authorization; this
// explicit check keeps the remote-side requirement visible in this helper.
func mergeCandidateAuthorCanWrite(current *vaultfile.Policy, deviceID string) bool {
	if current == nil || deviceID == "" {
		return false
	}
	var principal string
	for i := range current.Devices {
		if current.Devices[i].DeviceID == deviceID {
			principal = current.Devices[i].PrincipalID
			break
		}
	}
	if principal == "" {
		return false
	}
	for _, group := range [][]vaultfile.Member{current.Writers, current.Admins, current.Owners} {
		for i := range group {
			if group[i].PrincipalID == principal {
				return true
			}
		}
	}
	return false
}

// mergeCandidateDraft builds the candidate working-file draft from the
// authenticated R. It preserves R's format/version/encoding, vault, key epoch,
// policy sequence/digest and every signed policy proof; only the content
// sequence, previous digest, operation ID and author device are advanced.
func mergeCandidateDraft(remote *vaultfile.File, deviceID, opID string, prevDigest []byte) *vaultfile.File {
	return &vaultfile.File{
		Format:  remote.Format,
		Version: remote.Version,
		Header: vaultfile.Header{
			VaultID:        remote.Header.VaultID,
			KeyEpoch:       remote.Header.KeyEpoch,
			ContentSeq:     remote.Header.ContentSeq + 1,
			PrevDigest:     prevDigest,
			OpID:           opID,
			PolicySeq:      remote.Header.PolicySeq,
			PolicyDigest:   bytes.Clone(remote.Header.PolicyDigest),
			AuthorDeviceID: deviceID,
		},
		SignedPolicyProofs: append([]vaultfile.SignedPolicy(nil), remote.SignedPolicyProofs...),
		ContentEncoding:    remote.ContentEncoding,
	}
}

// mergeCandidateVerify checks the independently reopened sealed candidate
// against the exact authenticated R and the canonical merged items.
func mergeCandidateVerify(remoteFile, sealedFile *vaultfile.File, deviceID string, prevDigest []byte, opID string, metadata, sealedMetadata []byte, items, sealedItems []vault.Item) error {
	if remoteFile == nil || sealedFile == nil {
		return fmt.Errorf("%w: reopened candidate is absent", ErrMergeCandidateSeal)
	}
	if sealedFile.Header.VaultID != remoteFile.Header.VaultID ||
		sealedFile.Header.KeyEpoch != remoteFile.Header.KeyEpoch ||
		sealedFile.Header.PolicySeq != remoteFile.Header.PolicySeq ||
		!bytes.Equal(sealedFile.Header.PolicyDigest, remoteFile.Header.PolicyDigest) {
		return fmt.Errorf("%w: reopened candidate lost vault, epoch or policy continuity", ErrMergeCandidateSeal)
	}
	if sealedFile.Header.ContentSeq != remoteFile.Header.ContentSeq+1 {
		return fmt.Errorf("%w: reopened candidate sequence is not R+1", ErrMergeCandidateSeal)
	}
	if !bytes.Equal(sealedFile.Header.PrevDigest, prevDigest) {
		return fmt.Errorf("%w: reopened candidate is not linked to R's digest", ErrMergeCandidateSeal)
	}
	if sealedFile.Header.OpID != opID || sealedFile.Header.OpID == remoteFile.Header.OpID {
		return fmt.Errorf("%w: reopened candidate operation ID is not fresh", ErrMergeCandidateSeal)
	}
	if sealedFile.Header.AuthorDeviceID != deviceID {
		return fmt.Errorf("%w: reopened candidate author is not the caller device", ErrMergeCandidateSeal)
	}
	if sealedFile.Header.RevisionID == "" {
		return fmt.Errorf("%w: reopened candidate has no derived revision ID", ErrMergeCandidateSeal)
	}
	if !sameSignedProofs(remoteFile.SignedPolicyProofs, sealedFile.SignedPolicyProofs) {
		return fmt.Errorf("%w: reopened candidate did not preserve R's signed policy proofs", ErrMergeCandidateSeal)
	}
	if !bytes.Equal(metadata, sealedMetadata) {
		return fmt.Errorf("%w: reopened candidate metadata differs from R's metadata", ErrMergeCandidateSeal)
	}
	if !reflect.DeepEqual(items, sealedItems) {
		return fmt.Errorf("%w: reopened candidate items differ from the merged items", ErrMergeCandidateSeal)
	}
	return nil
}

// releaseMergeCandidateConflict clears every owned byte buffer of a conflict's
// present sides. It is used only by Clear.
func releaseMergeCandidateConflict(conflict *vaultmerge.Conflict) {
	if conflict == nil {
		return
	}
	clearMergeCandidateItem(conflict.Base)
	clearMergeCandidateItem(conflict.Local)
	clearMergeCandidateItem(conflict.Remote)
	conflict.Base = nil
	conflict.Local = nil
	conflict.Remote = nil
}

// clearMergeCandidateItem clears the mutable secret-equivalent []byte buffers of
// one owned conflict item. Strings are immutable and are only dropped with the
// item.
func clearMergeCandidateItem(item *vault.Item) {
	if item == nil {
		return
	}
	item.ClearPasskeys()
	clearSlice(item.Attachment)
	clearSlice(item.ImportSource)
	clearSlice(item.SSHSeed)
	clearSlice(item.SSHPublicKey)
	for i := range item.Attachments {
		clearSlice(item.Attachments[i].Content)
	}
}

// Binding domains. They are distinct from every protocol signature preimage and
// from each other; the source and result bindings are never interchangeable.
const (
	mergeCandidateSourceDomain = "locklark vault-file merge candidate source v1\x00"
	mergeCandidateResultDomain = "locklark vault-file merge candidate result v1\x00"
)

// mergeCandidateSourceBinding hashes a domain-separated, length-framed
// representation of the exact original source tuple. Each field is framed with
// its uint64 byte length, and the generation is written as a big-endian uint64,
// so concatenation is unambiguous.
func mergeCandidateSourceBinding(state vaultfilejournal.State) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(mergeCandidateSourceDomain))
	writeMergeCandidateFrame(h, state.BaseBytes)
	writeMergeCandidateFrame(h, state.WorkingBytes)
	writeMergeCandidateFrame(h, []byte(state.RemoteRevision))
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], state.Generation)
	_, _ = h.Write(generation[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// mergeCandidateResultBinding binds the source binding, the sealed R and (when
// present) sealed M digests, the opaque revision and the observed generation. A
// conflict result binds M's absence explicitly with a presence marker rather
// than treating nil as an empty file. Including the source binding makes a
// candidate replaced with bytes from a different exact source state detectable
// even when its R/M bytes, revision and generation look independently valid.
func mergeCandidateResultBinding(source [32]byte, remoteBytes, mergedBytes []byte, revision vaultfilebackend.Revision, generation uint64) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(mergeCandidateResultDomain))
	writeMergeCandidateFrame(h, source[:])
	writeMergeCandidateFrame(h, mergeCandidateDigest(remoteBytes))
	if mergedBytes == nil {
		_, _ = h.Write([]byte{0})
	} else {
		_, _ = h.Write([]byte{1})
		writeMergeCandidateFrame(h, mergeCandidateDigest(mergedBytes))
	}
	writeMergeCandidateFrame(h, []byte(revision))
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], generation)
	_, _ = h.Write(gen[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// writeMergeCandidateFrame writes an eight-byte big-endian length followed by
// exactly those bytes, so no two field sequences share one encoding.
func writeMergeCandidateFrame(h hash.Hash, field []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(field)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(field)
}

// mergeCandidateDigest returns the SHA-256 of one sealed output.
func mergeCandidateDigest(sealed []byte) []byte {
	sum := sha256.Sum256(sealed)
	return sum[:]
}
