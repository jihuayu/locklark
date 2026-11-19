package personal

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// VaultFileLegacyPartitionDisposition is the bounded durable outcome proven
// for one exactly pinned staged legacy-partition candidate. Its zero value is
// unknown: no outcome was established.
type VaultFileLegacyPartitionDisposition uint8

const (
	// VaultFileLegacyPartitionDispositionUnknown means the candidate outcome was
	// not established. No partial result is released.
	VaultFileLegacyPartitionDispositionUnknown VaultFileLegacyPartitionDisposition = iota
	// VaultFileLegacyPartitionPendingSafeForCAS means the journal still holds
	// the exact prepared proposal and the named live backend object is still the
	// original genesis at the unchanged original journal revision, so the
	// original compare-and-swap remains safe.
	VaultFileLegacyPartitionPendingSafeForCAS
	// VaultFileLegacyPartitionAppliedUnacknowledged means the journal still
	// holds the exact prepared proposal while the named live backend object is
	// exactly the candidate at a coherently different revision: the CAS
	// succeeded but the local acknowledgement did not.
	VaultFileLegacyPartitionAppliedUnacknowledged
	// VaultFileLegacyPartitionSettled means the journal settled exactly this
	// candidate and the named live backend object still reads it back at the
	// exact recorded revision.
	VaultFileLegacyPartitionSettled
)

// String names the disposition without exposing any journal or backend data.
func (d VaultFileLegacyPartitionDisposition) String() string {
	switch d {
	case VaultFileLegacyPartitionPendingSafeForCAS:
		return "pending-safe-for-cas"
	case VaultFileLegacyPartitionAppliedUnacknowledged:
		return "applied-unacknowledged"
	case VaultFileLegacyPartitionSettled:
		return "settled"
	default:
		return "unknown"
	}
}

// OwnedVaultFileLegacyPartitionReconciliationRequest is the narrow read-only
// input to one durable-outcome reconciliation of a previously staged
// legacy-partition candidate. It reuses the verification request's original
// archive material, explicit selector, source archive digest, exact candidate
// bytes, trusted genesis checkpoint/target and recovery factors, adding only an
// independently pinned nonzero candidate digest. Journal state, revisions,
// proposal records and expected archive contents are never accepted from the
// caller.
type OwnedVaultFileLegacyPartitionReconciliationRequest struct {
	OwnedVaultFileLegacyPartitionVerificationRequest
	ExpectedCandidateSHA256 [sha256.Size]byte
}

// VaultFileReconciledLegacyPartition is the bounded result of one durable
// outcome reconciliation. It retains only the verified source provenance, the
// identity-preserving item mapping and the proven disposition; it never retains
// candidate bytes, decrypted item content, recovery factors, a VUK or a signing
// key.
type VaultFileReconciledLegacyPartition struct {
	VaultFileVerifiedLegacyPartition
	Disposition VaultFileLegacyPartitionDisposition
}

// Clear drops every retained mapping, provenance value and disposition.
func (v *VaultFileReconciledLegacyPartition) Clear() {
	if v == nil {
		return
	}
	v.VaultFileVerifiedLegacyPartition.Clear()
	v.Disposition = VaultFileLegacyPartitionDispositionUnknown
}

// ReconcileOwnedVaultFileLegacyPartition determines, without writing anything,
// which exact durable outcome currently holds for one independently pinned
// staged legacy-partition candidate.
//
// The destination is authenticated with the same full factors, current owner
// record, exact named backend target and companion checkpoint as
// SealOwnedVaultFileFirstItemsFromLegacyPartition. The original archive is
// authenticated again with the same recovery factors and explicit selector; its
// independently pinned digest and the independently pinned candidate digest
// must match. The actual private journal is then read as either the exact
// generation-1 prepared proposal or the exact settled first successor, and the
// exact expected genesis, candidate transition, author device and represented
// legacy records are verified cryptographically and semantically.
//
// The named live backend object is read once as an atomically consistent bytes
// plus opaque revision pair. A pending proposal is safe for the original CAS
// only when the backend is still the original genesis at the unchanged original
// journal revision. A pending proposal whose backend is exactly the candidate at
// a coherently different revision is reported as applied but unacknowledged. A
// settled journal must read the exact candidate back at its exact recorded
// revision. The exact journal observation and live backend bytes/revision are
// re-read through the existing typed helpers, then the same session ownership
// scope is revalidated before the copied result is released.
//
// A different successor, a same-genesis changed backend revision, a missing or
// foreign journal, a wrong source or candidate digest, a wrong selector, a
// nondurable or incoherent record, a malformed transition and any live/owner/
// account drift fail closed with no partial result. No retry writes the journal,
// backend, personal store or archive.
func (s *Session) ReconcileOwnedVaultFileLegacyPartition(req OwnedVaultFileLegacyPartitionReconciliationRequest) (out VaultFileReconciledLegacyPartition, retErr error) {
	if s == nil {
		return out, ErrSessionLocked
	}
	if len(req.Candidate) == 0 {
		return out, ErrVaultFileBaselineVerification
	}
	var zeroDigest [sha256.Size]byte
	if req.ExpectedCandidateSHA256 == zeroDigest ||
		sha256.Sum256(req.Candidate) != req.ExpectedCandidateSHA256 {
		return out, ErrLegacyVaultPartitionPayload
	}
	if len(req.Source.Archive) == 0 || req.Source.VaultID == "" ||
		req.Source.RecoveryKit == "" ||
		req.ExpectedSourceArchiveSHA256 == zeroDigest {
		return out, ErrLegacyVaultPartitionPayload
	}
	if req.JournalPath == "" || len(req.ExpectedGenesis) == 0 {
		return out, ErrVaultFileEditVerification
	}

	scope, err := s.authenticateOwnedVaultFileWriteScope(req.Target, req.Checkpoint, req.Password, req.Key)
	if err != nil {
		return out, err
	}
	defer scope.clear()
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()

	if sha256.Sum256(req.Source.Archive) != req.ExpectedSourceArchiveSHA256 {
		return out, ErrLegacyVaultPartitionPayload
	}
	sourceDigest, declaration, items, err := authenticateLegacyVaultPartitionSource(req.Source)
	if err != nil {
		return out, err
	}
	defer clearAuthenticatedItems(items)
	if sourceDigest != req.ExpectedSourceArchiveSHA256 {
		return out, ErrLegacyVaultPartitionPayload
	}

	pending, prepared, disposition, mapping, backendBytes, backendRevision, err :=
		reconcileLegacyPartitionDurableOutcome(req, scope, items)
	if err != nil {
		return out, err
	}
	defer clear(backendBytes)
	defer func() {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
	}()

	if err := readOwnedVaultFileSuccessorBackend(req.Target, backendBytes, backendRevision); err != nil {
		return out, err
	}
	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		return out, err
	}
	if err := s.active(false); err != nil {
		return out, err
	}

	out.SourceArchiveSHA256 = sourceDigest
	out.SourceVaultID = req.Source.VaultID
	out.SourceVault = declaration
	out.DestinationVaultID = req.Checkpoint.VaultID
	out.ItemMapping = mapping
	out.Disposition = disposition
	return out, nil
}

// reconcileLegacyPartitionDurableOutcome reads the real private journal and the
// named backend once, proves the exact candidate and returns the observed live
// bytes/revision so the caller can recheck them with the existing bound reader.
// It also re-reads the exact journal observation before returning.
func reconcileLegacyPartitionDurableOutcome(req OwnedVaultFileLegacyPartitionReconciliationRequest, scope *ownedVaultFileWriteScope, items []vault.Item) (vaultfilejournal.State, vaultfilejournal.PreparedProposal, VaultFileLegacyPartitionDisposition, map[string]string, []byte, vaultfilebackend.Revision, error) {
	var (
		pending     vaultfilejournal.State
		prepared    vaultfilejournal.PreparedProposal
		disposition VaultFileLegacyPartitionDisposition
		mapping     map[string]string
		backend     []byte
		revision    vaultfilebackend.Revision
	)

	// The pending reader opens the generation-1 state shape. The settled reader
	// uses its own version-2 validated open, so a settled journal cannot be read
	// through OpenExisting. Try the pending shape first, then the settled shape
	// only after the pending read definitely failed and closed cleanly.
	j, openErr := vaultfilejournal.OpenExisting(req.JournalPath)
	if openErr == nil {
		var pendingErr error
		pending, prepared, pendingErr = j.LoadOwnedFirstPending()
		closeErr := j.Close()
		if pendingErr == nil && closeErr == nil {
			var reconcileErr error
			disposition, mapping, backend, revision, reconcileErr = reconcileLegacyPartitionPending(req, scope, items, pending, prepared)
			if reconcileErr != nil {
				clear(pending.BaseBytes)
				clear(pending.WorkingBytes)
				clear(prepared.Proposal.Bytes)
				return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", reconcileErr
			}
			return pending, prepared, disposition, mapping, backend, revision, nil
		}
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		if pendingErr == nil || closeErr != nil {
			return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
		}
	}

	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(req.JournalPath, req.Target.Pin)
	if err != nil {
		return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
	}
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)

	disposition, mapping, backend, revision, err = reconcileLegacyPartitionSettled(req, scope, items, record)
	if err != nil {
		return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	if err := verifyLegacyPartitionSettledUnchanged(req.JournalPath, req.Target.Pin, record); err != nil {
		clear(backend)
		return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	return vaultfilejournal.State{}, vaultfilejournal.PreparedProposal{}, disposition, mapping, backend, revision, nil
}

func reconcileLegacyPartitionPending(req OwnedVaultFileLegacyPartitionReconciliationRequest, scope *ownedVaultFileWriteScope, items []vault.Item, pending vaultfilejournal.State, prepared vaultfilejournal.PreparedProposal) (VaultFileLegacyPartitionDisposition, map[string]string, []byte, vaultfilebackend.Revision, error) {
	if !bytes.Equal(pending.BaseBytes, req.ExpectedGenesis) ||
		pending.Generation != 1 || prepared.WorkingGeneration != 1 ||
		prepared.Proposal.Generation != 1 || len(pending.RemoteRevision) == 0 ||
		prepared.Proposal.ExpectedRevision != pending.RemoteRevision ||
		!bytes.Equal(prepared.Proposal.Bytes, req.Candidate) ||
		!bytes.Equal(pending.WorkingBytes, req.Candidate) {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
	}
	deviceID, _, err := verifyLegacyPartitionGenesisRecord(pending.BaseBytes, req.Target, req.Checkpoint, scope)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	candidateFile, err := vaultfile.ParseFile(req.Candidate)
	if err != nil || candidateFile.Header.OpID != prepared.Proposal.OperationID {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineVerification
	}
	mapping, err := verifyLegacyPartitionCandidate(req.Candidate, vaultfilejournal.State{BaseBytes: pending.BaseBytes}, req.Checkpoint, scope, deviceID, items)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}

	backend, revision, err := readLegacyPartitionBackendObservation(req.Target)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	switch {
	case bytes.Equal(backend, pending.BaseBytes) && revision == pending.RemoteRevision:
		if err := verifyLegacyPartitionPendingUnchanged(req.JournalPath, pending, prepared); err != nil {
			clear(backend)
			return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
		}
		return VaultFileLegacyPartitionPendingSafeForCAS, mapping, backend, revision, nil
	case bytes.Equal(backend, req.Candidate) && revision != pending.RemoteRevision:
		if err := verifyLegacyPartitionPendingUnchanged(req.JournalPath, pending, prepared); err != nil {
			clear(backend)
			return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
		}
		return VaultFileLegacyPartitionAppliedUnacknowledged, mapping, backend, revision, nil
	default:
		clear(backend)
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
	}
}

func reconcileLegacyPartitionSettled(req OwnedVaultFileLegacyPartitionReconciliationRequest, scope *ownedVaultFileWriteScope, items []vault.Item, record vaultfilejournal.OwnedFirstSuccessor) (VaultFileLegacyPartitionDisposition, map[string]string, []byte, vaultfilebackend.Revision, error) {
	if !bytes.Equal(record.GenesisBytes, req.ExpectedGenesis) ||
		len(record.GenesisRevision) == 0 || len(record.SuccessorRevision) == 0 ||
		record.GenesisRevision == record.SuccessorRevision ||
		!bytes.Equal(record.SuccessorBytes, req.Candidate) {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
	}
	deviceID, _, err := verifyLegacyPartitionGenesisRecord(record.GenesisBytes, req.Target, req.Checkpoint, scope)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	mapping, err := verifyLegacyPartitionCandidate(req.Candidate, vaultfilejournal.State{BaseBytes: record.GenesisBytes}, req.Checkpoint, scope, deviceID, items)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}

	backend, revision, err := readLegacyPartitionBackendObservation(req.Target)
	if err != nil {
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", err
	}
	if !bytes.Equal(backend, req.Candidate) || revision != record.SuccessorRevision {
		clear(backend)
		return VaultFileLegacyPartitionDispositionUnknown, nil, nil, "", ErrVaultFileBaselineJournal
	}
	return VaultFileLegacyPartitionSettled, mapping, backend, revision, nil
}

// verifyLegacyPartitionGenesisRecord authenticates one exact genesis record
// against the trusted owned target, companion checkpoint and current account
// device. It requires empty represented content and returns the current writer
// device and principal public identifiers.
func verifyLegacyPartitionGenesisRecord(genesis []byte, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, scope *ownedVaultFileWriteScope) (string, string, error) {
	if scope == nil || scope.ageIdentity == nil || len(genesis) == 0 ||
		!validOwnedVaultFileFirstSuccessorTarget(target) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return "", "", ErrVaultFileBaselineVerification
	}
	if sha256.Sum256(genesis) != target.Pin.SealedSHA256 {
		return "", "", ErrVaultFileBaselineVerification
	}
	genesisCheckpoint, err := vaultfile.VerifyGenesis(genesis, &target.Pin.Root)
	if err != nil || !sameVaultFilePolicyCheckpoint(genesisCheckpoint, checkpoint) {
		clearVaultFilePolicyCheckpoint(genesisCheckpoint)
		return "", "", ErrVaultFileBaselineVerification
	}
	clearVaultFilePolicyCheckpoint(genesisCheckpoint)

	base, err := vaultfile.ParseFile(genesis)
	if err != nil || len(base.SignedPolicyProofs) == 0 ||
		base.Header.OpID != target.Pin.OperationID ||
		base.Header.VaultID != checkpoint.VaultID ||
		base.Header.ContentSeq != 0 {
		return "", "", ErrVaultFileBaselineVerification
	}
	policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != base.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), base.Header.PolicyDigest) {
		return "", "", ErrVaultFileBaselineVerification
	}
	writerID, writerOK := localVaultFileWriterDevice(policy, scope.recipient, scope.signerPublic)
	readerID, readerOK := localVaultFileReaderDevice(policy, scope.recipient, scope.signerPublic)
	if !writerOK || !readerOK || writerID != readerID {
		return "", "", ErrVaultFileBaselineVerification
	}
	principal, principalOK := ownedVaultFileDevicePrincipal(policy, writerID)
	if !principalOK {
		return "", "", ErrVaultFileBaselineVerification
	}

	_, metadata, current, err := vault.OpenAuthenticatedItems(genesis, checkpoint, writerID, scope.ageIdentity)
	if err != nil {
		return "", "", ErrVaultFileBaselineVerification
	}
	defer clear(metadata)
	defer clearAuthenticatedItems(current)
	if len(metadata) != 0 || len(current) != 0 {
		return "", "", ErrVaultFileEditReview
	}
	return writerID, principal, nil
}

// readLegacyPartitionBackendObservation returns the exact live bytes and opaque
// revision from one atomic backend read. The caller owns and must clear the
// bytes. A missing, unreadable, empty or revision-less read fails closed.
func readLegacyPartitionBackendObservation(target OwnedVaultFileFirstSuccessorTarget) ([]byte, vaultfilebackend.Revision, error) {
	backend, err := vaultfilebackend.OpenExistingDir(target.BackendRoot)
	if err != nil {
		return nil, "", ErrVaultFileBaselineJournal
	}
	result, readErr := backend.Read(context.Background(), target.BackendName)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil || len(result.Bytes) == 0 || result.Revision == "" {
		clear(result.Bytes)
		return nil, "", ErrVaultFileBaselineJournal
	}
	return result.Bytes, result.Revision, nil
}

func sameLegacyPartitionPrepared(a vaultfilejournal.PreparedProposal, b vaultfilejournal.PreparedProposal) bool {
	return a.WorkingGeneration == b.WorkingGeneration &&
		a.Proposal.Generation == b.Proposal.Generation &&
		a.Proposal.OperationID == b.Proposal.OperationID &&
		a.Proposal.ExpectedRevision == b.Proposal.ExpectedRevision &&
		bytes.Equal(a.Proposal.Bytes, b.Proposal.Bytes)
}

func verifyLegacyPartitionPendingUnchanged(journalPath string, wantState vaultfilejournal.State, wantPrepared vaultfilejournal.PreparedProposal) error {
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return ErrVaultFileBaselineJournal
	}
	state, prepared, loadErr := j.LoadOwnedFirstPending()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	defer clear(prepared.Proposal.Bytes)
	if loadErr != nil || closeErr != nil {
		return ErrVaultFileBaselineJournal
	}
	if !sameOwnedVaultFileState(state, wantState) ||
		!sameLegacyPartitionPrepared(prepared, wantPrepared) {
		return ErrVaultFileBaselineJournal
	}
	return nil
}

func verifyLegacyPartitionSettledUnchanged(journalPath string, pin vaultfilejournal.OwnedGenesisPin, want vaultfilejournal.OwnedFirstSuccessor) error {
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(journalPath, pin)
	if err != nil {
		return ErrVaultFileBaselineJournal
	}
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if !bytes.Equal(record.GenesisBytes, want.GenesisBytes) ||
		record.GenesisRevision != want.GenesisRevision ||
		!bytes.Equal(record.SuccessorBytes, want.SuccessorBytes) ||
		record.SuccessorRevision != want.SuccessorRevision {
		return ErrVaultFileBaselineJournal
	}
	return nil
}
