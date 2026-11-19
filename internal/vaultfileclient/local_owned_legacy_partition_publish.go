package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// PublishStagedLocalOwnedLegacyPartition publishes exactly one previously
// staged, already signed multi-item legacy-partition candidate to the named
// local backend and settles it through the ordinary owned first-successor
// journal records.
//
// The caller supplies the same authenticated account, strict local locator,
// exact expected journal, full factors, selected legacy source archive and the
// two independent nonzero digests used by StageLocalOwnedLegacyPartition and
// VerifyStagedLocalOwnedLegacyPartition. This entry never reseals, resigns or
// replaces the staged candidate and never accepts caller ciphertext.
//
// A pristine destination is verified with VerifyStagedLocalOwnedLegacyPartition
// before the exact signed successor is durably prepared with
// PrepareWorkingIfState, compared-and-swapped once against the original signed
// genesis bytes and opaque revision, read back once and acknowledged only
// through AckOwnedFirstSuccessor. A pending journal left by an interruption is
// reauthenticated from the exact archived source and sidecar candidate and
// classified with ReconcileOwnedVaultFileLegacyPartition before any action:
// pending-safe-for-CAS retries the original CAS from the same origin bytes and
// revision, applied-unacknowledged acknowledges the already-written exact
// candidate at its observed different revision without a second write, and
// settled returns the exact settled result only while the journal record and
// live backend bytes/revision still match.
//
// A changed backend revision, an equivalent genesis at a new revision, a
// different successor, a foreign or advanced journal, a wrong source or
// candidate digest, a wrong selector, a stale locator, a locked session and an
// unresolved observation all fail closed. The sidecar, source archive, journal
// recovery records and any foreign backend value are preserved on every
// outcome; no empty or partial success result is returned for an unknown.
func PublishStagedLocalOwnedLegacyPartition(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) ||
		len(source.Archive) == 0 || len(source.Archive) > localOwnedLegacyPartitionMaxArchive ||
		source.VaultID == "" || source.RecoveryKit == "" ||
		expectedSourceArchiveSHA256 == ([sha256.Size]byte{}) ||
		expectedCandidateSHA256 == ([sha256.Size]byte{}) {
		return empty, fmt.Errorf("%w: invalid request", ErrLocalOwnedLegacyPartitionReview)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	sourceDigest := sha256.Sum256(source.Archive)
	if sourceDigest != expectedSourceArchiveSHA256 {
		return empty, fmt.Errorf("%w: source archive digest", ErrLocalOwnedLegacyPartitionConflict)
	}

	pristine, pristineErr := readLocalGenesisPristine(s, configPath, workspaceRoot, vaultID, expectedJournal)
	if pristineErr == nil {
		defer pristine.clear()
		return publishLocalOwnedLegacyPartitionPristine(ctx, s, pristine, password, key,
			source, expectedSourceArchiveSHA256, expectedCandidateSHA256)
	}
	return publishLocalOwnedLegacyPartitionRecovered(ctx, s, configPath, workspaceRoot, vaultID,
		expectedJournal, password, key, source, expectedSourceArchiveSHA256,
		expectedCandidateSHA256, pristineErr)
}

func publishLocalOwnedLegacyPartitionPristine(ctx context.Context, s *personal.Session, pristine *localGenesisPristine, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if pristine == nil || pristine.checkpoint == nil || len(pristine.state.BaseBytes) == 0 {
		return empty, fmt.Errorf("%w: missing pristine authorization", ErrLocalOwnedLegacyPartitionReview)
	}
	sidecar, err := localOwnedLegacyPartitionSidecarPath(pristine)
	if err != nil {
		return empty, err
	}
	candidate, candidateFile, err := readLocalOwnedLegacyPartitionCandidate(sidecar, expectedCandidateSHA256)
	if err != nil {
		return empty, err
	}
	defer clear(candidate)

	claim, err := s.BeginLegacyPartitionPublishClaim()
	if err != nil {
		return empty, fmt.Errorf("%w: publish claim", ErrLocalOwnedLegacyPartitionCanceled)
	}
	defer claim.Release(s)

	// The pristine entry deliberately performs the full staged verification
	// before any preparation. It re-reads the sidecar itself and requires the
	// caller's independent candidate digest.
	verified, err := VerifyStagedLocalOwnedLegacyPartition(ctx, s,
		pristine.configPath, pristine.workspaceRoot, pristine.vaultID, pristine.manifest.Journal,
		password, key, source, expectedSourceArchiveSHA256, expectedCandidateSHA256)
	if err != nil {
		return empty, err
	}
	defer verified.Clear()

	if err := recheckLocalOwnedLegacyPartitionCandidate(sidecar, candidate, expectedCandidateSHA256); err != nil {
		return empty, err
	}

	origin := pristine.state
	proposal := vaultfilejournal.Proposal{
		Generation:       origin.Generation + 1,
		OperationID:      candidateFile.Header.OpID,
		ExpectedRevision: origin.RemoteRevision,
		Bytes:            candidate,
	}
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	j, err := vaultfilejournal.OpenExisting(pristine.manifest.Journal)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	defer func() { _ = j.Close() }()
	if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhasePrepare); err != nil {
		return empty, fmt.Errorf("%w: lock before preparation: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	if err := j.PrepareWorkingIfState(origin, proposal); err != nil {
		return empty, mapLocalOwnedFirstPrepare(err)
	}
	if localOwnedFirstWriteAfterPrepareForTest != nil {
		localOwnedFirstWriteAfterPrepareForTest()
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: prepared before write: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
	}
	if err := claim.Ready(ctx, s); err != nil {
		return empty, fmt.Errorf("%w: lock or authorization changed after preparation: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
	}

	wantState := vaultfilejournal.State{
		BaseBytes:      bytes.Clone(origin.BaseBytes),
		WorkingBytes:   bytes.Clone(proposal.Bytes),
		RemoteRevision: origin.RemoteRevision,
		Generation:     proposal.Generation,
	}
	wantPrepared := vaultfilejournal.PreparedProposal{WorkingGeneration: proposal.Generation, Proposal: proposal}
	if err := localOwnedLegacyPartitionCheckPending(j, wantState, wantPrepared); err != nil {
		return empty, err
	}
	if err := recheckLocalOwnedLegacyPartitionCandidate(sidecar, candidate, expectedCandidateSHA256); err != nil {
		return empty, err
	}
	backend, err := vaultfilebackend.OpenExistingDir(pristine.manifest.BackendRoot)
	if err != nil {
		if errors.Is(err, vaultfilebackend.ErrUnsupported) {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionUnsupported, err)
		}
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
	}
	defer func() { _ = backend.Close() }()
	if err := confirmLocalGenesisLocator(s, pristine.configPath, pristine.workspaceRoot,
		pristine.vaultID, pristine.manifest.Journal, pristine.manifest, pristine.manifestSHA256,
		pristine.companion); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: prepared before write: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
	}
	if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhasePublish); err != nil {
		return empty, fmt.Errorf("%w: lock before write: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
	}
	writeErr := backend.ReplaceIfVersion(ctx, pristine.manifest.Name, origin.RemoteRevision, proposal.Bytes)
	if localOwnedFirstWriteAfterPublishForTest != nil {
		localOwnedFirstWriteAfterPublishForTest()
	}
	boundary := localOwnedLegacyPartitionAckBoundary(ctx, s, claim, pristine.configPath,
		pristine.workspaceRoot, pristine.vaultID, pristine.manifest.Journal, pristine.manifest,
		pristine.manifestSHA256, pristine.companion, backend)
	result, err := finishLocalOwnedFirstWrite(ctx, j, backend, pristine, origin, proposal,
		candidateFile.Header.AuthorDeviceID, writeErr, boundary)
	if err != nil {
		return empty, err
	}
	if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhaseDeliver); err != nil {
		return empty, fmt.Errorf("%w: lock before final success: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
	}
	return result, nil
}

func publishLocalOwnedLegacyPartitionRecovered(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte, pristineErr error) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	manifest, manifestSHA256, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil || manifest.Journal != expectedJournal || companion.Resume.Checkpoint == nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(pristineErr)
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return empty, fmt.Errorf("%w: owner root", ErrLocalOwnedLegacyPartitionReview)
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return empty, fmt.Errorf("%w: owner pin", ErrLocalOwnedLegacyPartitionReview)
	}
	defer clear(pin.Root.OwnerRootPublicKey)
	target := personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: manifest.BackendRoot,
		BackendName: manifest.Name,
		Pin:         cloneLocalGenesisGenesisPin(pin),
	}
	defer clear(target.Pin.Root.OwnerRootPublicKey)

	var (
		pending     vaultfilejournal.State
		prepared    vaultfilejournal.PreparedProposal
		havePending bool
		record      vaultfilejournal.OwnedFirstSuccessor
		haveSettled bool
	)
	if j, openErr := vaultfilejournal.OpenExisting(manifest.Journal); openErr == nil {
		state, preparedProposal, loadErr := j.LoadOwnedFirstPending()
		closeErr := j.Close()
		if loadErr == nil && closeErr == nil {
			pending, prepared, havePending = state, preparedProposal, true
		} else {
			clear(state.BaseBytes)
			clear(state.WorkingBytes)
			clear(preparedProposal.Proposal.Bytes)
		}
	}
	if !havePending {
		if settled, settledErr := vaultfilejournal.ReadOwnedFirstSuccessor(manifest.Journal, pin); settledErr == nil {
			record, haveSettled = settled, true
		}
	}
	if havePending {
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		return publishLocalOwnedLegacyPartitionPending(ctx, s, configPath, workspaceRoot, vaultID,
			expectedJournal, manifest, manifestSHA256, companion, pin, target, pending, prepared,
			password, key, source, expectedSourceArchiveSHA256, expectedCandidateSHA256)
	}
	if haveSettled {
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		return publishLocalOwnedLegacyPartitionSettled(ctx, s, configPath, workspaceRoot, vaultID,
			expectedJournal, manifest, manifestSHA256, companion, pin, target, record,
			password, key, source, expectedSourceArchiveSHA256, expectedCandidateSHA256)
	}
	return empty, fmt.Errorf("%w: unknown durable outcome", ErrLocalOwnedLegacyPartitionConflict)
}

func publishLocalOwnedLegacyPartitionPending(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, manifest Manifest, manifestSHA256 string, companion Companion, pin vaultfilejournal.OwnedGenesisPin, target personal.OwnedVaultFileFirstSuccessorTarget, pending vaultfilejournal.State, prepared vaultfilejournal.PreparedProposal, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if err := localOwnedLegacyPartitionValidatePending(pending, prepared, pin, manifest); err != nil {
		return empty, err
	}
	checkpoint, err := localOwnedLegacyPartitionGenesisCheckpoint(manifest, companion, pin, pending.BaseBytes)
	if err != nil {
		return empty, err
	}
	defer clearLocalGenesisCheckpoint(checkpoint)
	sidecar, err := localOwnedLegacyPartitionPublishSidecar(manifest, configPath)
	if err != nil {
		return empty, err
	}
	candidate, candidateFile, err := readLocalOwnedLegacyPartitionCandidate(sidecar, expectedCandidateSHA256)
	if err != nil {
		return empty, err
	}
	defer clear(candidate)
	if !bytes.Equal(candidate, prepared.Proposal.Bytes) ||
		candidateFile.Header.OpID != prepared.Proposal.OperationID {
		return empty, fmt.Errorf("%w: sidecar/journal candidate mismatch", ErrLocalOwnedLegacyPartitionConflict)
	}
	claim, err := s.BeginLegacyPartitionPublishClaim()
	if err != nil {
		return empty, fmt.Errorf("%w: publish claim", ErrLocalOwnedLegacyPartitionUnknown)
	}
	defer claim.Release(s)

	reconciled, err := s.ReconcileOwnedVaultFileLegacyPartition(personal.OwnedVaultFileLegacyPartitionReconciliationRequest{
		OwnedVaultFileLegacyPartitionVerificationRequest: personal.OwnedVaultFileLegacyPartitionVerificationRequest{
			OwnedVaultFileLegacyPartitionRequest: personal.OwnedVaultFileLegacyPartitionRequest{
				JournalPath:     manifest.Journal,
				Target:          target,
				Checkpoint:      checkpoint,
				ExpectedGenesis: pending.BaseBytes,
				Password:        password,
				Key:             key,
				Source:          source,
			},
			Candidate:                   candidate,
			ExpectedSourceArchiveSHA256: expectedSourceArchiveSHA256,
		},
		ExpectedCandidateSHA256: expectedCandidateSHA256,
	})
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPersonal(err)
	}
	defer reconciled.Clear()
	if reconciled.DestinationVaultID != manifest.VaultID ||
		reconciled.SourceArchiveSHA256 != expectedSourceArchiveSHA256 {
		return empty, fmt.Errorf("%w: reconciliation binding", ErrLocalOwnedLegacyPartitionConflict)
	}
	if err := recheckLocalOwnedLegacyPartitionCandidate(sidecar, candidate, expectedCandidateSHA256); err != nil {
		return empty, err
	}

	switch reconciled.Disposition {
	case personal.VaultFileLegacyPartitionPendingSafeForCAS:
		j, err := vaultfilejournal.OpenExisting(manifest.Journal)
		if err != nil {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
		}
		defer func() { _ = j.Close() }()
		if err := localOwnedLegacyPartitionCheckPending(j, pending, prepared); err != nil {
			return empty, err
		}
		if err := recheckLocalOwnedLegacyPartitionCandidate(sidecar, candidate, expectedCandidateSHA256); err != nil {
			return empty, err
		}
		origin := localOwnedLegacyPartitionOrigin(pending)
		defer clear(origin.BaseBytes)
		defer clear(origin.WorkingBytes)
		backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
		if err != nil {
			if errors.Is(err, vaultfilebackend.ErrUnsupported) {
				return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionUnsupported, err)
			}
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
		}
		defer func() { _ = backend.Close() }()
		if err := confirmLocalGenesisLocator(s, configPath, workspaceRoot, vaultID,
			expectedJournal, manifest, manifestSHA256, companion); err != nil {
			return empty, mapLocalOwnedLegacyPartitionPreflight(err)
		}
		if err := ctx.Err(); err != nil {
			return empty, fmt.Errorf("%w: prepared before write: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhasePublish); err != nil {
			return empty, fmt.Errorf("%w: lock before write: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		writeErr := backend.ReplaceIfVersion(ctx, manifest.Name, origin.RemoteRevision, prepared.Proposal.Bytes)
		if localOwnedFirstWriteAfterPublishForTest != nil {
			localOwnedFirstWriteAfterPublishForTest()
		}
		boundary := localOwnedLegacyPartitionAckBoundary(ctx, s, claim, configPath, workspaceRoot,
			vaultID, expectedJournal, manifest, manifestSHA256, companion, backend)
		result, err := finishLocalOwnedFirstWrite(ctx, j, backend,
			&localGenesisPristine{manifest: manifest, pin: pin, checkpoint: checkpoint},
			origin, prepared.Proposal, candidateFile.Header.AuthorDeviceID, writeErr, boundary)
		if err != nil {
			return empty, err
		}
		if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhaseDeliver); err != nil {
			return empty, fmt.Errorf("%w: lock before final success: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		return result, nil
	case personal.VaultFileLegacyPartitionAppliedUnacknowledged:
		j, err := vaultfilejournal.OpenExisting(manifest.Journal)
		if err != nil {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
		}
		defer func() { _ = j.Close() }()
		if err := localOwnedLegacyPartitionCheckPending(j, pending, prepared); err != nil {
			return empty, err
		}
		origin := localOwnedLegacyPartitionOrigin(pending)
		defer clear(origin.BaseBytes)
		defer clear(origin.WorkingBytes)
		backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
		if err != nil {
			if errors.Is(err, vaultfilebackend.ErrUnsupported) {
				return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionUnsupported, err)
			}
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
		}
		defer func() { _ = backend.Close() }()
		if err := confirmLocalGenesisLocator(s, configPath, workspaceRoot, vaultID,
			expectedJournal, manifest, manifestSHA256, companion); err != nil {
			return empty, mapLocalOwnedLegacyPartitionPreflight(err)
		}
		data, revision, err := localOwnedLegacyPartitionReadBackendAt(ctx, backend, manifest)
		if err != nil {
			return empty, err
		}
		defer clear(data)
		if !bytes.Equal(data, candidate) || revision == origin.RemoteRevision {
			return empty, fmt.Errorf("%w: acknowledgement backend mismatch", ErrLocalOwnedLegacyPartitionConflict)
		}
		if err := ctx.Err(); err != nil {
			return empty, fmt.Errorf("%w: prepared before acknowledgement: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		if localOwnedFirstWriteAfterPublishForTest != nil {
			localOwnedFirstWriteAfterPublishForTest()
		}
		boundary := localOwnedLegacyPartitionAckBoundary(ctx, s, claim, configPath, workspaceRoot,
			vaultID, expectedJournal, manifest, manifestSHA256, companion, backend)
		result, err := acknowledgeLocalOwnedFirstWrite(ctx, j, manifest, pin, origin, prepared.Proposal,
			data, revision, checkpoint, candidateFile.Header.AuthorDeviceID, boundary)
		if err != nil {
			return empty, err
		}
		if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhaseDeliver); err != nil {
			return empty, fmt.Errorf("%w: lock before final success: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		return result, nil
	default:
		return empty, fmt.Errorf("%w: disposition %s", ErrLocalOwnedLegacyPartitionConflict, reconciled.Disposition)
	}
}

func publishLocalOwnedLegacyPartitionSettled(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, manifest Manifest, manifestSHA256 string, companion Companion, pin vaultfilejournal.OwnedGenesisPin, target personal.OwnedVaultFileFirstSuccessorTarget, record vaultfilejournal.OwnedFirstSuccessor, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if len(record.GenesisBytes) == 0 || len(record.SuccessorBytes) == 0 ||
		len(record.GenesisRevision) == 0 || len(record.SuccessorRevision) == 0 ||
		record.GenesisRevision == record.SuccessorRevision {
		return empty, fmt.Errorf("%w: settled record shape", ErrLocalOwnedLegacyPartitionConflict)
	}
	checkpoint, err := localOwnedLegacyPartitionGenesisCheckpoint(manifest, companion, pin, record.GenesisBytes)
	if err != nil {
		return empty, err
	}
	defer clearLocalGenesisCheckpoint(checkpoint)
	sidecar, err := localOwnedLegacyPartitionPublishSidecar(manifest, configPath)
	if err != nil {
		return empty, err
	}
	candidate, candidateFile, err := readLocalOwnedLegacyPartitionCandidate(sidecar, expectedCandidateSHA256)
	if err != nil {
		return empty, err
	}
	defer clear(candidate)
	if !bytes.Equal(candidate, record.SuccessorBytes) {
		return empty, fmt.Errorf("%w: sidecar/settled candidate mismatch", ErrLocalOwnedLegacyPartitionConflict)
	}

	reconciled, err := s.ReconcileOwnedVaultFileLegacyPartition(personal.OwnedVaultFileLegacyPartitionReconciliationRequest{
		OwnedVaultFileLegacyPartitionVerificationRequest: personal.OwnedVaultFileLegacyPartitionVerificationRequest{
			OwnedVaultFileLegacyPartitionRequest: personal.OwnedVaultFileLegacyPartitionRequest{
				JournalPath:     manifest.Journal,
				Target:          target,
				Checkpoint:      checkpoint,
				ExpectedGenesis: record.GenesisBytes,
				Password:        password,
				Key:             key,
				Source:          source,
			},
			Candidate:                   candidate,
			ExpectedSourceArchiveSHA256: expectedSourceArchiveSHA256,
		},
		ExpectedCandidateSHA256: expectedCandidateSHA256,
	})
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPersonal(err)
	}
	defer reconciled.Clear()
	if reconciled.Disposition != personal.VaultFileLegacyPartitionSettled ||
		reconciled.DestinationVaultID != manifest.VaultID ||
		reconciled.SourceArchiveSHA256 != expectedSourceArchiveSHA256 {
		return empty, fmt.Errorf("%w: unsettled reconciliation", ErrLocalOwnedLegacyPartitionConflict)
	}
	if err := recheckLocalOwnedLegacyPartitionCandidate(sidecar, candidate, expectedCandidateSHA256); err != nil {
		return empty, err
	}
	if err := confirmLocalGenesisLocator(s, configPath, workspaceRoot, vaultID,
		expectedJournal, manifest, manifestSHA256, companion); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	current, err := vaultfilejournal.ReadOwnedFirstSuccessor(manifest.Journal, pin)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	defer clear(current.GenesisBytes)
	defer clear(current.SuccessorBytes)
	if !bytes.Equal(current.GenesisBytes, record.GenesisBytes) ||
		current.GenesisRevision != record.GenesisRevision ||
		!bytes.Equal(current.SuccessorBytes, record.SuccessorBytes) ||
		current.SuccessorRevision != record.SuccessorRevision {
		return empty, fmt.Errorf("%w: settled journal changed", ErrLocalOwnedLegacyPartitionConflict)
	}
	data, revision, err := localOwnedLegacyPartitionReadBackend(manifest)
	if err != nil {
		return empty, err
	}
	defer clear(data)
	if !bytes.Equal(data, current.SuccessorBytes) || revision != current.SuccessorRevision {
		return empty, fmt.Errorf("%w: settled backend changed", ErrLocalOwnedLegacyPartitionConflict)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	claim, err := s.BeginLegacyPartitionPublishClaim()
	if err != nil {
		return empty, fmt.Errorf("%w: publish claim", ErrLocalOwnedLegacyPartitionCanceled)
	}
	defer claim.Release(s)
	if err := localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhaseDeliver); err != nil {
		return empty, fmt.Errorf("%w: lock before final success: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	return LocalOwnedFirstWriteResult{
		VaultID:     manifest.VaultID,
		JournalPath: manifest.Journal,
		OperationID: candidateFile.Header.OpID,
		Revision:    string(current.SuccessorRevision),
	}, nil
}

func localOwnedLegacyPartitionPublishSidecar(manifest Manifest, configPath string) (string, error) {
	return localOwnedLegacyPartitionSidecarPath(&localGenesisPristine{
		configPath: configPath,
		manifest:   manifest,
	})
}

// localOwnedLegacyPartitionPhaseHookForTest is nil in production. Tests use it
// to interleave a real RequestLock, cancellation or durability-proof failure
// immediately before one claimed phase. It receives only the fixed phase name.
var localOwnedLegacyPartitionPhaseHookForTest func(step string) error

func localOwnedLegacyPartitionClaimPhase(ctx context.Context, s *personal.Session,
	claim *personal.LegacyPartitionPublishClaim, phase personal.LegacyPartitionPublishPhase) error {
	if localOwnedLegacyPartitionPhaseHookForTest != nil {
		if err := localOwnedLegacyPartitionPhaseHookForTest("before-" + phase.String()); err != nil {
			return err
		}
	}
	return claim.Claim(ctx, s, phase)
}

// localOwnedLegacyPartitionAckBoundary performs every slow check before the
// single-use acknowledgement claim: the real locator and the directory
// durability proof over the same open backend and exact observed revision.
func localOwnedLegacyPartitionAckBoundary(ctx context.Context, s *personal.Session,
	claim *personal.LegacyPartitionPublishClaim, configPath, workspaceRoot, vaultID,
	expectedJournal string, manifest Manifest, manifestSHA256 string, companion Companion,
	backend vaultfilebackend.Backend) func([]byte, vaultfilebackend.Revision) error {
	return func(_ []byte, revision vaultfilebackend.Revision) error {
		if err := claim.Ready(ctx, s); err != nil {
			return err
		}
		if err := confirmLocalGenesisLocator(s, configPath, workspaceRoot, vaultID,
			expectedJournal, manifest, manifestSHA256, companion); err != nil {
			return err
		}
		if err := localOwnedLegacyPartitionProveDurable(ctx, backend, manifest, revision); err != nil {
			return fmt.Errorf("durability proof: %w", err)
		}
		return localOwnedLegacyPartitionClaimPhase(ctx, s, claim, personal.LegacyPartitionPhaseAck)
	}
}

func localOwnedLegacyPartitionProveDurable(ctx context.Context, backend vaultfilebackend.Backend,
	manifest Manifest, revision vaultfilebackend.Revision) error {
	if backend == nil || revision.Zero() {
		return fmt.Errorf("%w: %w", vaultfilebackend.ErrUnknown, vaultfilebackend.ErrDurabilityUnproven)
	}
	if localOwnedLegacyPartitionPhaseHookForTest != nil {
		if err := localOwnedLegacyPartitionPhaseHookForTest("durability"); err != nil {
			return localOwnedLegacyPartitionDurabilityError(err)
		}
	}
	prover, ok := backend.(vaultfilebackend.DurabilityProver)
	if !ok {
		return fmt.Errorf("%w: %w", vaultfilebackend.ErrUnknown, vaultfilebackend.ErrDurabilityUnproven)
	}
	if err := prover.ProveDurable(ctx, manifest.Name, revision); err != nil {
		return localOwnedLegacyPartitionDurabilityError(err)
	}
	return nil
}

func localOwnedLegacyPartitionDurabilityError(err error) error {
	if errors.Is(err, vaultfilebackend.ErrUnknown) {
		return err
	}
	return fmt.Errorf("%w: %w: %w", vaultfilebackend.ErrUnknown,
		vaultfilebackend.ErrDurabilityUnproven, err)
}

func localOwnedLegacyPartitionReadBackendAt(ctx context.Context, backend vaultfilebackend.Backend,
	manifest Manifest) ([]byte, vaultfilebackend.Revision, error) {
	result, err := backend.Read(ctx, manifest.Name)
	if err != nil || len(result.Bytes) == 0 || result.Revision == "" {
		clear(result.Bytes)
		return nil, "", fmt.Errorf("%w: backend observation", ErrLocalOwnedLegacyPartitionConflict)
	}
	return result.Bytes, result.Revision, nil
}

func readLocalOwnedLegacyPartitionCandidate(sidecar string, expected [sha256.Size]byte) ([]byte, *vaultfile.File, error) {
	if !teamfiles.ValidPath(sidecar) || expected == ([sha256.Size]byte{}) {
		return nil, nil, fmt.Errorf("%w: sidecar candidate request", ErrLocalOwnedLegacyPartitionReview)
	}
	candidate, err := teamfiles.Read(sidecar, localOwnedLegacyPartitionMaxArchive, true)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	if sha256.Sum256(candidate) != expected {
		clear(candidate)
		return nil, nil, fmt.Errorf("%w: candidate digest", ErrLocalOwnedLegacyPartitionConflict)
	}
	file, err := vaultfile.ParseFile(candidate)
	if err != nil || file.Header.OpID == "" || file.Header.AuthorDeviceID == "" {
		clear(candidate)
		return nil, nil, fmt.Errorf("%w: candidate signature", ErrLocalOwnedLegacyPartitionConflict)
	}
	return candidate, file, nil
}

func recheckLocalOwnedLegacyPartitionCandidate(sidecar string, want []byte, expected [sha256.Size]byte) error {
	current, err := teamfiles.Read(sidecar, localOwnedLegacyPartitionMaxArchive, true)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	defer clear(current)
	if sha256.Sum256(current) != expected || !bytes.Equal(current, want) {
		return fmt.Errorf("%w: sidecar candidate changed", ErrLocalOwnedLegacyPartitionConflict)
	}
	return nil
}

func localOwnedLegacyPartitionGenesisCheckpoint(manifest Manifest, companion Companion, pin vaultfilejournal.OwnedGenesisPin, genesis []byte) (*vaultfile.PolicyCheckpoint, error) {
	if len(genesis) == 0 || sha256.Sum256(genesis) != pin.SealedSHA256 {
		return nil, fmt.Errorf("%w: genesis pin", ErrLocalOwnedLegacyPartitionConflict)
	}
	file, err := vaultfile.ParseFile(genesis)
	if err != nil || file.Header.OpID != pin.OperationID || file.Header.VaultID != manifest.VaultID {
		return nil, fmt.Errorf("%w: genesis identity", ErrLocalOwnedLegacyPartitionConflict)
	}
	checkpoint, err := vaultfile.VerifyGenesis(genesis, &pin.Root)
	if err != nil || checkpoint == nil ||
		!localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, fmt.Errorf("%w: genesis checkpoint", ErrLocalOwnedLegacyPartitionConflict)
	}
	return checkpoint, nil
}

func localOwnedLegacyPartitionValidatePending(pending vaultfilejournal.State, prepared vaultfilejournal.PreparedProposal, pin vaultfilejournal.OwnedGenesisPin, manifest Manifest) error {
	if pending.Generation != 1 || prepared.WorkingGeneration != 1 ||
		prepared.Proposal.Generation != 1 || len(pending.RemoteRevision) == 0 ||
		prepared.Proposal.ExpectedRevision != pending.RemoteRevision ||
		len(prepared.Proposal.Bytes) == 0 || prepared.Proposal.OperationID == "" ||
		!bytes.Equal(prepared.Proposal.Bytes, pending.WorkingBytes) {
		return fmt.Errorf("%w: pending tuple", ErrLocalOwnedLegacyPartitionConflict)
	}
	if sha256.Sum256(pending.BaseBytes) != pin.SealedSHA256 {
		return fmt.Errorf("%w: pending genesis pin", ErrLocalOwnedLegacyPartitionConflict)
	}
	genesis, err := vaultfile.ParseFile(pending.BaseBytes)
	if err != nil || genesis.Header.OpID != pin.OperationID || genesis.Header.VaultID != manifest.VaultID {
		return fmt.Errorf("%w: pending genesis identity", ErrLocalOwnedLegacyPartitionConflict)
	}
	candidate, err := vaultfile.ParseFile(prepared.Proposal.Bytes)
	if err != nil || candidate.Header.OpID != prepared.Proposal.OperationID {
		return fmt.Errorf("%w: pending candidate identity", ErrLocalOwnedLegacyPartitionConflict)
	}
	return nil
}

func localOwnedLegacyPartitionCheckPending(j *vaultfilejournal.Journal, wantState vaultfilejournal.State, wantPrepared vaultfilejournal.PreparedProposal) error {
	if j == nil {
		return fmt.Errorf("%w: missing journal", ErrLocalOwnedLegacyPartitionConflict)
	}
	state, prepared, err := j.LoadOwnedFirstPending()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	defer clear(prepared.Proposal.Bytes)
	if !sameLocalOwnedFirstState(state, wantState) ||
		!sameLocalOwnedFirstPrepared(prepared, wantPrepared) {
		return fmt.Errorf("%w: pending changed", ErrLocalOwnedLegacyPartitionConflict)
	}
	return nil
}

func localOwnedLegacyPartitionOrigin(pending vaultfilejournal.State) vaultfilejournal.State {
	return vaultfilejournal.State{
		BaseBytes:      bytes.Clone(pending.BaseBytes),
		WorkingBytes:   bytes.Clone(pending.BaseBytes),
		RemoteRevision: pending.RemoteRevision,
		Generation:     0,
	}
}

func localOwnedLegacyPartitionReadBackend(manifest Manifest) ([]byte, vaultfilebackend.Revision, error) {
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		if errors.Is(err, vaultfilebackend.ErrUnsupported) {
			return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionUnsupported, err)
		}
		return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	result, readErr := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil || len(result.Bytes) == 0 || result.Revision == "" {
		clear(result.Bytes)
		return nil, "", fmt.Errorf("%w: backend observation", ErrLocalOwnedLegacyPartitionConflict)
	}
	return result.Bytes, result.Revision, nil
}
