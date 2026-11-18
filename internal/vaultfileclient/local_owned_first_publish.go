package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

var (
	errLocalOwnedFirstStale     = errors.New("local owned first write: stale state")
	errLocalOwnedFirstReview    = errors.New("local owned first write: review")
	errLocalOwnedFirstJournal   = errors.New("local owned first write: journal")
	errLocalOwnedFirstDifferent = errors.New("local owned first write: different backend value")
)

// These private seams are nil in production. They receive no factor, key,
// token, capability, ciphertext or secret. Tests use them to place a real
// interleaving only after the durable preparation or after the one CAS write,
// so the public entry point still owns every decision.
var (
	localOwnedFirstWriteAfterPrepareForTest func()
	localOwnedFirstWriteAfterPublishForTest func()
	localOwnedFirstWriteAfterSealForTest    func()
)

func sameLocalOwnedFirstCheckpoint(a, b *vaultfile.PolicyCheckpoint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq && bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest)
}

func localOwnedFirstPullVerifier(origin vaultfilejournal.State, proposal vaultfilejournal.Proposal) vaultfilepublish.PullVerifier {
	return func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		if bytes.Equal(data, proposal.Bytes) || bytes.Equal(data, origin.BaseBytes) {
			return nil
		}
		return errLocalOwnedFirstDifferent
	}
}

func checkLocalOwnedFirstBase(ctx context.Context, backend vaultfilepublish.ReadBackend, name string, genesis []byte, revision vaultfilebackend.Revision) error {
	_, err := vaultfilepublish.ReadPulled(ctx, backend, name, func(_ context.Context, data []byte, observed vaultfilebackend.Revision) error {
		if !bytes.Equal(data, genesis) || observed != revision {
			return errLocalOwnedFirstStale
		}
		return nil
	})
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, errLocalOwnedFirstStale), errors.Is(err, vaultfilepublish.ErrVerification),
		errors.Is(err, vaultfilebackend.ErrNotFound), errors.Is(err, vaultfilebackend.ErrConflict):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	case errors.Is(err, vaultfilebackend.ErrUnsupported):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteUnsupported, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
	}
}

func readLocalOwnedFirstObservation(ctx context.Context, backend vaultfilepublish.ReadBackend, name string, origin vaultfilejournal.State, proposal vaultfilejournal.Proposal) ([]byte, vaultfilebackend.Revision, error) {
	pulled, err := vaultfilepublish.ReadPulled(ctx, backend, name, localOwnedFirstPullVerifier(origin, proposal))
	if err != nil {
		switch {
		case errors.Is(err, errLocalOwnedFirstDifferent), errors.Is(err, vaultfilepublish.ErrVerification),
			errors.Is(err, vaultfilebackend.ErrNotFound), errors.Is(err, vaultfilebackend.ErrConflict):
			return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
		case errors.Is(err, vaultfilebackend.ErrUnsupported):
			return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteUnsupported, err)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
		default:
			return nil, "", fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
		}
	}
	return pulled.Bytes(), pulled.Revision(), nil
}

func verifyLocalOwnedFirstProposal(pin vaultfilejournal.OwnedGenesisPin, origin vaultfilejournal.State, proposal vaultfilejournal.Proposal, checkpoint *vaultfile.PolicyCheckpoint, authorDeviceID string) error {
	if pin.Root.VaultID == "" || checkpoint == nil || authorDeviceID == "" ||
		origin.Generation != 0 || !bytes.Equal(origin.BaseBytes, origin.WorkingBytes) ||
		proposal.Generation != 1 || proposal.ExpectedRevision != origin.RemoteRevision ||
		len(proposal.Bytes) == 0 {
		return errLocalOwnedFirstStale
	}
	if sha256.Sum256(origin.BaseBytes) != pin.SealedSHA256 {
		return errLocalOwnedFirstReview
	}
	genesisCheckpoint, err := vaultfile.VerifyGenesis(origin.BaseBytes, &pin.Root)
	if err != nil || !sameLocalOwnedFirstCheckpoint(genesisCheckpoint, checkpoint) {
		clearLocalGenesisCheckpoint(genesisCheckpoint)
		return errLocalOwnedFirstReview
	}
	clearLocalGenesisCheckpoint(genesisCheckpoint)
	genesis, err := vaultfile.ParseFile(origin.BaseBytes)
	if err != nil || genesis.Header.OpID != pin.OperationID ||
		genesis.Header.VaultID != checkpoint.VaultID || genesis.Header.ContentSeq != 0 {
		return errLocalOwnedFirstReview
	}
	if vaultfile.VerifyContentTransition(origin.BaseBytes, proposal.Bytes, checkpoint) != nil {
		return errLocalOwnedFirstReview
	}
	successor, err := vaultfile.ParseFile(proposal.Bytes)
	if err != nil || successor.Header.OpID != proposal.OperationID ||
		successor.Header.AuthorDeviceID != authorDeviceID ||
		successor.Header.ContentSeq != 1 ||
		successor.Header.VaultID != checkpoint.VaultID ||
		successor.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(successor.Header.PolicyDigest, checkpoint.PolicyDigest) {
		return errLocalOwnedFirstReview
	}
	return nil
}

func mapLocalOwnedFirstPrepare(err error) error {
	switch {
	case errors.Is(err, vaultfilejournal.ErrStateMismatch),
		errors.Is(err, vaultfilejournal.ErrPreparedExists),
		errors.Is(err, vaultfilejournal.ErrPendingRecords),
		errors.Is(err, vaultfilejournal.ErrCorrupt),
		errors.Is(err, vaultfilejournal.ErrStateExists),
		errors.Is(err, vaultfilejournal.ErrEmpty),
		errors.Is(err, vaultfilejournal.ErrLocked):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	case errors.Is(err, vaultfilejournal.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
	}
}

func localOwnedFirstIndeterminate(writeErr, outcome error) error {
	if outcome == nil {
		return nil
	}
	if errors.Is(writeErr, vaultfilebackend.ErrUnknown) {
		return fmt.Errorf("%w: %w: write outcome unknown: %w", ErrLocalOwnedFirstWriteIndeterminate, outcome, writeErr)
	}
	return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, outcome)
}

func localOwnedFirstWriteFailed(writeErr error) error {
	switch {
	case writeErr == nil:
		return fmt.Errorf("%w: write reported success without an observed successor", ErrLocalOwnedFirstWriteIndeterminate)
	case errors.Is(writeErr, vaultfilebackend.ErrConflict):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, writeErr)
	case errors.Is(writeErr, vaultfilebackend.ErrUnknown):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, writeErr)
	case errors.Is(writeErr, vaultfilebackend.ErrUnsupported):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteUnsupported, writeErr)
	case errors.Is(writeErr, vaultfilebackend.ErrDenied):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, writeErr)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, writeErr)
	}
}

func acknowledgeLocalOwnedFirstWrite(ctx context.Context, j *vaultfilejournal.Journal, manifest Manifest,
	pin vaultfilejournal.OwnedGenesisPin, origin vaultfilejournal.State, proposal vaultfilejournal.Proposal,
	data []byte, revision vaultfilebackend.Revision, checkpoint *vaultfile.PolicyCheckpoint, authorDeviceID string) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if err := verifyLocalOwnedFirstProposal(pin, origin, proposal, checkpoint, authorDeviceID); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
	}
	if err := j.AckOwnedFirstSuccessor(origin, pin, proposal, data, revision); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
	}
	return LocalOwnedFirstWriteResult{
		VaultID:     manifest.VaultID,
		JournalPath: manifest.Journal,
		OperationID: proposal.OperationID,
		Revision:    string(revision),
	}, nil
}

// finishLocalOwnedFirstWrite performs exactly one readback after the one CAS
// attempt and acknowledges only the typed ownership-aware journal record. It
// never retries the CAS, never falls back to generic Ack/rebase and never
// infers success from the write response. The prepared record is preserved on
// every non-acknowledged outcome.
func finishLocalOwnedFirstWrite(ctx context.Context, j *vaultfilejournal.Journal, backend vaultfilepublish.ReadBackend,
	pristine *localGenesisPristine, origin vaultfilejournal.State, proposal vaultfilejournal.Proposal,
	authorDeviceID string, writeErr error) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if pristine == nil || pristine.checkpoint == nil {
		return empty, fmt.Errorf("%w: missing authorization", ErrLocalOwnedFirstWriteIndeterminate)
	}
	data, revision, readErr := readLocalOwnedFirstObservation(ctx, backend, pristine.manifest.Name, origin, proposal)
	if readErr != nil {
		if errors.Is(writeErr, vaultfilebackend.ErrConflict) {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, readErr)
		}
		return empty, localOwnedFirstIndeterminate(writeErr, readErr)
	}
	defer clear(data)
	switch {
	case bytes.Equal(data, proposal.Bytes):
		if err := verifyLocalOwnedFirstProposal(pristine.pin, origin, proposal, pristine.checkpoint, authorDeviceID); err != nil {
			return empty, localOwnedFirstIndeterminate(writeErr, err)
		}
		return acknowledgeLocalOwnedFirstWrite(ctx, j, pristine.manifest, pristine.pin, origin, proposal,
			data, revision, pristine.checkpoint, authorDeviceID)
	case bytes.Equal(data, origin.BaseBytes):
		if revision != origin.RemoteRevision {
			if errors.Is(writeErr, vaultfilebackend.ErrUnknown) {
				return empty, localOwnedFirstIndeterminate(writeErr,
					fmt.Errorf("%w: original bytes at a new revision", ErrLocalOwnedFirstWriteConflict))
			}
			return empty, fmt.Errorf("%w: original bytes at a new revision", ErrLocalOwnedFirstWriteConflict)
		}
		return empty, localOwnedFirstWriteFailed(writeErr)
	default:
		if errors.Is(writeErr, vaultfilebackend.ErrConflict) {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, writeErr)
		}
		return empty, localOwnedFirstIndeterminate(writeErr,
			fmt.Errorf("%w: different backend successor", ErrLocalOwnedFirstWriteConflict))
	}
}
