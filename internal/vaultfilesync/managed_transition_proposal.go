package vaultfilesync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// ErrManagedTransitionProposalRejected reports that a caller-pinned managed
// policy/epoch transition proposal was rejected: a malformed or
// unauthenticated base or candidate, a proposal operation or revision that
// does not match, or a candidate that is not the exact authenticated managed
// successor of the base. The cause is available through errors.Unwrap. Neither
// the message nor the cause includes untrusted file bytes, revisions or
// plaintext. Context cancellation is returned unchanged and is never wrapped
// in this sentinel.
var ErrManagedTransitionProposalRejected = errors.New("vault file sync: managed transition proposal rejected")

// managedTransitionProposalVerifier is the state of one caller-pinned managed
// transition check. pin is a private snapshot of the caller's checkpoint,
// including owned copies of its two byte fields, so later mutation of the
// caller's checkpoint cannot change what this verifier trusts. The value is
// immutable after construction.
type managedTransitionProposalVerifier struct {
	pin vaultfile.PolicyCheckpoint
}

// NewManagedTransitionProposalVerifier returns a
// vaultfilepublish.ProposalVerifier for the exact managed policy/epoch
// successor of a caller-pinned base.
//
// This is the managed sibling of NewContentProposalVerifier. The ordinary
// content verifier intentionally refuses every policy change; this verifier
// admits only a complete managed transition that the existing
// vaultfile.VerifyManagedTransition authenticates. It adds no policy,
// invitation, delegation, key or unlock semantics of its own: the vaultfile
// verifier remains the only authority for the transition.
//
// The returned verifier is pure and performs no I/O, decryption, key handling
// or journaling. It does not mutate its base, revision, proposal or checkpoint
// inputs. It snapshots checkpoint at construction, cloning OwnerRootPublicKey
// and PolicyDigest, so the caller may mutate or discard its checkpoint
// afterwards. A nil checkpoint is rejected; no verifier is returned.
//
// The verifier parses and authenticates both the base and the candidate with
// vaultfile.VerifyPolicyCheckpoint under exactly the captured pin. It then
// requires:
//
//   - a non-zero, in-bounds base revision that is byte-for-byte equal to
//     proposal.ExpectedRevision;
//   - candidate.Header.OpID equal to proposal.OperationID, so the journal's
//     exact operation is bound to the candidate it prepared;
//   - vaultfile.VerifyManagedTransition(base, candidate, pin) to accept. That
//     existing verifier requires the exact old-to-next continuation: the same
//     vault, KeyEpoch, ContentSeq and PolicySeq each exactly old+1, the raw
//     FileDigest of the base, the authenticated old current policy as the
//     successor's predecessor, a different operation and revision id, an
//     author already writer-or-stronger in the old authenticated policy, and
//     a root-signed or already-supported delegated successor chain.
//
// No policy, roster or key is read from the candidate as authority: the
// captured pin and the authenticated base are the only trust inputs. There is
// no fallback to an older policy, no same-policy content admission, and no
// self-authorization by a newly added writer or revocation subject. ParseFile,
// VerifyPolicyCheckpoint and VerifyManagedTransition errors are wrapped in
// ErrManagedTransitionProposalRejected; context cancellation is returned
// unchanged.
func NewManagedTransitionProposalVerifier(checkpoint *vaultfile.PolicyCheckpoint) (vaultfilepublish.ProposalVerifier, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("%w: nil checkpoint", ErrManagedTransitionProposalRejected)
	}
	v := &managedTransitionProposalVerifier{
		pin: vaultfile.PolicyCheckpoint{
			VaultID:            checkpoint.VaultID,
			OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
			OwnerRootPublicKey: append(ed25519.PublicKey(nil), checkpoint.OwnerRootPublicKey...),
			PolicySeq:          checkpoint.PolicySeq,
			PolicyDigest:       append([]byte(nil), checkpoint.PolicyDigest...),
		},
	}
	return v.verify, nil
}

// verify is the ProposalVerifier returned by
// NewManagedTransitionProposalVerifier. It reads its inputs and the captured
// pin only; it keeps no reference to any of them after returning.
func (v *managedTransitionProposalVerifier) verify(
	ctx context.Context,
	base []byte,
	baseRevision vaultfilebackend.Revision,
	proposal vaultfilejournal.Proposal,
) error {
	if ctx == nil {
		return managedTransitionRejected("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// The coordinator's revision is opaque, but this verifier requires a real
	// non-create revision and the exact same value on the proposal.
	if baseRevision == "" || len(baseRevision) > vaultfilebackend.MaxRevisionSize {
		return managedTransitionRejected("invalid base revision")
	}
	if proposal.ExpectedRevision != baseRevision {
		return managedTransitionRejected("proposal revision does not match base revision")
	}
	if len(proposal.Bytes) == 0 {
		return managedTransitionRejected("empty candidate")
	}

	baseFile, err := vaultfile.ParseFile(base)
	if err != nil {
		return managedTransitionRejectedCause("base does not parse", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(baseFile, &v.pin); err != nil {
		return managedTransitionRejectedCause("base does not verify under the captured pin", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	candidate, err := vaultfile.ParseFile(proposal.Bytes)
	if err != nil {
		return managedTransitionRejectedCause("candidate does not parse", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(candidate, &v.pin); err != nil {
		return managedTransitionRejectedCause("candidate does not verify under the captured pin", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Bind the exact journal operation to the authenticated candidate before
	// asking the managed transition verifier for the exact successor.
	if candidate.Header.OpID != proposal.OperationID {
		return managedTransitionRejected("candidate operation ID does not match the proposal")
	}
	if err := vaultfile.VerifyManagedTransition(base, proposal.Bytes, &v.pin); err != nil {
		return managedTransitionRejectedCause("candidate is not the exact managed successor", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// managedTransitionRejected builds a rejection whose message names only a
// constant reason.
func managedTransitionRejected(reason string) error {
	return fmt.Errorf("%w: %s", ErrManagedTransitionProposalRejected, reason)
}

// managedTransitionRejectedCause wraps a safe structured cause. It is used
// only for vaultfile errors, whose messages contain at most a field path and a
// constant code, never the offending value.
func managedTransitionRejectedCause(reason string, cause error) error {
	return fmt.Errorf("%w: %s: %w", ErrManagedTransitionProposalRejected, reason, cause)
}
