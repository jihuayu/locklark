package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// ErrContentProposalRejected reports that a caller-pinned content proposal was
// rejected: a malformed or unauthenticated base or candidate, a candidate that
// is not the immediate next ordinary-content revision of the base, a
// mismatched proposal operation, or any attempted policy change. The cause is
// available through errors.Unwrap. Neither the message nor the cause includes
// untrusted file bytes, revisions or plaintext. Context cancellation is
// returned unchanged and is never wrapped in this sentinel.
var ErrContentProposalRejected = errors.New("vault file sync: content proposal rejected")

// contentProposalVerifier is the state of one caller-pinned proposal check.
// pin is a private snapshot of the caller's checkpoint, including owned copies
// of the two byte fields, so later mutation of the caller's checkpoint cannot
// change what this verifier trusts. The value is immutable after construction.
type contentProposalVerifier struct {
	pin vaultfile.PolicyCheckpoint
}

// NewContentProposalVerifier returns a vaultfilepublish.ProposalVerifier that
// accepts only the ordinary-content successor of the caller-pinned base.
//
// The returned verifier is pure and performs no I/O, decryption, merge or key
// handling. It does not mutate its base, revision, proposal or checkpoint
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
//   - the same vault ID and key epoch;
//   - the same current policy sequence and digest; policy changes are rejected
//     even when the candidate carries a valid, root-signed successor policy;
//   - R.ContentSeq != math.MaxUint64 and P.ContentSeq == R.ContentSeq+1;
//   - P.Header.PrevDigest equal to the raw 32 bytes of vaultfile.FileDigest(R);
//   - P.Header.OpID equal to proposal.OperationID.
//
// The candidate author is authorized only from R's independently parsed
// current policy document, as a writer, admin or owner. Candidate policy state
// is never a trust input. ParseFile and VerifyPolicyCheckpoint errors are
// wrapped in ErrContentProposalRejected; context cancellation is returned
// unchanged.
func NewContentProposalVerifier(checkpoint *vaultfile.PolicyCheckpoint) (vaultfilepublish.ProposalVerifier, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("%w: nil checkpoint", ErrContentProposalRejected)
	}
	v := &contentProposalVerifier{
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

// verify is the ProposalVerifier returned by NewContentProposalVerifier. It
// reads its inputs and the captured pin only; it keeps no reference to any of
// them after returning.
func (v *contentProposalVerifier) verify(
	ctx context.Context,
	base []byte,
	baseRevision vaultfilebackend.Revision,
	proposal vaultfilejournal.Proposal,
) error {
	if ctx == nil {
		return contentProposalRejected("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// The coordinator's revision is opaque, but this verifier requires a real
	// non-create revision and the exact same value on the proposal.
	if baseRevision == "" || len(baseRevision) > vaultfilebackend.MaxRevisionSize {
		return contentProposalRejected("invalid base revision")
	}
	if proposal.ExpectedRevision != baseRevision {
		return contentProposalRejected("proposal revision does not match base revision")
	}

	baseFile, err := vaultfile.ParseFile(base)
	if err != nil {
		return contentProposalRejectedCause("base does not parse", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(baseFile, &v.pin); err != nil {
		return contentProposalRejectedCause("base does not verify under the captured pin", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	candidate, err := vaultfile.ParseFile(proposal.Bytes)
	if err != nil {
		return contentProposalRejectedCause("candidate does not parse", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(candidate, &v.pin); err != nil {
		return contentProposalRejectedCause("candidate does not verify under the captured pin", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Authority comes only from R's authenticated current policy. The last
	// proof is the current one; re-parse its canonical Document to obtain an
	// independent policy value, after binding that document to R's header.
	basePolicy, err := contentProposalCurrentPolicy(baseFile)
	if err != nil {
		return err
	}
	if !contentProposalCanAuthor(basePolicy, candidate.Header.AuthorDeviceID) {
		return contentProposalRejected("candidate author is not an authorized writer")
	}

	// No policy update is an ordinary content proposal. Requiring the exact R
	// policy sequence and digest rejects a valid, root-signed successor policy
	// even when the newly added writer signs the candidate.
	if candidate.Header.PolicySeq != baseFile.Header.PolicySeq ||
		!bytes.Equal(candidate.Header.PolicyDigest, baseFile.Header.PolicyDigest) {
		return contentProposalRejected("candidate changes the current policy")
	}

	if candidate.Header.VaultID != baseFile.Header.VaultID {
		return contentProposalRejected("candidate vault ID does not match the base")
	}
	if candidate.Header.KeyEpoch != baseFile.Header.KeyEpoch {
		return contentProposalRejected("candidate key epoch does not match the base")
	}

	if baseFile.Header.ContentSeq == math.MaxUint64 {
		return contentProposalRejected("base content sequence cannot advance")
	}
	if candidate.Header.ContentSeq != baseFile.Header.ContentSeq+1 {
		return contentProposalRejected("candidate content sequence is not the immediate successor")
	}

	prevDigestHex, err := vaultfile.FileDigest(baseFile)
	if err != nil {
		return contentProposalRejectedCause("base file digest", err)
	}
	prevDigest, err := hex.DecodeString(prevDigestHex)
	if err != nil || len(prevDigest) != 32 {
		return contentProposalRejected("base file digest is not a 32-byte value")
	}
	if !bytes.Equal(candidate.Header.PrevDigest, prevDigest) {
		return contentProposalRejected("candidate previous digest does not match the base")
	}

	if candidate.Header.OpID != proposal.OperationID {
		return contentProposalRejected("candidate operation ID does not match the proposal")
	}
	if proposal.ExpectedRevision != baseRevision {
		return contentProposalRejected("proposal revision does not match base revision")
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// contentProposalCurrentPolicy returns an independent policy value parsed
// from R's final signed policy document. R has already been authenticated, but
// the sequence and digest are re-bound explicitly so a document that is not
// exactly the current policy R's header selects can never contribute
// authority. ParsePolicyDocument allocates the returned policy, so it shares
// no mutable storage with R.
func contentProposalCurrentPolicy(base *vaultfile.File) (*vaultfile.Policy, error) {
	if len(base.SignedPolicyProofs) == 0 {
		return nil, contentProposalRejected("base carries no current policy proof")
	}
	last := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1]
	current, err := vaultfile.ParsePolicyDocument(last.Document)
	if err != nil {
		return nil, contentProposalRejectedCause("base current policy document does not parse", err)
	}
	if current.PolicySeq != base.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(current), base.Header.PolicyDigest) {
		return nil, contentProposalRejected("base current policy does not match its header")
	}
	return current, nil
}

// contentProposalCanAuthor reports whether deviceID is a device in p whose
// principal is a writer, admin or owner of p. It reads only p; the candidate's
// own roster is never consulted.
func contentProposalCanAuthor(p *vaultfile.Policy, deviceID string) bool {
	var principalID string
	found := false
	for i := range p.Devices {
		if p.Devices[i].DeviceID == deviceID {
			principalID = p.Devices[i].PrincipalID
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, role := range [][]vaultfile.Member{p.Writers, p.Admins, p.Owners} {
		for i := range role {
			if role[i].PrincipalID == principalID {
				return true
			}
		}
	}
	return false
}

// contentProposalRejected builds a rejection whose message names only a
// constant reason.
func contentProposalRejected(reason string) error {
	return fmt.Errorf("%w: %s", ErrContentProposalRejected, reason)
}

// contentProposalRejectedCause wraps a safe structured cause. It is used only
// for vaultfile errors, whose messages contain at most a field path and a
// constant code, never the offending value.
func contentProposalRejectedCause(reason string, cause error) error {
	return fmt.Errorf("%w: %s: %w", ErrContentProposalRejected, reason, cause)
}
