package vaultfile

import (
	"bytes"
	"math"
)

// VerifyManagedTransition authenticates a managed policy/epoch successor M
// against the caller-trusted checkpoint and the exact old-file bytes R.
//
// It performs no decryption and changes no bytes or JSON shape. Both files
// are authenticated first; the candidate is then authenticated again from the
// old file's authenticated current policy pin, so no authority is read from
// the successor roster. The only policy transitions accepted are those the
// existing verifier accepts: the owner root, or the predecessor policy's
// already-supported InviteReaders delegation. This function adds no admin
// scope and performs no successor self-authorization.
//
// The transition is exact:
//   - KeyEpoch, ContentSeq and PolicySeq are each R+1, with overflow refused;
//   - M.PrevDigest is exactly FileDigest(R), never nil or empty;
//   - M's current policy PrevPolicyDigest is exactly R's authenticated
//     policy digest;
//   - M.OpID and M.RevisionID differ from R;
//   - M's author already holds writer, admin or owner authority in the
//     authenticated old R policy. Being added as a writer by M is not enough.
//
// This verifier does not authenticate backend freshness, a server token or a
// database grant. The consumer must bind the exact R bytes and its own
// token/CAS record after this check.
func VerifyManagedTransition(oldR, nextM []byte, c *PolicyCheckpoint) error {
	if c == nil {
		return Err("", CodeInvalidValue)
	}
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(oldR, c)
	if err != nil {
		return err
	}
	nextFile, nextCurrent, err := verifyParsedAuthenticatedFile(nextM, c)
	if err != nil {
		return err
	}
	oldH, nextH := &oldFile.Header, &nextFile.Header
	if nextH.VaultID != oldH.VaultID {
		return Err("vault_id", CodeInvalidValue)
	}
	if oldH.KeyEpoch == math.MaxUint64 || nextH.KeyEpoch != oldH.KeyEpoch+1 {
		return Err("key_epoch", CodeInvalidValue)
	}
	if oldH.ContentSeq == math.MaxUint64 || nextH.ContentSeq != oldH.ContentSeq+1 {
		return Err("content_seq", CodeInvalidValue)
	}
	if oldH.PolicySeq == math.MaxUint64 || nextH.PolicySeq != oldH.PolicySeq+1 {
		return Err("", CodePolicyCheckpointFailed)
	}
	oldDigest, err := deriveFileDigestBytes(oldFile)
	if err != nil {
		return err
	}
	if len(nextH.PrevDigest) != len(oldDigest) ||
		!bytes.Equal(nextH.PrevDigest, oldDigest) {
		return Err("prev_digest", CodeInvalidValue)
	}
	if !bytes.Equal(nextCurrent.PrevPolicyDigest, oldH.PolicyDigest) {
		return Err("", CodePolicyCheckpointFailed)
	}
	if nextH.OpID == oldH.OpID {
		return Err("op_id", CodeInvalidValue)
	}
	if nextH.RevisionID == oldH.RevisionID {
		return Err("revision_id", CodeInvalidValue)
	}

	// The next author must already be writer-or-stronger in the authenticated
	// old policy. A root-signed successor that adds a new writer does not
	// retroactively authorize that writer to author this transition.
	nextAuthor := findDevice(oldCurrent, nextH.AuthorDeviceID)
	if nextAuthor == nil ||
		!oldCurrent.hasRole(nextAuthor.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) {
		return Err("content_signature", CodePolicyCheckpointFailed)
	}

	// Authenticate the same candidate chain from the old-current policy, not
	// from any successor roster. The existing verifier decides root versus
	// InviteReaders authority using the old predecessor only.
	oldPin := oldCurrentCheckpoint(oldFile, c)
	if err := VerifyPolicyCheckpoint(nextFile, oldPin); err != nil {
		return err
	}
	return nil
}
