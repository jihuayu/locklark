package vaultfile

import (
	"bytes"
	"math"
)

// VerifyContentTransition authenticates an ordinary next content file M
// against the caller-trusted checkpoint and the exact old-file bytes R.
//
// It performs no decryption and changes no bytes or JSON shape. Both files
// are parsed, validated and authenticated first; R must verify under c and M
// must carry the same authenticated policy and content signature rules.
//
// The transition is ordinary-content only:
//   - VaultID, KeyEpoch, PolicySeq and PolicyDigest are unchanged;
//   - M.ContentSeq is exactly R.ContentSeq+1, with 64-bit overflow refused;
//   - M.PrevDigest is exactly the raw FileDigest(R), never nil or empty;
//   - M.OpID and M.RevisionID differ from R;
//   - M's author already has writer, admin or owner authority in the
//     authenticated old R policy. The old file's author alone is not
//     sufficient.
//
// A policy or key-epoch change is refused here; managed rotation has a
// separate verifier. This verifier does not authenticate backend freshness,
// a server token or a database grant. The consumer must bind the exact R
// bytes and its own token/CAS record after this check.
func VerifyContentTransition(oldR, nextM []byte, c *PolicyCheckpoint) error {
	if c == nil {
		return Err("", CodeInvalidValue)
	}
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(oldR, c)
	if err != nil {
		return err
	}
	nextFile, _, err := verifyParsedAuthenticatedFile(nextM, c)
	if err != nil {
		return err
	}
	return verifyContentTransitionAuthenticated(oldFile, oldCurrent, nextFile)
}

// verifyContentTransitionAuthenticated applies the ordinary-content
// continuation rules after both files and the old current policy have been
// authenticated. It is separate so the old-policy author authority rule can
// be exercised without giving the verifier an unauthenticated file path.
func verifyContentTransitionAuthenticated(oldFile *File, oldCurrent *Policy, nextFile *File) error {
	oldH, nextH := &oldFile.Header, &nextFile.Header
	if nextH.VaultID != oldH.VaultID {
		return Err("vault_id", CodeInvalidValue)
	}
	if nextH.KeyEpoch != oldH.KeyEpoch {
		return Err("key_epoch", CodeInvalidValue)
	}
	if nextH.PolicySeq != oldH.PolicySeq ||
		!bytes.Equal(nextH.PolicyDigest, oldH.PolicyDigest) {
		return Err("", CodePolicyCheckpointFailed)
	}

	// The old author must already be a writer-or-stronger in the authenticated
	// old policy; a file's carried author ID is never trust by itself.
	oldAuthor := findDevice(oldCurrent, oldH.AuthorDeviceID)
	if oldAuthor == nil ||
		!oldCurrent.hasRole(oldAuthor.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) {
		return Err("content_signature", CodePolicyCheckpointFailed)
	}
	// The next author must already hold that authority in the authenticated
	// old policy; the old file's author does not carry it over.
	nextAuthor := findDevice(oldCurrent, nextH.AuthorDeviceID)
	if nextAuthor == nil ||
		!oldCurrent.hasRole(nextAuthor.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) {
		return Err("content_signature", CodePolicyCheckpointFailed)
	}

	if oldH.ContentSeq == math.MaxUint64 ||
		nextH.ContentSeq != oldH.ContentSeq+1 {
		return Err("content_seq", CodeInvalidValue)
	}
	oldDigest, err := deriveFileDigestBytes(oldFile)
	if err != nil {
		return err
	}
	if len(nextH.PrevDigest) != len(oldDigest) ||
		!bytes.Equal(nextH.PrevDigest, oldDigest) {
		return Err("prev_digest", CodeInvalidValue)
	}
	if nextH.OpID == oldH.OpID {
		return Err("op_id", CodeInvalidValue)
	}
	if nextH.RevisionID == oldH.RevisionID {
		return Err("revision_id", CodeInvalidValue)
	}
	return nil
}
