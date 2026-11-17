package vaultfile

import (
	"bytes"
	"crypto/ed25519"
)

// GenesisRootPin is the vault ID and independent owner-root public identity
// pinned by the caller before it receives the genesis file. Neither these
// fields nor their authority may be inferred from the file being checked.
type GenesisRootPin struct {
	VaultID            string
	OwnerRootKeyID     string
	OwnerRootPublicKey ed25519.PublicKey
}

// VerifyGenesis authenticates one canonical sealed genesis file against an
// independently pinned owner root. It first verifies the sole root-signed
// policy proof, then verifies the current writer's content signature under
// that authenticated policy. The returned checkpoint owns its byte slices.
//
// This does not establish remote freshness, VUK or KDBX readability, or a
// server-side grant. A caller publishing a genesis file must separately open
// the exact bytes with its recovery device and bind authoritative readback.
func VerifyGenesis(encoded []byte, expected *GenesisRootPin) (*PolicyCheckpoint, error) {
	if expected == nil || !validID(expected.VaultID, MaxIDLength) ||
		!validID(expected.OwnerRootKeyID, MaxKeyIDLength) ||
		!validEd25519Key(expected.OwnerRootPublicKey) {
		return nil, Err("", CodeInvalidValue)
	}
	// Own the caller's public-key bytes throughout validation. The result gets
	// another independent copy and retains no pointer to the input pin.
	rootKey := bytes.Clone(expected.OwnerRootPublicKey)
	vaultID, rootID := expected.VaultID, expected.OwnerRootKeyID
	f, err := ParseFile(encoded)
	if err != nil {
		return nil, err
	}
	if len(f.SignedPolicyProofs) != 1 || f.Header.PolicySeq != 0 ||
		f.Header.ContentSeq != 0 || f.Header.KeyEpoch != 1 ||
		f.Header.PrevDigest != nil {
		return nil, Err("", CodeInvalidValue)
	}
	sp := &f.SignedPolicyProofs[0]
	if sp.Policy.PolicySeq != 0 || sp.Policy.PrevPolicyDigest != nil {
		return nil, Err("", CodeInvalidValue)
	}
	if f.Header.VaultID != vaultID || sp.Policy.VaultID != vaultID ||
		sp.Policy.OwnerRoot.KeyID != rootID ||
		sp.Policy.OwnerRoot.Alg != PolicySigAlgEd25519 ||
		!bytes.Equal(sp.Policy.OwnerRoot.PublicKey, rootKey) ||
		sp.SignerID != rootID || sp.Alg != PolicySigAlgEd25519 {
		return nil, Err("", CodePolicyCheckpointFailed)
	}
	if !verifyPolicyProofSignature(sp, rootKey) {
		return nil, Err(pathIndex(fieldSignedPolicyProofs, 0), CodeSignatureVerifyFailed)
	}
	checkpoint := &PolicyCheckpoint{
		VaultID:            vaultID,
		OwnerRootKeyID:     rootID,
		OwnerRootPublicKey: bytes.Clone(rootKey),
		PolicySeq:          0,
		PolicyDigest:       policyDigest(sp),
	}
	if err := VerifyPolicyCheckpoint(f, checkpoint); err != nil {
		return nil, err
	}
	return checkpoint, nil
}
