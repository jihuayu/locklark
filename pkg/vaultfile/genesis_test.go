package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// genesisSealFixture uses the real file sealer and independent root, content,
// and age identities. Its checkpoint is a sealing input, not the verifier's
// source of root authority; VerifyGenesis receives the separate root pin.
func genesisSealFixture(t *testing.T, badRootSignature bool) ([]byte, *GenesisRootPin, *PolicyCheckpoint) {
	t.Helper()
	k := newCPKeys(t)
	ownerAge, recoveryAge := tGenID(t), tGenID(t)
	policy := &Policy{
		Format: Format, Version: Version, VaultID: "vault-01", PolicySeq: 0,
		OwnerRoot: OwnerRoot{KeyID: "owner-root-01", Alg: PolicySigAlgEd25519,
			PublicKey: bytes.Clone(k.root), Owners: []Principal{{PrincipalID: "alice", Label: "Alice"}}},
		Owners: []Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []Device{
			{DeviceID: "device-1", PrincipalID: "alice", Label: "Owner device",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev1)},
				AgeEncryptionKey:  ownerAge.Recipient().String()},
			{DeviceID: "device-2", PrincipalID: "alice", Label: "Recovery device",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: bytes.Clone(k.dev2)},
				AgeEncryptionKey:  recoveryAge.Recipient().String()},
		},
	}
	if err := ValidatePolicy(policy); err != nil {
		t.Fatal("GENESIS_POLICY_FIXTURE_INVALID")
	}
	document, err := EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("GENESIS_DOCUMENT_FIXTURE_INVALID")
	}
	proof := SignedPolicy{Document: document, Policy: *clonePolicy(policy),
		SignerID: policy.OwnerRoot.KeyID, Alg: PolicySigAlgEd25519}
	rootSigner := k.rootPriv
	if badRootSignature {
		rootSigner = k.otherRootPrv
	}
	signPolicyProof(&proof, rootSigner)
	draft := &File{Format: Format, Version: Version,
		Header: Header{VaultID: policy.VaultID, KeyEpoch: 1, ContentSeq: 0,
			OpID: "genesis-op", PolicySeq: 0, PolicyDigest: PolicyDigest(policy),
			AuthorDeviceID: "device-1"},
		SignedPolicyProofs: []SignedPolicy{proof},
	}
	vuk := make([]byte, CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("GENESIS_VUK_FIXTURE_FAILED")
	}
	sealingCheckpoint := &PolicyCheckpoint{VaultID: policy.VaultID,
		OwnerRootKeyID: policy.OwnerRoot.KeyID, OwnerRootPublicKey: bytes.Clone(k.root),
		PolicySeq: 0, PolicyDigest: PolicyDigest(policy)}
	encoded, err := SealAuthenticatedFile(draft, payloadFixtureDB(t), sealingCheckpoint, vuk, k.dev1Priv)
	if err != nil {
		t.Fatal("GENESIS_REAL_SEAL_FAILED")
	}
	return encoded, &GenesisRootPin{VaultID: policy.VaultID,
		OwnerRootKeyID: policy.OwnerRoot.KeyID, OwnerRootPublicKey: bytes.Clone(k.root)}, sealingCheckpoint
}

func TestVerifyGenesisRealSeal(t *testing.T) {
	encoded, pin, sealingCheckpoint := genesisSealFixture(t, false)
	got, err := VerifyGenesis(encoded, pin)
	if err != nil || got == nil || got.PolicySeq != 0 || got.VaultID != pin.VaultID ||
		got.OwnerRootKeyID != pin.OwnerRootKeyID ||
		!bytes.Equal(got.OwnerRootPublicKey, pin.OwnerRootPublicKey) ||
		!bytes.Equal(got.PolicyDigest, sealingCheckpoint.PolicyDigest) {
		t.Fatal("GENESIS_VERIFIED_CHECKPOINT_MISMATCH")
	}
}

func TestVerifyGenesisRejectsBadAnchorSignatureTrustedByCheckpoint(t *testing.T) {
	encoded, pin, sealingCheckpoint := genesisSealFixture(t, true)
	f, err := ParseFile(encoded)
	if err != nil || VerifyPolicyCheckpoint(f, sealingCheckpoint) != nil {
		t.Fatal("GENESIS_BAD_ANCHOR_CONTROL_DID_NOT_PASS_OLD_VERIFIER")
	}
	got, err := VerifyGenesis(encoded, pin)
	if got != nil {
		t.Fatal("GENESIS_BAD_ANCHOR_RETURNED_CHECKPOINT")
	}
	wantCodeAt(t, err, CodeSignatureVerifyFailed, "signed_policy_proofs[0]")
}

func TestVerifyGenesisRefusesForeignPinAndBadContentSignature(t *testing.T) {
	encoded, pin, _ := genesisSealFixture(t, false)
	foreign := *pin
	foreign.VaultID = "foreign-vault"
	if got, err := VerifyGenesis(encoded, &foreign); got != nil {
		t.Fatal("GENESIS_FOREIGN_VAULT_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
	}
	foreign = *pin
	foreign.OwnerRootPublicKey = bytes.Repeat([]byte{0x5a}, ed25519.PublicKeySize)
	if got, err := VerifyGenesis(encoded, &foreign); got != nil {
		t.Fatal("GENESIS_FOREIGN_PIN_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
	}
	foreign = *pin
	foreign.OwnerRootKeyID = "foreign-root"
	if got, err := VerifyGenesis(encoded, &foreign); got != nil {
		t.Fatal("GENESIS_FOREIGN_ROOT_ID_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodePolicyCheckpointFailed, "")
	}
	short := *pin
	short.OwnerRootPublicKey = short.OwnerRootPublicKey[:31]
	if got, err := VerifyGenesis(encoded, &short); got != nil {
		t.Fatal("GENESIS_SHORT_PIN_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodeInvalidValue, "")
	}
	f, err := ParseFile(encoded)
	if err != nil {
		t.Fatal("GENESIS_CONTENT_FIXTURE_PARSE_FAILED")
	}
	f.ContentSignature.Sig[0] ^= 1
	badContent, err := EncodeFile(f)
	if err != nil {
		t.Fatal("GENESIS_BAD_CONTENT_FIXTURE_NOT_STRUCTURAL")
	}
	if _, err := ParseFile(badContent); err != nil {
		t.Fatal("GENESIS_BAD_CONTENT_FIXTURE_NOT_CANONICAL")
	}
	if got, err := VerifyGenesis(badContent, pin); got != nil {
		t.Fatal("GENESIS_BAD_CONTENT_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodeSignatureVerifyFailed, "")
	}
}

func TestVerifyGenesisRefusesValidNonGenesisSuccessor(t *testing.T) {
	fx := newSealFixture(t)
	encoded, err := SealAuthenticatedFile(fx.draft(), payloadFixtureDB(t),
		fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatal("NON_GENESIS_REAL_SEAL_FAILED")
	}
	if _, err := ParseFile(encoded); err != nil {
		t.Fatal("NON_GENESIS_FILE_NOT_VALID")
	}
	pin := &GenesisRootPin{VaultID: fx.chain.anchor.VaultID,
		OwnerRootKeyID:     fx.chain.anchor.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(fx.chain.anchor.OwnerRootPublicKey)}
	if got, err := VerifyGenesis(encoded, pin); got != nil {
		t.Fatal("NON_GENESIS_RETURNED_CHECKPOINT")
	} else {
		wantCodeAt(t, err, CodeInvalidValue, "")
	}
}

func TestVerifyGenesisResultDoesNotAliasInputs(t *testing.T) {
	encoded, pin, _ := genesisSealFixture(t, false)
	originalBytes := bytes.Clone(encoded)
	originalKey := bytes.Clone(pin.OwnerRootPublicKey)
	got, err := VerifyGenesis(encoded, pin)
	if err != nil {
		t.Fatal("GENESIS_ALIAS_FIXTURE_FAILED")
	}
	wantKey, wantDigest := bytes.Clone(got.OwnerRootPublicKey), bytes.Clone(got.PolicyDigest)
	encoded[0] ^= 1
	pin.OwnerRootPublicKey[0] ^= 1
	if !bytes.Equal(got.OwnerRootPublicKey, wantKey) || !bytes.Equal(got.PolicyDigest, wantDigest) {
		t.Fatal("GENESIS_RESULT_ALIASES_INPUT")
	}
	mutatedInput := bytes.Clone(encoded)
	mutatedPin := bytes.Clone(pin.OwnerRootPublicKey)
	got.OwnerRootPublicKey[0] ^= 1
	got.PolicyDigest[0] ^= 1
	if !bytes.Equal(pin.OwnerRootPublicKey, mutatedPin) ||
		!bytes.Equal(encoded, mutatedInput) ||
		mutatedPin[0] != originalKey[0]^1 || mutatedInput[0] != originalBytes[0]^1 {
		t.Fatal("GENESIS_RESULT_ALIASES_CALLER_INPUT")
	}
}
