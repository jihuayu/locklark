//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

const ownedTestSuccessorRevision = vaultfilebackend.Revision("first-note-revision")

type ownedSignedFixture struct {
	intent   GenesisIntent
	pin      OwnedGenesisPin
	proposal Proposal
	identity *age.X25519Identity
}

func newOwnedSignedFixture(t *testing.T, wrongParent bool) ownedSignedFixture {
	t.Helper()
	fixture, err := buildOwnedSignedFixture(t, wrongParent, true)
	if err != nil {
		t.Fatal("owned fixture genesis did not authenticate")
	}
	return fixture
}

// buildOwnedSignedFixture seals a genesis and authenticates it with
// VerifyGenesis before any successor is constructed. Only the authenticated
// checkpoint is used to seal and verify the immediate successor. A false
// policyProofFramed keeps the original missing-separator proof: sealing can
// still succeed because the provisional checkpoint trusts its own digest, so
// the returned error is the independent oracle rejecting that proof.
func buildOwnedSignedFixture(t *testing.T, wrongParent, policyProofFramed bool) (ownedSignedFixture, error) {
	t.Helper()
	root, rootSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("root key generation failed")
	}
	defer clear(rootSigner)
	author, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("author key generation failed")
	}
	defer clear(signer)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("recipient generation failed")
	}
	member := vaultfile.Member{PrincipalID: "owner", Label: "Owner"}
	policy := vaultfile.Policy{
		Format: vaultfile.Format, Version: vaultfile.Version, VaultID: "owned-vault", PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID: "root", Alg: vaultfile.PolicySigAlgEd25519, PublicKey: root,
			Owners: []vaultfile.Principal{{PrincipalID: member.PrincipalID, Label: member.Label}},
		},
		Owners: []vaultfile.Member{member},
		Devices: []vaultfile.Device{{
			DeviceID: "local-device", PrincipalID: member.PrincipalID, Label: "Local device",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: author},
			AgeEncryptionKey:  identity.Recipient().String(),
		}},
	}
	document, err := vaultfile.EncodePolicyDocument(&policy)
	if err != nil {
		t.Fatal("genesis policy encoding failed")
	}
	policyFraming := []byte(vaultfile.DomainPolicyDocumentSignature + "\x00")
	if !policyProofFramed {
		policyFraming = []byte(vaultfile.DomainPolicyDocumentSignature)
	}
	proof := vaultfile.SignedPolicy{
		Policy: policy, Document: document, SignerID: policy.OwnerRoot.KeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: ed25519.Sign(rootSigner, append(policyFraming, document...)),
	}
	rootPin := vaultfile.GenesisRootPin{VaultID: policy.VaultID, OwnerRootKeyID: policy.OwnerRoot.KeyID, OwnerRootPublicKey: root}
	// The provisional checkpoint exists only to let the genesis builder seal
	// and is never promoted to the downstream trust anchor.
	provisional := vaultfile.PolicyCheckpoint{
		VaultID: rootPin.VaultID, OwnerRootKeyID: rootPin.OwnerRootKeyID, OwnerRootPublicKey: rootPin.OwnerRootPublicKey,
		PolicySeq: policy.PolicySeq, PolicyDigest: vaultfile.PolicyDigest(&policy),
	}
	draft := vaultfile.File{
		Format: vaultfile.Format, Version: vaultfile.Version, SignedPolicyProofs: []vaultfile.SignedPolicy{proof},
		Header: vaultfile.Header{
			VaultID: policy.VaultID, PolicySeq: policy.PolicySeq, PolicyDigest: provisional.PolicyDigest,
			ContentSeq: 0, KeyEpoch: 1, OpID: "genesis-operation", AuthorDeviceID: "local-device",
		},
	}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("epoch key generation failed")
	}
	defer clear(vuk)
	genesis, err := vault.SealAuthenticatedItems(&draft, []byte{}, []vault.Item{}, &provisional, vuk, signer)
	if err != nil {
		t.Fatal("genesis seal failed")
	}
	checkpoint, err := vaultfile.VerifyGenesis(genesis, &rootPin)
	if err != nil {
		return ownedSignedFixture{}, err
	}
	file, err := vaultfile.ParseFile(genesis)
	if err != nil {
		t.Fatal("genesis parse failed")
	}
	digest, err := vaultfile.FileDigest(file)
	if err != nil {
		t.Fatal("genesis file digest failed")
	}
	parent, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal("parent digest decoding failed")
	}
	if wrongParent {
		parent[0] ^= 1
	}
	intent := GenesisIntent{
		Name: "owned", VaultID: checkpoint.VaultID, OwnerRootKeyID: checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(checkpoint.OwnerRootPublicKey), PolicySeq: checkpoint.PolicySeq,
		PolicyDigest: bytes.Clone(checkpoint.PolicyDigest), OperationID: file.Header.OpID, SealedBytes: genesis,
	}
	draft.Header.PolicySeq = checkpoint.PolicySeq
	draft.Header.PolicyDigest = bytes.Clone(checkpoint.PolicyDigest)
	draft.Header.ContentSeq = file.Header.ContentSeq + 1
	draft.Header.PrevDigest = parent
	draft.Header.OpID = "first-note-operation"
	note := vault.Item{
		ID: "first-note", Kind: string(vault.CategorySecureNote),
		Category: vault.CategorySecureNote, Title: "First note", Notes: "Journal acceptance fixture",
	}
	successor, err := vault.SealAuthenticatedItems(&draft, []byte{}, []vault.Item{note}, checkpoint, vuk, signer)
	if err != nil {
		t.Fatal("successor seal failed")
	}
	if err := vaultfile.VerifyContentTransition(genesis, successor, checkpoint); (err != nil) != wrongParent {
		t.Fatal("signed transition fixture did not match intent")
	}
	return ownedSignedFixture{
		intent: intent, identity: identity,
		pin:      OwnedGenesisPin{Root: rootPin, SealedSHA256: sha256.Sum256(genesis), OperationID: intent.OperationID},
		proposal: Proposal{Generation: 1, OperationID: draft.Header.OpID, ExpectedRevision: "genesis-revision", Bytes: successor},
	}, nil
}

func (f ownedSignedFixture) openGenesis(t *testing.T) (string, *Journal, State) {
	t.Helper()
	path := filepath.Join(privateDir(t), "owned.journal")
	if err := CreateNewGenesisIntent(path, f.intent); err != nil {
		t.Fatal("genesis intent creation failed")
	}
	intent, err := OpenExistingIntent(path)
	if err != nil {
		t.Fatal("genesis intent open failed")
	}
	ackErr := intent.AckGenesis(f.intent, f.intent.SealedBytes, f.proposal.ExpectedRevision)
	if closeErr := intent.Close(); ackErr != nil || closeErr != nil {
		t.Fatal("genesis acknowledgement failed")
	}
	j, err := OpenExisting(path)
	if err != nil {
		t.Fatal("genesis journal open failed")
	}
	t.Cleanup(func() { _ = j.Close() })
	state, err := j.LoadGenesisBaseline()
	if err != nil {
		t.Fatal("genesis baseline load failed")
	}
	return path, j, state
}

func requireOwnedPrepared(t *testing.T, j *Journal, origin State, proposal Proposal) {
	t.Helper()
	state, err := j.LoadState()
	if err != nil || state.Generation != proposal.Generation || state.RemoteRevision != origin.RemoteRevision ||
		!bytes.Equal(state.BaseBytes, origin.BaseBytes) || !bytes.Equal(state.WorkingBytes, proposal.Bytes) {
		t.Fatal("first prepared state mismatch")
	}
	prepared, err := j.LoadPrepared()
	if err != nil || !samePrepared(prepared, PreparedProposal{WorkingGeneration: proposal.Generation, Proposal: proposal}) {
		t.Fatal("first prepared proposal mismatch")
	}
}

func requireOwnedReadback(t *testing.T, path string, fixture ownedSignedFixture) OwnedFirstSuccessor {
	t.Helper()
	record, err := ReadOwnedFirstSuccessor(path, fixture.pin)
	if err != nil || !bytes.Equal(record.GenesisBytes, fixture.intent.SealedBytes) ||
		record.GenesisRevision != fixture.proposal.ExpectedRevision || !bytes.Equal(record.SuccessorBytes, fixture.proposal.Bytes) ||
		record.SuccessorRevision != ownedTestSuccessorRevision {
		t.Fatal("typed owned readback mismatch")
	}
	checkpoint, err := vaultfile.VerifyGenesis(record.GenesisBytes, &fixture.pin.Root)
	if err != nil {
		t.Fatal("retained genesis verification failed")
	}
	file, _, items, err := vault.OpenAuthenticatedItems(record.SuccessorBytes, checkpoint, "local-device", fixture.identity)
	if err != nil || file.Header.VaultID != checkpoint.VaultID || file.Header.OpID != fixture.proposal.OperationID ||
		len(items) != 1 || items[0].Category != vault.CategorySecureNote {
		t.Fatal("successor item read failed")
	}
	return record
}

func TestOwnedFirstSuccessorFixtureAuthenticatesGenesis(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	checkpoint, err := vaultfile.VerifyGenesis(fixture.intent.SealedBytes, &fixture.pin.Root)
	if err != nil || checkpoint == nil {
		t.Fatal("sealed genesis did not authenticate")
	}
	if checkpoint.VaultID != fixture.pin.Root.VaultID ||
		checkpoint.OwnerRootKeyID != fixture.pin.Root.OwnerRootKeyID ||
		!bytes.Equal(checkpoint.OwnerRootPublicKey, fixture.pin.Root.OwnerRootPublicKey) ||
		checkpoint.PolicySeq != fixture.intent.PolicySeq ||
		!bytes.Equal(checkpoint.PolicyDigest, fixture.intent.PolicyDigest) {
		t.Fatal("authenticated genesis origin mismatch")
	}
	genesis, err := vaultfile.ParseFile(fixture.intent.SealedBytes)
	if err != nil || genesis.Header.VaultID != checkpoint.VaultID ||
		genesis.Header.OpID != fixture.pin.OperationID || genesis.Header.ContentSeq != 0 ||
		genesis.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(genesis.Header.PolicyDigest, checkpoint.PolicyDigest) {
		t.Fatal("authenticated genesis header mismatch")
	}
	successor, err := vaultfile.ParseFile(fixture.proposal.Bytes)
	if err != nil || successor.Header.VaultID != checkpoint.VaultID ||
		successor.Header.OpID != fixture.proposal.OperationID ||
		successor.Header.ContentSeq != genesis.Header.ContentSeq+1 ||
		successor.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(successor.Header.PolicyDigest, checkpoint.PolicyDigest) {
		t.Fatal("immediate successor header mismatch")
	}
	parent, err := vaultfile.FileDigest(genesis)
	if err != nil || hex.EncodeToString(successor.Header.PrevDigest) != parent {
		t.Fatal("immediate successor parent mismatch")
	}
	record := OwnedFirstSuccessor{
		GenesisBytes: fixture.intent.SealedBytes, GenesisRevision: fixture.proposal.ExpectedRevision,
		SuccessorBytes: fixture.proposal.Bytes, SuccessorRevision: ownedTestSuccessorRevision,
	}
	op, err := verifyOwnedFirstSuccessor(record, fixture.pin)
	if err != nil || op != fixture.proposal.OperationID {
		t.Fatal("owned trust gate rejected immediate successor")
	}
	if _, err := buildOwnedSignedFixture(t, false, false); err == nil {
		t.Fatal("unframed genesis policy proof authenticated")
	} else {
		var vfErr *vaultfile.Error
		if !errors.As(err, &vfErr) || vfErr.Code != vaultfile.CodeSignatureVerifyFailed {
			t.Fatal("unframed genesis policy proof was not a signature failure")
		}
	}
}

func TestOwnedFirstSuccessorAtomicSettlement(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	path, j, origin := fixture.openGenesis(t)
	if err := j.PrepareWorkingIfState(origin, fixture.proposal); err != nil {
		t.Fatal("first prepare failed")
	}
	if err := j.AckOwnedFirstSuccessor(origin, fixture.pin, fixture.proposal, fixture.proposal.Bytes, ownedTestSuccessorRevision); err != nil {
		t.Fatal("owned acknowledgement failed")
	}
	if err := j.Close(); err != nil {
		t.Fatal("journal close failed")
	}
	requireOwnedReadback(t, path, fixture)
	if _, err := OpenExisting(path); !errors.Is(err, ErrCorrupt) {
		t.Fatal("legacy existing open accepted owned state")
	}
	if _, err := Open(path); !errors.Is(err, ErrCorrupt) {
		t.Fatal("legacy open accepted owned state")
	}
	for _, mutate := range []func(*OwnedGenesisPin){
		func(pin *OwnedGenesisPin) { pin.Root.VaultID += "-foreign" },
		func(pin *OwnedGenesisPin) { pin.Root.OwnerRootPublicKey = make([]byte, ed25519.PublicKeySize) },
		func(pin *OwnedGenesisPin) { pin.SealedSHA256[0] ^= 1 },
		func(pin *OwnedGenesisPin) { pin.OperationID += "-foreign" },
	} {
		pin := fixture.pin
		mutate(&pin)
		if got, err := ReadOwnedFirstSuccessor(path, pin); !errors.Is(err, ErrCorrupt) || got.GenesisBytes != nil || got.SuccessorBytes != nil {
			t.Fatal("wrong original pin accepted")
		}
	}
}

func TestOwnedFirstSuccessorRefusesMismatchedPreparation(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	_, j, origin := fixture.openGenesis(t)
	p := fixture.proposal
	ack := func(g State, proposal Proposal, readback []byte, revision vaultfilebackend.Revision) error {
		return j.AckOwnedFirstSuccessor(g, fixture.pin, proposal, readback, revision)
	}
	if err := ack(origin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrStateMismatch) {
		t.Fatal("pristine state accepted without preparation")
	}
	if err := j.UpdateWorking(origin.Generation, p.Bytes); err != nil {
		t.Fatal("working update failed")
	}
	if err := ack(origin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatal("working state accepted without proposal")
	}
	wrongProposal := p
	wrongProposal.OperationID += "-foreign"
	if err := j.Prepare(p.Generation, wrongProposal); err != nil {
		t.Fatal("prepared mismatch fixture failed")
	}
	if err := ack(origin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatal("unmatched stored operation accepted")
	}
	if err := ack(origin, wrongProposal, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatal("operation inconsistent with signed successor accepted")
	}
	requireOwnedPrepared(t, j, origin, wrongProposal)
}

func TestOwnedFirstSuccessorRefusesRevisionsAndCompetingRecords(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	path, j, origin := fixture.openGenesis(t)
	p := fixture.proposal
	if err := j.PrepareWorkingIfState(origin, p); err != nil {
		t.Fatal("first prepare failed")
	}
	ack := func(g State, proposal Proposal, readback []byte, revision vaultfilebackend.Revision) error {
		return j.AckOwnedFirstSuccessor(g, fixture.pin, proposal, readback, revision)
	}
	changed := origin
	changed.RemoteRevision = "different-original-revision"
	changedProposal := p
	changedProposal.ExpectedRevision = changed.RemoteRevision
	if err := ack(changed, changedProposal, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrStateMismatch) {
		t.Fatal("wrong original revision accepted")
	}
	for _, revision := range []vaultfilebackend.Revision{"", origin.RemoteRevision} {
		if err := ack(origin, p, p.Bytes, revision); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid successor revision accepted")
		}
	}
	if err := ack(origin, p, origin.BaseBytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatal("unmatched successor readback accepted")
	}
	requireOwnedPrepared(t, j, origin, p)
	if err := j.Save(p); err != nil {
		t.Fatal("legacy proposal fixture failed")
	}
	if err := ack(origin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPendingRecords) {
		t.Fatal("owned acknowledgement accepted competing proposal")
	}
	requireOwnedPrepared(t, j, origin, p)
	if saved, err := j.Load(); err != nil || !sameProposal(saved, p) {
		t.Fatal("competing proposal changed")
	}
	if err := j.Close(); err != nil {
		t.Fatal("journal close failed")
	}
	if _, err := ReadOwnedFirstSuccessor(path, fixture.pin); !errors.Is(err, ErrPendingRecords) {
		t.Fatal("typed reader accepted pending legacy state")
	}
}

func TestOwnedFirstSuccessorRefusesWrongSignedParent(t *testing.T) {
	fixture := newOwnedSignedFixture(t, true)
	_, j, origin := fixture.openGenesis(t)
	p := fixture.proposal
	if err := j.PrepareWorkingIfState(origin, p); err != nil {
		t.Fatal("first prepare failed")
	}
	if err := j.AckOwnedFirstSuccessor(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatal("wrong signed parent accepted")
	}
	requireOwnedPrepared(t, j, origin, p)
}

func TestOwnedFirstSuccessorAckFaults(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	for _, committed := range []bool{false, true} {
		path, j, origin := fixture.openGenesis(t)
		p := fixture.proposal
		if err := j.PrepareWorkingIfState(origin, p); err != nil {
			t.Fatal("first prepare failed")
		}
		injected := errors.New("injected transaction result")
		update := func(body func(*bolt.Tx) error) error {
			err := j.db.Update(func(tx *bolt.Tx) error {
				if err := body(tx); err != nil {
					return err
				}
				if !committed {
					return injected
				}
				return nil
			})
			if err != nil {
				return err
			}
			return injected
		}
		err := j.ackOwnedFirstSuccessorWithUpdate(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision, update)
		if !errors.Is(err, injected) || j.Close() != nil {
			t.Fatal("transaction fault was not observed")
		}
		if committed {
			requireOwnedReadback(t, path, fixture)
			continue
		}
		reopened, err := OpenExisting(path)
		if err != nil {
			t.Fatal("rollback journal reopen failed")
		}
		requireOwnedPrepared(t, reopened, origin, p)
		if err := reopened.Close(); err != nil {
			t.Fatal("rollback journal close failed")
		}
		if _, err := ReadOwnedFirstSuccessor(path, fixture.pin); !errors.Is(err, ErrPendingRecords) {
			t.Fatal("rollback exposed an owned successor")
		}
	}
}

func TestOwnedFirstSuccessorRejectsLegacyMutators(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	path, j, origin := fixture.openGenesis(t)
	p := fixture.proposal
	if err := j.PrepareWorkingIfState(origin, p); err != nil ||
		j.AckOwnedFirstSuccessor(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision) != nil {
		t.Fatal("owned settlement fixture failed")
	}
	for _, change := range []struct {
		name  string
		apply func() error
	}{
		{"Save", func() error { return j.Save(p) }},
		{"InitializeState", func() error { return j.InitializeState(origin) }},
		{"InitializeEmptyState", func() error { return j.InitializeEmptyState(origin) }},
		{"UpdateWorking", func() error { return j.UpdateWorking(p.Generation, p.Bytes) }},
		{"Prepare", func() error { return j.Prepare(p.Generation, p) }},
		{"PrepareWorkingIfState", func() error { return j.PrepareWorkingIfState(origin, p) }},
		{"Ack", func() error { return j.Ack(p.OperationID, p.Bytes, ownedTestSuccessorRevision) }},
		{"RebaseAndPrepare", func() error { return j.RebaseAndPrepare(origin, p.Bytes, p.ExpectedRevision, p) }},
		{"ReconcileRebaseAndPrepare", func() error {
			_, err := j.ReconcileRebaseAndPrepare(origin, p.Bytes, p.ExpectedRevision, p)
			return err
		}},
		{"AckOwnedFirstSuccessor replay", func() error {
			return j.AckOwnedFirstSuccessor(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision)
		}},
	} {
		if err := change.apply(); err == nil {
			t.Fatal(change.name, "accepted owned state")
		}
	}
	if _, err := j.Load(); !errors.Is(err, ErrEmpty) {
		t.Fatal("legacy proposal appeared")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatal("prepared proposal appeared")
	}
	if err := j.Close(); err != nil {
		t.Fatal("journal close failed")
	}
	requireOwnedReadback(t, path, fixture)
}

func TestOwnedFirstSuccessorRefusesIntentAndAdvancedLegacyState(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	intentPath := filepath.Join(privateDir(t), "pending.journal")
	if err := CreateNewGenesisIntent(intentPath, fixture.intent); err != nil {
		t.Fatal("pending intent fixture failed")
	}
	if _, err := ReadOwnedFirstSuccessor(intentPath, fixture.pin); !errors.Is(err, ErrPendingGenesisIntent) {
		t.Fatal("typed reader accepted pending intent")
	}
	intent, err := OpenExistingIntent(intentPath)
	if err != nil {
		t.Fatal("pending intent changed")
	}
	t.Cleanup(func() { _ = intent.Close() })
	p := fixture.proposal
	origin := State{BaseBytes: fixture.intent.SealedBytes, WorkingBytes: fixture.intent.SealedBytes, RemoteRevision: p.ExpectedRevision}
	if err := intent.journal.AckOwnedFirstSuccessor(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrPendingGenesisIntent) {
		t.Fatal("owned acknowledgement accepted pending intent")
	}

	path, j, origin := fixture.openGenesis(t)
	if err := j.PrepareWorkingIfState(origin, p); err != nil || j.Ack(p.OperationID, p.Bytes, ownedTestSuccessorRevision) != nil {
		t.Fatal("advanced legacy fixture failed")
	}
	if err := j.AckOwnedFirstSuccessor(origin, fixture.pin, p, p.Bytes, ownedTestSuccessorRevision); !errors.Is(err, ErrStateMismatch) {
		t.Fatal("advanced legacy state was eligible for backfill")
	}
	state, err := j.LoadState()
	if err != nil || state.Generation != p.Generation || state.RemoteRevision != ownedTestSuccessorRevision ||
		!bytes.Equal(state.BaseBytes, p.Bytes) || !bytes.Equal(state.WorkingBytes, p.Bytes) {
		t.Fatal("advanced legacy state changed")
	}
	if err := j.Close(); err != nil {
		t.Fatal("legacy journal close failed")
	}
	if _, err := ReadOwnedFirstSuccessor(path, fixture.pin); !errors.Is(err, ErrCorrupt) {
		t.Fatal("typed reader accepted advanced legacy state")
	}
}

func TestOwnedFirstSuccessorReaderRejectsUnverifiedTransition(t *testing.T) {
	fixture := newOwnedSignedFixture(t, true)
	path, j, origin := fixture.openGenesis(t)
	record := OwnedFirstSuccessor{
		GenesisBytes: origin.BaseBytes, GenesisRevision: origin.RemoteRevision,
		SuccessorBytes: fixture.proposal.Bytes, SuccessorRevision: ownedTestSuccessorRevision,
	}
	if err := j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte(stateKey), encodeOwnedFirstSuccessor(record))
	}); err != nil || j.Close() != nil {
		t.Fatal("invalid authenticated endpoint fixture failed")
	}
	got, err := ReadOwnedFirstSuccessor(path, fixture.pin)
	if !errors.Is(err, ErrCorrupt) || got.GenesisBytes != nil || got.SuccessorBytes != nil {
		t.Fatal("readback accepted signed successor with wrong parent")
	}
}

func TestOwnedFirstSuccessorDecoderRejectsMalformed(t *testing.T) {
	fixture := newOwnedSignedFixture(t, false)
	record := OwnedFirstSuccessor{
		GenesisBytes: fixture.intent.SealedBytes, GenesisRevision: fixture.proposal.ExpectedRevision,
		SuccessorBytes: fixture.proposal.Bytes, SuccessorRevision: ownedTestSuccessorRevision,
	}
	raw := encodeOwnedFirstSuccessor(record)
	for _, malformed := range [][]byte{
		raw[:ownedStateHeader],
		raw[:len(raw)-1],
		append(bytes.Clone(raw), 0),
	} {
		if _, err := decodeOwnedFirstSuccessor(malformed); !errors.Is(err, ErrCorrupt) {
			t.Fatal("malformed length accepted")
		}
	}
	corruptLength := bytes.Clone(raw)
	binary.BigEndian.PutUint32(corruptLength[ownedStateHeader:], ^uint32(0))
	if _, err := decodeOwnedFirstSuccessor(corruptLength); !errors.Is(err, ErrCorrupt) {
		t.Fatal("overflow length accepted")
	}
	raw[len(raw)-1] ^= 1
	if _, err := decodeOwnedFirstSuccessor(raw); !errors.Is(err, ErrCorrupt) {
		t.Fatal("malformed integrity digest accepted")
	}
}
