//go:build darwin || linux

package vaultfilesync

// Issue #122 clean same-base two-device offline acceptance.
//
// This is the missing positive companion to
// TestPipelinePublishThirdWriterOnRustFS and
// TestPipelineResumePreparedUnknownThenLaterWriterOnRustFS, which deliberately
// cover a conflicting racing writer and an unknown publication outcome. Here
// two distinct, separately authorized devices start from the exact same
// authenticated remote B/Brev. Both make an offline edit to a different item
// with no provider write. Device 2 then publishes its edit through the real
// journal, BuildMergeCandidate, AdoptMergeCandidate and ResumePrepared path,
// making that edit the remote R/Rrev. Device 1 sees that exact provider pair,
// merges it with its own local edit through the same production functions, and
// publishes the merged successor. The test then reopens a fresh provider
// adapter and the durable active journal and checks the exact merged bytes,
// changed opaque revision, both edits and the absence of a pending proposal.
//
// The remote snapshot B is supplied by the synthetic fixture (the package's
// static test policy plus a second synthetic writer device) and is committed
// once through the real backend before either device bootstraps. Everything
// after that seed is produced by the production journal/pipeline. No provider
// write occurs during either offline edit.
//
// The test is opt-in and local-only. It uses the same pinned RustFS
// environment, credentials, TLS guard, unique bucket ownership and cleanup as
// TestPipelinePublishThirdWriterOnRustFS; see pipeline_rustfs_posix_test.go.
// It never contacts a cloud or external endpoint and is skipped unless
// RUSTFS_SMOKE_ENABLE=1 plus the documented endpoint, CA and private credential
// file are supplied. It is a focused acceptance of this one merge path, not a
// claim that the store or read layer itself proves multi-device use.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

const (
	twoDeviceOneID = fixtureDeviceID
	twoDeviceTwoID = "device-2"

	twoDeviceOneTitle = "Login edited offline by synthetic device one"
	twoDeviceTwoTitle = "Document edited offline by synthetic device two"
)

// twoDeviceKey is one synthetic device's real age identity and real Ed25519
// content-signing key. The fixture generation below gives device-1 its
// existing material and generates distinct material only for device-2.
type twoDeviceKey struct {
	identity *age.X25519Identity
	signing  ed25519.PrivateKey
}

// twoDeviceMaterial is the single authenticated policy both devices use.
// device-2 is added to the fixture's static current policy before B is sealed,
// so both devices are writers under the same policy rather than under two
// independently fabricated policies.
type twoDeviceMaterial struct {
	policy   *vaultfile.Policy
	document []byte
	pin      *vaultfile.PolicyCheckpoint
	keys     map[string]twoDeviceKey
}

// newTwoDeviceMaterial reuses the package's static fixture policy, device-1
// keys and checkpoint helper. It creates only the minimal second writer
// material: a distinct DeviceID, content-signing key and age identity under
// the same already-present writer principal, alice. The proof signature of the
// current policy is the fixture's existing zero anchor signature; the caller
// checkpoint trusts this synthetic anchor by digest exactly as the rest of the
// package fixture does, so no authorization check is bypassed.
func newTwoDeviceMaterial(t *testing.T) *twoDeviceMaterial {
	t.Helper()
	p, id1, signing1 := fixtureInputs(t)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic device two age identity: %s", rustfsPipelineSafeError(err))
	}
	pub2, signing2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic device two signing key: %s", rustfsPipelineSafeError(err))
	}
	p.Devices = append(p.Devices, vaultfile.Device{
		DeviceID:          twoDeviceTwoID,
		PrincipalID:       "alice",
		Label:             "Synthetic second authorized device",
		ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: pub2},
		AgeEncryptionKey:  id2.Recipient().String(),
	})
	if err := vaultfile.ValidatePolicy(p); err != nil {
		t.Fatalf("synthetic two-device policy is invalid: %s", rustfsPipelineSafeError(err))
	}
	document, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode synthetic two-device policy: %s", rustfsPipelineSafeError(err))
	}
	material := &twoDeviceMaterial{
		policy:   p,
		document: document,
		pin:      fixturePin(t, p),
		keys: map[string]twoDeviceKey{
			twoDeviceOneID: {identity: id1, signing: signing1},
			twoDeviceTwoID: {identity: id2, signing: signing2},
		},
	}
	if twoDeviceOneID == twoDeviceTwoID {
		t.Fatal("synthetic device IDs are not distinct")
	}
	if !contentProposalCanAuthor(p, twoDeviceOneID) || !contentProposalCanAuthor(p, twoDeviceTwoID) {
		t.Fatal("synthetic two-device policy does not authorize both writers")
	}
	if bytes.Equal(material.keys[twoDeviceOneID].signing.Public().(ed25519.PublicKey),
		material.keys[twoDeviceTwoID].signing.Public().(ed25519.PublicKey)) {
		t.Fatal("synthetic devices do not have distinct content-signing keys")
	}
	if id1.Recipient().String() == id2.Recipient().String() {
		t.Fatal("synthetic devices do not have distinct age identities")
	}
	return material
}

// twoDeviceFixture is the one seeded remote B plus the synthetic two-device
// policy and keys. remote is a real backend handle, wrapped only to count the
// fixture's reads.
type twoDeviceFixture struct {
	remote   *trackingBackend
	material *twoDeviceMaterial
	bytes    []byte
}

// newTwoDeviceFixtureAt seals B under the two-device policy with device-1's
// existing signing key and commits it exactly once through backend. Both
// devices independently open the sealed baseline before the test proceeds, so
// the fixture cannot pass by giving only device-1 a readable snapshot.
func newTwoDeviceFixtureAt(t *testing.T, backend vaultfilebackend.Backend, material *twoDeviceMaterial) *twoDeviceFixture {
	t.Helper()
	draft := fixtureDraft(t, material.policy)
	draft.SignedPolicyProofs[0].Document = bytes.Clone(material.document)
	encoded, err := vaultfile.SealAuthenticatedFile(draft, itemDatabase(t), material.pin, makeVUK(t), material.keys[twoDeviceOneID].signing)
	if err != nil {
		t.Fatalf("seal synthetic two-device baseline: %s", rustfsPipelineSafeError(err))
	}
	for deviceID := range material.keys {
		file, db, err := vaultfile.OpenAuthenticatedFile(encoded, material.pin, deviceID, material.keys[deviceID].identity)
		if err != nil {
			t.Fatalf("synthetic two-device baseline does not open for an authorized device: %s", rustfsPipelineSafeError(err))
		}
		metadata, items, err := vault.ReadItemDatabase(db)
		releaseDatabase(db)
		releaseFile(file)
		if err != nil {
			t.Fatalf("synthetic two-device baseline item database is unreadable: %s", rustfsPipelineSafeError(err))
		}
		releasePlaintext(metadata, items)
	}
	remote := &trackingBackend{Backend: backend}
	if err := remote.CreateIfAbsent(context.Background(), remoteName, encoded); err != nil {
		t.Fatalf("seed synthetic two-device remote: %s", rustfsPipelineSafeError(err))
	}
	return &twoDeviceFixture{remote: remote, material: material, bytes: encoded}
}

// twoDeviceOpen authenticates and decrypts one sealed snapshot for deviceID.
// Its failure text is deliberately constant.
func twoDeviceOpen(t *testing.T, encoded []byte, material *twoDeviceMaterial, deviceID string) (*vaultfile.File, []vault.Item) {
	t.Helper()
	file, db, err := vaultfile.OpenAuthenticatedFile(encoded, material.pin, deviceID, material.keys[deviceID].identity)
	if err != nil {
		t.Fatalf("synthetic two-device authenticated open failed: %s", rustfsPipelineSafeError(err))
	}
	defer releaseDatabase(db)
	metadata, items, err := vault.ReadItemDatabase(db)
	if err != nil {
		releaseFile(file)
		t.Fatalf("synthetic two-device item database failed: %s", rustfsPipelineSafeError(err))
	}
	t.Cleanup(func() {
		releaseFile(file)
		releasePlaintext(metadata, items)
	})
	return file, items
}

// twoDeviceItems returns the decrypted items of encoded for deviceID. The
// caller-owned buffers are released at test cleanup.
func twoDeviceItems(t *testing.T, encoded []byte, material *twoDeviceMaterial, deviceID string) []vault.Item {
	t.Helper()
	_, items := twoDeviceOpen(t, encoded, material, deviceID)
	return items
}

// twoDeviceVerifyAuthor parses encoded, verifies its carried policy chain and
// content signature under the single pinned policy, and requires the expected
// synthetic author. It returns the verified file; no bytes are printed.
func twoDeviceVerifyAuthor(t *testing.T, encoded []byte, material *twoDeviceMaterial, wantDeviceID string) *vaultfile.File {
	t.Helper()
	file, err := vaultfile.ParseFile(encoded)
	if err != nil {
		t.Fatalf("sealed object does not parse: %s", rustfsPipelineSafeError(err))
	}
	if err := vaultfile.VerifyPolicyCheckpoint(file, material.pin); err != nil {
		t.Fatalf("sealed object does not verify under the pinned two-device policy: %s", rustfsPipelineSafeError(err))
	}
	if file.Header.AuthorDeviceID != wantDeviceID || file.ContentSignature.SignerID != wantDeviceID {
		t.Fatal("sealed object is not authored and signed by the expected synthetic device")
	}
	return file
}

// twoDeviceReplace returns an edit of one synthetic item by ID. The failure
// text never includes the item's plaintext.
func twoDeviceReplace(t *testing.T, id, title string) func([]vault.Item) []vault.Item {
	t.Helper()
	return func(items []vault.Item) []vault.Item {
		out := append([]vault.Item(nil), items...)
		found := -1
		for i := range out {
			if out[i].ID != id {
				continue
			}
			if found >= 0 {
				t.Fatal("synthetic fixture item role is duplicated")
			}
			found = i
		}
		if found < 0 {
			t.Fatal("synthetic fixture item role is absent")
		}
		if out[found].Title == title {
			t.Fatal("synthetic offline edit did not change the item")
		}
		out[found].Title = title
		return out
	}
}

// twoDeviceEdit applies one offline edit through UpdateWorkingItems and checks
// that it advanced only the local journal generation.
func twoDeviceEdit(t *testing.T, j *vaultfilejournal.Journal, material *twoDeviceMaterial, deviceID string, edit func([]vault.Item) []vault.Item) {
	t.Helper()
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("load device journal before offline edit: %s", rustfsPipelineSafeError(err))
	}
	receipt, err := UpdateWorkingItems(context.Background(), j, before.Generation,
		edit(twoDeviceItems(t, before.WorkingBytes, material, deviceID)), material.pin,
		deviceID, material.keys[deviceID].identity, material.keys[deviceID].signing)
	if err != nil {
		t.Fatalf("offline edit failed: %s", rustfsPipelineSafeError(err))
	}
	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("load device journal after offline edit: %s", rustfsPipelineSafeError(err))
	}
	if receipt.Generation != before.Generation+1 || after.Generation != receipt.Generation ||
		!bytes.Equal(after.BaseBytes, before.BaseBytes) || after.RemoteRevision != before.RemoteRevision {
		t.Fatal("offline edit did not advance only the local journal generation")
	}
}

// twoDeviceRef returns the journal's exact base pair.
func twoDeviceRef(t *testing.T, j *vaultfilejournal.Journal) pipelineRef {
	t.Helper()
	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("load device journal base: %s", rustfsPipelineSafeError(err))
	}
	return pipelineRef{bytes: state.BaseBytes, rev: state.RemoteRevision}
}

// twoDeviceWantNoPending requires that the known-success journal carries no
// prepared or legacy proposal. It never prints record bytes.
func twoDeviceWantNoPending(t *testing.T, j *vaultfilejournal.Journal) {
	t.Helper()
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal unexpectedly holds a prepared proposal: %s", rustfsPipelineSafeError(err))
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal unexpectedly holds a legacy proposal: %s", rustfsPipelineSafeError(err))
	}
}

// twoDevicePullVerifier accepts only bytes that authenticate under the pinned
// policy for deviceID.
func twoDevicePullVerifier(t *testing.T, material *twoDeviceMaterial, deviceID string) vaultfilepublish.PullVerifier {
	t.Helper()
	return func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		file, db, err := vaultfile.OpenAuthenticatedFile(data, material.pin, deviceID, material.keys[deviceID].identity)
		releaseDatabase(db)
		releaseFile(file)
		return err
	}
}

// TestPipelineTwoDeviceOfflineMergeOnRustFS is the real-provider acceptance.
// It follows the same opt-in, local-only RustFS harness as the existing
// pipeline tests and owns only its run's unique bucket and prefix.
func TestPipelineTwoDeviceOfflineMergeOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	const prefix = "two-device-offline-merge-pipeline"

	first := env.newBackendAt(t, bucket, prefix)
	runTwoDeviceOfflineMergeScenario(t, first, func(t *testing.T) vaultfilebackend.Backend {
		return env.newBackendAt(t, bucket, prefix)
	})
}

// runTwoDeviceOfflineMergeScenario seeds one authenticated B, bootstraps two
// separately closed/reopened on-disk journals from the exact same B/Brev, and
// runs device 2's real publish followed by device 1's real merge and publish.
// newHandle must construct a genuinely independent real backend handle over
// the same owned object.
func runTwoDeviceOfflineMergeScenario(t *testing.T, seeded vaultfilebackend.Backend, newHandle func(*testing.T) vaultfilebackend.Backend) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lateAckTimeout)
	defer cancel()

	material := newTwoDeviceMaterial(t)
	f := newTwoDeviceFixtureAt(t, seeded, material)
	second := newHandle(t)

	one := openNewJournal(t)
	onePath := journalPath(t, one)
	two := openNewJournal(t)
	twoPath := journalPath(t, two)

	// Both devices bootstrap independently from the exact same authenticated
	// remote B/Brev. The fixture supplies only this preexisting baseline.
	for deviceID, journal := range map[string]*vaultfilejournal.Journal{
		twoDeviceOneID: one,
		twoDeviceTwoID: two,
	} {
		if _, err := Bootstrap(context.Background(), f.remote, journal, remoteName,
			material.pin, deviceID, material.keys[deviceID].identity); err != nil {
			t.Fatalf("synthetic device bootstrap failed: %s", rustfsPipelineSafeError(err))
		}
	}
	b1 := twoDeviceRef(t, one)
	b2 := twoDeviceRef(t, two)
	if !bytes.Equal(b1.bytes, f.bytes) || b1.rev == "" ||
		!bytes.Equal(b1.bytes, b2.bytes) || b1.rev != b2.rev {
		t.Fatal("the two journals did not start at the exact common authenticated B/Brev")
	}

	baseItems := twoDeviceItems(t, b1.bytes, material, twoDeviceOneID)
	if len(baseItems) == 0 {
		t.Fatal("synthetic two-device fixture item database is empty")
	}
	editOne := twoDeviceReplace(t, "login-1", twoDeviceOneTitle)
	editTwo := twoDeviceReplace(t, "document-1", twoDeviceTwoTitle)
	wantOne := editOne(baseItems)
	wantTwo := editTwo(baseItems)
	wantBoth := editTwo(wantOne)

	// Each device edits a different item offline. These calls only advance the
	// on-disk journal generations; no provider write is performed.
	twoDeviceEdit(t, one, material, twoDeviceOneID, editOne)
	twoDeviceEdit(t, two, material, twoDeviceTwoID, editTwo)

	// The provider is still exactly the seeded B at its original revision.
	unchanged, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read remote after offline edits: %s", rustfsPipelineSafeError(err))
	}
	if unchanged.Revision != b1.rev || !bytes.Equal(unchanged.Bytes, b1.bytes) {
		t.Fatal("an offline edit wrote to the provider or changed its revision")
	}

	// Both journals are independently closed and reopened while still naming
	// the exact common encrypted revision.
	closeNow(t, one)
	one = openJournalAt(t, onePath)
	closeNow(t, two)
	two = openJournalAt(t, twoPath)
	oneState, err := one.LoadState()
	if err != nil {
		t.Fatalf("reopened device one state failed: %s", rustfsPipelineSafeError(err))
	}
	twoState, err := two.LoadState()
	if err != nil {
		t.Fatalf("reopened device two state failed: %s", rustfsPipelineSafeError(err))
	}
	if oneState.Generation != 1 || twoState.Generation != 1 ||
		!bytes.Equal(oneState.BaseBytes, b1.bytes) || oneState.RemoteRevision != b1.rev ||
		!bytes.Equal(twoState.BaseBytes, b1.bytes) || twoState.RemoteRevision != b1.rev {
		t.Fatal("a reopened journal no longer starts at the exact common B/Brev generation 1")
	}
	laterWriterAssertItems(t, "device one offline edit item DB", twoDeviceItems(t, oneState.WorkingBytes, material, twoDeviceOneID), wantOne)
	laterWriterAssertItems(t, "device two offline edit item DB", twoDeviceItems(t, twoState.WorkingBytes, material, twoDeviceTwoID), wantTwo)
	twoDeviceWantNoPending(t, one)
	twoDeviceWantNoPending(t, two)

	// Device 2 publishes its offline edit through the real pipeline. The
	// candidate, adoption, prepared record, CAS, readback and Ack are all
	// production code; only the baseline B came from the fixture.
	candidateTwo, err := BuildMergeCandidate(ctx, second, remoteName, two, material.pin,
		twoDeviceTwoID, material.keys[twoDeviceTwoID].identity, material.keys[twoDeviceTwoID].signing)
	if err != nil {
		t.Fatalf("device two BuildMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	defer candidateTwo.Clear()
	if candidateTwo.Conflicts == nil || len(candidateTwo.Conflicts) != 0 || candidateTwo.MergedBytes == nil ||
		!bytes.Equal(candidateTwo.RemoteBytes, b1.bytes) || candidateTwo.RemoteRevision != b1.rev ||
		candidateTwo.ExpectedGeneration != twoState.Generation {
		t.Fatal("device two candidate is not the conflict-free successor of the exact common B/Brev")
	}
	if err := AdoptMergeCandidate(ctx, two, candidateTwo, material.pin,
		twoDeviceTwoID, material.keys[twoDeviceTwoID].identity); err != nil {
		t.Fatalf("device two AdoptMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	preparedTwo, err := two.LoadPrepared()
	if err != nil {
		t.Fatalf("device two prepared record failed: %s", rustfsPipelineSafeError(err))
	}
	fileTwo := twoDeviceVerifyAuthor(t, candidateTwo.MergedBytes, material, twoDeviceTwoID)
	if preparedTwo.WorkingGeneration != twoState.Generation+1 ||
		preparedTwo.Proposal.Generation != preparedTwo.WorkingGeneration ||
		preparedTwo.Proposal.ExpectedRevision != b1.rev ||
		preparedTwo.Proposal.OperationID != fileTwo.Header.OpID ||
		!bytes.Equal(preparedTwo.Proposal.Bytes, candidateTwo.MergedBytes) {
		t.Fatal("device two prepared record does not name its exact candidate over B/Brev")
	}
	verifier, err := NewContentProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("proposal verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	if err := verifier(ctx, candidateTwo.RemoteBytes, candidateTwo.RemoteRevision, preparedTwo.Proposal); err != nil {
		t.Fatalf("device two candidate is not a verifiable authorized successor: %s", rustfsPipelineSafeError(err))
	}
	coordinatorTwo, err := vaultfilepublish.NewCoordinator(second, two, remoteName, verifier)
	if err != nil {
		t.Fatalf("device two coordinator construction failed: %s", rustfsPipelineSafeError(err))
	}
	pullVerifierTwo := twoDevicePullVerifier(t, material, twoDeviceTwoID)
	pulledB, err := vaultfilepublish.ReadPulled(ctx, second, remoteName, pullVerifierTwo)
	if err != nil {
		t.Fatalf("device two authenticated pull failed: %s", rustfsPipelineSafeError(err))
	}
	if pulledB.Revision() != b1.rev || !bytes.Equal(pulledB.Bytes(), b1.bytes) {
		t.Fatal("device two did not pull the exact common B/Brev")
	}
	if err := coordinatorTwo.ResumePrepared(ctx, pulledB, pullVerifierTwo); err != nil {
		t.Fatalf("device two ResumePrepared failed: %s", rustfsPipelineSafeError(err))
	}
	remoteR, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read device two published remote failed: %s", rustfsPipelineSafeError(err))
	}
	if remoteR.Revision == b1.rev || !bytes.Equal(remoteR.Bytes, candidateTwo.MergedBytes) {
		t.Fatal("device two publish did not commit its exact sealed candidate at a changed revision")
	}
	rBytes := bytes.Clone(remoteR.Bytes)
	rRevision := remoteR.Revision
	twoDeviceVerifyAuthor(t, rBytes, material, twoDeviceTwoID)
	laterWriterAssertItems(t, "published device two item DB", twoDeviceItems(t, rBytes, material, twoDeviceTwoID), wantTwo)
	twoDeviceWantNoPending(t, two)
	ackTwo, err := two.LoadState()
	if err != nil {
		t.Fatalf("device two acknowledged state failed: %s", rustfsPipelineSafeError(err))
	}
	if ackTwo.Generation != preparedTwo.WorkingGeneration || ackTwo.RemoteRevision != rRevision ||
		!bytes.Equal(ackTwo.BaseBytes, rBytes) || !bytes.Equal(ackTwo.WorkingBytes, rBytes) {
		t.Fatal("device two journal did not acknowledge the exact published R/Rrev")
	}
	closeNow(t, two)
	two = openJournalAt(t, twoPath)
	reopenedTwo, err := two.LoadState()
	if err != nil {
		t.Fatalf("reopened device two acknowledged state failed: %s", rustfsPipelineSafeError(err))
	}
	if !bytes.Equal(reopenedTwo.BaseBytes, rBytes) || reopenedTwo.RemoteRevision != rRevision ||
		!bytes.Equal(reopenedTwo.WorkingBytes, rBytes) {
		t.Fatal("reopened device two journal did not retain the exact published R/Rrev")
	}
	twoDeviceWantNoPending(t, two)

	// Device 1 independently sees that exact R/Rrev through its own real
	// handle and merges its offline edit with it using the production merge.
	mergeHandle := newHandle(t)
	candidateOne, err := BuildMergeCandidate(ctx, mergeHandle, remoteName, one, material.pin,
		twoDeviceOneID, material.keys[twoDeviceOneID].identity, material.keys[twoDeviceOneID].signing)
	if err != nil {
		t.Fatalf("device one BuildMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	defer candidateOne.Clear()
	if candidateOne.Conflicts == nil || len(candidateOne.Conflicts) != 0 || candidateOne.MergedBytes == nil ||
		!bytes.Equal(candidateOne.RemoteBytes, rBytes) || candidateOne.RemoteRevision != rRevision ||
		candidateOne.ExpectedGeneration != oneState.Generation {
		t.Fatal("device one candidate is not the conflict-free merge of the exact R/Rrev")
	}
	twoDeviceVerifyAuthor(t, candidateOne.MergedBytes, material, twoDeviceOneID)
	laterWriterAssertItems(t, "device one merged candidate item DB", twoDeviceItems(t, candidateOne.MergedBytes, material, twoDeviceOneID), wantBoth)
	laterWriterAssertItems(t, "device two view of merged candidate item DB", twoDeviceItems(t, candidateOne.MergedBytes, material, twoDeviceTwoID), wantBoth)

	if err := AdoptMergeCandidate(ctx, one, candidateOne, material.pin,
		twoDeviceOneID, material.keys[twoDeviceOneID].identity); err != nil {
		t.Fatalf("device one AdoptMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	preparedOne, err := one.LoadPrepared()
	if err != nil {
		t.Fatalf("device one prepared record failed: %s", rustfsPipelineSafeError(err))
	}
	fileOne := twoDeviceVerifyAuthor(t, candidateOne.MergedBytes, material, twoDeviceOneID)
	if preparedOne.WorkingGeneration != oneState.Generation+1 ||
		preparedOne.Proposal.Generation != preparedOne.WorkingGeneration ||
		preparedOne.Proposal.ExpectedRevision != rRevision ||
		preparedOne.Proposal.OperationID != fileOne.Header.OpID ||
		!bytes.Equal(preparedOne.Proposal.Bytes, candidateOne.MergedBytes) {
		t.Fatal("device one prepared record does not name its exact merged candidate over R/Rrev")
	}
	if err := verifier(ctx, candidateOne.RemoteBytes, candidateOne.RemoteRevision, preparedOne.Proposal); err != nil {
		t.Fatalf("device one candidate is not a verifiable authorized successor: %s", rustfsPipelineSafeError(err))
	}

	// Device 1 publishes the adopted candidate with the existing prepared
	// contract: one authenticated pull of R, then the real coordinator CAS.
	coordinatorOne, err := vaultfilepublish.NewCoordinator(mergeHandle, one, remoteName, verifier)
	if err != nil {
		t.Fatalf("device one coordinator construction failed: %s", rustfsPipelineSafeError(err))
	}
	pullVerifierOne := twoDevicePullVerifier(t, material, twoDeviceOneID)
	pulledR, err := vaultfilepublish.ReadPulled(ctx, mergeHandle, remoteName, pullVerifierOne)
	if err != nil {
		t.Fatalf("device one authenticated pull failed: %s", rustfsPipelineSafeError(err))
	}
	if pulledR.Revision() != rRevision || !bytes.Equal(pulledR.Bytes(), rBytes) {
		t.Fatal("device one did not pull the exact published R/Rrev")
	}
	if err := coordinatorOne.ResumePrepared(ctx, pulledR, pullVerifierOne); err != nil {
		t.Fatalf("device one ResumePrepared failed: %s", rustfsPipelineSafeError(err))
	}

	// A fresh real adapter independently reads the merged successor, and the
	// durable active journal is independently reopened.
	fresh := newHandle(t)
	published, err := fresh.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("fresh adapter read after merged publish failed: %s", rustfsPipelineSafeError(err))
	}
	if published.Revision == b1.rev || published.Revision == rRevision ||
		!bytes.Equal(published.Bytes, candidateOne.MergedBytes) {
		t.Fatal("merged publish is not the exact candidate at a changed opaque revision")
	}
	twoDeviceVerifyAuthor(t, published.Bytes, material, twoDeviceOneID)
	closeNow(t, one)
	one = openJournalAt(t, onePath)
	active, err := one.LoadState()
	if err != nil {
		t.Fatalf("active device journal state failed: %s", rustfsPipelineSafeError(err))
	}
	if active.Generation != preparedOne.WorkingGeneration ||
		active.RemoteRevision != published.Revision ||
		!bytes.Equal(active.BaseBytes, published.Bytes) ||
		!bytes.Equal(active.WorkingBytes, published.Bytes) {
		t.Fatal("active journal does not hold the exact merged provider bytes and revision")
	}
	twoDeviceWantNoPending(t, one)

	// The exact merged bytes match between provider and both the base and
	// working records of the durable active journal. Both edits authenticate
	// and decrypt under both distinct device identities.
	if !bytes.Equal(active.BaseBytes, published.Bytes) || !bytes.Equal(active.WorkingBytes, published.Bytes) {
		t.Fatal("merged provider and journal bytes differ")
	}
	laterWriterAssertItems(t, "final provider item DB via device one", twoDeviceItems(t, published.Bytes, material, twoDeviceOneID), wantBoth)
	laterWriterAssertItems(t, "final provider item DB via device two", twoDeviceItems(t, published.Bytes, material, twoDeviceTwoID), wantBoth)
	laterWriterAssertItems(t, "final journal item DB via device one", twoDeviceItems(t, active.WorkingBytes, material, twoDeviceOneID), wantBoth)
	laterWriterAssertItems(t, "final journal item DB via device two", twoDeviceItems(t, active.WorkingBytes, material, twoDeviceTwoID), wantBoth)

	// The old R basis is genuinely stale. A real provider CAS from it must
	// conflict and leave the final merged bytes and revision unchanged.
	if err := fresh.ReplaceIfVersion(ctx, remoteName, candidateOne.RemoteRevision, candidateOne.RemoteBytes); !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("stale-basis CAS did not conflict: %s", rustfsPipelineSafeError(err))
	}
	afterStale, err := fresh.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read after stale-basis CAS failed: %s", rustfsPipelineSafeError(err))
	}
	if afterStale.Revision != published.Revision || !bytes.Equal(afterStale.Bytes, published.Bytes) {
		t.Fatal("a stale-basis conflict changed the final provider bytes or revision")
	}
	twoDeviceWantNoPending(t, one)
}
