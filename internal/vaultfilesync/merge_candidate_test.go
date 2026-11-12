package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// These tests use the real fixture path: a private temporary directory backend,
// real signed age/KDBX files sealed through vaultfile.SealAuthenticatedFile, and
// a real bbolt journal. No fake journal or plaintext-only backend substitutes
// for the authenticated file boundary.

func mergeCandidateMetadata() []byte {
	return []byte(`{"fixture":"merge-candidate-metadata","v":1}`)
}

func mergeCandidatePrevious(seq uint64) []byte {
	if seq == 0 {
		return nil
	}
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(seq)
	}
	return out
}

// mergeCandidateLogin returns a valid login whose non-title fields are derived
// only from id, so two versions of the same ID differ by title alone.
func mergeCandidateLogin(id, title string) vault.Item {
	return vault.Item{
		ID:        id,
		Kind:      "login",
		Title:     title,
		Username:  "user-" + id,
		Password:  "pass-" + id,
		URL:       "https://example.com/" + id,
		Notes:     "notes-" + id,
		CreatedAt: 1,
		UpdatedAt: 2,
	}
}

// mergeCandidateDocument returns a valid document item with an owned attachment
// body, used to prove conflict-side buffers are deep copies.
func mergeCandidateDocument(id, title, body string) vault.Item {
	return vault.Item{
		ID:                  id,
		Kind:                "document",
		Title:               title,
		Filename:            id + ".bin",
		Attachment:          []byte(body),
		AttachmentProtected: true,
	}
}

// mergeCandidateSeal builds one real signed file under the caller's policy pin.
// The caller supplies the test VUK explicitly so B, L and R in one epoch can
// share the protocol's single per-vault, per-epoch key.
func mergeCandidateSeal(t *testing.T, pin *vaultfile.PolicyCheckpoint, policy *vaultfile.Policy, epoch, seq uint64, opID string, prev, vuk []byte, items []vault.Item) []byte {
	t.Helper()
	doc, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatalf("EncodePolicyDocument: %v", err)
	}
	draft := &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        policy.VaultID,
			KeyEpoch:       epoch,
			ContentSeq:     seq,
			PrevDigest:     prev,
			OpID:           opID,
			PolicySeq:      policy.PolicySeq,
			PolicyDigest:   vaultfile.PolicyDigest(policy),
			AuthorDeviceID: fixtureDeviceID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{{
			Document: doc,
			Policy:   *policy,
			SignerID: policy.OwnerRoot.KeyID,
			Alg:      vaultfile.PolicySigAlgEd25519,
			Sig:      make([]byte, ed25519.SignatureSize),
		}},
	}
	db, err := vault.NewItemDatabase(mergeCandidateMetadata(), items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	defer releaseDatabase(db)
	_, _, signingKey := fixtureInputs(t)
	encoded, err := vaultfile.SealAuthenticatedFile(draft, db, pin, vuk, signingKey)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	return encoded
}

// mergeCandidateTestVUK returns one real test VUK shared by the files of one
// vault/key epoch and registers clearing it at test cleanup.
func mergeCandidateTestVUK(t *testing.T) []byte {
	t.Helper()
	vuk := makeVUK(t)
	t.Cleanup(func() { clear(vuk) })
	return vuk
}

// mergeCandidateAlternatePolicy returns a structurally valid policy with the
// same sequence and device keys but a different canonical document and digest,
// so a sealed file under the alternate pin is a realistic authenticated policy
// change rather than malformed JSON.
func mergeCandidateAlternatePolicy(t *testing.T, p *vaultfile.Policy) *vaultfile.Policy {
	t.Helper()
	doc, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("EncodePolicyDocument: %v", err)
	}
	other, err := vaultfile.ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	if len(other.Writers) == 0 {
		t.Fatal("fixture policy has no writer to alter")
	}
	other.Writers = append([]vaultfile.Member(nil), other.Writers...)
	other.Writers[0].Label = other.Writers[0].Label + " changed by test"
	return other
}

// mergeCandidateUseRemote replaces the fixture's remote file with remote and
// returns the exact read pair the next BuildMergeCandidate will observe through
// the recording adapter.
func mergeCandidateUseRemote(t *testing.T, f *fixture, remote []byte) vaultfilebackend.ReadResult {
	t.Helper()
	cur, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("read current fixture revision: %v", err)
	}
	if err := f.remote.ReplaceIfVersion(context.Background(), remoteName, cur.Revision, remote); err != nil {
		t.Fatalf("ReplaceIfVersion: %v", err)
	}
	f.bytes = remote
	// Re-read only for the opaque revision, but return the exact bytes that
	// were replaced so callers can bind fixture state to the served content.
	res, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("read replaced remote: %v", err)
	}
	return vaultfilebackend.ReadResult{Bytes: bytes.Clone(remote), Revision: res.Revision}
}

// mergeCandidateJournalWithState initializes a real journal with base/local and
// advances it to the requested generation. The initial remote revision is a
// fixed opaque value; the remote backend revision is unrelated metadata.
func mergeCandidateJournalWithState(t *testing.T, f *fixture, base, local []byte, generation uint64) (*vaultfilejournal.Journal, vaultfilejournal.State) {
	t.Helper()
	j := f.openJournal(t)
	if err := j.InitializeState(vaultfilejournal.State{
		BaseBytes:      base,
		RemoteRevision: vaultfilebackend.Revision("base-revision-v1"),
		WorkingBytes:   local,
	}); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	for state.Generation < generation {
		if err := j.UpdateWorking(state.Generation, local); err != nil {
			t.Fatalf("UpdateWorking: %v", err)
		}
		state, err = j.LoadState()
		if err != nil {
			t.Fatalf("LoadState after UpdateWorking: %v", err)
		}
	}
	if state.Generation != generation {
		t.Fatalf("journal generation = %d, want %d", state.Generation, generation)
	}
	return j, state
}

// mergeCandidateSavePending writes one legacy proposal and one prepared
// proposal so every test can prove neither pending record is consumed.
func mergeCandidateSavePending(t *testing.T, j *vaultfilejournal.Journal, state vaultfilejournal.State) {
	t.Helper()
	legacy := vaultfilejournal.Proposal{
		Generation:       state.Generation + 5,
		OperationID:      "op-legacy-pending",
		ExpectedRevision: state.RemoteRevision,
		Bytes:            []byte("synthetic legacy sealed proposal"),
	}
	if err := j.Save(legacy); err != nil {
		t.Fatalf("Save legacy proposal: %v", err)
	}
	prepared := vaultfilejournal.Proposal{
		Generation:       state.Generation + 2,
		OperationID:      "op-prepared-pending",
		ExpectedRevision: state.RemoteRevision,
		Bytes:            bytes.Clone(state.WorkingBytes),
	}
	if err := j.Prepare(state.Generation, prepared); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
}

type mergeCandidateJournalSnapshot struct {
	state      vaultfilejournal.State
	stateOK    bool
	legacy     vaultfilejournal.Proposal
	legacyOK   bool
	prepared   vaultfilejournal.PreparedProposal
	preparedOK bool
}

func mergeCandidateSnapshotJournal(t *testing.T, j *vaultfilejournal.Journal) mergeCandidateJournalSnapshot {
	t.Helper()
	var s mergeCandidateJournalSnapshot
	state, err := j.LoadState()
	switch {
	case err == nil:
		s.state, s.stateOK = state, true
	case errors.Is(err, vaultfilejournal.ErrEmpty):
	default:
		t.Fatalf("LoadState snapshot: %v", err)
	}
	legacy, err := j.Load()
	switch {
	case err == nil:
		s.legacy, s.legacyOK = legacy, true
	case errors.Is(err, vaultfilejournal.ErrEmpty):
	default:
		t.Fatalf("Load snapshot: %v", err)
	}
	prepared, err := j.LoadPrepared()
	switch {
	case err == nil:
		s.prepared, s.preparedOK = prepared, true
	case errors.Is(err, vaultfilejournal.ErrEmpty):
	default:
		t.Fatalf("LoadPrepared snapshot: %v", err)
	}
	return s
}

func mergeCandidateAssertJournalUnchanged(t *testing.T, j *vaultfilejournal.Journal, want mergeCandidateJournalSnapshot) {
	t.Helper()
	got := mergeCandidateSnapshotJournal(t, j)
	if got.stateOK != want.stateOK || (want.stateOK && !reflect.DeepEqual(got.state, want.state)) {
		t.Fatalf("journal state changed: got %+v want %+v", got.state, want.state)
	}
	if got.legacyOK != want.legacyOK || (want.legacyOK && !reflect.DeepEqual(got.legacy, want.legacy)) {
		t.Fatalf("legacy proposal changed: got %+v want %+v", got.legacy, want.legacy)
	}
	if got.preparedOK != want.preparedOK || (want.preparedOK && !reflect.DeepEqual(got.prepared, want.prepared)) {
		t.Fatalf("prepared proposal changed: got %+v want %+v", got.prepared, want.prepared)
	}
}

func mergeCandidateReadBackend(t *testing.T, f *fixture) vaultfilebackend.ReadResult {
	t.Helper()
	res, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("backend Read: %v", err)
	}
	return vaultfilebackend.ReadResult{Bytes: bytes.Clone(res.Bytes), Revision: res.Revision}
}

func mergeCandidateAssertBackendUnchanged(t *testing.T, f *fixture, want vaultfilebackend.ReadResult) {
	t.Helper()
	got := mergeCandidateReadBackend(t, f)
	if got.Revision != want.Revision || !bytes.Equal(got.Bytes, want.Bytes) {
		t.Fatal("backend bytes or revision changed")
	}
}

func mergeCandidateAssertZero(t *testing.T, c MergeCandidate) {
	t.Helper()
	if c.RemoteBytes != nil || c.MergedBytes != nil || c.RemoteRevision != "" ||
		c.ExpectedGeneration != 0 || c.Conflicts != nil ||
		c.sourceBinding != ([32]byte{}) || c.resultBinding != ([32]byte{}) {
		t.Fatalf("error path returned a non-zero candidate: %+v", c)
	}
}

func mergeCandidateAssertNoPlaintext(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, marker := range plaintextMarkers {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error leaked plaintext %q", marker)
		}
	}
}

// TestBuildMergeCandidateMergesIndependentEdits covers the clean path: local
// and remote edits to different IDs merge, M is sealed from R, and every journal
// field and pending record is unchanged.
func TestBuildMergeCandidateMergesIndependentEdits(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)

	baseItems := []vault.Item{
		mergeCandidateLogin("item-a", "A base"),
		mergeCandidateLogin("item-b", "B base"),
	}
	localItems := []vault.Item{
		mergeCandidateLogin("item-a", "A local"),
		mergeCandidateLogin("item-b", "B base"),
		mergeCandidateLogin("item-local", "Local only"),
	}
	remoteItems := []vault.Item{
		mergeCandidateLogin("item-b", "B remote"),
		mergeCandidateLogin("item-a", "A base"),
		mergeCandidateLogin("item-remote", "Remote only"),
	}

	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
	local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
	remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
	backendBefore := mergeCandidateUseRemote(t, f, remote)

	j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
	mergeCandidateSavePending(t, j, state)
	journalBefore := mergeCandidateSnapshotJournal(t, j)
	readsBefore := f.remote.readCount()

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if reads := f.remote.readCount(); reads != readsBefore+1 {
		t.Fatalf("backend reads = %d, want exactly one more than %d", reads, readsBefore)
	}
	if candidate.MergedBytes == nil {
		t.Fatal("clean merge returned no sealed candidate")
	}
	if candidate.Conflicts == nil || len(candidate.Conflicts) != 0 {
		t.Fatalf("clean merge conflicts = %#v, want non-nil empty", candidate.Conflicts)
	}
	if candidate.RemoteBytes == nil || !bytes.Equal(candidate.RemoteBytes, backendBefore.Bytes) {
		t.Fatal("candidate remote bytes are not the exact read bytes")
	}
	if candidate.RemoteRevision != backendBefore.Revision {
		t.Fatalf("candidate revision = %q, want %q", candidate.RemoteRevision, backendBefore.Revision)
	}
	if candidate.ExpectedGeneration != state.Generation {
		t.Fatalf("candidate generation = %d, want %d", candidate.ExpectedGeneration, state.Generation)
	}
	if candidate.sourceBinding != mergeCandidateSourceBinding(state) {
		t.Fatal("source binding does not match the exact observed journal state")
	}
	if candidate.resultBinding != mergeCandidateResultBinding(candidate.sourceBinding, candidate.RemoteBytes, candidate.MergedBytes, candidate.RemoteRevision, candidate.ExpectedGeneration) {
		t.Fatal("result binding does not match the returned outputs")
	}

	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)

	remoteFile, remoteMetadata, _ := openWorkingState(t, remote, f.pin, f.id)
	mergedFile, mergedMetadata, mergedItems := openWorkingState(t, candidate.MergedBytes, f.pin, f.id)
	wantItems := []vault.Item{
		mergeCandidateLogin("item-a", "A local"),
		mergeCandidateLogin("item-b", "B remote"),
		mergeCandidateLogin("item-local", "Local only"),
		mergeCandidateLogin("item-remote", "Remote only"),
	}
	if !reflect.DeepEqual(mergedItems, wantItems) {
		t.Fatalf("merged items:\n got %+v\nwant %+v", mergedItems, wantItems)
	}
	if !bytes.Equal(mergedMetadata, remoteMetadata) {
		t.Fatal("candidate metadata is not R's metadata")
	}
	if mergedFile.Header.ContentSeq != remoteFile.Header.ContentSeq+1 {
		t.Fatalf("candidate sequence = %d, want %d", mergedFile.Header.ContentSeq, remoteFile.Header.ContentSeq+1)
	}
	remoteDigest, err := vaultfile.FileDigest(remoteFile)
	if err != nil {
		t.Fatalf("FileDigest(R): %v", err)
	}
	rawRemoteDigest, err := hex.DecodeString(remoteDigest)
	if err != nil || len(rawRemoteDigest) != 32 {
		t.Fatalf("decoded R digest is invalid: %v", err)
	}
	if !bytes.Equal(mergedFile.Header.PrevDigest, rawRemoteDigest) {
		t.Fatal("candidate previous digest is not the raw FileDigest(R)")
	}
	if mergedFile.Header.OpID == remoteFile.Header.OpID || !strings.HasPrefix(mergedFile.Header.OpID, "op-") {
		t.Fatalf("candidate operation ID %q is not fresh", mergedFile.Header.OpID)
	}
	if mergedFile.Header.AuthorDeviceID != fixtureDeviceID {
		t.Fatalf("candidate author = %q, want %q", mergedFile.Header.AuthorDeviceID, fixtureDeviceID)
	}
	if !sameSignedProofs(remoteFile.SignedPolicyProofs, mergedFile.SignedPolicyProofs) {
		t.Fatal("candidate did not preserve R's signed policy proofs")
	}
	remoteVUK := workingVUKForTest(t, remoteFile, f.id)
	mergedVUK := workingVUKForTest(t, mergedFile, f.id)
	if !bytes.Equal(remoteVUK, mergedVUK) {
		t.Fatal("candidate did not reuse R's epoch VUK")
	}

	// Output ownership: mutating an output must not reach the backend or the
	// journal copies.
	candidate.RemoteBytes[0] ^= 0xff
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)

	remoteBuf := candidate.RemoteBytes
	mergedBuf := candidate.MergedBytes
	candidate.Clear()
	if !allMergeCandidateZero(remoteBuf) || !allMergeCandidateZero(mergedBuf) {
		t.Fatal("Clear did not zero the owned sealed buffers")
	}
	mergeCandidateAssertZero(t, candidate)
}

// TestBuildMergeCandidateConflicts covers a real conflict result, including nil
// sides, deep ownership of conflict buffers, no M, and unchanged journal/backend.
func TestBuildMergeCandidateConflicts(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)

	baseItems := []vault.Item{
		mergeCandidateLogin("item-conflict", "Conflict base"),
		mergeCandidateDocument("item-delete", "Delete base", "base body"),
		mergeCandidateLogin("item-clean", "Clean base"),
	}
	localItems := []vault.Item{
		mergeCandidateLogin("item-conflict", "Conflict local"),
		mergeCandidateLogin("item-add", "Add local"),
		mergeCandidateLogin("item-clean", "Clean local"),
	}
	remoteItems := []vault.Item{
		mergeCandidateLogin("item-conflict", "Conflict remote"),
		mergeCandidateDocument("item-delete", "Delete remote", "remote body"),
		mergeCandidateLogin("item-add", "Add remote"),
		mergeCandidateLogin("item-clean", "Clean base"),
	}

	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
	local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
	remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
	backendBefore := mergeCandidateUseRemote(t, f, remote)

	j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
	mergeCandidateSavePending(t, j, state)
	journalBefore := mergeCandidateSnapshotJournal(t, j)

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if candidate.MergedBytes != nil {
		t.Fatal("conflict result produced an M")
	}
	if candidate.Conflicts == nil || len(candidate.Conflicts) != 3 {
		t.Fatalf("conflicts = %#v, want 3", candidate.Conflicts)
	}
	if candidate.RemoteRevision != backendBefore.Revision || !bytes.Equal(candidate.RemoteBytes, backendBefore.Bytes) {
		t.Fatal("conflict result did not preserve the exact read pair")
	}
	if candidate.resultBinding != mergeCandidateResultBinding(candidate.sourceBinding, candidate.RemoteBytes, nil, candidate.RemoteRevision, candidate.ExpectedGeneration) {
		t.Fatal("conflict result binding does not match the returned outputs")
	}
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)

	byID := map[string]vaultmergeConflict{}
	for i := range candidate.Conflicts {
		c := candidate.Conflicts[i]
		byID[c.ID] = vaultmergeConflict{Base: c.Base, Local: c.Local, Remote: c.Remote}
	}
	if len(byID) != 3 {
		t.Fatalf("conflict IDs are not unique: %#v", candidate.Conflicts)
	}
	// Sorted by exact ID.
	wantOrder := []string{"item-add", "item-conflict", "item-delete"}
	for i, id := range wantOrder {
		if candidate.Conflicts[i].ID != id {
			t.Fatalf("conflict %d ID = %q, want %q", i, candidate.Conflicts[i].ID, id)
		}
	}

	add := byID["item-add"]
	if add.Base != nil {
		t.Fatal("add conflict has a base side")
	}
	if add.Local == nil || add.Local.Title != "Add local" || add.Remote == nil || add.Remote.Title != "Add remote" {
		t.Fatalf("add conflict sides = %+v", add)
	}
	conflict := byID["item-conflict"]
	if conflict.Base == nil || conflict.Base.Title != "Conflict base" ||
		conflict.Local == nil || conflict.Local.Title != "Conflict local" ||
		conflict.Remote == nil || conflict.Remote.Title != "Conflict remote" {
		t.Fatalf("both-edit conflict sides = %+v", conflict)
	}
	deleted := byID["item-delete"]
	if deleted.Base == nil || deleted.Base.Title != "Delete base" {
		t.Fatalf("delete conflict base = %+v", deleted.Base)
	}
	if deleted.Local != nil {
		t.Fatal("delete conflict has a local side")
	}
	if deleted.Remote == nil || deleted.Remote.Title != "Delete remote" ||
		!bytes.Equal(deleted.Remote.Attachment, []byte("remote body")) {
		t.Fatalf("delete conflict remote = %+v", deleted.Remote)
	}

	// Conflict sides are deep copies: mutating one must not reach independently
	// opened source items.
	_, _, remoteOpenedItems := openWorkingState(t, remote, f.pin, f.id)
	var openedDelete *vault.Item
	for i := range remoteOpenedItems {
		if remoteOpenedItems[i].ID == "item-delete" {
			openedDelete = &remoteOpenedItems[i]
			break
		}
	}
	if openedDelete == nil {
		t.Fatal("independently opened remote has no item-delete")
	}
	wantAttachment := bytes.Clone(openedDelete.Attachment)
	candidateConflict := byID["item-delete"].Remote
	if candidateConflict == nil || len(candidateConflict.Attachment) == 0 {
		t.Fatal("conflict remote side has no attachment buffer")
	}
	conflictBuf := candidateConflict.Attachment
	conflictBuf[0] ^= 0xff
	if !bytes.Equal(openedDelete.Attachment, wantAttachment) {
		t.Fatal("mutating a conflict side reached the independently opened remote item")
	}

	remoteBuf := candidate.RemoteBytes
	candidate.Clear()
	if len(conflictBuf) > 0 && !allMergeCandidateZero(conflictBuf) {
		t.Fatal("Clear did not zero a conflict-side attachment buffer")
	}
	if !allMergeCandidateZero(remoteBuf) {
		t.Fatal("Clear did not zero the remote sealed buffer")
	}
	mergeCandidateAssertZero(t, candidate)
}

type vaultmergeConflict struct {
	Base   *vault.Item
	Local  *vault.Item
	Remote *vault.Item
}

// TestBuildMergeCandidateMissingBase proves a missing local base is rejected
// before the backend is read and without mutation.
func TestBuildMergeCandidateMissingBase(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if err := j.InitializeState(vaultfilejournal.State{
		WorkingBytes: bytes.Clone(f.bytes),
	}); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
	journalBefore := mergeCandidateSnapshotJournal(t, j)
	backendBefore := mergeCandidateReadBackend(t, f)
	readsBefore := f.remote.readCount()

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if !errors.Is(err, ErrMergeCandidateRejected) {
		t.Fatalf("missing base = %v, want ErrMergeCandidateRejected", err)
	}
	mergeCandidateAssertZero(t, candidate)
	mergeCandidateAssertNoPlaintext(t, err)
	if f.remote.readCount() != readsBefore {
		t.Fatal("missing base read the backend")
	}
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
}

// TestBuildMergeCandidateRejectsAuthenticationChanges covers a real cross-epoch
// file set and an authenticated policy change rejected by the caller's pin.
func TestBuildMergeCandidateRejectsAuthenticationChanges(t *testing.T) {
	baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
	localItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}
	remoteItems := []vault.Item{mergeCandidateLogin("item-a", "A remote")}

	t.Run("cross epoch", func(t *testing.T) {
		f := newFixture(t)
		policy, _, _ := fixtureInputs(t)
		vuk := mergeCandidateTestVUK(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
		vuk2 := mergeCandidateTestVUK(t)
		remote := mergeCandidateSeal(t, f.pin, policy, 2, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk2, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("cross-epoch merge = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertNoPlaintext(t, err)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	t.Run("caller pin policy change", func(t *testing.T) {
		f := newFixture(t)
		policy, _, _ := fixtureInputs(t)
		vuk := mergeCandidateTestVUK(t)
		alternate := mergeCandidateAlternatePolicy(t, policy)
		alternatePin := fixturePin(t, alternate)
		base := mergeCandidateSeal(t, alternatePin, alternate, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
		local := mergeCandidateSeal(t, alternatePin, alternate, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
		remote := mergeCandidateSeal(t, alternatePin, alternate, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		// f.pin is the original policy digest; the files are authentic under the
		// alternate digest, so this is a real caller-pin/policy change.
		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("policy-change merge = %v, want ErrMergeCandidateVerify", err)
		}
		if code := vaultfileCode(err); code != vaultfile.CodePolicyCheckpointFailed {
			t.Fatalf("policy-change merge failed with %q, want %q", code, vaultfile.CodePolicyCheckpointFailed)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertNoPlaintext(t, err)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})
}

// TestBuildMergeCandidateSequenceRules covers rollback, equal-sequence forks, an
// accepted exact equal-sequence base and the MaxUint64 guard.
func TestBuildMergeCandidateSequenceRules(t *testing.T) {
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)
	baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
	localItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}
	remoteItems := []vault.Item{mergeCandidateLogin("item-a", "A remote")}

	t.Run("rollback rejected", func(t *testing.T) {
		f := newFixture(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-base-0005", mergeCandidatePrevious(5), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 6, "op-local-0006", mergeCandidatePrevious(6), vuk, localItems)
		remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("rollback merge = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	t.Run("equal sequence fork rejected", func(t *testing.T) {
		f := newFixture(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-base-0005", mergeCandidatePrevious(5), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 6, "op-local-0006", mergeCandidatePrevious(6), vuk, localItems)
		remote := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-remote-0005", mergeCandidatePrevious(5), vuk, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("equal-sequence fork = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	t.Run("exact equal sequence accepted", func(t *testing.T) {
		f := newFixture(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-base-0005", mergeCandidatePrevious(5), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 7, "op-local-0007", mergeCandidatePrevious(7), vuk, localItems)
		backendBefore := mergeCandidateUseRemote(t, f, base)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if err != nil {
			t.Fatalf("exact equal-sequence merge: %v", err)
		}
		if candidate.MergedBytes == nil || candidate.Conflicts == nil || len(candidate.Conflicts) != 0 {
			t.Fatal("exact equal-sequence merge did not produce a clean candidate")
		}
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)

		mergedFile, _, mergedItems := openWorkingState(t, candidate.MergedBytes, f.pin, f.id)
		if mergedFile.Header.ContentSeq != 6 {
			t.Fatalf("candidate sequence = %d, want 6", mergedFile.Header.ContentSeq)
		}
		want := []vault.Item{mergeCandidateLogin("item-a", "A local")}
		if !reflect.DeepEqual(mergedItems, want) {
			t.Fatalf("equal-sequence merge items:\n got %+v\nwant %+v", mergedItems, want)
		}
	})

	t.Run("local rollback rejected", func(t *testing.T) {
		f := newFixture(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-base-0005", mergeCandidatePrevious(5), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-local-0004", mergeCandidatePrevious(4), vuk, localItems)
		backendBefore := mergeCandidateUseRemote(t, f, base)
		// The fixtures themselves are authentic under the caller pin; the
		// rejection below must come from the sequence guard, not a bad signature.
		openWorkingState(t, base, f.pin, f.id)
		openWorkingState(t, local, f.pin, f.id)
		openWorkingState(t, backendBefore.Bytes, f.pin, f.id)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("local rollback = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	t.Run("equal sequence local fork rejected", func(t *testing.T) {
		f := newFixture(t)
		forkItems := []vault.Item{mergeCandidateLogin("item-a", "A local fork")}
		base := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-base-0005", mergeCandidatePrevious(5), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 5, "op-local-fork-0005", mergeCandidatePrevious(5), vuk, forkItems)
		backendBefore := mergeCandidateUseRemote(t, f, base)
		openWorkingState(t, base, f.pin, f.id)
		openWorkingState(t, local, f.pin, f.id)
		openWorkingState(t, backendBefore.Bytes, f.pin, f.id)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("equal-sequence local fork = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	t.Run("max uint64 rejected", func(t *testing.T) {
		f := newFixture(t)
		base := mergeCandidateSeal(t, f.pin, policy, 1, 1, "op-base-0001", mergeCandidatePrevious(1), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-local-0002", mergeCandidatePrevious(2), vuk, localItems)
		remote := mergeCandidateSeal(t, f.pin, policy, 1, math.MaxUint64, "op-remote-max", mergeCandidatePrevious(math.MaxUint64), vuk, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if !errors.Is(err, ErrMergeCandidateVerify) {
			t.Fatalf("MaxUint64 remote = %v, want ErrMergeCandidateVerify", err)
		}
		mergeCandidateAssertZero(t, candidate)
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})
}

// TestBuildMergeCandidateCancellationAfterRead proves a cancellation observed
// immediately after the single backend read yields the zero candidate and no
// mutation.
func TestBuildMergeCandidateCancellationAfterRead(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)
	baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
	localItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}
	remoteItems := []vault.Item{mergeCandidateLogin("item-a", "A remote")}
	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
	local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
	remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
	backendBefore := mergeCandidateUseRemote(t, f, remote)
	j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
	mergeCandidateSavePending(t, j, state)
	journalBefore := mergeCandidateSnapshotJournal(t, j)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.remote.cancel = cancel
	readsBefore := f.remote.readCount()

	candidate, err := BuildMergeCandidate(ctx, f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-read cancellation = %v, want context.Canceled", err)
	}
	if !errors.Is(err, ErrMergeCandidateRejected) {
		t.Fatalf("post-read cancellation = %v, want ErrMergeCandidateRejected", err)
	}
	mergeCandidateAssertZero(t, candidate)
	mergeCandidateAssertNoPlaintext(t, err)
	if f.remote.readCount() != readsBefore+1 {
		t.Fatal("cancellation after read did not perform exactly one read")
	}
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
}

// TestMergeCandidateBindings proves the source and result bindings are stable
// for one exact tuple, sensitive to every bound field, and domain-separated.
func TestMergeCandidateBindings(t *testing.T) {
	state := vaultfilejournal.State{
		BaseBytes:      []byte("base"),
		WorkingBytes:   []byte("working"),
		RemoteRevision: "revision",
		Generation:     7,
	}
	source := mergeCandidateSourceBinding(state)
	if source == ([32]byte{}) {
		t.Fatal("source binding is zero")
	}
	if again := mergeCandidateSourceBinding(state); again != source {
		t.Fatal("source binding is not deterministic")
	}
	sourceCases := []vaultfilejournal.State{
		{BaseBytes: []byte("base2"), WorkingBytes: []byte("working"), RemoteRevision: "revision", Generation: 7},
		{BaseBytes: []byte("base"), WorkingBytes: []byte("working2"), RemoteRevision: "revision", Generation: 7},
		{BaseBytes: []byte("base"), WorkingBytes: []byte("working"), RemoteRevision: "revision2", Generation: 7},
		{BaseBytes: []byte("base"), WorkingBytes: []byte("working"), RemoteRevision: "revision", Generation: 8},
	}
	for i, changed := range sourceCases {
		if mergeCandidateSourceBinding(changed) == source {
			t.Fatalf("source binding did not change for case %d", i)
		}
	}

	result := mergeCandidateResultBinding(source, []byte("remote"), []byte("merged"), "revision", 7)
	if result == ([32]byte{}) {
		t.Fatal("result binding is zero")
	}
	if again := mergeCandidateResultBinding(source, []byte("remote"), []byte("merged"), "revision", 7); again != result {
		t.Fatal("result binding is not deterministic")
	}
	type resultCase struct {
		source     [32]byte
		remote     []byte
		merged     []byte
		revision   vaultfilebackend.Revision
		generation uint64
	}
	resultCases := []resultCase{
		{source: mergeCandidateSourceBinding(sourceCases[0]), remote: []byte("remote"), merged: []byte("merged"), revision: "revision", generation: 7},
		{source: source, remote: []byte("remote2"), merged: []byte("merged"), revision: "revision", generation: 7},
		{source: source, remote: []byte("remote"), merged: []byte("merged2"), revision: "revision", generation: 7},
		{source: source, remote: []byte("remote"), merged: []byte("merged"), revision: "revision2", generation: 7},
		{source: source, remote: []byte("remote"), merged: []byte("merged"), revision: "revision", generation: 8},
		{source: source, remote: []byte("remote"), merged: nil, revision: "revision", generation: 7},
	}
	for i, changed := range resultCases {
		got := mergeCandidateResultBinding(changed.source, changed.remote, changed.merged, changed.revision, changed.generation)
		if got == result {
			t.Fatalf("result binding did not change for case %d", i)
		}
	}
}

func allMergeCandidateZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// fixtureInputsKey returns device-1's real content-signing key without exposing
// any key material in a failure message.
func fixtureInputsKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, _, key := fixtureInputs(t)
	return key
}

// mergeCandidateReadRecorder records the exact caller-owned slice Backend.Read
// returns so a test can prove the builder cleared it.
type mergeCandidateReadRecorder struct {
	vaultfilebackend.Backend
	returned []byte
}

func (b *mergeCandidateReadRecorder) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	res, err := b.Backend.Read(ctx, name)
	b.returned = res.Bytes
	return res, err
}

// mergeCandidateReadStub returns one exact Read pair without a real backend.
// Its embedded nil Backend is never called for the non-Read methods.
type mergeCandidateReadStub struct {
	vaultfilebackend.Backend
	result vaultfilebackend.ReadResult
	err    error
}

func (b *mergeCandidateReadStub) Read(context.Context, string) (vaultfilebackend.ReadResult, error) {
	return b.result, b.err
}

// TestBuildMergeCandidateClearsReadBuffer proves the exact caller-owned Read
// buffer is cleared on success and on every early rejection, including a
// partial result returned with an error, while the output keeps its own copy.
func TestBuildMergeCandidateClearsReadBuffer(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	t.Run("success clears read buffer and keeps owned copy", func(t *testing.T) {
		vuk := mergeCandidateTestVUK(t)
		baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
		localItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}
		remoteItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}

		base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
		local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk, localItems)
		remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk, remoteItems)
		backendBefore := mergeCandidateUseRemote(t, f, remote)
		j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
		mergeCandidateSavePending(t, j, state)
		journalBefore := mergeCandidateSnapshotJournal(t, j)

		recorder := &mergeCandidateReadRecorder{Backend: f.remote}
		candidate, err := BuildMergeCandidate(context.Background(), recorder, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
		if err != nil {
			t.Fatalf("BuildMergeCandidate: %v", err)
		}
		if len(recorder.returned) == 0 {
			t.Fatal("test did not observe the Read result buffer")
		}
		if !allMergeCandidateZero(recorder.returned) {
			t.Fatal("the caller-owned Read buffer was not cleared")
		}
		if len(candidate.RemoteBytes) == 0 || allMergeCandidateZero(candidate.RemoteBytes) {
			t.Fatal("the owned output copy is empty or was cleared with the Read buffer")
		}
		if !bytes.Equal(candidate.RemoteBytes, backendBefore.Bytes) {
			t.Fatal("the owned output copy is not the exact Read result")
		}
		mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
		mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
	})

	validState := func(t *testing.T) *vaultfilejournal.Journal {
		t.Helper()
		j := openNewJournal(t)
		if err := j.InitializeState(vaultfilejournal.State{
			BaseBytes:      []byte("base"),
			RemoteRevision: "base-revision",
			WorkingBytes:   []byte("working"),
		}); err != nil {
			t.Fatalf("InitializeState: %v", err)
		}
		return j
	}

	cases := []struct {
		name   string
		result vaultfilebackend.ReadResult
		err    error
	}{
		{
			name:   "error with partial result",
			result: vaultfilebackend.ReadResult{Bytes: []byte("partial read bytes"), Revision: "rev"},
			err:    errors.New("synthetic read failure"),
		},
		{
			name:   "oversize bytes",
			result: vaultfilebackend.ReadResult{Bytes: make([]byte, vaultfilebackend.MaxValueSize+1), Revision: "rev"},
		},
		{
			name:   "zero revision",
			result: vaultfilebackend.ReadResult{Bytes: []byte("sealed bytes"), Revision: ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := validState(t)
			stub := &mergeCandidateReadStub{result: tc.result, err: tc.err}
			candidate, err := BuildMergeCandidate(context.Background(), stub, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
			if !errors.Is(err, ErrMergeCandidateRead) {
				t.Fatalf("read rejection = %v, want ErrMergeCandidateRead", err)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("read rejection = %v, want the backend cause", err)
			}
			mergeCandidateAssertZero(t, candidate)
			mergeCandidateAssertNoPlaintext(t, err)
			if !allMergeCandidateZero(tc.result.Bytes) {
				t.Fatal("the caller-owned Read buffer was not cleared on rejection")
			}
		})
	}
}

// TestBuildMergeCandidateRejectsDifferentEpochVUK proves three individually
// authentic same-policy, same-epoch files are rejected when they do not share
// the protocol's one VUK for that epoch.
func TestBuildMergeCandidateRejectsDifferentEpochVUK(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk1 := mergeCandidateTestVUK(t)
	vuk2 := mergeCandidateTestVUK(t)
	baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
	localItems := []vault.Item{mergeCandidateLogin("item-a", "A local")}
	remoteItems := []vault.Item{mergeCandidateLogin("item-a", "A remote")}

	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk1, baseItems)
	local := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-local-0003", mergeCandidatePrevious(3), vuk1, localItems)
	remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-remote-0004", mergeCandidatePrevious(4), vuk2, remoteItems)
	backendBefore := mergeCandidateUseRemote(t, f, remote)
	j, state := mergeCandidateJournalWithState(t, f, base, local, 1)
	mergeCandidateSavePending(t, j, state)
	journalBefore := mergeCandidateSnapshotJournal(t, j)

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if !errors.Is(err, ErrMergeCandidateVerify) {
		t.Fatalf("different-VUK merge = %v, want ErrMergeCandidateVerify", err)
	}
	mergeCandidateAssertZero(t, candidate)
	mergeCandidateAssertNoPlaintext(t, err)
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
}

// TestBuildMergeCandidateSourceBindingAfterAck reproduces the Ack/source race:
// a candidate is built at a generation that Ack preserves, but Ack changes the
// base and remote revision. The private source binding must change.
func TestBuildMergeCandidateSourceBindingAfterAck(t *testing.T) {
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)
	baseItems := []vault.Item{mergeCandidateLogin("item-a", "A base")}
	l1Items := []vault.Item{mergeCandidateLogin("item-a", "A L1")}
	l2Items := []vault.Item{mergeCandidateLogin("item-a", "A L2")}

	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, "op-base-0002", mergeCandidatePrevious(2), vuk, baseItems)
	l1 := mergeCandidateSeal(t, f.pin, policy, 1, 3, "op-l1-0003", mergeCandidatePrevious(3), vuk, l1Items)
	l2 := mergeCandidateSeal(t, f.pin, policy, 1, 4, "op-l2-0004", mergeCandidatePrevious(4), vuk, l2Items)
	// R is the exact base, so the merge is conflict-free and the remote read is
	// independent of the later journal Ack mutation.
	backendBefore := mergeCandidateUseRemote(t, f, base)

	j, state := mergeCandidateJournalWithState(t, f, base, l1, 1)
	prepared := vaultfilejournal.Proposal{
		Generation:       state.Generation + 3,
		OperationID:      "op-ack-source",
		ExpectedRevision: state.RemoteRevision,
		Bytes:            bytes.Clone(l1),
	}
	if err := j.Prepare(state.Generation, prepared); err != nil {
		t.Fatalf("Prepare exact L1: %v", err)
	}
	if err := j.UpdateWorking(state.Generation, l2); err != nil {
		t.Fatalf("UpdateWorking L2: %v", err)
	}
	beforeAck, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState before build: %v", err)
	}
	if beforeAck.Generation != state.Generation+1 {
		t.Fatalf("generation before build = %d, want %d", beforeAck.Generation, state.Generation+1)
	}
	preparedBefore, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared before build: %v", err)
	}
	journalBefore := mergeCandidateSnapshotJournal(t, j)

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if candidate.MergedBytes == nil || candidate.Conflicts == nil || len(candidate.Conflicts) != 0 {
		t.Fatal("expected a clean preview candidate")
	}
	mergeCandidateAssertJournalUnchanged(t, j, journalBefore)
	preparedAfterBuild, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after build: %v", err)
	}
	if !reflect.DeepEqual(preparedAfterBuild, preparedBefore) {
		t.Fatal("the preview builder resolved or changed the pending prepared record")
	}
	if candidate.ExpectedGeneration != beforeAck.Generation {
		t.Fatalf("candidate generation = %d, want %d", candidate.ExpectedGeneration, beforeAck.Generation)
	}
	if candidate.sourceBinding != mergeCandidateSourceBinding(beforeAck) {
		t.Fatal("candidate source binding does not match the pre-Ack state")
	}
	if candidate.resultBinding != mergeCandidateResultBinding(candidate.sourceBinding, candidate.RemoteBytes, candidate.MergedBytes, candidate.RemoteRevision, candidate.ExpectedGeneration) {
		t.Fatal("candidate result binding does not include the source binding and outputs")
	}

	if err := j.Ack("op-ack-source", l1, vaultfilebackend.Revision("revision-after-ack")); err != nil {
		t.Fatalf("Ack L1: %v", err)
	}
	afterAck, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after Ack: %v", err)
	}
	if afterAck.Generation != beforeAck.Generation {
		t.Fatalf("Ack changed generation from %d to %d", beforeAck.Generation, afterAck.Generation)
	}
	if !bytes.Equal(afterAck.WorkingBytes, l2) {
		t.Fatal("Ack did not preserve the newer working L2")
	}
	if !bytes.Equal(afterAck.BaseBytes, l1) {
		t.Fatal("Ack did not promote L1 to the base")
	}
	if afterAck.RemoteRevision != "revision-after-ack" {
		t.Fatalf("Ack revision = %q, want revision-after-ack", afterAck.RemoteRevision)
	}
	if candidate.ExpectedGeneration != afterAck.Generation {
		t.Fatal("test needs an unchanged generation to exercise the generation-only blind spot")
	}
	if candidate.sourceBinding == mergeCandidateSourceBinding(afterAck) {
		t.Fatal("stale candidate source binding still matches the post-Ack state")
	}
	postAckResult := mergeCandidateResultBinding(mergeCandidateSourceBinding(afterAck), candidate.RemoteBytes, candidate.MergedBytes, candidate.RemoteRevision, candidate.ExpectedGeneration)
	if candidate.resultBinding == postAckResult {
		t.Fatal("combined result binding did not change when the source binding changed")
	}
	mergeCandidateAssertBackendUnchanged(t, f, backendBefore)
}
