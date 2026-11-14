//go:build darwin || linux

package vaultfilesync

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// These tests run two complete real pipelines end to end on the platforms the
// directory backend implements: Bootstrap, successive offline item edits made
// through UpdateWorkingItems, a conflict-free BuildMergeCandidate, durable
// AdoptMergeCandidate, and the real ReplaceIfVersion CAS, authenticated
// readback and Ack through the existing vaultfilepublish Coordinator bound to
// NewContentProposalVerifier. Every remote version is a genuinely
// authenticated sealed file, including the independent remote branch R, which
// a second real journal authors through UpdateWorkingItems. No fake backend
// substitutes for the directory, journal or authenticated file boundary.
// Unknown outcomes and late acknowledgements are separate follow-ups and are
// deliberately not exercised here.
//
// The file is tagged darwin || linux because the pipeline depends on the
// directory backend; boot_test.go owns TestMain, so the portable core of the
// package stays buildable on every other platform.

// pipelineRef is one remote version observed through the directory backend:
// the exact bytes and the opaque revision they were committed at.
type pipelineRef struct {
	bytes []byte
	rev   vaultfilebackend.Revision
}

// pipelineCanonicalMetadata is a non-nil metadata payload for the
// canonicalization round trip; NewItemDatabase rejects nil metadata.
var pipelineCanonicalMetadata = []byte(`{"fixture":"pipeline-canonical"}`)

// pipelineItem returns item in the canonical NewItemDatabase/ReadItemDatabase
// representation, so expected values compare exactly with reopened items.
func pipelineItem(t *testing.T, item vault.Item) vault.Item {
	t.Helper()
	db, err := vault.NewItemDatabase(pipelineCanonicalMetadata, []vault.Item{item})
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	defer releaseDatabase(db)
	_, items, err := vault.ReadItemDatabase(db)
	if err != nil {
		t.Fatalf("ReadItemDatabase: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("canonical round trip returned %d items, want 1", len(items))
	}
	defer releasePlaintext(nil, items)
	return items[0]
}

// pipelineItems opens encoded under the caller pin and device and returns its
// canonical items, released at test cleanup.
func pipelineItems(t *testing.T, f *fixture, encoded []byte) []vault.Item {
	t.Helper()
	_, _, items := openWorkingState(t, encoded, f.pin, f.id)
	return items
}

// pipelineOnlyItem returns the single index of id in items. It fails the test
// when the fixture ID has drifted (no match) or is duplicated, so an edit can
// never silently apply to zero or several items.
func pipelineOnlyItem(t *testing.T, items []vault.Item, id string) int {
	t.Helper()
	found := -1
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if found >= 0 {
			t.Fatalf("fixture ID %q appears more than once, want exactly one item", id)
		}
		found = i
	}
	if found < 0 {
		t.Fatalf("fixture ID %q is absent, want exactly one item (fixture drift)", id)
	}
	return found
}

// pipelineEditedFixtureItems returns base with both fixture edits applied. Each
// expected ID must match exactly one base item before its title changes. The
// result is compared irrespective of order, because the merge emits a stable
// order that is not required to be the base order.
func pipelineEditedFixtureItems(t *testing.T, base []vault.Item) []vault.Item {
	t.Helper()
	out := append([]vault.Item(nil), base...)
	for _, edit := range []struct{ id, title string }{
		{"login-1", "Login edited offline"},
		{"document-1", "Document edited offline"},
	} {
		out[pipelineOnlyItem(t, out, edit.id)].Title = edit.title
	}
	return out
}

// pipelineAssertItems asserts that got holds exactly want, in any order.
func pipelineAssertItems(t *testing.T, label string, got, want []vault.Item) {
	t.Helper()
	sorted := func(items []vault.Item) []vault.Item {
		out := append([]vault.Item(nil), items...)
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out
	}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Fatalf("%s:\n got %+v\nwant %+v", label, sorted(got), sorted(want))
	}
}

// pipelineReplace returns an edit that changes only the title of item id,
// after requiring exactly one matching item and that its title actually
// changed, so a drifted or duplicated fixture ID fails instead of producing a
// no-op edit.
func pipelineReplace(t *testing.T, id, title string) func([]vault.Item) []vault.Item {
	t.Helper()
	return func(items []vault.Item) []vault.Item {
		out := append([]vault.Item(nil), items...)
		i := pipelineOnlyItem(t, out, id)
		before := out[i].Title
		out[i].Title = title
		if out[i].Title == before {
			t.Fatalf("edit of %q did not change its title %q", id, before)
		}
		return out
	}
}

// pipelineEdit applies one offline edit through UpdateWorkingItems and checks
// that it moved only the local CAS generation: B and its revision are
// unchanged. Whether the served remote still equals B is provisioned by the
// callers, because the second test serves R, which is deliberately ahead.
func pipelineEdit(t *testing.T, f *fixture, j *vaultfilejournal.Journal, edit func([]vault.Item) []vault.Item) {
	t.Helper()
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState before edit: %v", err)
	}
	r, err := UpdateWorkingItems(context.Background(), j, before.Generation, edit(pipelineItems(t, f, before.WorkingBytes)), f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("UpdateWorkingItems: %v", err)
	}
	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after edit: %v", err)
	}
	if r.Generation != before.Generation+1 || after.Generation != r.Generation {
		t.Fatalf("edit generation = %d (stored %d), want %d", r.Generation, after.Generation, before.Generation+1)
	}
	if !bytes.Equal(after.BaseBytes, before.BaseBytes) || after.RemoteRevision != before.RemoteRevision {
		t.Fatal("an offline edit changed the journal base or revision")
	}
}

// pipelinePull reads the published name through vaultfilepublish.ReadPulled
// under the caller pin and reports how many backend reads that took.
func pipelinePull(t *testing.T, f *fixture) (pipelineRef, int) {
	t.Helper()
	reads := f.remote.readCount()
	verifier := func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		_, opened, err := vaultfile.OpenAuthenticatedFile(data, f.pin, fixtureDeviceID, f.id)
		releaseDatabase(opened)
		return err
	}
	pulled, err := vaultfilepublish.ReadPulled(context.Background(), f.remote, remoteName, verifier)
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	return pipelineRef{bytes: pulled.Bytes(), rev: pulled.Revision()}, f.remote.readCount() - reads
}

// pipelineOpenPair opens two sealed versions under the caller pin and device
// and returns both authenticated Files and item lists, released at cleanup.
func pipelineOpenPair(t *testing.T, f *fixture, a, b []byte) (*vaultfile.File, *vaultfile.File, []vault.Item, []vault.Item) {
	t.Helper()
	aFile, _, aItems := openWorkingState(t, a, f.pin, f.id)
	bFile, _, bItems := openWorkingState(t, b, f.pin, f.id)
	return aFile, bFile, aItems, bItems
}

// pipelinePublish adopts the conflict-free candidate c, publishes exactly it
// through the existing coordinator, then closes and reopens the journal and
// verifies the complete durable outcome. src is the exact source state
// B/L/revision/generation the candidate was built from and r is the served R;
// the adoption audit must still record src as its old state and r as its new
// remote pair, while the state and prepared record target R/Rrev/M. It returns
// the reopened journal, its state and the adoption audit record.
func pipelinePublish(t *testing.T, f *fixture, j *vaultfilejournal.Journal, c MergeCandidate, src vaultfilejournal.State, r pipelineRef, wantItems []vault.Item) (*vaultfilejournal.Journal, vaultfilejournal.State, vaultfilejournal.RebaseAudit) {
	t.Helper()
	if c.MergedBytes == nil || c.Conflicts == nil || len(c.Conflicts) != 0 {
		t.Fatal("candidate is not a conflict-free sealed result")
	}
	if c.ExpectedGeneration != src.Generation ||
		c.sourceBinding != mergeCandidateSourceBinding(src) ||
		c.resultBinding != mergeCandidateResultBinding(c.sourceBinding, c.RemoteBytes, c.MergedBytes, c.RemoteRevision, c.ExpectedGeneration) {
		t.Fatal("candidate bindings do not name the exact journal state and served remote it was built from")
	}
	mFile, _ := vaultfile.ParseFile(c.MergedBytes)
	if err := AdoptMergeCandidate(context.Background(), j, c, f.pin, fixtureDeviceID, f.id); err != nil {
		t.Fatalf("AdoptMergeCandidate: %v", err)
	}

	// Adoption keeps the original B/L/revision/generation as its audit
	// source and targets R/Rrev/M in the state and prepared record.
	adopted, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after adoption: %v", err)
	}
	if adopted.Generation != src.Generation+1 {
		t.Fatalf("adopted generation = %d, want %d", adopted.Generation, src.Generation+1)
	}
	if !bytes.Equal(adopted.BaseBytes, c.RemoteBytes) || adopted.RemoteRevision != c.RemoteRevision {
		t.Fatal("adopted base/revision is not the exact candidate R/Rrev")
	}
	if !bytes.Equal(adopted.WorkingBytes, c.MergedBytes) {
		t.Fatal("adopted working bytes are not the exact candidate M")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present after adoption: %v", err)
	}
	prepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after adoption: %v", err)
	}
	if prepared.WorkingGeneration != src.Generation+1 ||
		prepared.Proposal.ExpectedRevision != c.RemoteRevision ||
		prepared.Proposal.Generation != src.Generation+1 ||
		prepared.Proposal.OperationID != mFile.Header.OpID ||
		!bytes.Equal(prepared.Proposal.Bytes, c.MergedBytes) {
		t.Fatal("prepared record is not the exact G+1 / Rrev / M proposal")
	}
	audit, err := j.LoadRebaseAudit(src.Generation + 1)
	if err != nil {
		t.Fatalf("LoadRebaseAudit: %v", err)
	}
	if audit.NewGeneration != src.Generation+1 {
		t.Fatalf("audit new generation = %d, want %d", audit.NewGeneration, src.Generation+1)
	}
	if !reflect.DeepEqual(audit.OldState, src) {
		t.Fatal("audit old state is not the exact original B/L/revision/generation state")
	}
	if audit.RemoteRevision != r.rev || !bytes.Equal(audit.RemoteBase, r.bytes) {
		t.Fatal("audit remote pair is not the adopted R/Rrev")
	}
	if audit.Proposal.OperationID != prepared.Proposal.OperationID || !bytes.Equal(audit.Proposal.Bytes, prepared.Proposal.Bytes) {
		t.Fatal("audit proposal is not the prepared M")
	}

	// The real directory CAS, authenticated readback and Ack through the
	// existing coordinator and verifier.
	verifier, err := NewContentProposalVerifier(f.pin)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	coord, err := vaultfilepublish.NewCoordinator(f.remote, j, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	// Exactly one authenticated pull of the current remote. That same
	// verified Pulled is compared with the intended R/Rrev and the candidate,
	// then handed to ResumePrepared; it is never re-read into a second,
	// unverified value.
	reads := f.remote.readCount()
	pulled, err := vaultfilepublish.ReadPulled(context.Background(), f.remote, remoteName, pipelinePullVerifier(t, f))
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("authenticated pull of the current remote performed %d backend reads, want 1", got)
	}
	if pulled.Revision() != r.rev || !bytes.Equal(pulled.Bytes(), r.bytes) ||
		pulled.Revision() != c.RemoteRevision || !bytes.Equal(pulled.Bytes(), c.RemoteBytes) {
		t.Fatal("authenticated pull is not the exact candidate R at Rrev")
	}
	if err := coord.ResumePrepared(context.Background(), pulled, pipelinePullVerifier(t, f)); err != nil {
		t.Fatalf("ResumePrepared: %v", err)
	}
	published, reads := pipelinePull(t, f)
	if reads != 1 || !bytes.Equal(published.bytes, c.MergedBytes) || published.rev == c.RemoteRevision {
		t.Fatal("published remote is not exactly M at a new revision")
	}

	// Close and reopen the database before asserting the durable state.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	state, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reopened LoadState: %v", err)
	}
	if _, err := reopened.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	if _, err := reopened.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened Load = %v, want ErrEmpty", err)
	}
	if state.Generation != adopted.Generation {
		t.Fatalf("Ack changed the local generation: %d, want %d", state.Generation, adopted.Generation)
	}
	if state.RemoteRevision != published.rev || !bytes.Equal(state.BaseBytes, published.bytes) {
		t.Fatal("reopened state base/revision is not the exact published readback")
	}
	if !bytes.Equal(state.WorkingBytes, published.bytes) || !bytes.Equal(state.WorkingBytes, c.MergedBytes) {
		t.Fatal("reopened state working bytes are not the exact M")
	}
	ackedFile, readbackFile, ackedItems, readbackItems := pipelineOpenPair(t, f, state.WorkingBytes, published.bytes)
	if ackedFile.Header.RevisionID != mFile.Header.RevisionID || readbackFile.Header.RevisionID != mFile.Header.RevisionID ||
		ackedFile.Header.OpID != mFile.Header.OpID || ackedFile.Header.ContentSeq != mFile.Header.ContentSeq {
		t.Fatal("reopened state and readback are not the adopted M")
	}
	pipelineAssertItems(t, "reopened state item DB", ackedItems, wantItems)
	pipelineAssertItems(t, "reopened readback item DB", readbackItems, wantItems)
	return reopened, state, audit
}

// pipelinePullVerifier accepts only bytes that open under the caller pin.
func pipelinePullVerifier(t *testing.T, f *fixture) vaultfilepublish.PullVerifier {
	return func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		_, opened, err := vaultfile.OpenAuthenticatedFile(data, f.pin, fixtureDeviceID, f.id)
		releaseDatabase(opened)
		return err
	}
}

// pipelineRawDigest decodes vaultfile.FileDigest.
func pipelineRawDigest(t *testing.T, file *vaultfile.File) []byte {
	t.Helper()
	digest, err := vaultfile.FileDigest(file)
	if err != nil {
		t.Fatalf("FileDigest: %v", err)
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 32 {
		t.Fatalf("FileDigest is not 32 lowercase hex bytes: %v", err)
	}
	return raw
}

// bootstrapRef returns the exact remote pair Bootstrap read and recorded, so
// later adapter reads of the same file cannot be mistaken for it.
func bootstrapRef(t *testing.T, f *fixture, j *vaultfilejournal.Journal) pipelineRef {
	t.Helper()
	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after Bootstrap: %v", err)
	}
	return pipelineRef{bytes: state.BaseBytes, rev: state.RemoteRevision}
}

// TestPipelinePublishUnchangedRemote runs the complete pipeline while the
// remote still equals the journal base B: Bootstrap, two successive offline
// edits to distinct items, a conflict-free candidate, adoption, the real
// CAS/readback/Ack, and a reopened journal holding both offline edits in the
// authenticated item DB.
func TestPipelinePublishUnchangedRemote(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	b := bootstrapRef(t, f, j)

	_, _, baseItems, _ := pipelineOpenPair(t, f, b.bytes, b.bytes)
	pipelineEdit(t, f, j, pipelineReplace(t, "login-1", "Login edited offline"))
	pipelineEdit(t, f, j, pipelineReplace(t, "document-1", "Document edited offline"))

	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after edits: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 2 {
		t.Fatalf("journal base/revision/generation = %q/%d, want B/Brev/2", src.RemoteRevision, src.Generation)
	}
	remote, reads := pipelinePull(t, f)
	if reads != 1 || remote.rev != b.rev || !bytes.Equal(remote.bytes, b.bytes) {
		t.Fatal("remote is not the unchanged B")
	}
	c, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if c.RemoteRevision != b.rev || !bytes.Equal(c.RemoteBytes, b.bytes) {
		t.Fatal("candidate R is not the unchanged remote B")
	}
	bFile, mFile, _, _ := pipelineOpenPair(t, f, b.bytes, c.MergedBytes)
	if mFile.Header.ContentSeq != bFile.Header.ContentSeq+1 {
		t.Fatalf("M.ContentSeq = %d, want B+1 = %d", mFile.Header.ContentSeq, bFile.Header.ContentSeq+1)
	}
	if !bytes.Equal(mFile.Header.PrevDigest, pipelineRawDigest(t, bFile)) {
		t.Fatal("M is not linked to B's digest")
	}
	if _, _, localItems, _ := pipelineOpenPair(t, f, src.WorkingBytes, src.WorkingBytes); len(localItems) != len(baseItems) {
		t.Fatalf("local item count = %d, want the base count %d (edits only)", len(localItems), len(baseItems))
	}
	if len(baseItems) != 2 {
		t.Fatalf("fixture item count = %d, want 2", len(baseItems))
	}
	wantItems := pipelineEditedFixtureItems(t, baseItems)
	pipelineAssertItems(t, "candidate items", pipelineItems(t, f, c.MergedBytes), wantItems)

	_, state, _ := pipelinePublish(t, f, j, c, src, b, wantItems)
	if state.Generation != src.Generation+1 {
		t.Fatalf("reopened generation = %d, want the adopted generation %d", state.Generation, src.Generation+1)
	}
}

// TestPipelinePublishIndependentRemoteBranch runs the complete pipeline while
// an independent remote branch R, authored in a second real journal through
// UpdateWorkingItems and committed with a real Dir ReplaceIfVersion from B's
// old revision, is strictly ahead of B. Both local offline edits and the
// remote-only edit must survive.
func TestPipelinePublishIndependentRemoteBranch(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	b := bootstrapRef(t, f, j)

	// The independent remote branch: a second real journal starting at B,
	// edited through UpdateWorkingItems with one remote-only item.
	rj := openJournalAt(t, journalDBPath(t))
	if err := rj.InitializeState(vaultfilejournal.State{BaseBytes: b.bytes, RemoteRevision: b.rev, WorkingBytes: b.bytes}); err != nil {
		t.Fatalf("InitializeState (remote branch): %v", err)
	}
	remoteOnly := pipelineItem(t, mergeCandidateLogin("item-remote", "Remote only"))
	remoteItems := append(pipelineItems(t, f, b.bytes), vault.CloneItem(remoteOnly))
	if _, err := UpdateWorkingItems(context.Background(), rj, 0, remoteItems, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t)); err != nil {
		t.Fatalf("UpdateWorkingItems (remote branch): %v", err)
	}
	rws, err := rj.LoadState()
	if err != nil {
		t.Fatalf("LoadState (remote branch): %v", err)
	}
	if !bytes.Equal(rws.BaseBytes, b.bytes) || rws.RemoteRevision != b.rev || rws.Generation != 1 {
		t.Fatal("remote branch edit did not keep B and its old revision at generation 1")
	}
	closeNow(t, rj)

	// Commit R on the real directory from B's old revision.
	if err := f.remote.ReplaceIfVersion(context.Background(), remoteName, b.rev, rws.WorkingBytes); err != nil {
		t.Fatalf("ReplaceIfVersion: %v", err)
	}
	committed, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("Read committed R: %v", err)
	}
	err = f.remote.ReplaceIfVersion(context.Background(), remoteName, b.rev, rws.WorkingBytes)
	if !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("reusing B's old revision = %v, want ErrConflict", err)
	}
	f.bytes = rws.WorkingBytes
	rr, reads := pipelinePull(t, f)
	if reads != 1 || rr.rev != committed.Revision || !bytes.Equal(rr.bytes, rws.WorkingBytes) {
		t.Fatal("remote branch was not committed at a new revision")
	}
	if !bytes.Equal(committed.Bytes, rws.WorkingBytes) {
		t.Fatal("the committed directory record is not R")
	}
	bFile, rFile, _, _ := pipelineOpenPair(t, f, b.bytes, rws.WorkingBytes)
	if rFile.Header.ContentSeq <= bFile.Header.ContentSeq {
		t.Fatalf("R.ContentSeq = %d, want strictly above B.ContentSeq = %d", rFile.Header.ContentSeq, bFile.Header.ContentSeq)
	}
	if !bytes.Equal(rFile.Header.PrevDigest, pipelineRawDigest(t, bFile)) {
		t.Fatal("R is not linked to B's digest")
	}

	// Two separate local offline edits on top of B.
	_, _, baseItems, _ := pipelineOpenPair(t, f, b.bytes, b.bytes)
	pipelineEdit(t, f, j, pipelineReplace(t, "login-1", "Login edited offline"))
	pipelineEdit(t, f, j, pipelineReplace(t, "document-1", "Document edited offline"))

	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after local edits: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 2 {
		t.Fatal("local journal base/revision/generation is not the original B/Brev/2")
	}
	c, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if c.RemoteRevision != rr.rev || !bytes.Equal(c.RemoteBytes, rws.WorkingBytes) {
		t.Fatal("candidate R is not the independent remote branch")
	}
	_, mFile, _, _ := pipelineOpenPair(t, f, rws.WorkingBytes, c.MergedBytes)
	if mFile.Header.ContentSeq != rFile.Header.ContentSeq+1 {
		t.Fatalf("M.ContentSeq = %d, want R+1 = %d", mFile.Header.ContentSeq, rFile.Header.ContentSeq+1)
	}
	verify, err := NewContentProposalVerifier(f.pin)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	if err := verify(context.Background(), c.RemoteBytes, c.RemoteRevision, vaultfilejournal.Proposal{
		Generation:       src.Generation + 1,
		OperationID:      mFile.Header.OpID,
		ExpectedRevision: c.RemoteRevision,
		Bytes:            c.MergedBytes,
	}); err != nil {
		t.Fatalf("proposal verification of R to M: %v", err)
	}
	wantItems := append(pipelineEditedFixtureItems(t, baseItems), vault.CloneItem(remoteOnly))
	pipelineAssertItems(t, "candidate items", pipelineItems(t, f, c.MergedBytes), wantItems)

	// Adoption must target R, not the local base B: the reopened audit pair
	// is the exact R committed at Rrev.
	_, state, audit := pipelinePublish(t, f, j, c, src, rr, wantItems)
	if !bytes.Equal(audit.RemoteBase, rr.bytes) || audit.RemoteRevision != rr.rev {
		t.Fatal("adoption targeted something other than R at Rrev")
	}
	if bytes.Equal(audit.RemoteBase, b.bytes) || bytes.Equal(audit.OldState.BaseBytes, rr.bytes) {
		t.Fatal("adoption confused the local base B with the remote target R")
	}

	// The acknowledged base is the published M, exactly one above R.
	ackedFile, _, _ := openWorkingState(t, state.BaseBytes, f.pin, f.id)
	if ackedFile.Header.ContentSeq != rFile.Header.ContentSeq+1 || ackedFile.Header.RevisionID != mFile.Header.RevisionID {
		t.Fatalf("acknowledged base sequence = %d, want R+1 = %d", ackedFile.Header.ContentSeq, rFile.Header.ContentSeq+1)
	}
}
