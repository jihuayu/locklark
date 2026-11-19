//go:build darwin || linux

package vaultfilesync

// Issue #122 regression: a prepared publication is applied at the real provider,
// but its successful response and its first verified readback are both lost.
// Before any recovery, a second real handler and its own file-backed journal
// pull the exact committed M and independently commit an authenticated immediate
// successor T from M's exact revision. Recovery then pulls T and must refuse to
// acknowledge anything: the prepared M remains pending and the remote stays T.
//
// The opt-in RustFS test runs the shared scenario through the production
// vaultfilebackend.NewS3 constructor against an already-running local RustFS.
// It reuses the same harness, credentials, TLS and redaction guards as
// TestPipelinePublishThirdWriterOnRustFS and is skipped unless that opt-in is
// configured. The ordinary test runs the identical scenario through the real
// local directory backend, so the coordination invariant has a normal local
// runtime checkpoint too.
//
// Only the transport is faulted. The real ReplaceIfVersion commits first and
// only its nil response is replaced with ErrUnknown; the next real read is
// replaced once with a bounded synthetic transient failure. No CAS outcome or
// readback is mocked, no ETag is fabricated, and no write is unconditional. The
// later writer authors T with the existing trusted fixture writer and the same
// synthetic fixture device identity; independence comes from its separate
// backend handle and separate bbolt journal, not from a different identity.

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// TestPipelineResumePreparedUnknownThenLaterWriter is the ordinary local
// runtime checkpoint. Both backends are real directory handles on the same
// store, and both journals are real file-backed bbolt databases.
func TestPipelineResumePreparedUnknownThenLaterWriter(t *testing.T) {
	f, store := newThirdWriterFixture(t)
	second, err := vaultfilebackend.OpenDir(store)
	if err != nil {
		t.Fatalf("OpenDir (later writer): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	runUnknownThenLaterWriterScenario(t, f, second)
}

// TestPipelineResumePreparedUnknownThenLaterWriterOnRustFS runs the same
// scenario over the production S3 backend and a real local RustFS provider. It
// is opt-in and never contacts a cloud or external endpoint; see
// pipeline_rustfs_posix_test.go for the required environment and credential
// file.
func TestPipelineResumePreparedUnknownThenLaterWriterOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	const prefix = "unknown-later-writer-pipeline"

	first := env.newBackendAt(t, bucket, prefix)
	second := env.newBackendAt(t, bucket, prefix)
	f := newThirdWriterFixtureAt(t, first)
	runUnknownThenLaterWriterScenario(t, f, second)
}

// runUnknownThenLaterWriterScenario publishes M over the exact base B, loses
// that successful response and the first readback, lets an independent real
// handle advance the remote to T from M's exact revision, then reopens the
// original journal and requires ResumePrepared to report ErrUnknownReview with
// no second publication and no Ack.
//
// f.remote is the original path's real backend (possibly a redacting wrapper
// over RustFS). second is a separately constructed real handle to the same
// objects, owned by the caller.
func runUnknownThenLaterWriterScenario(t *testing.T, f *fixture, second vaultfilebackend.Backend) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lateAckTimeout)
	defer cancel()

	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	b := bootstrapRef(t, f, j)
	_, _, baseItems, _ := pipelineOpenPair(t, f, b.bytes, b.bytes)
	if len(baseItems) == 0 {
		t.Fatal("fixture item database is empty")
	}

	const (
		localTitle = "Login edited before unknown publication"
		laterTitle = "Document edited by later real writer"
	)
	localEdit := pipelineReplace(t, "login-1", localTitle)
	laterEdit := pipelineReplace(t, "document-1", laterTitle)
	wantM := localEdit(baseItems)
	wantT := laterEdit(wantM)

	// The original path edits one item above B and adopts the conflict-free
	// candidate M, but publishes nothing yet.
	pipelineEdit(t, f, j, localEdit)
	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after local edit: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 1 {
		t.Fatal("original path is not at the exact common base B/Brev generation 1")
	}

	c, err := BuildMergeCandidate(ctx, f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	defer c.Clear()
	if c.Conflicts == nil || len(c.Conflicts) != 0 || c.MergedBytes == nil {
		t.Fatal("original candidate is not a conflict-free sealed result")
	}
	if c.RemoteRevision != b.rev || !bytes.Equal(c.RemoteBytes, b.bytes) ||
		c.ExpectedGeneration != src.Generation || c.sourceBinding != mergeCandidateSourceBinding(src) {
		t.Fatal("original candidate does not name the exact common base and source state")
	}
	laterWriterAssertItems(t, "original candidate M item DB", pipelineItems(t, f, c.MergedBytes), wantM)

	if err := AdoptMergeCandidate(ctx, j, c, f.pin, fixtureDeviceID, f.id); err != nil {
		t.Fatalf("AdoptMergeCandidate: %v", err)
	}
	adopted, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after adoption: %v", err)
	}
	if adopted.Generation != src.Generation+1 ||
		!bytes.Equal(adopted.BaseBytes, b.bytes) || adopted.RemoteRevision != b.rev ||
		!bytes.Equal(adopted.WorkingBytes, c.MergedBytes) {
		t.Fatal("adopted state is not B/Brev with working M at generation 2")
	}
	prepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after adoption: %v", err)
	}
	mFile, _, _ := openWorkingState(t, c.MergedBytes, f.pin, f.id)
	if prepared.WorkingGeneration != adopted.Generation ||
		prepared.Proposal.ExpectedRevision != b.rev ||
		prepared.Proposal.Generation != adopted.Generation ||
		prepared.Proposal.OperationID != mFile.Header.OpID ||
		!bytes.Equal(prepared.Proposal.Bytes, c.MergedBytes) {
		t.Fatal("prepared record is not the exact M proposal over B/Brev")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal present after adoption: %v", err)
	}
	assertAdoptionAudit(t, j, src, b, prepared)

	// The transport fault: the real provider CAS is applied first and only its
	// nil response is lost, then the one readback fails with a bounded
	// synthetic transient error. The two sentinels are distinct, so the result
	// must prove both faults happened.
	lostResponse := errors.New("synthetic lost write response after applied publication")
	transientRead := errors.New("synthetic transient readback after applied publication")
	adapter := &appliedUnknownBackend{Backend: f.remote}
	armAppliedUnknownWrite(t, adapter, lostResponse, transientRead)
	verifier, err := NewContentProposalVerifier(f.pin)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	coord, err := vaultfilepublish.NewCoordinator(adapter, j, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	// One caller-pinned pull of B, then the actual resume retry. The CAS uses
	// the exact prepared bytes and expected revision over B.
	pullVerify := pipelinePullVerifier(t, f)
	reads := f.remote.readCount()
	adapterReads := adapter.readCalls()
	pulledB, err := vaultfilepublish.ReadPulled(ctx, adapter, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (B): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("authenticated pull of B performed %d backend reads, want 1", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("authenticated pull of B performed %d adapter reads, want 1", got)
	}
	if pulledB.Revision() != b.rev || !bytes.Equal(pulledB.Bytes(), b.bytes) {
		t.Fatal("authenticated pull is not the exact B/Brev")
	}

	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	err = coord.ResumePrepared(ctx, pulledB, pullVerify)
	if err == nil {
		t.Fatal("ResumePrepared returned nil, want ErrUnknown with a lost readback")
	}
	if !errors.Is(err, vaultfilebackend.ErrUnknown) || !errors.Is(err, lostResponse) || !errors.Is(err, transientRead) {
		t.Fatalf("ResumePrepared = %v, want ErrUnknown, the lost response and the transient readback", err)
	}
	mergeCandidateAssertNoPlaintext(t, err)
	if got := f.remote.readCount() - reads; got != 0 {
		t.Fatalf("the transient readback delegated %d reads to the real backend, want 0", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("failed readback performed %d adapter reads, want exactly 1", got)
	}
	applied, transientCount, delegated := adapter.counts()
	if applied != 1 || transientCount != 1 || delegated != 1 {
		t.Fatalf("adapter applied writes = %d, transient reads = %d, delegated reads = %d; want 1, 1, 1", applied, transientCount, delegated)
	}
	if calls := adapter.replaceCalls(); calls != 1 {
		t.Fatalf("ReplaceIfVersion calls = %d, want exactly 1 total", calls)
	}

	// The real provider CAS committed M from B/Brev even though no caller saw
	// its response. Read it through the independent handle before recovery.
	committedM, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("Read committed M: %v", err)
	}
	if committedM.Revision == b.rev ||
		!bytes.Equal(committedM.Bytes, c.MergedBytes) ||
		!bytes.Equal(committedM.Bytes, prepared.Proposal.Bytes) {
		t.Fatal("the real provider did not commit the exact authenticated prepared M at a new revision")
	}
	laterWriterAssertItems(t, "committed M item DB", pipelineItems(t, f, committedM.Bytes), wantM)

	// The later writer uses its own real journal, starts from the exact changed
	// M revision, and authors the immediate successor T with the existing
	// trusted fixture writer. T keeps M's edit and adds a distinguishable
	// independent edit. The fixture device identity is the same as M's; only
	// the journal and backend handle are independent.
	laterJournal := openJournalAt(t, journalDBPath(t))
	if err := laterJournal.InitializeState(vaultfilejournal.State{
		BaseBytes:      committedM.Bytes,
		RemoteRevision: committedM.Revision,
		WorkingBytes:   committedM.Bytes,
	}); err != nil {
		t.Fatalf("InitializeState (later writer): %v", err)
	}
	pipelineEdit(t, f, laterJournal, laterEdit)
	laterState, err := laterJournal.LoadState()
	if err != nil {
		t.Fatalf("LoadState (later writer): %v", err)
	}
	if !bytes.Equal(laterState.BaseBytes, committedM.Bytes) ||
		laterState.RemoteRevision != committedM.Revision ||
		laterState.Generation != 1 {
		t.Fatal("later writer state is not the exact committed M revision at generation 1")
	}
	if bytes.Equal(laterState.WorkingBytes, committedM.Bytes) {
		t.Fatal("later writer did not author a changed successor")
	}
	closeNow(t, laterJournal)

	_, tFile, _, _ := pipelineOpenPair(t, f, committedM.Bytes, laterState.WorkingBytes)
	if tFile.Header.ContentSeq != mFile.Header.ContentSeq+1 {
		t.Fatalf("later writer ContentSeq = %d, want M+1 = %d", tFile.Header.ContentSeq, mFile.Header.ContentSeq+1)
	}
	if !bytes.Equal(tFile.Header.PrevDigest, pipelineRawDigest(t, mFile)) {
		t.Fatal("later writer is not linked to the committed M digest")
	}
	if tFile.Header.AuthorDeviceID != fixtureDeviceID {
		t.Fatalf("later writer author = %q, want the same authorized fixture device", tFile.Header.AuthorDeviceID)
	}
	// Positive authorization assertion: T is the immediate, policy-preserving
	// successor of the exact M revision, authored by a current writer.
	if err := verifier(ctx, committedM.Bytes, committedM.Revision, vaultfilejournal.Proposal{
		Generation:       laterState.Generation,
		OperationID:      tFile.Header.OpID,
		ExpectedRevision: committedM.Revision,
		Bytes:            laterState.WorkingBytes,
	}); err != nil {
		t.Fatalf("later writer proposal verification: %v", err)
	}
	laterWriterAssertItems(t, "later writer T item DB", pipelineItems(t, f, laterState.WorkingBytes), wantT)

	// Commit T with an independent CAS from M's exact revision. The CAS
	// adapter records that this path really ran and really succeeded.
	independent := &thirdWriterCAS{Backend: second}
	if err := independent.ReplaceIfVersion(ctx, remoteName, committedM.Revision, laterState.WorkingBytes); err != nil {
		t.Fatalf("later writer CAS: %v", err)
	}
	if attempts, successes := independent.counts(); attempts != 1 || successes != 1 {
		t.Fatalf("later writer CAS attempts = %d, successes = %d; want 1, 1", attempts, successes)
	}
	if independent.expected() != committedM.Revision {
		t.Fatal("later writer CAS did not use the exact changed M revision")
	}
	authedT, err := vaultfilepublish.ReadPulled(ctx, second, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (T through later writer): %v", err)
	}
	if authedT.Revision() == committedM.Revision || !bytes.Equal(authedT.Bytes(), laterState.WorkingBytes) {
		t.Fatal("later writer did not commit the exact authenticated immediate successor T")
	}
	tRevision := authedT.Revision()
	tBytes := bytes.Clone(authedT.Bytes())
	laterWriterAssertItems(t, "provider T item DB", pipelineItems(t, f, tBytes), wantT)

	// Close and reopen the original real bbolt journal before recovery.
	originalPath := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, originalPath)
	beforeRecovery, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reopened LoadState before recovery: %v", err)
	}
	if !lateAckStateEqual(beforeRecovery, adopted) {
		t.Fatal("reopen changed the adopted base, working, generation or revision")
	}
	beforeRecoveryPrepared, err := reopened.LoadPrepared()
	if err != nil {
		t.Fatalf("reopened LoadPrepared before recovery: %v", err)
	}
	if !thirdWriterPreparedEqual(beforeRecoveryPrepared, prepared) {
		t.Fatal("reopen changed the pending prepared M proposal")
	}
	assertAdoptionAudit(t, reopened, src, b, prepared)

	// One fresh caller-pinned authenticated pull of T, then the actual
	// coordinator resume. T is neither M nor B, so nothing may be written or
	// acknowledged.
	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	pulledT, err := vaultfilepublish.ReadPulled(ctx, adapter, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (T): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("fresh pull of T performed %d backend reads, want 1", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("fresh pull of T performed %d adapter reads, want 1", got)
	}
	if pulledT.Revision() != tRevision || !bytes.Equal(pulledT.Bytes(), tBytes) {
		t.Fatal("fresh pull is not the exact remote T at its opaque revision")
	}

	coord, err = vaultfilepublish.NewCoordinator(adapter, reopened, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator (reopened): %v", err)
	}
	replaceBefore := adapter.replaceCalls()
	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	err = coord.ResumePrepared(ctx, pulledT, pullVerify)
	if !errors.Is(err, vaultfilepublish.ErrUnknownReview) {
		t.Fatalf("ResumePrepared on T = %v, want ErrUnknownReview", err)
	}
	mergeCandidateAssertNoPlaintext(t, err)
	if adapter.replaceCalls() != replaceBefore {
		t.Fatalf("unknown-review recovery performed a CAS: %d calls, want %d", adapter.replaceCalls(), replaceBefore)
	}
	if got := f.remote.readCount() - reads; got != 0 {
		t.Fatalf("unknown-review recovery performed %d real backend reads after its pull, want 0", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 0 {
		t.Fatalf("unknown-review recovery performed %d adapter reads after its pull, want 0", got)
	}

	stateAfterRefusal, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("LoadState after unknown-review refusal: %v", err)
	}
	if !lateAckStateEqual(stateAfterRefusal, adopted) {
		t.Fatal("unknown-review refusal changed the adopted base, working, generation or revision")
	}
	preparedAfterRefusal, err := reopened.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after unknown-review refusal: %v", err)
	}
	if !thirdWriterPreparedEqual(preparedAfterRefusal, prepared) {
		t.Fatal("unknown-review refusal changed the exact pending prepared M proposal")
	}
	if _, err := reopened.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal present after unknown-review refusal: %v", err)
	}
	assertAdoptionAudit(t, reopened, src, b, prepared)

	// A repeated refusal with the same authenticated pull must stay a pure
	// review: no pull, CAS, Ack or state change.
	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	replaceBefore = adapter.replaceCalls()
	err = coord.ResumePrepared(ctx, pulledT, pullVerify)
	if !errors.Is(err, vaultfilepublish.ErrUnknownReview) {
		t.Fatalf("repeated ResumePrepared on T = %v, want ErrUnknownReview", err)
	}
	if adapter.replaceCalls() != replaceBefore {
		t.Fatalf("repeated unknown-review recovery performed a CAS: %d calls, want %d", adapter.replaceCalls(), replaceBefore)
	}
	if got := f.remote.readCount() - reads; got != 0 {
		t.Fatalf("repeated unknown-review recovery performed %d real backend reads, want 0", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 0 {
		t.Fatalf("repeated unknown-review recovery performed %d adapter reads, want 0", got)
	}

	// Causal counts: exactly one original CAS applied, exactly one independent
	// later-writer CAS succeeded, and recovery made no CAS at all.
	applied, transientCount, delegated = adapter.counts()
	if applied != 1 || transientCount != 1 || delegated != 2 {
		t.Fatalf("adapter applied writes = %d, transient reads = %d, delegated reads = %d; want 1, 1, 2", applied, transientCount, delegated)
	}
	if calls := adapter.replaceCalls(); calls != 1 {
		t.Fatalf("total ReplaceIfVersion calls = %d, want exactly the one original CAS", calls)
	}
	if attempts, successes := independent.counts(); attempts != 1 || successes != 1 {
		t.Fatalf("independent CAS attempts = %d, successes = %d; want 1, 1", attempts, successes)
	}
	if independent.expected() != committedM.Revision {
		t.Fatal("independent CAS no longer names the exact changed M revision")
	}

	// A further independent reopen must still show the pending M and the
	// unchanged adopted state, while the provider still holds exactly T.
	closeNow(t, reopened)
	final := openJournalAt(t, originalPath)
	finalState, err := final.LoadState()
	if err != nil {
		t.Fatalf("final LoadState: %v", err)
	}
	if !lateAckStateEqual(finalState, adopted) {
		t.Fatal("final reopen changed the adopted base, working, generation or revision")
	}
	finalPrepared, err := final.LoadPrepared()
	if err != nil {
		t.Fatalf("final LoadPrepared: %v", err)
	}
	if !thirdWriterPreparedEqual(finalPrepared, prepared) {
		t.Fatal("final reopen changed the exact pending prepared M proposal")
	}
	if _, err := final.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("final Load = %v, want ErrEmpty", err)
	}
	assertAdoptionAudit(t, final, src, b, prepared)
	laterWriterAssertItems(t, "final local M item DB", pipelineItems(t, f, finalState.WorkingBytes), wantM)

	finalRemote, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("final Read of T: %v", err)
	}
	if finalRemote.Revision != tRevision || !bytes.Equal(finalRemote.Bytes, tBytes) {
		t.Fatal("the remote no longer holds the exact T bytes and opaque revision")
	}
	laterWriterAssertItems(t, "final remote T item DB", pipelineItems(t, f, finalRemote.Bytes), wantT)
}

// laterWriterAssertItems compares decrypted items without printing their
// values. Only counts and an opaque mismatch label are reported.
func laterWriterAssertItems(t *testing.T, label string, got, want []vault.Item) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s item count = %d, want %d", label, len(got), len(want))
	}
	sorted := func(items []vault.Item) []vault.Item {
		out := append([]vault.Item(nil), items...)
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out
	}
	if !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Fatalf("%s decrypted items differ from the synthetic expected edits", label)
	}
}
