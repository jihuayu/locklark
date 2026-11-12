//go:build darwin || linux

package vaultfilesync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// TestPipelineResumePreparedUnknownApplyThenReadFailureRecovers is the
// applied-but-unacknowledged regression: the real directory ReplaceIfVersion
// commits the prepared M, the coordinator loses that response as
// vaultfilebackend.ErrUnknown, and its one readback then fails with a bounded
// synthetic transient read error, so the prepared record stays pending. A
// restart of the real journal and one fresh, strictly caller-pinned
// authenticated ReadPulled of the exact M let ResumePrepared verify M and Ack it
// without a second write.
//
// The fault is only in the transport: a test adapter embeds the real backend,
// calls its real ReplaceIfVersion first and replaces only the response that
// came back nil, and fails only the first read after that applied write. The
// real Dir write itself completes, including its temporary-file Sync, checked
// data-directory Sync and post-replace digest check, before the response is
// lost. RebaseAndPrepare, Ack and the whole readback path run unmodified, and
// their nil returns are the journal's bbolt NoSync:false commits. The reopen
// assertions follow those successful sync boundaries; this test does not
// simulate a power cut or an fdatasync failure, it proves how the coordinator
// and journal resolve a durably applied write whose response and first readback
// were lost.
func TestPipelineResumePreparedUnknownApplyThenReadFailureRecovers(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	b := bootstrapRef(t, f, j)

	// The independent remote branch R, authored in a second real journal and
	// committed with the real Dir ReplaceIfVersion from B's old revision, so
	// adoption targets a remote that is strictly ahead of the local base.
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
	closeNow(t, rj)
	if err := f.remote.ReplaceIfVersion(context.Background(), remoteName, b.rev, rws.WorkingBytes); err != nil {
		t.Fatalf("ReplaceIfVersion (remote branch): %v", err)
	}
	f.bytes = rws.WorkingBytes
	rr, reads := pipelinePull(t, f)
	if reads != 1 || !bytes.Equal(rr.bytes, rws.WorkingBytes) || rr.rev == b.rev {
		t.Fatal("remote branch was not committed as R at a new revision")
	}

	// Two distinct offline edits on top of B through the existing helper.
	_, _, baseItems, _ := pipelineOpenPair(t, f, b.bytes, b.bytes)
	pipelineEdit(t, f, j, pipelineReplace(t, "login-1", "Login edited offline"))
	pipelineEdit(t, f, j, pipelineReplace(t, "document-1", "Document edited offline"))
	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after edits: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 2 {
		t.Fatal("local journal base/revision/generation is not the original B/Brev/2")
	}

	c, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if c.Conflicts == nil || len(c.Conflicts) != 0 || c.MergedBytes == nil {
		t.Fatal("candidate is not a conflict-free sealed result")
	}
	if c.RemoteRevision != rr.rev || !bytes.Equal(c.RemoteBytes, rr.bytes) {
		t.Fatal("candidate R is not the independent remote branch")
	}
	if c.ExpectedGeneration != src.Generation || c.sourceBinding != mergeCandidateSourceBinding(src) {
		t.Fatal("candidate does not name the exact adopted source state")
	}
	if err := AdoptMergeCandidate(context.Background(), j, c, f.pin, fixtureDeviceID, f.id); err != nil {
		t.Fatalf("AdoptMergeCandidate: %v", err)
	}
	adopted, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after adoption: %v", err)
	}
	if adopted.Generation != src.Generation+1 ||
		!bytes.Equal(adopted.BaseBytes, rr.bytes) || adopted.RemoteRevision != rr.rev ||
		!bytes.Equal(adopted.WorkingBytes, c.MergedBytes) {
		t.Fatal("adopted state is not R/Rrev with working M at generation G+1")
	}
	prepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after adoption: %v", err)
	}
	mFile, _, _ := openWorkingState(t, c.MergedBytes, f.pin, f.id)
	if prepared.WorkingGeneration != adopted.Generation ||
		prepared.Proposal.ExpectedRevision != rr.rev ||
		prepared.Proposal.Generation != adopted.Generation ||
		prepared.Proposal.OperationID != mFile.Header.OpID ||
		!bytes.Equal(prepared.Proposal.Bytes, c.MergedBytes) {
		t.Fatal("prepared record is not the exact M proposal over R/Rrev")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present after adoption: %v", err)
	}
	wantItems := append(pipelineEditedFixtureItems(t, baseItems), vault.CloneItem(remoteOnly))

	// The transport fault: the real write is applied first and only its nil
	// response is lost, and the first read after it fails once. The two faults
	// are distinct sentinels, so the error must prove that both happened.
	lostResponse := errors.New("synthetic lost write response after applied write")
	transientRead := errors.New("synthetic transient readback after applied write")
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

	// First flow: a strict caller-pinned pull of the exact R, then
	// ResumePrepared, which retries the same prepared operation against R.
	// The real write is applied, its response is lost, and the one readback
	// fails transiently, so nothing may be acknowledged.
	pullVerify := pipelinePullVerifier(t, f)
	reads = f.remote.readCount()
	adapterReads := adapter.readCalls()
	pulledR, err := vaultfilepublish.ReadPulled(context.Background(), adapter, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (R): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("authenticated pull of R performed %d backend reads, want 1", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("authenticated pull of R performed %d adapter reads, want 1", got)
	}
	if pulledR.Revision() != rr.rev || !bytes.Equal(pulledR.Bytes(), rr.bytes) {
		t.Fatal("authenticated pull is not the exact R at Rrev")
	}
	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	err = coord.ResumePrepared(context.Background(), pulledR, pullVerify)
	if err == nil {
		t.Fatal("ResumePrepared returned nil, want ErrUnknown with a lost readback")
	}
	if !errors.Is(err, vaultfilebackend.ErrUnknown) || !errors.Is(err, lostResponse) || !errors.Is(err, transientRead) {
		t.Fatalf("ResumePrepared = %v, want ErrUnknown, the lost write response and the transient readback failure", err)
	}
	mergeCandidateAssertNoPlaintext(t, err)
	// The single failed readback is exactly one adapter Read that returned
	// the transient sentinel without delegating to the real backend.
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("failed readback performed %d adapter reads, want exactly 1", got)
	}
	if got := f.remote.readCount() - reads; got != 0 {
		t.Fatalf("the transient readback delegated %d reads to the real backend, want 0", got)
	}
	// Before the restart the only adapter read to delegate is the strict pull
	// of R; the applied write was never followed by a real read.
	applied, transientCount, delegated := adapter.counts()
	if applied != 1 || transientCount != 1 || delegated != 1 {
		t.Fatalf("adapter applied writes = %d, transient reads = %d, delegated reads = %d; want 1, 1, 1 (the R pull)", applied, transientCount, delegated)
	}
	if calls := adapter.replaceCalls(); calls != 1 {
		t.Fatalf("ReplaceIfVersion calls = %d, want exactly 1 total", calls)
	}

	// In-handle consistency only: while still pending, the records name the
	// exact adopted base, working M, prepared M and audit. This is not a
	// durability proof; the reopen below is where the durable outcome is read.
	pending, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState while pending: %v", err)
	}
	if pending.Generation != adopted.Generation ||
		!bytes.Equal(pending.BaseBytes, rr.bytes) || pending.RemoteRevision != rr.rev ||
		!bytes.Equal(pending.WorkingBytes, c.MergedBytes) {
		t.Fatal("pending state is not the exact adopted R/Rrev and working M")
	}
	pendingPrepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared while pending: %v", err)
	}
	if pendingPrepared.WorkingGeneration != prepared.WorkingGeneration ||
		pendingPrepared.Proposal.Generation != prepared.Proposal.Generation ||
		pendingPrepared.Proposal.OperationID != prepared.Proposal.OperationID ||
		pendingPrepared.Proposal.ExpectedRevision != prepared.Proposal.ExpectedRevision ||
		!bytes.Equal(pendingPrepared.Proposal.Bytes, prepared.Proposal.Bytes) {
		t.Fatal("pending prepared record is not the exact adopted M")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present while pending: %v", err)
	}
	assertAdoptionAudit(t, j, src, rr, prepared)

	// Restart the real journal at the same path, then resume from a fresh
	// strictly caller-pinned authenticated pull of the exact M. This fresh
	// pull is what establishes M and the revision the applied write
	// committed, which no caller ever observed before the restart.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	reads = f.remote.readCount()
	adapterReads = adapter.readCalls()
	fresh, err := vaultfilepublish.ReadPulled(context.Background(), adapter, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (M after restart): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("fresh pull of M performed %d backend reads, want 1", got)
	}
	if got := adapter.readCalls() - adapterReads; got != 1 {
		t.Fatalf("fresh pull of M performed %d adapter reads, want 1", got)
	}
	readbackRevision := fresh.Revision()
	if !bytes.Equal(fresh.Bytes(), c.MergedBytes) || readbackRevision == rr.rev {
		t.Fatal("fresh pull is not the exact M at a new revision")
	}
	coord, err = vaultfilepublish.NewCoordinator(adapter, reopened, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator (restarted): %v", err)
	}
	if err := coord.ResumePrepared(context.Background(), fresh, pullVerify); err != nil {
		t.Fatalf("ResumePrepared after restart: %v", err)
	}
	applied, transientCount, delegated = adapter.counts()
	if applied != 1 || transientCount != 1 || delegated != 2 {
		t.Fatalf("after resume applied writes = %d, transient reads = %d, delegated reads = %d; want 1, 1, 2", applied, transientCount, delegated)
	}
	if calls := adapter.replaceCalls(); calls != 1 {
		t.Fatalf("ReplaceIfVersion calls after recovery = %d, want exactly 1 total", calls)
	}
	if _, err := reopened.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record present after Ack: %v", err)
	}
	if _, err := reopened.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present after Ack: %v", err)
	}

	// Close and reopen again to read the durable outcome of the Ack.
	closeNow(t, reopened)
	final := openJournalAt(t, path)
	state, err := final.LoadState()
	if err != nil {
		t.Fatalf("reopened LoadState: %v", err)
	}
	if !bytes.Equal(state.BaseBytes, c.MergedBytes) || state.RemoteRevision != readbackRevision {
		t.Fatal("acknowledged base/revision is not the exact readback M / revision")
	}
	if !bytes.Equal(state.WorkingBytes, c.MergedBytes) {
		t.Fatal("acknowledged working bytes are not the exact M")
	}
	if state.Generation != adopted.Generation {
		t.Fatalf("Ack changed the local generation: %d, want %d", state.Generation, adopted.Generation)
	}
	if _, err := final.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	if _, err := final.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened Load = %v, want ErrEmpty", err)
	}
	assertAdoptionAudit(t, final, src, rr, prepared)

	// Read the real directory directly, without the fault adapter, to confirm
	// its current bytes and revision are the acknowledged M.
	direct, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("direct Read of the real directory: %v", err)
	}
	if direct.Revision != readbackRevision || !bytes.Equal(direct.Bytes, c.MergedBytes) || !bytes.Equal(direct.Bytes, state.BaseBytes) {
		t.Fatal("the real directory does not hold the exact acknowledged M at the readback revision")
	}
	ackedFile, _, ackedItems := openWorkingState(t, state.BaseBytes, f.pin, f.id)
	if ackedFile.Header.RevisionID != mFile.Header.RevisionID ||
		ackedFile.Header.OpID != mFile.Header.OpID ||
		ackedFile.Header.ContentSeq != mFile.Header.ContentSeq ||
		!bytes.Equal(ackedFile.Header.PrevDigest, mFile.Header.PrevDigest) {
		t.Fatal("acknowledged base is not the authenticated M")
	}
	pipelineAssertItems(t, "reopened acknowledged item DB", ackedItems, wantItems)
}

// assertAdoptionAudit requires the audit for the adopted generation to record
// exactly src as its old state and rr / prepared M as its remote pair and
// proposal, so the append-only history survives the pending write and the Ack.
func assertAdoptionAudit(t *testing.T, j *vaultfilejournal.Journal, src vaultfilejournal.State, rr pipelineRef, prepared vaultfilejournal.PreparedProposal) {
	t.Helper()
	audit, err := j.LoadRebaseAudit(src.Generation + 1)
	if err != nil {
		t.Fatalf("LoadRebaseAudit(%d): %v", src.Generation+1, err)
	}
	old := audit.OldState
	if audit.NewGeneration != src.Generation+1 {
		t.Fatalf("audit new generation = %d, want %d", audit.NewGeneration, src.Generation+1)
	}
	if old.Generation != src.Generation ||
		!bytes.Equal(old.BaseBytes, src.BaseBytes) ||
		!bytes.Equal(old.WorkingBytes, src.WorkingBytes) ||
		old.RemoteRevision != src.RemoteRevision {
		t.Fatal("audit old state is not the exact original B/L/revision/generation")
	}
	if audit.RemoteRevision != rr.rev || !bytes.Equal(audit.RemoteBase, rr.bytes) {
		t.Fatal("audit remote pair is not the adopted R/Rrev")
	}
	if audit.Proposal.Generation != prepared.Proposal.Generation ||
		audit.Proposal.OperationID != prepared.Proposal.OperationID ||
		audit.Proposal.ExpectedRevision != prepared.Proposal.ExpectedRevision ||
		!bytes.Equal(audit.Proposal.Bytes, prepared.Proposal.Bytes) {
		t.Fatal("audit proposal is not the exact prepared M")
	}
}

// appliedUnknownBackend is a narrow test transport adapter over the real
// directory backend. ReplaceIfVersion first calls the embedded real method. It
// propagates any non-nil result unchanged, and only replaces a nil result (the
// real Dir write, including its temporary-file and directory syncs and its
// post-replace digest check, has already completed) with ErrUnknown wrapping
// the armed lost-response sentinel. The next Read then returns the armed
// transient-read sentinel exactly once, without touching the real backend;
// every other Read delegates to it. CreateIfAbsent, List and Close are the
// embedded backend's, unmodified.
type appliedUnknownBackend struct {
	vaultfilebackend.Backend
	mu               sync.Mutex
	lostResponse     error
	transientRead    error
	replaceTotal     int
	applied          int
	transientCounted int
	delegateTotal    int
	readTotal        int
	failNextRead     bool
}

// armAppliedUnknownWrite arms adapter so its next ReplaceIfVersion that the
// real backend applies reports lost instead of its nil result, and the first
// Read after it reports transient once instead of delegating.
func armAppliedUnknownWrite(t *testing.T, adapter *appliedUnknownBackend, lost, transient error) {
	t.Helper()
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if lost == nil || transient == nil || lost == transient || errors.Is(lost, transient) {
		t.Fatal("adapter needs two distinct fault sentinels")
	}
	if adapter.lostResponse != nil || adapter.transientRead != nil || adapter.replaceTotal != 0 || adapter.readTotal != 0 {
		t.Fatal("adapter fault is already armed or was consumed")
	}
	adapter.lostResponse = lost
	adapter.transientRead = transient
}

func (a *appliedUnknownBackend) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	a.mu.Lock()
	a.replaceTotal++
	armed := a.lostResponse != nil && a.applied == 0
	lost := a.lostResponse
	a.mu.Unlock()
	err := a.Backend.ReplaceIfVersion(ctx, name, expected, value)
	if err != nil || !armed {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applied++
	a.failNextRead = true
	return fmt.Errorf("%w: substitute response for an applied write: %w", vaultfilebackend.ErrUnknown, lost)
}

func (a *appliedUnknownBackend) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	a.mu.Lock()
	a.readTotal++
	if a.failNextRead {
		a.failNextRead = false
		a.transientCounted++
		transient := a.transientRead
		a.mu.Unlock()
		return vaultfilebackend.ReadResult{}, fmt.Errorf("%w: synthetic transient readback", transient)
	}
	a.mu.Unlock()
	res, err := a.Backend.Read(ctx, name)
	a.mu.Lock()
	a.delegateTotal++
	a.mu.Unlock()
	return res, err
}

// counts returns the applied real writes, the transient reads that were not
// delegated to the real backend, and the adapter reads that were delegated.
// The delegated reads are the strict pull of R and the fresh post-restart pull
// of M; the applied write itself is never followed by an adapter-issued read.
func (a *appliedUnknownBackend) counts() (applied, transientCounted, delegated int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applied, a.transientCounted, a.delegateTotal
}

func (a *appliedUnknownBackend) replaceCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.replaceTotal
}

func (a *appliedUnknownBackend) readCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.readTotal
}
