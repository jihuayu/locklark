//go:build darwin || linux

package vaultfilesync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// TestPipelineResumePreparedLateAckKeepsWorkingEdit is the late-acknowledgement
// regression: a local edit is committed to the real journal at the adopted
// generation while ResumePrepared is already inside its publication window, so
// the journal has moved on to a newer generation before the real Dir
// ReplaceIfVersion is allowed to commit the prepared M. The real coordinator's
// readback and Journal.Ack must still promote Base to M at its new revision
// while preserving the newer Working W2 and its generation, and must leave the
// adoption audit untouched.
//
// The only synchronisation is a channel barrier in a tiny test adapter that
// embeds the real tracking backend. Its ReplaceIfVersion signals entered and
// waits for release before delegating the exact CAS to the real Dir backend;
// no sleep and no timing decides which side runs first. The prepared edit is
// the same two distinct offline pipelineEdit edits the earlier pipelines use,
// and W2 is exactly the prepared M items plus one new local-only item.
//
// A single test-wide context bounds every wait, and a deferred once-guarded
// release opens the barrier on every exit, so a missing signal or an early
// failure fails the test instead of hanging it. The timeout is only a failure
// guard: channel order, never timing, interleaves the edit and the CAS.
func TestPipelineResumePreparedLateAckKeepsWorkingEdit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), lateAckTimeout)
	defer cancel()

	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	b := bootstrapRef(t, f, j)
	_, _, baseItems, _ := pipelineOpenPair(t, f, b.bytes, b.bytes)
	if len(baseItems) == 0 {
		t.Fatal("fixture item database is empty")
	}

	// Two distinct offline edits on top of B capture the exact source state S.
	pipelineEdit(t, f, j, pipelineReplace(t, "login-1", "Login edited offline"))
	pipelineEdit(t, f, j, pipelineReplace(t, "document-1", "Document edited offline"))
	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after edits: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 2 {
		t.Fatal("source state S is not the original B/Brev at generation 2")
	}

	// R is the unchanged remote B; the strict caller pin pins the candidate.
	r, reads := pipelinePull(t, f)
	if reads != 1 || r.rev != b.rev || !bytes.Equal(r.bytes, b.bytes) {
		t.Fatal("strict pull of R is not the unchanged B")
	}
	c, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if c.MergedBytes == nil || c.Conflicts == nil || len(c.Conflicts) != 0 {
		t.Fatal("candidate is not a conflict-free sealed result")
	}
	if c.RemoteRevision != r.rev || !bytes.Equal(c.RemoteBytes, r.bytes) ||
		c.ExpectedGeneration != src.Generation || c.sourceBinding != mergeCandidateSourceBinding(src) {
		t.Fatal("candidate does not name the exact source state S and served R")
	}

	// The exact candidate M items; opening M under the caller pin keeps its
	// authenticated header for the final comparison.
	mFile, _, _ := openWorkingState(t, c.MergedBytes, f.pin, f.id)
	wantItems := pipelineEditedFixtureItems(t, baseItems)
	pipelineAssertItems(t, "candidate items", pipelineItems(t, f, c.MergedBytes), wantItems)

	if err := AdoptMergeCandidate(context.Background(), j, c, f.pin, fixtureDeviceID, f.id); err != nil {
		t.Fatalf("AdoptMergeCandidate: %v", err)
	}
	adopted, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after adoption: %v", err)
	}
	if adopted.Generation != src.Generation+1 ||
		!bytes.Equal(adopted.BaseBytes, c.RemoteBytes) || adopted.RemoteRevision != c.RemoteRevision ||
		!bytes.Equal(adopted.WorkingBytes, c.MergedBytes) {
		t.Fatal("adopted state is not R/Rrev with working M at G+1")
	}
	prepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after adoption: %v", err)
	}
	if prepared.WorkingGeneration != adopted.Generation ||
		prepared.Proposal.ExpectedRevision != c.RemoteRevision ||
		prepared.Proposal.Generation != adopted.Generation ||
		!bytes.Equal(prepared.Proposal.Bytes, c.MergedBytes) {
		t.Fatal("prepared record is not the exact M proposal at the adopted generation")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present after adoption: %v", err)
	}
	auditAfter, err := j.LoadRebaseAudit(src.Generation + 1)
	if err != nil {
		t.Fatalf("LoadRebaseAudit after adoption: %v", err)
	}
	if auditAfter.NewGeneration != src.Generation+1 ||
		auditAfter.RemoteRevision != r.rev || !bytes.Equal(auditAfter.RemoteBase, r.bytes) ||
		!bytes.Equal(auditAfter.Proposal.Bytes, c.MergedBytes) ||
		auditAfter.Proposal.OperationID != prepared.Proposal.OperationID ||
		auditAfter.Proposal.Generation != prepared.Proposal.Generation ||
		auditAfter.Proposal.ExpectedRevision != prepared.Proposal.ExpectedRevision {
		t.Fatal("adoption audit is not R/Rrev with the exact prepared M")
	}
	assertAdoptionAudit(t, j, src, r, prepared)

	// The exact R through the authenticated pull, strictly pinned.
	pullVerify := pipelinePullVerifier(t, f)
	reads = f.remote.readCount()
	pulledR, err := vaultfilepublish.ReadPulled(context.Background(), f.remote, remoteName, pullVerify)
	if err != nil {
		t.Fatalf("ReadPulled (R): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("authenticated pull of R performed %d backend reads, want 1", got)
	}
	if pulledR.Revision() != r.rev || !bytes.Equal(pulledR.Bytes(), r.bytes) {
		t.Fatal("authenticated pull is not the exact R at Rrev")
	}

	verifier, err := NewContentProposalVerifier(f.pin)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	gate := newLateAckBackend(f.remote)
	defer gate.releaseOnce.Do(func() { close(gate.release) })
	coord, err := vaultfilepublish.NewCoordinator(gate, j, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	res := make(chan error, 1)
	go func() {
		res <- coord.ResumePrepared(ctx, pulledR, pullVerify)
	}()

	// Wait for the coordinator to be inside the publication window, before
	// any write was delegated to the real Dir. The read count is recorded
	// here, after the standalone pull of R has completed and after
	// trackingBackend has accounted for every read before the barrier, so the
	// single read ResumePrepared makes after its CAS is measured exactly.
	awaitChannel(t, ctx, gate.entered, "entry into the windowed ReplaceIfVersion")
	readsBeforeCAS := f.remote.readCount()
	select {
	case err := <-res:
		t.Fatalf("ResumePrepared finished while its CAS was still blocked: %v", err)
	default:
	}
	if got := f.remote.readCount(); got != readsBeforeCAS {
		t.Fatalf("the blocked CAS already performed %d backend reads, want 0", got-readsBeforeCAS)
	}
	direct, err := f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("direct Read while blocked: %v", err)
	}
	if direct.Revision != r.rev || !bytes.Equal(direct.Bytes, r.bytes) {
		t.Fatal("the real directory is no longer exactly R before the CAS committed")
	}

	// The late local edit: W2 = exact prepared M items plus one new local-only
	// item, saved at the adopted generation, so the prepared generation stays
	// older than W2's.
	localOnly := pipelineItem(t, mergeCandidateLogin("item-local", "Local only during publication"))
	w2Items := append(pipelineItems(t, f, c.MergedBytes), vault.CloneItem(localOnly))
	w2r, err := UpdateWorkingItems(context.Background(), j, adopted.Generation, w2Items, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("UpdateWorkingItems (W2): %v", err)
	}
	if w2r.Generation != adopted.Generation+1 {
		t.Fatalf("W2 generation = %d, want %d", w2r.Generation, adopted.Generation+1)
	}
	w2s, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after W2: %v", err)
	}
	if w2s.Generation != w2r.Generation || prepared.WorkingGeneration >= w2s.Generation {
		t.Fatalf("prepared generation %d is not older than W2 generation %d", prepared.WorkingGeneration, w2s.Generation)
	}
	if !bytes.Equal(w2s.BaseBytes, r.bytes) || w2s.RemoteRevision != r.rev {
		t.Fatal("W2 changed the base R/Rrev")
	}
	w2File, _, w2Stored := openWorkingState(t, w2s.WorkingBytes, f.pin, f.id)
	if w2File.Header.OpID != w2r.OperationID || w2File.Header.ContentSeq != w2r.ContentSeq ||
		bytes.Equal(w2s.WorkingBytes, c.MergedBytes) {
		t.Fatal("W2 working bytes are not the updated local edit")
	}
	pipelineAssertItems(t, "W2 item DB", w2Stored, w2Items)
	mid, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared during the window: %v", err)
	}
	if mid.WorkingGeneration != prepared.WorkingGeneration ||
		mid.Proposal.Generation != prepared.Proposal.Generation ||
		mid.Proposal.OperationID != prepared.Proposal.OperationID ||
		mid.Proposal.ExpectedRevision != prepared.Proposal.ExpectedRevision ||
		!bytes.Equal(mid.Proposal.Bytes, prepared.Proposal.Bytes) ||
		mid.WorkingGeneration >= w2s.Generation {
		t.Fatal("W2 did not preserve the exact prepared M")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present during the window: %v", err)
	}
	assertAdoptionAudit(t, j, src, r, prepared)
	if calls := gate.replaceCalls(); calls != 1 {
		t.Fatalf("in-flight ReplaceIfVersion calls = %d, want 1", calls)
	}

	// Release the barrier: the exact CAS commits, the coordinator reads back
	// the exact M and acks it.
	gate.releaseOnce.Do(func() { close(gate.release) })
	if err := awaitChannel(t, ctx, res, "ResumePrepared result"); err != nil {
		t.Fatalf("ResumePrepared: %v", err)
	}
	attempts, successes := gate.counts()
	if attempts != 1 || successes != 1 {
		t.Fatalf("ReplaceIfVersion attempts = %d, real Dir successes = %d; want 1, 1", attempts, successes)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record still present after ResumePrepared: %v", err)
	}
	// The coordinator's own strict pinned readback is its only backend read
	// after the barrier; its captured bytes and revision are what was acked.
	if got := f.remote.readCount() - readsBeforeCAS; got != 1 {
		t.Fatalf("ResumePrepared performed %d backend reads after its CAS, want exactly 1 readback", got)
	}
	readback := f.remote.lastRead()
	published := pipelineRef{bytes: readback.Bytes, rev: readback.Revision}
	if !bytes.Equal(published.bytes, c.MergedBytes) || published.rev == r.rev {
		t.Fatal("coordinator readback is not exactly M at a new revision")
	}
	acked, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after Ack: %v", err)
	}
	if !bytes.Equal(acked.BaseBytes, c.MergedBytes) || acked.RemoteRevision != published.rev {
		t.Fatal("Ack did not promote Base to the exact readback M / revision")
	}
	if !bytes.Equal(acked.WorkingBytes, w2s.WorkingBytes) || acked.Generation != adopted.Generation+1 {
		t.Fatal("Ack did not preserve Working W2 at its newer generation")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record present after Ack: %v", err)
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record present after Ack: %v", err)
	}
	assertAdoptionAudit(t, j, src, r, prepared)

	// Close and reopen the real journal before asserting the durable outcome.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	state, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reopened LoadState: %v", err)
	}
	if !bytes.Equal(state.BaseBytes, c.MergedBytes) || state.RemoteRevision != published.rev {
		t.Fatal("reopened base/revision is not the exact readback M")
	}
	if !bytes.Equal(state.WorkingBytes, w2s.WorkingBytes) || state.Generation != adopted.Generation+1 {
		t.Fatal("reopened working/generation is not W2 at the adopted generation + 1")
	}
	if _, err := reopened.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	if _, err := reopened.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened Load = %v, want ErrEmpty", err)
	}
	reopenedAudit, err := reopened.LoadRebaseAudit(src.Generation + 1)
	if err != nil {
		t.Fatalf("reopened LoadRebaseAudit: %v", err)
	}
	if !lateAckStateEqual(reopenedAudit.OldState, src) {
		t.Fatal("reopened audit old state is not exactly S (B/L/revision/generation)")
	}
	if reopenedAudit.RemoteRevision != r.rev || !bytes.Equal(reopenedAudit.RemoteBase, r.bytes) ||
		!bytes.Equal(reopenedAudit.Proposal.Bytes, c.MergedBytes) ||
		reopenedAudit.Proposal.Generation != prepared.Proposal.Generation {
		t.Fatal("reopened audit target/proposal is not exactly R/Rrev/M")
	}
	assertAdoptionAudit(t, reopened, src, r, prepared)

	direct, err = f.remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("direct Read of the real directory: %v", err)
	}
	if direct.Revision != published.rev || !bytes.Equal(direct.Bytes, c.MergedBytes) {
		t.Fatal("the real directory does not hold the exact M at the readback revision")
	}

	// Authenticate both reopened records with the caller pin.
	baseFile, _, baseGot := openWorkingState(t, state.BaseBytes, f.pin, f.id)
	workFile, _, workGot := openWorkingState(t, state.WorkingBytes, f.pin, f.id)
	if baseFile.Header.RevisionID != mFile.Header.RevisionID || baseFile.Header.OpID != mFile.Header.OpID ||
		baseFile.Header.ContentSeq != mFile.Header.ContentSeq {
		t.Fatal("reopened base is not the authenticated M")
	}
	if workFile.Header.OpID != w2File.Header.OpID || workFile.Header.RevisionID != w2File.Header.RevisionID ||
		!bytes.Equal(workFile.Header.PrevDigest, pipelineRawDigest(t, baseFile)) ||
		workFile.Header.ContentSeq != baseFile.Header.ContentSeq+1 {
		t.Fatal("reopened working is not authenticated on top of M")
	}
	pipelineAssertItems(t, "reopened base item DB", baseGot, wantItems)

	edited := pipelineEditedFixtureItems(t, baseItems)
	local := pipelineItems(t, f, w2s.WorkingBytes)
	pipelineAssertItems(t, "reopened working item DB", workGot, append(edited, vault.CloneItem(localOnly)))
	for _, edit := range []struct{ id, title string }{
		{"login-1", "Login edited offline"},
		{"document-1", "Document edited offline"},
	} {
		if local[pipelineOnlyItem(t, local, edit.id)].Title != edit.title {
			t.Fatalf("working item %q does not carry its offline edit", edit.id)
		}
	}
	if local[pipelineOnlyItem(t, local, localOnly.ID)].Title != localOnly.Title {
		t.Fatal("working item DB lost the new local-only item")
	}
}

// lateAckTimeout bounds every wait of the late-ack test. It is only a failure
// guard for a missing signal or a deadlock; the interleaving itself is decided
// by the channel barrier.
const lateAckTimeout = 30 * time.Second

// awaitChannel receives one value from ch, failing the test with ctx's error
// instead of blocking forever when the producer never arrives or ctx expires.
func awaitChannel[T any](t *testing.T, ctx context.Context, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		var zero T
		t.Fatalf("timed out waiting for %s: %v", what, ctx.Err())
		return zero
	}
}

// lateAckStateEqual reports whether a and b hold the same state bytes,
// revision and generation.
func lateAckStateEqual(a, b vaultfilejournal.State) bool {
	return a.Generation == b.Generation &&
		a.RemoteRevision == b.RemoteRevision &&
		bytes.Equal(a.BaseBytes, b.BaseBytes) &&
		bytes.Equal(a.WorkingBytes, b.WorkingBytes)
}

// lateAckBackend is a narrow test adapter over the real backend. Its
// ReplaceIfVersion signals entered, waits for release and only then delegates
// the exact CAS to the embedded real backend; the result is propagated
// unchanged. Read, CreateIfAbsent, List and Close are the embedded backend's,
// unmodified.
type lateAckBackend struct {
	vaultfilebackend.Backend
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	mu          sync.Mutex
	attempts    int
	successes   int
}

// newLateAckBackend wraps b with a fresh barrier; release is opened exactly
// once through releaseOnce, by the test after its late local edit or by its
// deferred guard on every exit.
func newLateAckBackend(b vaultfilebackend.Backend) *lateAckBackend {
	return &lateAckBackend{
		Backend: b,
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (a *lateAckBackend) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	a.mu.Lock()
	a.attempts++
	a.mu.Unlock()
	a.entered <- struct{}{}
	select {
	case <-a.release:
	case <-ctx.Done():
		return fmt.Errorf("late ack barrier: %w", ctx.Err())
	}
	err := a.Backend.ReplaceIfVersion(ctx, name, expected, value)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.successes++
	a.mu.Unlock()
	return nil
}

func (a *lateAckBackend) replaceCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts
}

func (a *lateAckBackend) counts() (attempts, successes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attempts, a.successes
}
