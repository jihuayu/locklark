//go:build darwin || linux

package vaultfilesync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// TestPipelinePublishThirdWriterPreservesLocalWorking is the local-provider CAS
// third-writer regression. Two independent, correctly authorized publisher
// paths start from the exact common base B. The active path has already read
// its merge source and adopted its conflict-free candidate M when its first
// legitimate ReplaceIfVersion is entered. At that instant, deterministically
// inside the CAS call, a second real backend handle commits a genuine third
// version T from B's exact revision and then the active CAS is forwarded,
// unmodified, to the real directory backend. The real CAS must report its own
// conflict; the journal must not acknowledge M, and must preserve M's local
// working edit plus the original base and prepared recovery record across a
// close and reopen while T remains the exact advanced remote version.
//
// The interleaving is in-call ordering, never a sleep: the hook runs after the
// active call is inside ReplaceIfVersion and before the losing candidate is
// delegated. The second handle is a separate real Dir on the same store, so
// the third write is a real directory CAS at exactly the expected revision.
func TestPipelinePublishThirdWriterPreservesLocalWorking(t *testing.T) {
	f, store := newThirdWriterFixture(t)
	second, err := vaultfilebackend.OpenDir(store)
	if err != nil {
		t.Fatalf("OpenDir (second handle): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	runThirdWriterScenario(t, f, second)
}

// runThirdWriterScenario is the shared end-to-end third-writer scenario. The
// caller supplies the fixture's first real backend handle through f and one
// independently constructed second real handle on the same store. The two
// handles must address the same remote objects, but neither may be a mock or a
// second view of in-memory state.
func runThirdWriterScenario(t *testing.T, f *fixture, second vaultfilebackend.Backend) {
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
		localTitle = "Login edited offline"
		thirdTitle = "Document edited by third writer"
	)
	localEdit := pipelineReplace(t, "login-1", localTitle)
	thirdEdit := pipelineReplace(t, "document-1", thirdTitle)
	wantLocal := localEdit(baseItems)
	wantThird := thirdEdit(baseItems)
	wantBoth := thirdEdit(wantLocal)

	// The active publisher path edits one item above the exact common base B
	// and adopts its conflict-free candidate M without publishing it.
	pipelineEdit(t, f, j, localEdit)
	src, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after local edit: %v", err)
	}
	if !bytes.Equal(src.BaseBytes, b.bytes) || src.RemoteRevision != b.rev || src.Generation != 1 {
		t.Fatal("active local state is not the exact common base B/Brev at generation 1")
	}

	c, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	defer c.Clear()
	if c.Conflicts == nil || len(c.Conflicts) != 0 || c.MergedBytes == nil {
		t.Fatal("losing candidate is not a conflict-free sealed result")
	}
	if c.RemoteRevision != b.rev || !bytes.Equal(c.RemoteBytes, b.bytes) ||
		c.ExpectedGeneration != src.Generation || c.sourceBinding != mergeCandidateSourceBinding(src) {
		t.Fatal("losing candidate does not name the exact common base and source state")
	}
	pipelineAssertItems(t, "losing candidate item DB", pipelineItems(t, f, c.MergedBytes), wantLocal)

	if err := AdoptMergeCandidate(context.Background(), j, c, f.pin, fixtureDeviceID, f.id); err != nil {
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

	// The independent third publisher path also starts from the exact common
	// base and edits a different item. UpdateWorkingItems produces a genuinely
	// authenticated successor of B, not a fabricated file.
	tj := openJournalAt(t, journalDBPath(t))
	if err := tj.InitializeState(vaultfilejournal.State{BaseBytes: b.bytes, RemoteRevision: b.rev, WorkingBytes: b.bytes}); err != nil {
		t.Fatalf("InitializeState (third writer): %v", err)
	}
	pipelineEdit(t, f, tj, thirdEdit)
	thirdState, err := tj.LoadState()
	if err != nil {
		t.Fatalf("LoadState (third writer): %v", err)
	}
	if !bytes.Equal(thirdState.BaseBytes, b.bytes) || thirdState.RemoteRevision != b.rev || thirdState.Generation != 1 {
		t.Fatal("third writer state is not the exact common base B/Brev at generation 1")
	}
	closeNow(t, tj)

	bFile, tFile, _, _ := pipelineOpenPair(t, f, b.bytes, thirdState.WorkingBytes)
	if tFile.Header.ContentSeq != bFile.Header.ContentSeq+1 {
		t.Fatalf("third writer ContentSeq = %d, want B+1 = %d", tFile.Header.ContentSeq, bFile.Header.ContentSeq+1)
	}
	if !bytes.Equal(tFile.Header.PrevDigest, pipelineRawDigest(t, bFile)) {
		t.Fatal("third writer is not linked to the common base digest")
	}
	if tFile.Header.AuthorDeviceID != fixtureDeviceID {
		t.Fatalf("third writer author = %q, want the authorized fixture device", tFile.Header.AuthorDeviceID)
	}
	verifier, err := NewContentProposalVerifier(f.pin)
	if err != nil {
		t.Fatalf("NewContentProposalVerifier: %v", err)
	}
	// Positive authorization assertion: the third bytes are the immediate,
	// policy-preserving successor of B, authored by a current writer.
	if err := verifier(ctx, b.bytes, b.rev, vaultfilejournal.Proposal{
		Generation:       thirdState.Generation,
		OperationID:      tFile.Header.OpID,
		ExpectedRevision: b.rev,
		Bytes:            thirdState.WorkingBytes,
	}); err != nil {
		t.Fatalf("third writer proposal verification: %v", err)
	}

	// The caller supplied a second, independently constructed real handle on
	// exactly the same store.
	third := &thirdWriterCAS{Backend: second}

	// The active path pulls its merge source exactly once: the original B at
	// Brev. This is the value ResumePrepared will use, and it is already read
	// before the CAS hook runs.
	reads := f.remote.readCount()
	pulledB, err := vaultfilepublish.ReadPulled(ctx, f.remote, remoteName, pipelinePullVerifier(t, f))
	if err != nil {
		t.Fatalf("ReadPulled (active merge source): %v", err)
	}
	if got := f.remote.readCount() - reads; got != 1 {
		t.Fatalf("active merge-source pull performed %d backend reads, want 1", got)
	}
	if pulledB.Revision() != b.rev || !bytes.Equal(pulledB.Bytes(), b.bytes) {
		t.Fatal("active merge source is not the exact common base B/Brev")
	}

	var (
		thirdRevision vaultfilebackend.Revision
		thirdBytes    []byte
	)
	gate := &thirdWriterCAS{Backend: f.remote}
	gate.onFirstReplace = func(callCtx context.Context, expected vaultfilebackend.Revision) error {
		if expected != b.rev || expected != prepared.Proposal.ExpectedRevision {
			return fmt.Errorf("active CAS expected revision is not the common base")
		}
		direct, err := second.Read(callCtx, remoteName)
		if err != nil {
			return fmt.Errorf("read before third writer CAS: %w", err)
		}
		if direct.Revision != expected || !bytes.Equal(direct.Bytes, b.bytes) {
			return fmt.Errorf("real directory is not the exact common base before the third writer CAS")
		}
		if err := third.ReplaceIfVersion(callCtx, remoteName, expected, thirdState.WorkingBytes); err != nil {
			return fmt.Errorf("third writer CAS: %w", err)
		}
		committed, err := second.Read(callCtx, remoteName)
		if err != nil {
			return fmt.Errorf("read after third writer CAS: %w", err)
		}
		if committed.Revision == expected || !bytes.Equal(committed.Bytes, thirdState.WorkingBytes) {
			return fmt.Errorf("third writer CAS did not advance to its exact sealed contents")
		}
		thirdRevision = committed.Revision
		thirdBytes = bytes.Clone(committed.Bytes)
		return nil
	}

	coord, err := vaultfilepublish.NewCoordinator(gate, j, remoteName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	err = coord.ResumePrepared(ctx, pulledB, pipelinePullVerifier(t, f))
	if err == nil {
		t.Fatal("ResumePrepared returned nil, want the real directory CAS conflict")
	}
	if !errors.Is(err, vaultfilepublish.ErrConflict) || !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("ResumePrepared = %v, want the real directory CAS conflict", err)
	}
	if errors.Is(err, vaultfilebackend.ErrUnknown) {
		t.Fatalf("ResumePrepared = %v, want a definite conflict, not an unknown outcome", err)
	}

	if attempts, successes := gate.counts(); attempts != 1 || successes != 0 {
		t.Fatalf("active CAS attempts = %d, real Dir successes = %d; want 1, 0", attempts, successes)
	}
	if gate.expected() != prepared.Proposal.ExpectedRevision {
		t.Fatal("active CAS did not use the prepared expected revision")
	}
	if attempts, successes := third.counts(); attempts != 1 || successes != 1 {
		t.Fatalf("third writer CAS attempts = %d, real Dir successes = %d; want 1, 1", attempts, successes)
	}
	if third.expected() != b.rev || third.expected() != prepared.Proposal.ExpectedRevision {
		t.Fatal("third writer CAS did not use the exact active expected revision")
	}
	if thirdRevision == b.rev || len(thirdBytes) == 0 {
		t.Fatal("third writer did not advance to a new exact revision")
	}

	// The exact advanced revision and authenticated third contents won.
	published, reads := pipelinePull(t, f)
	if reads != 1 || published.rev != thirdRevision || !bytes.Equal(published.bytes, thirdBytes) {
		t.Fatal("remote does not hold the exact advanced third revision and contents")
	}
	pipelineAssertItems(t, "third writer item DB", pipelineItems(t, f, published.bytes), wantThird)
	if bytes.Equal(published.bytes, c.MergedBytes) {
		t.Fatal("the losing candidate was written despite the real CAS conflict")
	}

	// No acknowledgement or clobber: the durable state is still exactly the
	// adopted B/Brev + local M, and the prepared recovery record is untouched.
	afterConflict, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after conflict: %v", err)
	}
	if !lateAckStateEqual(afterConflict, adopted) {
		t.Fatal("conflict changed the adopted base, working or generation")
	}
	pipelineAssertItems(t, "durable losing local working item DB", pipelineItems(t, f, afterConflict.WorkingBytes), wantLocal)
	preparedAfterConflict, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after conflict: %v", err)
	}
	if !thirdWriterPreparedEqual(preparedAfterConflict, prepared) {
		t.Fatal("conflict changed the prepared recovery record")
	}
	if _, err := j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal present after conflict: %v", err)
	}
	assertAdoptionAudit(t, j, src, b, prepared)

	// Positive mergeability assertion: a fresh candidate over the losing local
	// M and the winning third version T preserves both independent base edits.
	recovery, err := BuildMergeCandidate(ctx, f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate (recovery): %v", err)
	}
	defer recovery.Clear()
	if recovery.Conflicts == nil || len(recovery.Conflicts) != 0 || recovery.MergedBytes == nil {
		t.Fatal("recovery candidate is not conflict-free; the independent base edits do not merge")
	}
	if recovery.RemoteRevision != thirdRevision || !bytes.Equal(recovery.RemoteBytes, thirdBytes) {
		t.Fatal("recovery candidate did not read the exact advanced third revision")
	}
	pipelineAssertItems(t, "recovery candidate item DB", pipelineItems(t, f, recovery.MergedBytes), wantBoth)

	// Close and reopen the real journal. The local edit and the original
	// base/prepared recovery information must survive without a false Ack or
	// another write.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	state, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reopened LoadState: %v", err)
	}
	if !lateAckStateEqual(state, adopted) {
		t.Fatal("reopened state is not the unchanged adopted B/Brev + local M")
	}
	pipelineAssertItems(t, "reopened local working item DB", pipelineItems(t, f, state.WorkingBytes), wantLocal)
	reopenedPrepared, err := reopened.LoadPrepared()
	if err != nil {
		t.Fatalf("reopened LoadPrepared: %v", err)
	}
	if !thirdWriterPreparedEqual(reopenedPrepared, prepared) {
		t.Fatal("reopened prepared recovery record is not the exact pending M proposal")
	}
	if _, err := reopened.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("reopened Load = %v, want ErrEmpty", err)
	}
	assertAdoptionAudit(t, reopened, src, b, prepared)
	if attempts, successes := gate.counts(); attempts != 1 || successes != 0 {
		t.Fatalf("reopen changed active CAS attempts/successes to %d/%d, want 1/0", attempts, successes)
	}
	if attempts, successes := third.counts(); attempts != 1 || successes != 1 {
		t.Fatalf("reopen changed third CAS attempts/successes to %d/%d, want 1/1", attempts, successes)
	}

	final, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("final Read of the real directory: %v", err)
	}
	if final.Revision != thirdRevision || !bytes.Equal(final.Bytes, thirdBytes) {
		t.Fatal("real directory no longer holds the exact advanced third revision")
	}
	pipelineAssertItems(t, "final third writer item DB", pipelineItems(t, f, final.Bytes), wantThird)
}

// thirdWriterPreparedEqual reports whether two prepared records are the same
// binding: working generation, proposal generation, operation, expected
// revision and bytes.
func thirdWriterPreparedEqual(a, b vaultfilejournal.PreparedProposal) bool {
	return a.WorkingGeneration == b.WorkingGeneration &&
		a.Proposal.Generation == b.Proposal.Generation &&
		a.Proposal.OperationID == b.Proposal.OperationID &&
		a.Proposal.ExpectedRevision == b.Proposal.ExpectedRevision &&
		bytes.Equal(a.Proposal.Bytes, b.Proposal.Bytes)
}

// newThirdWriterFixture builds the same real written remote fixture as
// newFixture over the real directory backend, but returns the store path too so
// the test can open a second real Dir handle on exactly that store. It reuses
// the package's fixture helpers and tracking backend.
func newThirdWriterFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatalf("Mkdir store: %v", err)
	}
	backend, err := vaultfilebackend.OpenDir(store)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return newThirdWriterFixtureAt(t, backend), store
}

// newThirdWriterFixtureAt builds the written remote fixture over backend. The
// caller owns backend's Close, so the same fixture can serve the local
// directory regression and the opt-in real S3 provider scenario.
func newThirdWriterFixtureAt(t *testing.T, backend vaultfilebackend.Backend) *fixture {
	t.Helper()
	p, id, _ := fixtureInputs(t)
	remoteBytes := sealRemote(t)
	remote := &trackingBackend{Backend: backend}
	if err := remote.CreateIfAbsent(context.Background(), remoteName, remoteBytes); err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	return &fixture{remote: remote, pin: fixturePin(t, p), id: id, bytes: remoteBytes}
}

// thirdWriterCAS is a narrow test adapter over the real backend. It records
// each ReplaceIfVersion, runs the optional first-call hook while the active CAS
// is still inside the call, then delegates the exact expected revision and
// value to the embedded unmodified backend and propagates its result. The hook
// is cleared before it runs, so the adversarial transition can fire only once.
type thirdWriterCAS struct {
	vaultfilebackend.Backend
	mu             sync.Mutex
	onFirstReplace func(context.Context, vaultfilebackend.Revision) error
	replaces       int
	successes      int
	lastExpected   vaultfilebackend.Revision
}

func (b *thirdWriterCAS) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	b.mu.Lock()
	b.replaces++
	b.lastExpected = expected
	inject := b.onFirstReplace
	b.onFirstReplace = nil
	b.mu.Unlock()
	if inject != nil {
		if err := inject(ctx, expected); err != nil {
			return err
		}
	}
	err := b.Backend.ReplaceIfVersion(ctx, name, expected, value)
	if err == nil {
		b.mu.Lock()
		b.successes++
		b.mu.Unlock()
	}
	return err
}

func (b *thirdWriterCAS) counts() (attempts, successes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.replaces, b.successes
}

func (b *thirdWriterCAS) expected() vaultfilebackend.Revision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastExpected
}
