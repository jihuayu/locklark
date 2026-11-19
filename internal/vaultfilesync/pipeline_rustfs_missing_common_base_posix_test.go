//go:build darwin || linux

package vaultfilesync

// Issue #122 missing-common-base refusal on the real local RustFS provider.
//
// The in-memory TestBuildMergeCandidateMissingBase proves that a working-only
// durable State is rejected before the backend read. This is the real-provider
// companion: two distinct authorized devices bootstrap from one authenticated
// common sealed baseline, device one makes a genuine offline working edit, and
// device two publishes a real divergent successor through the production
// BuildMergeCandidate/AdoptMergeCandidate/ResumePrepared and authenticated pull
// paths. A separate real on-disk recovery journal is then initialized with only
// device one's retained working bytes through the supported
// Journal.InitializeState initializer, so it has no durable base bytes and no
// remote revision. The source journal is left intact.
//
// BuildMergeCandidate is called on that recovered working-only journal through
// an independent real RustFS adapter that counts operations only. The call must
// return ErrMergeCandidateRejected with no candidate, no prepared or legacy
// proposal, no state change and no provider access at all. The test then
// reopens the recovery journal and reads the provider through a fresh handle,
// authenticating the restored local edit and the exact divergent remote
// version under both device identities. The recovered journal must still have a
// missing base anchor; neither the current remote revision nor a synthesized
// base may be adopted.
//
// This is opt-in and local-only, reusing requireRustFSPipeline,
// provisionRustFSPipelineBucket, the owned unique bucket and the pinned TLS
// guard from pipeline_rustfs_posix_test.go. It never contacts an external
// endpoint and is a focused acceptance of this one refusal path, not a claim
// about all providers.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// missingBaseOperations is a comparable snapshot of the only provider
// operations the refused call could perform.
type missingBaseOperations struct {
	reads    int
	replaces int
	creates  int
	lists    int
}

// missingBaseCountingBackend delegates every operation unchanged to one
// independent real adapter and counts the operations. It has no other behavior:
// no retry, no rewrite and no error translation.
type missingBaseCountingBackend struct {
	vaultfilebackend.Backend

	mu sync.Mutex
	op missingBaseOperations
}

func (b *missingBaseCountingBackend) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	b.mu.Lock()
	b.op.reads++
	b.mu.Unlock()
	return b.Backend.Read(ctx, name)
}

func (b *missingBaseCountingBackend) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	b.mu.Lock()
	b.op.creates++
	b.mu.Unlock()
	return b.Backend.CreateIfAbsent(ctx, name, value)
}

func (b *missingBaseCountingBackend) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	b.mu.Lock()
	b.op.replaces++
	b.mu.Unlock()
	return b.Backend.ReplaceIfVersion(ctx, name, expected, value)
}

func (b *missingBaseCountingBackend) List(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	b.op.lists++
	b.mu.Unlock()
	return b.Backend.List(ctx)
}

func (b *missingBaseCountingBackend) counts() missingBaseOperations {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.op
}

// missingBaseLoadState loads one durable journal state. Its failure text is a
// fixed label plus the redacted error class.
func missingBaseLoadState(t *testing.T, j *vaultfilejournal.Journal, label string) vaultfilejournal.State {
	t.Helper()
	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("%s journal state is unavailable: %s", label, rustfsPipelineSafeError(err))
	}
	return state
}

// missingBaseWantEstablishedState requires the exact common base pair and
// working generation. It never prints state bytes.
func missingBaseWantEstablishedState(t *testing.T, state vaultfilejournal.State, base pipelineRef, wantGeneration uint64, label string) {
	t.Helper()
	if !bytes.Equal(state.BaseBytes, base.bytes) || state.RemoteRevision != base.rev ||
		state.Generation != wantGeneration {
		t.Fatalf("%s journal does not carry the exact common base/revision/generation", label)
	}
}

// missingBaseWantWorkingOnly requires a retained working draft with no base
// bytes and no remote revision at the exact generation. It never prints bytes.
func missingBaseWantWorkingOnly(t *testing.T, state vaultfilejournal.State, wantWorking []byte, wantGeneration uint64, label string) {
	t.Helper()
	if len(state.BaseBytes) != 0 || state.RemoteRevision != "" ||
		!bytes.Equal(state.WorkingBytes, wantWorking) || state.Generation != wantGeneration {
		t.Fatalf("%s is not the exact working-only draft without a common-base anchor", label)
	}
}

// missingBaseWantNoCandidate requires the zero candidate on rejection without
// formatting any candidate field.
func missingBaseWantNoCandidate(t *testing.T, c MergeCandidate) {
	t.Helper()
	if c.RemoteBytes != nil || c.MergedBytes != nil || c.RemoteRevision != "" ||
		c.ExpectedGeneration != 0 || c.Conflicts != nil ||
		c.sourceBinding != ([32]byte{}) || c.resultBinding != ([32]byte{}) {
		t.Fatal("missing common base returned a candidate")
	}
}

// missingBaseWantNoPlaintext reports only a fixed class; it never prints the
// matched marker or the error text.
func missingBaseWantNoPlaintext(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, marker := range plaintextMarkers {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("missing-common-base rejection exposed plaintext")
		}
	}
}

// TestPipelineRustFSMissingCommonBasePreservesWorkingDraft is the real-provider
// acceptance for issue #122. It owns only this run's unique bucket and prefix.
func TestPipelineRustFSMissingCommonBasePreservesWorkingDraft(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	const prefix = "missing-common-base-pipeline"

	seeded := env.newBackendAt(t, bucket, prefix)
	runMissingCommonBaseScenario(t, seeded, func(t *testing.T) vaultfilebackend.Backend {
		return env.newBackendAt(t, bucket, prefix)
	})
}

// runMissingCommonBaseScenario seeds one authenticated B, establishes two
// independently closed/reopened on-disk journals at the exact same B/Brev,
// records device one's offline edit, publishes device two's divergent successor,
// and then proves that a recovered working-only journal is refused without any
// provider access or local mutation. newHandle must return a genuinely
// independent real backend handle over the same owned object.
func runMissingCommonBaseScenario(t *testing.T, seeded vaultfilebackend.Backend, newHandle func(*testing.T) vaultfilebackend.Backend) {
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

	// Both devices independently bootstrap from the exact same authenticated
	// common baseline supplied by the fixture.
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
		t.Fatal("the two journals did not start at the exact common authenticated baseline")
	}

	baseItems := twoDeviceItems(t, b1.bytes, material, twoDeviceOneID)
	if len(baseItems) == 0 {
		t.Fatal("synthetic two-device baseline item database is empty")
	}
	editOne := twoDeviceReplace(t, "login-1", twoDeviceOneTitle)
	editTwo := twoDeviceReplace(t, "document-1", twoDeviceTwoTitle)
	wantLocal := editOne(baseItems)
	wantRemote := editTwo(baseItems)

	// Device one keeps a genuine offline working edit. Device two also edits
	// offline and later publishes a real divergent successor.
	twoDeviceEdit(t, one, material, twoDeviceOneID, editOne)
	twoDeviceEdit(t, two, material, twoDeviceTwoID, editTwo)

	unchanged, err := second.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read remote after offline edits: %s", rustfsPipelineSafeError(err))
	}
	if unchanged.Revision != b1.rev || !bytes.Equal(unchanged.Bytes, b1.bytes) {
		t.Fatal("an offline edit wrote to the provider or changed its revision")
	}

	// Close and reopen both real journals. Device one's source journal retains
	// the exact common base, its recovered offline edit and generation 1.
	closeNow(t, one)
	one = openJournalAt(t, onePath)
	closeNow(t, two)
	two = openJournalAt(t, twoPath)
	oneState := missingBaseLoadState(t, one, "reopened device one")
	twoState := missingBaseLoadState(t, two, "reopened device two")
	missingBaseWantEstablishedState(t, oneState, b1, 1, "reopened device one")
	missingBaseWantEstablishedState(t, twoState, b1, 1, "reopened device two")
	laterWriterAssertItems(t, "device one offline edit item DB",
		twoDeviceItems(t, oneState.WorkingBytes, material, twoDeviceOneID), wantLocal)
	laterWriterAssertItems(t, "device two offline edit item DB",
		twoDeviceItems(t, twoState.WorkingBytes, material, twoDeviceTwoID), wantRemote)
	twoDeviceWantNoPending(t, one)
	twoDeviceWantNoPending(t, two)

	// Device two publishes its divergent offline edit through the production
	// candidate, adoption, prepared, authenticated-pull and coordinator paths.
	candidateTwo, err := BuildMergeCandidate(ctx, second, remoteName, two, material.pin,
		twoDeviceTwoID, material.keys[twoDeviceTwoID].identity, material.keys[twoDeviceTwoID].signing)
	if err != nil {
		t.Fatalf("device two BuildMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	defer candidateTwo.Clear()
	if candidateTwo.Conflicts == nil || len(candidateTwo.Conflicts) != 0 || candidateTwo.MergedBytes == nil ||
		!bytes.Equal(candidateTwo.RemoteBytes, b1.bytes) || candidateTwo.RemoteRevision != b1.rev ||
		candidateTwo.ExpectedGeneration != twoState.Generation {
		t.Fatal("device two candidate is not the conflict-free successor of the exact common baseline")
	}
	if err := AdoptMergeCandidate(ctx, two, candidateTwo, material.pin,
		twoDeviceTwoID, material.keys[twoDeviceTwoID].identity); err != nil {
		t.Fatalf("device two AdoptMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	preparedTwo, err := two.LoadPrepared()
	if err != nil {
		t.Fatalf("device two prepared record failed: %s", rustfsPipelineSafeError(err))
	}
	twoDeviceVerifyAuthor(t, candidateTwo.MergedBytes, material, twoDeviceTwoID)
	if preparedTwo.WorkingGeneration != twoState.Generation+1 ||
		preparedTwo.Proposal.ExpectedRevision != b1.rev ||
		!bytes.Equal(preparedTwo.Proposal.Bytes, candidateTwo.MergedBytes) {
		t.Fatal("device two prepared record does not name its exact candidate over the common baseline")
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
		t.Fatal("device two did not pull the exact common baseline")
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
	laterWriterAssertItems(t, "published device two item DB",
		twoDeviceItems(t, rBytes, material, twoDeviceTwoID), wantRemote)
	twoDeviceWantNoPending(t, two)
	if bytes.Equal(rBytes, oneState.WorkingBytes) || bytes.Equal(rBytes, b1.bytes) {
		t.Fatal("the published remote version is not genuinely divergent from the local draft and common baseline")
	}

	// The untouched source journal still holds the exact common base and the
	// genuine offline local edit at generation 1.
	source := missingBaseLoadState(t, one, "device one source")
	missingBaseWantEstablishedState(t, source, b1, 1, "device one source")
	laterWriterAssertItems(t, "device one source local edit item DB",
		twoDeviceItems(t, source.WorkingBytes, material, twoDeviceOneID), wantLocal)

	// Model local draft recovery in a separate real on-disk journal. Only the
	// retained working bytes are carried over through the supported initializer;
	// the durable common-base bytes and remote revision are deliberately absent.
	wantRecovered := bytes.Clone(source.WorkingBytes)
	recovered := openNewJournal(t)
	recoveryPath := journalPath(t, recovered)
	if err := recovered.InitializeState(vaultfilejournal.State{
		WorkingBytes: bytes.Clone(wantRecovered),
	}); err != nil {
		t.Fatalf("initialize recovered working-only journal failed: %s", rustfsPipelineSafeError(err))
	}
	missingBaseWantWorkingOnly(t, missingBaseLoadState(t, recovered, "recovered"),
		wantRecovered, 0, "recovered working-only journal")
	twoDeviceWantNoPending(t, recovered)

	// The refusal is observed through one independent real provider adapter
	// wrapped only to count operations.
	counting := &missingBaseCountingBackend{Backend: newHandle(t)}
	operationsBefore := counting.counts()
	candidate, err := BuildMergeCandidate(ctx, counting, remoteName, recovered, material.pin,
		twoDeviceOneID, material.keys[twoDeviceOneID].identity, material.keys[twoDeviceOneID].signing)
	if !errors.Is(err, ErrMergeCandidateRejected) {
		t.Fatalf("missing common base was not rejected: %s", rustfsPipelineSafeError(err))
	}
	missingBaseWantNoCandidate(t, candidate)
	missingBaseWantNoPlaintext(t, err)

	// The rejected call must not touch the provider at all, must not prepare or
	// record a proposal, and must not change generation, working bytes, base
	// bytes or revision.
	if after := counting.counts(); after != operationsBefore {
		t.Fatal("refused missing-base call accessed the provider")
	}
	missingBaseWantWorkingOnly(t, missingBaseLoadState(t, recovered, "post-refusal"),
		wantRecovered, 0, "post-refusal recovered journal")
	twoDeviceWantNoPending(t, recovered)

	// Reopen the established recovery journal and use a fresh independent
	// provider handle. The restored working-only bytes still authenticate under
	// both devices and carry the recovered local edit, while the missing base
	// anchor remains missing.
	closeNow(t, recovered)
	recovered = openJournalAt(t, recoveryPath)
	restored := missingBaseLoadState(t, recovered, "reopened recovered")
	missingBaseWantWorkingOnly(t, restored, wantRecovered, 0, "reopened recovered working-only journal")
	twoDeviceWantNoPending(t, recovered)
	twoDeviceVerifyAuthor(t, restored.WorkingBytes, material, twoDeviceOneID)
	laterWriterAssertItems(t, "reopened recovered local draft via device one",
		twoDeviceItems(t, restored.WorkingBytes, material, twoDeviceOneID), wantLocal)
	laterWriterAssertItems(t, "reopened recovered local draft via device two",
		twoDeviceItems(t, restored.WorkingBytes, material, twoDeviceTwoID), wantLocal)

	// The exact real remote version and opaque revision are unchanged, and its
	// independent remote edit authenticates under both device identities.
	fresh := newHandle(t)
	remoteAfter, err := fresh.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("fresh provider read after refusal failed: %s", rustfsPipelineSafeError(err))
	}
	if remoteAfter.Revision != rRevision || !bytes.Equal(remoteAfter.Bytes, rBytes) {
		t.Fatal("the refused missing-base call changed the exact remote bytes or revision")
	}
	if remoteAfter.Revision == b1.rev || bytes.Equal(remoteAfter.Bytes, restored.WorkingBytes) {
		t.Fatal("the remote version is not the independent divergent version")
	}
	twoDeviceVerifyAuthor(t, remoteAfter.Bytes, material, twoDeviceTwoID)
	laterWriterAssertItems(t, "remote divergent version via device one",
		twoDeviceItems(t, remoteAfter.Bytes, material, twoDeviceOneID), wantRemote)
	laterWriterAssertItems(t, "remote divergent version via device two",
		twoDeviceItems(t, remoteAfter.Bytes, material, twoDeviceTwoID), wantRemote)

	// The real source journal was never vandalized: it still carries its exact
	// common base, revision, working edit and generation after the refusal.
	closeNow(t, one)
	one = openJournalAt(t, onePath)
	sourceAfter := missingBaseLoadState(t, one, "reopened device one source")
	if sourceAfter.Generation != source.Generation ||
		!bytes.Equal(sourceAfter.BaseBytes, source.BaseBytes) ||
		sourceAfter.RemoteRevision != source.RemoteRevision ||
		!bytes.Equal(sourceAfter.WorkingBytes, source.WorkingBytes) {
		t.Fatal("the real source journal changed during recovery and refusal")
	}
	twoDeviceWantNoPending(t, one)
}
