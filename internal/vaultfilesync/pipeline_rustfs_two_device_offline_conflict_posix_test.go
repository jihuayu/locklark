//go:build darwin || linux

package vaultfilesync

// Issue #122 same-item/same-field two-device offline conflict acceptance.
//
// This extends the committed two-device clean-merge evidence with exactly one
// conflicting case. Two distinct synthetic device identities, made only by the
// test fixture, independently bootstrap separate on-disk journals from the
// same authenticated remote B/Brev and edit the same item and the same field
// (its title) differently while offline. Device 2 then prepares, publishes and
// acknowledges its edit through the real pipeline. Device 1 sees that exact
// changed provider pair and asks the real BuildMergeCandidate for a successor.
// The result must be one same-item/same-field conflict with both complete
// sides, no merged authenticated bytes and no adoptable candidate. A real
// adoption attempt must fail closed without a journal or provider write.
//
// The identities are deliberately independent synthetic enrollment entries,
// not product/device enrolment. This test does not exercise enrolment, pairing,
// account material or production providers. It reuses the positive file's
// synthetic two-device material, baseline, journal and item helpers so both
// cases authenticate and decrypt through the same exact boundaries.
//
// The test is opt-in and local-only, using the same pinned RustFS environment,
// credentials, TLS guard, unique bucket ownership and cleanup as
// TestPipelineTwoDeviceOfflineMergeOnRustFS; see pipeline_rustfs_posix_test.go.
// It is skipped unless RUSTFS_SMOKE_ENABLE=1 plus the documented endpoint, CA
// and private credential file are supplied. No provider write occurs during
// the conflict preview or the failed adoption.

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

const (
	twoDeviceConflictCategory      = "same-item/same-field"
	twoDeviceConflictItemSelector  = "login-1"
	twoDeviceConflictFieldSelector = "title"
	twoDeviceConflictOneTitle      = "Login conflict edited offline by synthetic device one"
	twoDeviceConflictTwoTitle      = "Login conflict edited offline by synthetic device two"
)

// twoDeviceConflictTrackingBackend embeds the real provider handle and the
// package's read tracker, and counts every conditional write or creation at
// the test boundary. It never fakes a write: a zero count proves the embedded
// real backend was never asked to mutate anything.
type twoDeviceConflictTrackingBackend struct {
	*trackingBackend
	mu               sync.Mutex
	creates          int
	replaces         int
	replaceSuccesses int
}

func (b *twoDeviceConflictTrackingBackend) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	b.mu.Lock()
	b.creates++
	b.mu.Unlock()
	return b.Backend.CreateIfAbsent(ctx, name, value)
}

func (b *twoDeviceConflictTrackingBackend) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	b.mu.Lock()
	b.replaces++
	b.mu.Unlock()
	err := b.Backend.ReplaceIfVersion(ctx, name, expected, value)
	if err == nil {
		b.mu.Lock()
		b.replaceSuccesses++
		b.mu.Unlock()
	}
	return err
}

func (b *twoDeviceConflictTrackingBackend) writeCounts() (creates, replaces, successes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.creates, b.replaces, b.replaceSuccesses
}

// twoDeviceConflictAssertSameItemField checks the one conflict category this
// scenario expects: one exact selector whose base, local and remote sides are
// complete items that differ only in the selected field and carry three
// distinct synthetic edits. Failure text and the log never include item values.
func twoDeviceConflictAssertSameItemField(t *testing.T, candidate MergeCandidate, wantBase, wantLocal, wantRemote vault.Item) {
	t.Helper()
	if candidate.Conflicts == nil || len(candidate.Conflicts) != 1 {
		t.Fatalf("conflict count = %d, want exactly 1 same-item/same-field conflict", len(candidate.Conflicts))
	}
	conflict := candidate.Conflicts[0]
	if conflict.ID != twoDeviceConflictItemSelector {
		t.Fatalf("conflict selector does not name the exact item %q", twoDeviceConflictItemSelector)
	}
	if conflict.Base == nil || conflict.Local == nil || conflict.Remote == nil {
		t.Fatal("conflict does not retain all three complete same-item sides")
	}
	if !reflect.DeepEqual(*conflict.Base, wantBase) ||
		!reflect.DeepEqual(*conflict.Local, wantLocal) ||
		!reflect.DeepEqual(*conflict.Remote, wantRemote) {
		t.Fatal("conflict sides do not retain the exact expected complete items")
	}
	base, local, remote := *conflict.Base, *conflict.Local, *conflict.Remote
	base.Title, local.Title, remote.Title = "", "", ""
	if !reflect.DeepEqual(base, local) || !reflect.DeepEqual(base, remote) {
		t.Fatalf("conflict category is not the same item and same field (%s)", twoDeviceConflictFieldSelector)
	}
	if conflict.Base.Title == conflict.Local.Title ||
		conflict.Base.Title == conflict.Remote.Title ||
		conflict.Local.Title == conflict.Remote.Title {
		t.Fatal("same-item/same-field conflict sides do not retain three distinct edits")
	}
	t.Logf("offline conflict category=%s item=%s field=%s count=%d",
		twoDeviceConflictCategory, twoDeviceConflictItemSelector, twoDeviceConflictFieldSelector, len(candidate.Conflicts))
}

// twoDeviceConflictAssertState compares the exact journal generation, base,
// working bytes and remote revision without printing any of them.
func twoDeviceConflictAssertState(t *testing.T, label string, got, want vaultfilejournal.State) {
	t.Helper()
	if got.Generation != want.Generation ||
		got.RemoteRevision != want.RemoteRevision ||
		!bytes.Equal(got.BaseBytes, want.BaseBytes) ||
		!bytes.Equal(got.WorkingBytes, want.WorkingBytes) {
		t.Fatalf("%s no longer holds the exact base, working bytes and generation", label)
	}
}

// twoDeviceConflictWantNoAudit requires that no rebase audit exists for the
// next generation, the only audit a successful adoption could write here.
func twoDeviceConflictWantNoAudit(t *testing.T, journal *vaultfilejournal.Journal, generation uint64) {
	t.Helper()
	if _, err := journal.LoadRebaseAudit(generation + 1); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal unexpectedly holds a rebase audit: %s", rustfsPipelineSafeError(err))
	}
}

// TestPipelineTwoDeviceOfflineConflictOnRustFS is the real-provider
// acceptance for the same-item/same-field offline conflict. It owns only its
// run's unique bucket and prefix and follows the same opt-in local-only RustFS
// harness as the existing pipeline and positive two-device tests.
func TestPipelineTwoDeviceOfflineConflictOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	const prefix = "two-device-offline-conflict-pipeline"

	first := env.newBackendAt(t, bucket, prefix)
	runTwoDeviceOfflineConflictScenario(t, first, func(t *testing.T) vaultfilebackend.Backend {
		return env.newBackendAt(t, bucket, prefix)
	})
}

// runTwoDeviceOfflineConflictScenario seeds one authenticated B, bootstraps
// two separately closed/reopened on-disk journals from the same exact B/Brev,
// publishes Device 2's offline edit, and previews Device 1's conflicting edit
// against that exact changed provider pair. newHandle must construct a
// genuinely independent real backend handle over the same owned object.
func runTwoDeviceOfflineConflictScenario(t *testing.T, seeded vaultfilebackend.Backend, newHandle func(*testing.T) vaultfilebackend.Backend) {
	t.Helper()
	t.Log("enrollment category: independent synthetic enrollment; product/device enrolment: not exercised")
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
	editOne := twoDeviceReplace(t, twoDeviceConflictItemSelector, twoDeviceConflictOneTitle)
	editTwo := twoDeviceReplace(t, twoDeviceConflictItemSelector, twoDeviceConflictTwoTitle)
	wantOne := editOne(baseItems)
	wantTwo := editTwo(baseItems)
	wantBase := baseItems[pipelineOnlyItem(t, baseItems, twoDeviceConflictItemSelector)]
	wantLocal := wantOne[pipelineOnlyItem(t, wantOne, twoDeviceConflictItemSelector)]
	wantRemote := wantTwo[pipelineOnlyItem(t, wantTwo, twoDeviceConflictItemSelector)]

	// Both devices edit the same item and the same field offline. These calls
	// only advance their local journal generations; no provider write occurs.
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
	laterWriterAssertItems(t, "device one offline conflict edit item DB", twoDeviceItems(t, oneState.WorkingBytes, material, twoDeviceOneID), wantOne)
	laterWriterAssertItems(t, "device two offline edit item DB", twoDeviceItems(t, twoState.WorkingBytes, material, twoDeviceTwoID), wantTwo)
	twoDeviceWantNoPending(t, one)
	twoDeviceWantNoPending(t, two)
	twoDeviceConflictWantNoAudit(t, one, oneState.Generation)
	twoDeviceConflictWantNoAudit(t, two, twoState.Generation)

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

	// Device 1 has not changed since its offline edit. Capture the exact local
	// state before the conflict preview and adoption attempt.
	beforeOne, err := one.LoadState()
	if err != nil {
		t.Fatalf("load device one state before conflict preview failed: %s", rustfsPipelineSafeError(err))
	}
	if !bytes.Equal(beforeOne.BaseBytes, b1.bytes) || beforeOne.RemoteRevision != b1.rev {
		t.Fatal("device one base is not the exact common B/Brev before conflict preview")
	}
	twoDeviceConflictAssertState(t, "device one before conflict preview", beforeOne, oneState)
	twoDeviceWantNoPending(t, one)
	twoDeviceConflictWantNoAudit(t, one, beforeOne.Generation)

	// The tracking adapter embeds the real independent handle and counts every
	// conditional write or creation at the test boundary. Reads are counted
	// separately so the preview must perform exactly one provider read.
	readTracking := &trackingBackend{Backend: newHandle(t)}
	tracking := &twoDeviceConflictTrackingBackend{trackingBackend: readTracking}
	changed, err := tracking.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read changed provider before device one conflict preview failed: %s", rustfsPipelineSafeError(err))
	}
	if changed.Revision != rRevision || !bytes.Equal(changed.Bytes, rBytes) {
		t.Fatal("provider does not hold the exact changed R/Rrev before device one conflict preview")
	}
	twoDeviceVerifyAuthor(t, changed.Bytes, material, twoDeviceTwoID)
	laterWriterAssertItems(t, "device two authenticated edit before conflict preview", twoDeviceItems(t, changed.Bytes, material, twoDeviceTwoID), wantTwo)

	// Device 1 asks the real merge builder to merge its offline edit with the
	// changed authenticated provider pair. It must report one conflict and
	// produce no sealed successor.
	readsBefore := readTracking.readCount()
	candidateOne, err := BuildMergeCandidate(ctx, tracking, remoteName, one, material.pin,
		twoDeviceOneID, material.keys[twoDeviceOneID].identity, material.keys[twoDeviceOneID].signing)
	if err != nil {
		t.Fatalf("device one BuildMergeCandidate failed: %s", rustfsPipelineSafeError(err))
	}
	defer candidateOne.Clear()
	if candidateOne.MergedBytes != nil ||
		candidateOne.RemoteRevision != rRevision ||
		!bytes.Equal(candidateOne.RemoteBytes, changed.Bytes) ||
		candidateOne.ExpectedGeneration != beforeOne.Generation {
		t.Fatal("device one conflict candidate does not bind the exact changed provider pair and local generation")
	}
	twoDeviceConflictAssertSameItemField(t, candidateOne, wantBase, wantLocal, wantRemote)
	if got := readTracking.readCount() - readsBefore; got != 1 {
		t.Fatalf("conflict preview provider read count = %d, want exactly 1", got)
	}
	if creates, replaces, successes := tracking.writeCounts(); creates != 0 || replaces != 0 || successes != 0 {
		t.Fatalf("conflict preview attempted provider writes: creates=%d replaces=%d successes=%d",
			creates, replaces, successes)
	}
	twoDeviceWantNoPending(t, one)
	twoDeviceConflictWantNoAudit(t, one, beforeOne.Generation)

	// A conflicting candidate is not adoptable. The real adoption call must
	// reject it and leave the journal, prepared/legacy records and audit empty.
	adoptErr := AdoptMergeCandidate(ctx, one, candidateOne, material.pin,
		twoDeviceOneID, material.keys[twoDeviceOneID].identity)
	if adoptErr == nil || !errors.Is(adoptErr, ErrMergeCandidateAdoptRejected) {
		t.Fatalf("conflicted candidate adoption did not fail closed with ErrMergeCandidateAdoptRejected (error class %T)", adoptErr)
	}
	afterOne, err := one.LoadState()
	if err != nil {
		t.Fatalf("load device one state after rejected adoption failed: %s", rustfsPipelineSafeError(err))
	}
	twoDeviceConflictAssertState(t, "device one after rejected conflict adoption", afterOne, beforeOne)
	twoDeviceWantNoPending(t, one)
	twoDeviceConflictWantNoAudit(t, one, afterOne.Generation)
	if candidateOne.MergedBytes != nil || len(candidateOne.Conflicts) != 1 {
		t.Fatal("rejected adoption mutated the conflict candidate into a merged or adoptable result")
	}
	if creates, replaces, successes := tracking.writeCounts(); creates != 0 || replaces != 0 || successes != 0 {
		t.Fatalf("rejected adoption attempted provider writes: creates=%d replaces=%d successes=%d",
			creates, replaces, successes)
	}

	// The provider still holds the exact changed R/Rrev and Device 2's
	// authenticated edit, never Device 1's conflicting local edit.
	fresh := newHandle(t)
	afterRemote, err := fresh.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read provider after rejected conflict adoption failed: %s", rustfsPipelineSafeError(err))
	}
	if afterRemote.Revision != rRevision || !bytes.Equal(afterRemote.Bytes, rBytes) {
		t.Fatal("rejected conflict adoption changed the exact provider bytes or revision")
	}
	twoDeviceVerifyAuthor(t, afterRemote.Bytes, material, twoDeviceTwoID)
	laterWriterAssertItems(t, "provider item DB after rejected conflict adoption", twoDeviceItems(t, afterRemote.Bytes, material, twoDeviceTwoID), wantTwo)

	// Device 1's durable journal still holds its exact base, working bytes and
	// generation after an independent reopen, and both are readable.
	closeNow(t, one)
	one = openJournalAt(t, onePath)
	reopenedOne, err := one.LoadState()
	if err != nil {
		t.Fatalf("reopened device one state failed: %s", rustfsPipelineSafeError(err))
	}
	twoDeviceConflictAssertState(t, "reopened device one after rejected conflict adoption", reopenedOne, beforeOne)
	if !bytes.Equal(reopenedOne.BaseBytes, b1.bytes) || reopenedOne.RemoteRevision != b1.rev {
		t.Fatal("reopened device one no longer holds the exact common B/Brev base")
	}
	laterWriterAssertItems(t, "reopened device one base item DB", twoDeviceItems(t, reopenedOne.BaseBytes, material, twoDeviceOneID), baseItems)
	laterWriterAssertItems(t, "reopened device one retained conflict edit item DB", twoDeviceItems(t, reopenedOne.WorkingBytes, material, twoDeviceOneID), wantOne)
	twoDeviceWantNoPending(t, one)
	twoDeviceConflictWantNoAudit(t, one, reopenedOne.Generation)
}
