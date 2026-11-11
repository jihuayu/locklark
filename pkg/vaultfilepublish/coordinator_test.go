package vaultfilepublish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

// Package-level fixtures are shared by every test. Nothing here may write
// through them in place: every step below hands the code its own copy.
var (
	baseData           = []byte(`{"sealed":"base-v1"}`)
	baseRevision       = vaultfilebackend.Revision(`W/"rev-base-1"`)
	proposalData       = []byte(`{"sealed":"proposal-p"}`)
	readbackRevision   = vaultfilebackend.Revision(`W/"rev-readback"`)
	successorData      = []byte(`{"sealed":"someone-else"}`)
	successorRevision  = vaultfilebackend.Revision(`W/"rev-successor"`)
	localEditData      = []byte(`{"sealed":"local-edit"}`)
	proposalGeneration = uint64(7)
)

var (
	errProposalRejected = errors.New("proposal verifier rejected")
	errBackendInjected  = errors.New("backend injected failure")
	errPullRejected     = errors.New("pull verifier rejected")
)

const coordName = "vault.kdbx"

// own returns a private copy of b. The result shares no backing array with b,
// so neither appending to it nor mutating it can reach b (or any other copy
// made earlier through the same expression).
func own(b []byte) []byte {
	return append([]byte{}, b...)
}

// fakeBackend is a controllable ConditionalBackend with one version.
type fakeBackend struct {
	stored vaultfilebackend.ReadResult

	// onReplace replaces the default write behaviour when non-nil. Its return
	// value is the write result.
	onReplace func(f *fakeBackend, expected vaultfilebackend.Revision, value []byte) error
	// replaceErr is the write result when onReplace is nil; with a nil error
	// the write commits when expected matches the stored revision.
	replaceErr error
	// readErr makes every Read fail.
	readErr error

	reads     int
	replaces  int
	lastExp   vaultfilebackend.Revision
	lastValue []byte
	values    [][]byte
}

func (f *fakeBackend) Read(_ context.Context, _ string) (vaultfilebackend.ReadResult, error) {
	f.reads++
	if f.readErr != nil {
		return vaultfilebackend.ReadResult{}, f.readErr
	}
	return vaultfilebackend.ReadResult{
		Bytes:    append([]byte(nil), f.stored.Bytes...),
		Revision: f.stored.Revision,
	}, nil
}

func (f *fakeBackend) ReplaceIfVersion(_ context.Context, _ string, expected vaultfilebackend.Revision, value []byte) error {
	f.replaces++
	f.lastExp = expected
	f.lastValue = append([]byte(nil), value...)
	f.values = append(f.values, append([]byte(nil), value...))
	if f.onReplace != nil {
		return f.onReplace(f, expected, append([]byte(nil), value...))
	}
	if f.replaceErr != nil {
		return f.replaceErr
	}
	if f.stored.Revision != expected {
		return vaultfilebackend.ErrConflict
	}
	f.set(append([]byte(nil), value...), readbackRevision)
	return nil
}

// set installs a committed version. It copies data so the caller's slice never
// becomes backing storage for another value.
func (f *fakeBackend) set(data []byte, revision vaultfilebackend.Revision) {
	f.stored = vaultfilebackend.ReadResult{Bytes: append([]byte(nil), data...), Revision: revision}
}

// applyThenFail models a store that committed the value but whose response was
// lost or mangled.
func applyThenFail(data []byte, revision vaultfilebackend.Revision, err error) func(*fakeBackend, vaultfilebackend.Revision, []byte) error {
	return func(f *fakeBackend, expected vaultfilebackend.Revision, _ []byte) error {
		if f.stored.Revision == expected {
			f.set(data, revision)
		}
		return err
	}
}

func newJournalDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openJournal(t *testing.T, dir string) *vaultfilejournal.Journal {
	t.Helper()
	j, err := vaultfilejournal.Open(filepath.Join(dir, "journal.db"))
	if err != nil {
		t.Fatalf("vaultfilejournal.Open: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func loadState(t *testing.T, j *vaultfilejournal.Journal) vaultfilejournal.State {
	t.Helper()
	s, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	return s
}

func loadPrepared(t *testing.T, j *vaultfilejournal.Journal) vaultfilejournal.PreparedProposal {
	t.Helper()
	pp, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared: %v", err)
	}
	return pp
}

func assertState(t *testing.T, got, want vaultfilejournal.State) {
	t.Helper()
	if got.Generation != want.Generation ||
		got.RemoteRevision != want.RemoteRevision ||
		!bytes.Equal(got.BaseBytes, want.BaseBytes) ||
		!bytes.Equal(got.WorkingBytes, want.WorkingBytes) {
		t.Fatalf("state = {gen %d rev %q base %q working %q}\n    want {gen %d rev %q base %q working %q}",
			got.Generation, got.RemoteRevision, got.BaseBytes, got.WorkingBytes,
			want.Generation, want.RemoteRevision, want.BaseBytes, want.WorkingBytes)
	}
}

func sameProposal(a, b vaultfilejournal.Proposal) bool {
	return a.Generation == b.Generation &&
		a.OperationID == b.OperationID &&
		a.ExpectedRevision == b.ExpectedRevision &&
		bytes.Equal(a.Bytes, b.Bytes)
}

func assertPrepared(t *testing.T, got, want vaultfilejournal.PreparedProposal) {
	t.Helper()
	if got.WorkingGeneration != want.WorkingGeneration || !sameProposal(got.Proposal, want.Proposal) {
		t.Fatalf("prepared = {gen %d op %q rev %q bytes %q}\n     want {gen %d op %q rev %q bytes %q}",
			got.WorkingGeneration, got.Proposal.OperationID, got.Proposal.ExpectedRevision, got.Proposal.Bytes,
			want.WorkingGeneration, want.Proposal.OperationID, want.Proposal.ExpectedRevision, want.Proposal.Bytes)
	}
}

func assertNoPrepared(t *testing.T, j *vaultfilejournal.Journal) {
	t.Helper()
	if _, err := j.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("LoadPrepared: err = %v, want ErrEmpty", err)
	}
}

// fixture wires a coordinator to a real temporary journal and a fake backend
// that holds exactly the original base R.
type fixture struct {
	dir       string
	j         *vaultfilejournal.Journal
	backend   *fakeBackend
	coord     *Coordinator
	initial   vaultfilejournal.State
	proposal  vaultfilejournal.Proposal
	prepared  vaultfilejournal.PreparedProposal
	checks    []check
	numChecks int
}

// check is one recorded ProposalVerifier call.
type check struct {
	base     []byte
	revision vaultfilebackend.Revision
	proposal vaultfilejournal.Proposal
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: newJournalDir(t)}
	f.j = openJournal(t, f.dir)
	f.backend = &fakeBackend{}
	f.backend.set(baseData, baseRevision)
	f.initial = vaultfilejournal.State{
		BaseBytes:      own(baseData),
		RemoteRevision: baseRevision,
		WorkingBytes:   own(proposalData),
		Generation:     0,
	}
	if err := f.j.InitializeState(f.initial); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
	f.proposal = vaultfilejournal.Proposal{
		Generation:       proposalGeneration,
		OperationID:      "op-0001",
		ExpectedRevision: baseRevision,
		Bytes:            own(proposalData),
	}
	f.prepared = vaultfilejournal.PreparedProposal{WorkingGeneration: 0, Proposal: f.proposal}
	f.newCoord(t, f.verifier())
	return f
}

// newCoord installs a coordinator that uses verifier. verifier is bound for
// the coordinator's whole lifetime, so a fresh fixture coordinator is built
// for any other proposal verifier.
func (f *fixture) newCoord(t *testing.T, verifier ProposalVerifier) {
	t.Helper()
	coord, err := NewCoordinator(f.backend, f.j, coordName, verifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	f.coord = coord
}

// snapshotBase returns a private copy of the fixture's original base and
// revision, for assertions that must not be perturbed by later state.
func (f *fixture) snapshotBase() ([]byte, vaultfilebackend.Revision) {
	return own(f.initial.BaseBytes), f.initial.RemoteRevision
}

// verifier accepts only the exact prepared proposal, and only when it is
// handed R, the original base bytes and revision, as its base. Every call,
// accepted or not, is recorded.
func (f *fixture) verifier() ProposalVerifier {
	return func(_ context.Context, base []byte, rev vaultfilebackend.Revision, p vaultfilejournal.Proposal) error {
		f.numChecks++
		f.checks = append(f.checks, check{
			base:     own(base),
			revision: rev,
			proposal: vaultfilejournal.Proposal{
				Generation:       p.Generation,
				OperationID:      p.OperationID,
				ExpectedRevision: p.ExpectedRevision,
				Bytes:            own(p.Bytes),
			},
		})
		origBase, origRev := f.snapshotBase()
		if !bytes.Equal(base, origBase) || rev != origRev {
			return errProposalRejected
		}
		if !sameProposal(p, f.proposal) {
			return errProposalRejected
		}
		return nil
	}
}

// pinPullVerifier accepts the base the fixture started from and any version
// whose bytes equal one of want. It never accepts a different successor.
func (f *fixture) pinPullVerifier(want ...[]byte) PullVerifier {
	origBase, origRev := f.snapshotBase()
	return func(_ context.Context, got []byte, rev vaultfilebackend.Revision) error {
		if bytes.Equal(got, origBase) && rev == origRev {
			return nil
		}
		for _, w := range want {
			if bytes.Equal(got, w) {
				return nil
			}
		}
		return errPullRejected
	}
}

func anyPull(context.Context, []byte, vaultfilebackend.Revision) error { return nil }

// pull reads the backend without disturbing the read counters.
func (f *fixture) pull(t *testing.T) Pulled {
	t.Helper()
	saved := f.backend.reads
	pulled, err := ReadPulled(context.Background(), f.backend, coordName, anyPull)
	f.backend.reads = saved
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	return pulled
}

func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.j.Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	f.j = openJournal(t, f.dir)
	f.coord.journal = f.j
}

// assertBaseCalls asserts that every recorded proposal verifier call received
// exactly R as its base and the exact prepared proposal with ExpectedRevision
// R; the proposal is never its own base.
func assertBaseCalls(t *testing.T, checks []check, initial vaultfilejournal.State, proposal vaultfilejournal.Proposal) {
	t.Helper()
	if len(checks) == 0 {
		t.Fatal("proposal verifier was never called")
	}
	for i, c := range checks {
		if !bytes.Equal(c.base, initial.BaseBytes) || c.revision != initial.RemoteRevision {
			t.Fatalf("verifier call %d base = (%q, %q), want the original base R (%q, %q)",
				i, c.base, c.revision, initial.BaseBytes, initial.RemoteRevision)
		}
		if !sameProposal(c.proposal, proposal) {
			t.Fatalf("verifier call %d proposal = %+v, want the exact prepared proposal %+v", i, c.proposal, proposal)
		}
		if c.proposal.ExpectedRevision != initial.RemoteRevision {
			t.Fatalf("verifier call %d proposal expected revision = %q, want R %q", i, c.proposal.ExpectedRevision, initial.RemoteRevision)
		}
	}
}

func TestNewCoordinatorRejectsInvalidArguments(t *testing.T) {
	j := openJournal(t, newJournalDir(t))
	backend := &fakeBackend{}
	var nilFake *fakeBackend
	var nilJournal *vaultfilejournal.Journal
	verifier := ProposalVerifier(func(context.Context, []byte, vaultfilebackend.Revision, vaultfilejournal.Proposal) error { return nil })

	tests := []struct {
		name     string
		backend  ConditionalBackend
		journal  *vaultfilejournal.Journal
		fileName string
		verifier ProposalVerifier
		want     string
	}{
		{name: "nil backend", journal: j, fileName: coordName, verifier: verifier, want: "nil backend"},
		{name: "typed nil backend", backend: nilFake, journal: j, fileName: coordName, verifier: verifier, want: "nil backend"},
		{name: "nil journal", backend: backend, fileName: coordName, verifier: verifier, want: "nil journal"},
		{name: "typed nil journal", backend: backend, journal: nilJournal, fileName: coordName, verifier: verifier, want: "nil journal"},
		{name: "empty name", backend: backend, journal: j, fileName: "", verifier: verifier, want: "invalid backend name"},
		{name: "dotdot name", backend: backend, journal: j, fileName: "..", verifier: verifier, want: "invalid backend name"},
		{name: "nil verifier", backend: backend, journal: j, fileName: coordName, want: "nil proposal verifier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coord, err := NewCoordinator(tt.backend, tt.journal, tt.fileName, tt.verifier)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("NewCoordinator: err = %v, want ErrInvalidArgument", err)
			}
			if coord != nil {
				t.Fatal("NewCoordinator returned a coordinator together with an error")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tt.want)) {
				t.Fatalf("err = %q, want mention of %q", err, tt.want)
			}
		})
	}
	if backend.reads != 0 || backend.replaces != 0 {
		t.Fatalf("NewCoordinator touched the backend: reads=%d replaces=%d", backend.reads, backend.replaces)
	}
}

func TestPrepareAndPublishRejectsBeforeAnyIO(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	pulled := f.pull(t)

	tests := []struct {
		name   string
		ctx    context.Context
		pulled Pulled
		pull   PullVerifier
	}{
		{name: "nil context", ctx: nil, pulled: pulled, pull: anyPull},
		{name: "nil pull verifier", ctx: ctx, pulled: pulled},
		{name: "zero pulled base", ctx: ctx, pull: anyPull},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.backend.reads, f.backend.replaces = 0, 0
			checks := f.numChecks
			err := f.coord.PrepareAndPublish(tt.ctx, tt.pulled, f.proposal, tt.pull)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.backend.reads != 0 || f.backend.replaces != 0 {
				t.Fatalf("backend I/O before rejection: reads=%d replaces=%d", f.backend.reads, f.backend.replaces)
			}
			if f.numChecks != checks {
				t.Fatal("proposal verifier called for an invalid argument")
			}
			assertNoPrepared(t, f.j)
			assertState(t, loadState(t, f.j), f.initial)
		})
	}
}

func TestPrepareAndPublishPreparesBeforeSingleCAS(t *testing.T) {
	f := newFixture(t)
	var preparedAtWrite *vaultfilejournal.PreparedProposal
	f.backend.onReplace = func(b *fakeBackend, expected vaultfilebackend.Revision, value []byte) error {
		pp, err := f.j.LoadPrepared()
		if err != nil {
			t.Errorf("LoadPrepared from inside the write: %v", err)
			return errBackendInjected
		}
		preparedAtWrite = &pp
		b.set(value, readbackRevision)
		return nil
	}

	if err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("PrepareAndPublish: %v", err)
	}
	if preparedAtWrite == nil {
		t.Fatal("no prepared record existed when ReplaceIfVersion was called")
	}
	assertPrepared(t, *preparedAtWrite, f.prepared)

	if f.backend.replaces != 1 {
		t.Fatalf("ReplaceIfVersion calls = %d, want exactly 1", f.backend.replaces)
	}
	if f.backend.lastExp != baseRevision {
		t.Fatalf("write expected revision = %q, want the opaque base revision %q", f.backend.lastExp, baseRevision)
	}
	if !bytes.Equal(f.backend.lastValue, proposalData) {
		t.Fatalf("write value = %q, want the exact proposal bytes %q", f.backend.lastValue, proposalData)
	}
	if f.backend.reads != 1 {
		t.Fatalf("readback reads = %d, want exactly 1", f.backend.reads)
	}

	want := f.initial
	want.BaseBytes = own(proposalData)
	want.RemoteRevision = readbackRevision
	s := loadState(t, f.j)
	assertState(t, s, want)
	if s.RemoteRevision != f.backend.stored.Revision {
		t.Fatalf("stored revision = %q, want the opaque readback revision %q", s.RemoteRevision, f.backend.stored.Revision)
	}
	if s.RemoteRevision != readbackRevision {
		t.Fatalf("Ack revision = %q, want the verified readback revision %q", s.RemoteRevision, readbackRevision)
	}
	assertNoPrepared(t, f.j)
	if _, err := f.j.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy proposal record: err = %v, want ErrEmpty", err)
	}
	if f.numChecks != 2 {
		t.Fatalf("proposal verifier calls = %d, want 2 (before prepare and before ack)", f.numChecks)
	}
	assertBaseCalls(t, f.checks, f.initial, f.proposal)
}

func TestUnknownWithAppliedProposalIsReconciled(t *testing.T) {
	f := newFixture(t)
	f.backend.onReplace = applyThenFail(proposalData, readbackRevision, vaultfilebackend.ErrUnknown)

	if err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("PrepareAndPublish after an unknown-but-applied write: %v", err)
	}
	want := f.initial
	want.BaseBytes = own(proposalData)
	want.RemoteRevision = readbackRevision
	assertState(t, loadState(t, f.j), want)
	assertNoPrepared(t, f.j)
	if f.backend.replaces != 1 || f.backend.reads != 1 {
		t.Fatalf("reconcile used replaces=%d reads=%d, want 1 and 1", f.backend.replaces, f.backend.reads)
	}
	assertBaseCalls(t, f.checks, f.initial, f.proposal)
}

func TestUnknownWithOldBaseRetainsPreparedAndResumeRetries(t *testing.T) {
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrUnknown // nothing applied

	ctx := context.Background()
	err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier())
	if !errors.Is(err, ErrUnknownWrite) || !errors.Is(err, vaultfilebackend.ErrUnknown) {
		t.Fatalf("err = %v, want ErrUnknownWrite matching vaultfilebackend.ErrUnknown", err)
	}
	if f.backend.replaces != 1 || f.backend.reads != 1 {
		t.Fatalf("replaces=%d reads=%d, want 1 and 1", f.backend.replaces, f.backend.reads)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
	preparedCalls := f.numChecks

	// Restart, then resume against the unchanged original base.
	f.reopen(t)
	f.backend.replaceErr = nil
	if err := f.coord.ResumePrepared(ctx, f.pull(t), f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("ResumePrepared: %v", err)
	}
	if f.backend.replaces != 2 {
		t.Fatalf("ReplaceIfVersion calls = %d, want 2 (one unknown, one retried)", f.backend.replaces)
	}
	if !bytes.Equal(f.backend.values[0], f.backend.values[1]) {
		t.Fatalf("retry bytes = %q, want the exact first write bytes %q", f.backend.values[1], f.backend.values[0])
	}
	if !bytes.Equal(f.backend.lastValue, proposalData) || f.backend.lastExp != baseRevision {
		t.Fatalf("retry wrote (%q, %q), want (%q, %q)", f.backend.lastValue, f.backend.lastExp, proposalData, baseRevision)
	}
	want := f.initial
	want.BaseBytes = own(proposalData)
	want.RemoteRevision = readbackRevision
	assertState(t, loadState(t, f.j), want)
	assertNoPrepared(t, f.j)

	// The resume calls (retry, then the readback Ack) also saw only R.
	if f.numChecks != preparedCalls+2 {
		t.Fatalf("resume verifier calls = %d, want 2 (retry and ack)", f.numChecks-preparedCalls)
	}
	assertBaseCalls(t, f.checks, f.initial, f.proposal)
}

func TestDifferentSuccessorIsUnknownReviewAndNotOverwritten(t *testing.T) {
	f := newFixture(t)
	f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, _ []byte) error {
		// Another device won the race.
		b.set(successorData, successorRevision)
		return vaultfilebackend.ErrConflict
	}

	// The write reported a definite conflict, so the conflict is definite even
	// though the readback is a different successor. Nothing is acknowledged.
	err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, f.pinPullVerifier(successorData))
	if !errors.Is(err, ErrConflict) || !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict matching vaultfilebackend.ErrConflict", err)
	}
	if f.backend.replaces != 1 {
		t.Fatalf("ReplaceIfVersion calls = %d, want 1", f.backend.replaces)
	}
	if !bytes.Equal(f.backend.stored.Bytes, successorData) || f.backend.stored.Revision != successorRevision {
		t.Fatalf("successor overwritten: stored = (%q, %q)", f.backend.stored.Bytes, f.backend.stored.Revision)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)

	// A resume on the same successor refuses to act as well.
	f.backend.reads = 0
	err = f.coord.ResumePrepared(context.Background(), f.pull(t), anyPull)
	if !errors.Is(err, ErrUnknownReview) {
		t.Fatalf("ResumePrepared on a different successor: err = %v, want ErrUnknownReview", err)
	}
	if f.backend.replaces != 1 || f.backend.reads != 0 {
		t.Fatalf("ResumePrepared on a successor: replaces=%d reads=%d, want no new work", f.backend.replaces, f.backend.reads)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
}

func TestResumePreparedAcksExactProposalWithoutWrite(t *testing.T) {
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrUnknown
	ctx := context.Background()
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier()); !errors.Is(err, ErrUnknownWrite) {
		t.Fatalf("PrepareAndPublish: err = %v, want ErrUnknownWrite", err)
	}
	f.reopen(t)
	preparedCalls := f.numChecks

	// The remote applied the proposal after all; a local edit landed meanwhile.
	f.backend.set(proposalData, readbackRevision)
	if err := f.j.UpdateWorking(0, localEditData); err != nil {
		t.Fatalf("UpdateWorking: %v", err)
	}
	writes := f.backend.replaces
	if err := f.coord.ResumePrepared(ctx, f.pull(t), anyPull); err != nil {
		t.Fatalf("ResumePrepared: %v", err)
	}
	if f.backend.replaces != writes {
		t.Fatalf("ResumePrepared wrote %d times for an already applied proposal", f.backend.replaces-writes)
	}
	s := loadState(t, f.j)
	if !bytes.Equal(s.BaseBytes, proposalData) || s.RemoteRevision != readbackRevision {
		t.Fatalf("state = (%q, %q), want (%q, %q)", s.BaseBytes, s.RemoteRevision, proposalData, readbackRevision)
	}
	if !bytes.Equal(s.WorkingBytes, localEditData) || s.Generation != 1 {
		t.Fatalf("local edit lost: working=%q gen=%d", s.WorkingBytes, s.Generation)
	}
	assertNoPrepared(t, f.j)

	// After the local edit, the resume Ack still verified against R.
	if f.numChecks != preparedCalls+1 {
		t.Fatalf("resume verifier calls = %d, want 1 (the ack)", f.numChecks-preparedCalls)
	}
	assertBaseCalls(t, f.checks, f.initial, f.proposal)
}

func TestLocalEditDuringWriteSurvivesLateAck(t *testing.T) {
	f := newFixture(t)
	var editErr error
	f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, value []byte) error {
		// The local working file changes while the write is in flight.
		editErr = f.j.UpdateWorking(0, localEditData)
		b.set(value, readbackRevision)
		return nil
	}
	if err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("PrepareAndPublish: %v", err)
	}
	if editErr != nil {
		t.Fatalf("concurrent UpdateWorking: %v", editErr)
	}
	s := loadState(t, f.j)
	if !bytes.Equal(s.BaseBytes, proposalData) || s.RemoteRevision != readbackRevision {
		t.Fatalf("base = (%q, %q), want the proposal at the readback revision", s.BaseBytes, s.RemoteRevision)
	}
	if !bytes.Equal(s.WorkingBytes, localEditData) || s.Generation != 1 {
		t.Fatalf("newer working generation lost: working=%q gen=%d", s.WorkingBytes, s.Generation)
	}
	// The Ack-time verification used the snapshot R, not the edited state.
	assertBaseCalls(t, f.checks, f.initial, f.proposal)
}

func TestStaleInputOrVerifierRejectionCausesNoCAS(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		setup    func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal)
		verifier func(f *fixture) ProposalVerifier
		wantErr  error
		wantWrap error
	}{
		{
			name: "pulled bytes are not the stored base",
			setup: func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal) {
				f.backend.set([]byte(`{"sealed":"older"}`), baseRevision)
				return f.pull(t), f.proposal
			},
			wantErr: ErrStaleBase,
		},
		{
			name: "pulled revision is not the stored base revision",
			setup: func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal) {
				f.backend.set(baseData, successorRevision)
				return f.pull(t), f.proposal
			},
			wantErr: ErrStaleBase,
		},
		{
			name: "proposal expected revision is not the base revision",
			setup: func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal) {
				p := f.proposal
				p.Bytes = own(p.Bytes)
				p.ExpectedRevision = successorRevision
				return f.pull(t), p
			},
			wantErr: ErrStaleBase,
		},
		{
			name: "proposal bytes are not the working bytes",
			setup: func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal) {
				p := f.proposal
				p.Bytes = own(proposalData)
				p.Bytes[0] ^= 0xff
				return f.pull(t), p
			},
			wantErr: ErrStaleBase,
		},
		{
			name: "proposal verifier rejects",
			setup: func(t *testing.T, f *fixture) (Pulled, vaultfilejournal.Proposal) {
				return f.pull(t), f.proposal
			},
			verifier: func(*fixture) ProposalVerifier {
				return func(context.Context, []byte, vaultfilebackend.Revision, vaultfilejournal.Proposal) error {
					return errProposalRejected
				}
			},
			wantErr:  ErrVerification,
			wantWrap: errProposalRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.verifier != nil {
				f.newCoord(t, tt.verifier(f))
			}
			pulled, proposal := tt.setup(t, f)
			f.backend.reads, f.backend.replaces = 0, 0

			err := f.coord.PrepareAndPublish(ctx, pulled, proposal, anyPull)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantWrap != nil && !errors.Is(err, tt.wantWrap) {
				t.Fatalf("err = %v, want to wrap %v", err, tt.wantWrap)
			}
			if f.backend.reads != 0 || f.backend.replaces != 0 {
				t.Fatalf("backend I/O after rejection: reads=%d replaces=%d", f.backend.reads, f.backend.replaces)
			}
			assertNoPrepared(t, f.j)
			assertState(t, loadState(t, f.j), f.initial)
		})
	}
}

func TestJournalPrepareFailuresCauseNoCAS(t *testing.T) {
	ctx := context.Background()

	t.Run("newer local generation", func(t *testing.T) {
		f := newFixture(t)
		// The coordinator loads R and hands it to the proposal verifier. The
		// verifier changes the local working state exactly once, before
		// Journal.Prepare runs, so the generation it loaded is stale while the
		// remote base R is untouched.
		base := f.verifier()
		var edited bool
		f.newCoord(t, func(ctx context.Context, b []byte, rev vaultfilebackend.Revision, p vaultfilejournal.Proposal) error {
			if err := base(ctx, b, rev, p); err != nil {
				return err
			}
			if !edited {
				edited = true
				if err := f.j.UpdateWorking(0, localEditData); err != nil {
					return err
				}
			}
			return nil
		})

		err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, anyPull)
		if !errors.Is(err, vaultfilejournal.ErrPreparedMismatch) {
			t.Fatalf("err = %v, want ErrPreparedMismatch", err)
		}
		if !edited {
			t.Fatal("verifier never applied the concurrent local edit")
		}
		if f.numChecks != 1 {
			t.Fatalf("proposal verifier calls = %d, want 1 (no retry after a journal rejection)", f.numChecks)
		}
		if f.backend.replaces != 0 {
			t.Fatalf("ReplaceIfVersion calls = %d, want 0", f.backend.replaces)
		}
		assertNoPrepared(t, f.j)
		// The concurrent local edit remains durable; the base is unchanged.
		want := f.initial
		want.WorkingBytes = own(localEditData)
		want.Generation = 1
		assertState(t, loadState(t, f.j), want)
		if !bytes.Equal(f.backend.stored.Bytes, baseData) || f.backend.stored.Revision != baseRevision {
			t.Fatalf("remote base changed: stored = (%q, %q)", f.backend.stored.Bytes, f.backend.stored.Revision)
		}
		assertBaseCalls(t, f.checks, f.initial, f.proposal)
	})

	t.Run("different outstanding proposal", func(t *testing.T) {
		f := newFixture(t)
		other := f.prepared
		other.Proposal.OperationID = "op-other"
		if err := f.j.Prepare(0, other.Proposal); err != nil {
			t.Fatalf("Prepare other: %v", err)
		}
		err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, anyPull)
		if !errors.Is(err, vaultfilejournal.ErrPreparedExists) {
			t.Fatalf("err = %v, want ErrPreparedExists", err)
		}
		if f.backend.replaces != 0 {
			t.Fatalf("ReplaceIfVersion calls = %d, want 0", f.backend.replaces)
		}
		assertPrepared(t, loadPrepared(t, f.j), other)
	})
}

func TestConflictWithNonProposalReadbackIsDefinite(t *testing.T) {
	t.Run("unchanged original base", func(t *testing.T) {
		f := newFixture(t)
		f.backend.replaceErr = vaultfilebackend.ErrConflict
		err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, anyPull)
		if !errors.Is(err, ErrConflict) || !errors.Is(err, vaultfilebackend.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict matching vaultfilebackend.ErrConflict", err)
		}
		if errors.Is(err, ErrUnknownReview) || errors.Is(err, vaultfilebackend.ErrUnknown) {
			t.Fatalf("definite conflict misclassified as unknown: %v", err)
		}
		assertPrepared(t, loadPrepared(t, f.j), f.prepared)
		assertState(t, loadState(t, f.j), f.initial)
	})

	t.Run("different successor", func(t *testing.T) {
		f := newFixture(t)
		pulled := f.pull(t)
		f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, _ []byte) error {
			b.set(successorData, successorRevision)
			return vaultfilebackend.ErrConflict
		}
		err := f.coord.PrepareAndPublish(context.Background(), pulled, f.proposal, anyPull)
		if !errors.Is(err, ErrConflict) || !errors.Is(err, vaultfilebackend.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict matching vaultfilebackend.ErrConflict", err)
		}
		if errors.Is(err, ErrUnknownReview) {
			t.Fatalf("definite conflict misclassified as review: %v", err)
		}
		assertPrepared(t, loadPrepared(t, f.j), f.prepared)
		if !bytes.Equal(f.backend.stored.Bytes, successorData) || f.backend.stored.Revision != successorRevision {
			t.Fatalf("successor overwritten: stored = (%q, %q)", f.backend.stored.Bytes, f.backend.stored.Revision)
		}
	})

	t.Run("readback fails", func(t *testing.T) {
		f := newFixture(t)
		pulled := f.pull(t)
		f.backend.replaceErr = vaultfilebackend.ErrConflict
		f.backend.readErr = errBackendInjected
		err := f.coord.PrepareAndPublish(context.Background(), pulled, f.proposal, anyPull)
		if !errors.Is(err, errBackendInjected) {
			t.Fatalf("err = %v, want the readback error", err)
		}
		assertPrepared(t, loadPrepared(t, f.j), f.prepared)
		if !bytes.Equal(f.backend.stored.Bytes, baseData) || f.backend.stored.Revision != baseRevision {
			t.Fatalf("stored = (%q, %q), want the untouched original base", f.backend.stored.Bytes, f.backend.stored.Revision)
		}
	})
}

func TestDefiniteWriteErrorPropagatesAndPreservesPrepared(t *testing.T) {
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrDenied
	err := f.coord.PrepareAndPublish(context.Background(), f.pull(t), f.proposal, anyPull)
	if !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Fatalf("err = %v, want the backend error", err)
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrUnknownReview) || errors.Is(err, ErrUnknownWrite) {
		t.Fatalf("definite error misclassified: %v", err)
	}
	if f.backend.replaces != 1 {
		t.Fatalf("ReplaceIfVersion calls = %d, want 1 (no retry loop)", f.backend.replaces)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
}

func TestResumePreparedArgumentAndStateErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid arguments", func(t *testing.T) {
		f := newFixture(t)
		if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, anyPull); err != nil {
			t.Fatalf("PrepareAndPublish: %v", err)
		}
		f.backend.reads, f.backend.replaces = 0, 0
		current := f.pull(t)
		tests := []struct {
			name string
			ctx  context.Context
			cur  Pulled
			pull PullVerifier
		}{
			{name: "nil context", ctx: nil, cur: current, pull: anyPull},
			{name: "nil pull verifier", ctx: ctx, cur: current},
			{name: "zero current", ctx: ctx, pull: anyPull},
		}
		for _, tt := range tests {
			if err := f.coord.ResumePrepared(tt.ctx, tt.cur, tt.pull); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("%s: err = %v, want ErrInvalidArgument", tt.name, err)
			}
		}
		if f.backend.reads != 0 || f.backend.replaces != 0 {
			t.Fatalf("backend I/O before rejection: reads=%d replaces=%d", f.backend.reads, f.backend.replaces)
		}
	})

	t.Run("nothing prepared", func(t *testing.T) {
		f := newFixture(t)
		err := f.coord.ResumePrepared(ctx, f.pull(t), anyPull)
		if !errors.Is(err, vaultfilejournal.ErrEmpty) {
			t.Fatalf("err = %v, want vaultfilejournal.ErrEmpty", err)
		}
		if f.backend.replaces != 0 {
			t.Fatalf("ReplaceIfVersion calls = %d, want 0", f.backend.replaces)
		}
	})
}

func TestResumePreparedRejectsInconsistentBaseRevision(t *testing.T) {
	tests := []struct {
		name  string
		state func(f *fixture) vaultfilejournal.State
	}{
		{
			name: "stored base revision differs from the prepared proposal",
			state: func(f *fixture) vaultfilejournal.State {
				// The base moved on after preparation; the prepared proposal
				// still expects R.
				return vaultfilejournal.State{
					BaseBytes:      own(successorData),
					RemoteRevision: successorRevision,
					WorkingBytes:   own(proposalData),
					Generation:     0,
				}
			},
		},
		{
			name: "no stored base",
			state: func(f *fixture) vaultfilejournal.State {
				return vaultfilejournal.State{
					WorkingBytes: own(proposalData),
					Generation:   0,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t)
			// A prepared proposal expecting R sitting next to a base that is
			// no longer R: the journal's API cannot produce that pair, and its
			// own load paths accept it, so the coordinator must reject it
			// before writing or acknowledging anything.
			dir := newJournalDir(t)
			j := openJournal(t, dir)
			if err := j.InitializeState(f.initial); err != nil {
				t.Fatalf("InitializeState: %v", err)
			}
			if err := j.Prepare(0, f.proposal); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if err := j.Close(); err != nil {
				t.Fatalf("close seeded journal: %v", err)
			}
			transplantState(t, filepath.Join(dir, "journal.db"), tt.state(f))
			j = openJournal(t, dir)
			coord, err := NewCoordinator(f.backend, j, coordName, f.verifier())
			if err != nil {
				t.Fatalf("NewCoordinator: %v", err)
			}
			before := loadState(t, j)

			for _, remote := range []struct {
				name string
				data []byte
				rev  vaultfilebackend.Revision
			}{
				{name: "remote holds the prepared proposal", data: proposalData, rev: readbackRevision},
				{name: "remote holds R", data: baseData, rev: baseRevision},
			} {
				f.backend.set(remote.data, remote.rev)
				f.backend.reads, f.backend.replaces = 0, 0
				checks := f.numChecks
				err := coord.ResumePrepared(ctx, f.pull(t), anyPull)
				if !errors.Is(err, ErrStaleBase) {
					t.Fatalf("%s: err = %v, want ErrStaleBase", remote.name, err)
				}
				if f.backend.replaces != 0 {
					t.Fatalf("%s: ReplaceIfVersion calls = %d, want 0", remote.name, f.backend.replaces)
				}
				if f.numChecks != checks {
					t.Fatalf("%s: proposal verifier called on inconsistent state", remote.name)
				}
				assertState(t, loadState(t, j), before)
				assertPrepared(t, loadPrepared(t, j), f.prepared)
			}
		})
	}
}

func TestResumePreparedRejectsCrossRecordInconsistencyBeforeAnyWork(t *testing.T) {
	tests := []struct {
		name               string
		preparedGeneration uint64
		state              func(*fixture) vaultfilejournal.State
		check              func(*testing.T, vaultfilejournal.State, vaultfilejournal.PreparedProposal)
	}{
		{
			name:               "prepared generation is greater than state generation",
			preparedGeneration: 1,
			state: func(*fixture) vaultfilejournal.State {
				// The state rolled back to generation 0 while the prepared
				// record still carries the generation it was prepared at.
				return vaultfilejournal.State{
					BaseBytes:      own(baseData),
					RemoteRevision: baseRevision,
					WorkingBytes:   own(proposalData),
					Generation:     0,
				}
			},
			check: func(t *testing.T, s vaultfilejournal.State, pp vaultfilejournal.PreparedProposal) {
				t.Helper()
				if pp.WorkingGeneration <= s.Generation {
					t.Fatalf("prepared generation %d is not newer than state generation %d", pp.WorkingGeneration, s.Generation)
				}
			},
		},
		{
			name:               "equal generations but state working bytes differ",
			preparedGeneration: 0,
			state: func(*fixture) vaultfilejournal.State {
				// Same generation, but the working file no longer matches the
				// proposal the prepared record would Ack.
				return vaultfilejournal.State{
					BaseBytes:      own(baseData),
					RemoteRevision: baseRevision,
					WorkingBytes:   own(localEditData),
					Generation:     0,
				}
			},
			check: func(t *testing.T, s vaultfilejournal.State, pp vaultfilejournal.PreparedProposal) {
				t.Helper()
				if pp.WorkingGeneration != s.Generation {
					t.Fatalf("prepared generation %d != state generation %d", pp.WorkingGeneration, s.Generation)
				}
				if bytes.Equal(s.WorkingBytes, pp.Proposal.Bytes) {
					t.Fatal("state working bytes still equal the prepared proposal bytes")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t)

			// Each record is written through its public codec: Prepare only
			// sees a consistent state, then the state is transplanted to the
			// valid but cross-record-inconsistent value under test.
			dir := newJournalDir(t)
			j := openJournal(t, dir)
			seed := vaultfilejournal.State{
				BaseBytes:      own(baseData),
				RemoteRevision: baseRevision,
				WorkingBytes:   own(proposalData),
				Generation:     0,
			}
			if err := j.InitializeState(seed); err != nil {
				t.Fatalf("InitializeState: %v", err)
			}
			// InitializeState only accepts generation 0; reach the prepared
			// generation through the valid CAS API.
			for gen := uint64(0); gen < tt.preparedGeneration; gen++ {
				if err := j.UpdateWorking(gen, own(proposalData)); err != nil {
					t.Fatalf("UpdateWorking(%d): %v", gen, err)
				}
			}
			if err := j.Prepare(tt.preparedGeneration, f.proposal); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			inconsistent := tt.state(f)
			if err := j.Close(); err != nil {
				t.Fatalf("close seeded journal: %v", err)
			}
			transplantState(t, filepath.Join(dir, "journal.db"), inconsistent)
			j = openJournal(t, dir)
			coord, err := NewCoordinator(f.backend, j, coordName, f.verifier())
			if err != nil {
				t.Fatalf("NewCoordinator: %v", err)
			}
			beforeState := loadState(t, j)
			beforePrepared := loadPrepared(t, j)
			tt.check(t, beforeState, beforePrepared)

			for _, remote := range []struct {
				name string
				data []byte
				rev  vaultfilebackend.Revision
			}{
				{name: "remote holds the prepared proposal", data: proposalData, rev: readbackRevision},
				{name: "remote holds R", data: baseData, rev: baseRevision},
			} {
				t.Run(remote.name, func(t *testing.T) {
					f.backend.set(remote.data, remote.rev)
					current := f.pull(t)
					f.backend.reads, f.backend.replaces = 0, 0
					checks := f.numChecks

					err := coord.ResumePrepared(ctx, current, anyPull)
					if !errors.Is(err, ErrStaleBase) {
						t.Fatalf("err = %v, want ErrStaleBase", err)
					}
					if f.numChecks != checks {
						t.Fatal("proposal verifier called on cross-record-inconsistent records")
					}
					if f.backend.reads != 0 || f.backend.replaces != 0 {
						t.Fatalf("backend I/O on inconsistent records: reads=%d replaces=%d", f.backend.reads, f.backend.replaces)
					}
					// Ack would rewrite the state and delete the prepared
					// record; both surviving intact proves no Ack happened.
					assertState(t, loadState(t, j), beforeState)
					assertPrepared(t, loadPrepared(t, j), beforePrepared)
				})
			}
		})
	}
}

// transplantState replaces the journal's state record at dbPath with the exact
// record encoding of state, taken from a donor journal initialized with it.
func transplantState(t *testing.T, dbPath string, state vaultfilejournal.State) {
	t.Helper()
	donorPath := filepath.Join(newJournalDir(t), "journal.db")
	donor := openJournal(t, filepath.Dir(donorPath))
	if err := donor.InitializeState(state); err != nil {
		t.Fatalf("InitializeState donor: %v", err)
	}
	if err := donor.Close(); err != nil {
		t.Fatalf("close donor: %v", err)
	}

	bucket, raw := readStateRecord(t, donorPath)
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open journal db: %v", err)
	}
	defer func() { _ = db.Close() }()
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return errors.New("journal bucket is missing")
		}
		return b.Put([]byte("state"), raw)
	})
	if err != nil {
		t.Fatalf("write state record: %v", err)
	}
}

// readStateRecord returns the bucket name and a copy of the "state" value from
// the journal database at dbPath.
func readStateRecord(t *testing.T, dbPath string) (bucket string, raw []byte) {
	t.Helper()
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open journal db: %v", err)
	}
	defer func() { _ = db.Close() }()
	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if v := b.Get([]byte("state")); v != nil && bucket == "" {
				bucket, raw = string(name), append([]byte(nil), v...)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read state record: %v", err)
	}
	if bucket == "" {
		t.Fatal("journal db has no state record")
	}
	return bucket, raw
}

func TestUnknownWritePreservedThroughFailedReconciliation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		// setup installs the write behaviour and the remote state the readback
		// will observe. It runs before the base is pulled back for
		// PrepareAndPublish, so a setup must not break that Read.
		setup func(t *testing.T, f *fixture) PullVerifier
		// breakAck closes the fixture journal after the write, so the
		// exact-proposal Ack fails on a real ErrClosed.
		breakAck bool
		// want is the specific error or sentinel that must remain reachable.
		want error
	}{
		{
			name: "readback error",
			setup: func(t *testing.T, f *fixture) PullVerifier {
				f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, _ []byte) error {
					b.set(own(proposalData), readbackRevision)
					// Only the readback fails.
					b.readErr = errBackendInjected
					return vaultfilebackend.ErrUnknown
				}
				return anyPull
			},
			want: errBackendInjected,
		},
		{
			name: "exact bytes rejected by the proposal verifier",
			setup: func(t *testing.T, f *fixture) PullVerifier {
				f.backend.onReplace = applyThenFail(proposalData, readbackRevision, vaultfilebackend.ErrUnknown)
				// Accept the pre-write check, reject the readback check.
				var checks int
				base := f.verifier()
				f.newCoord(t, func(ctx context.Context, b []byte, rev vaultfilebackend.Revision, p vaultfilejournal.Proposal) error {
					checks++
					// Both calls are recorded; only the readback one rejects.
					_ = base(ctx, b, rev, p)
					if checks > 1 {
						return errProposalRejected
					}
					return nil
				})
				return anyPull
			},
			want: ErrVerification,
		},
		{
			name: "different successor",
			setup: func(t *testing.T, f *fixture) PullVerifier {
				f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, _ []byte) error {
					b.set(successorData, successorRevision)
					return vaultfilebackend.ErrUnknown
				}
				return f.pinPullVerifier(successorData)
			},
			want: ErrUnknownReview,
		},
		{
			// The write committed the exact proposal but its response was
			// lost; closing the real journal after Prepare makes the Ack fail
			// deterministically, after the readback and the verifier accepted.
			name: "exact proposal but Ack fails",
			setup: func(t *testing.T, f *fixture) PullVerifier {
				var closeErr error
				f.backend.onReplace = func(b *fakeBackend, _ vaultfilebackend.Revision, _ []byte) error {
					// Prepare has committed by now; the prepared record must
					// already be on disk before the journal is closed.
					if _, err := f.j.LoadPrepared(); err != nil {
						closeErr = fmt.Errorf("prepared record missing at write: %w", err)
						return vaultfilebackend.ErrUnknown
					}
					b.set(own(proposalData), readbackRevision)
					closeErr = f.j.Close()
					return vaultfilebackend.ErrUnknown
				}
				t.Cleanup(func() {
					if closeErr != nil {
						t.Errorf("close real journal after Prepare: %v", closeErr)
					}
				})
				return anyPull
			},
			breakAck: true,
			want:     vaultfilejournal.ErrClosed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			pullVerifier := tt.setup(t, f)
			// Pulled before the write, like a real caller that read the base
			// it is publishing against.
			pulled := f.pull(t)

			err := f.coord.PrepareAndPublish(ctx, pulled, f.proposal, pullVerifier)
			if err == nil {
				t.Fatalf("PrepareAndPublish = nil, want a reconciliation failure")
			}
			if !errors.Is(err, vaultfilebackend.ErrUnknown) {
				t.Fatalf("err = %v, want vaultfilebackend.ErrUnknown preserved", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v preserved alongside ErrUnknown", err, tt.want)
			}
			if errors.Is(err, vaultfilebackend.ErrConflict) || errors.Is(err, ErrConflict) {
				t.Fatalf("ErrUnknown write misclassified as a definite conflict: %v", err)
			}
			if tt.breakAck {
				if !bytes.Contains([]byte(err.Error()), []byte("ack")) {
					t.Fatalf("err = %q, want the Ack error", err)
				}
			}
			if f.backend.replaces != 1 || f.backend.reads != 1 {
				t.Fatalf("replaces=%d reads=%d, want 1 and 1", f.backend.replaces, f.backend.reads)
			}
			if tt.breakAck {
				// The journal the coordinator Acked is closed; reopen it from
				// disk to prove the prepared record and state survived.
				f.j = openJournal(t, f.dir)
			}
			assertPrepared(t, loadPrepared(t, f.j), f.prepared)
			assertState(t, loadState(t, f.j), f.initial)
			if tt.breakAck {
				// The exact proposal was read back and verified, so the error
				// is the Ack failure, not a review of the remote outcome.
				if errors.Is(err, ErrVerification) || errors.Is(err, ErrUnknownReview) || errors.Is(err, ErrUnknownWrite) {
					t.Fatalf("Ack failure misclassified: %v", err)
				}
				if f.numChecks != 2 {
					t.Fatalf("proposal verifier calls = %d, want 2 (before prepare and before ack)", f.numChecks)
				}
				assertBaseCalls(t, f.checks, f.initial, f.proposal)
			}
		})
	}
}

// rejectAfterFirstCheck returns the fixture verifier for its first ok checks
// (the pre-write verification) and errProposalRejected afterwards.
func rejectAfterFirstCheck(f *fixture, ok int) ProposalVerifier {
	base := f.verifier()
	return func(ctx context.Context, b []byte, rev vaultfilebackend.Revision, p vaultfilejournal.Proposal) error {
		if f.numChecks >= ok {
			f.numChecks++
			f.checks = append(f.checks, check{base: own(b), revision: rev, proposal: p})
			return errProposalRejected
		}
		return base(ctx, b, rev, p)
	}
}

func TestResumePreparedRejectedProposalWritesAndAcksNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrUnknown
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, anyPull); !errors.Is(err, ErrUnknownWrite) {
		t.Fatalf("PrepareAndPublish: err = %v, want ErrUnknownWrite", err)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)

	// The verifier is bound once by the constructor, so swap in a coordinator
	// whose bound verifier rejects.
	reject := func(context.Context, []byte, vaultfilebackend.Revision, vaultfilejournal.Proposal) error {
		return errProposalRejected
	}
	f.newCoord(t, reject)
	f.backend.replaceErr = nil
	f.backend.reads, f.backend.replaces = 0, 0

	// Original base: a retry the verifier rejects writes nothing.
	current := f.pull(t)
	err := f.coord.ResumePrepared(ctx, current, anyPull)
	if !errors.Is(err, ErrVerification) || !errors.Is(err, errProposalRejected) {
		t.Fatalf("rejected retry: err = %v, want ErrVerification wrapping the rejection", err)
	}
	if f.backend.replaces != 0 {
		t.Fatalf("rejected retry wrote %d times", f.backend.replaces)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)

	// Proposal on the remote: an Ack the verifier rejects acknowledges nothing.
	f.backend.set(proposalData, readbackRevision)
	err = f.coord.ResumePrepared(ctx, f.pull(t), anyPull)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("rejected ack: err = %v, want ErrVerification", err)
	}
	if f.backend.replaces != 0 {
		t.Fatalf("rejected ack wrote %d times", f.backend.replaces)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
}

func TestMemoryBackendRoundTrip(t *testing.T) {
	ctx := context.Background()
	mem := vaultfilebackend.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	if err := mem.CreateIfAbsent(ctx, coordName, own(baseData)); err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	anchor, err := mem.Read(ctx, coordName)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	j := openJournal(t, newJournalDir(t))
	if err := j.InitializeState(vaultfilejournal.State{
		BaseBytes:      own(baseData),
		RemoteRevision: anchor.Revision,
		WorkingBytes:   own(proposalData),
	}); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}

	var sawBase bool
	proposalVerifier := func(_ context.Context, base []byte, rev vaultfilebackend.Revision, p vaultfilejournal.Proposal) error {
		if bytes.Equal(base, baseData) && rev == anchor.Revision {
			sawBase = true
		}
		if !bytes.Equal(p.Bytes, proposalData) || p.ExpectedRevision != anchor.Revision {
			return errProposalRejected
		}
		return nil
	}
	pullVerifier := func(_ context.Context, data []byte, rev vaultfilebackend.Revision) error {
		switch {
		case bytes.Equal(data, baseData) && rev == anchor.Revision:
			return nil
		case bytes.Equal(data, proposalData):
			return nil
		}
		return errPullRejected
	}
	coord, err := NewCoordinator(mem, j, coordName, proposalVerifier)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	pulled, err := ReadPulled(ctx, mem, coordName, pullVerifier)
	if err != nil {
		t.Fatalf("ReadPulled: %v", err)
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       proposalGeneration,
		OperationID:      "op-mem",
		ExpectedRevision: anchor.Revision,
		Bytes:            own(proposalData),
	}
	if err := coord.PrepareAndPublish(ctx, pulled, proposal, pullVerifier); err != nil {
		t.Fatalf("PrepareAndPublish: %v", err)
	}

	after, err := mem.Read(ctx, coordName)
	if err != nil {
		t.Fatalf("Read after publish: %v", err)
	}
	if !bytes.Equal(after.Bytes, proposalData) || after.Revision == anchor.Revision {
		t.Fatalf("backend = (%q, %q), want the proposal at a new revision", after.Bytes, after.Revision)
	}
	s := loadState(t, j)
	if !bytes.Equal(s.BaseBytes, proposalData) || s.RemoteRevision != after.Revision {
		t.Fatalf("state = (%q, %q), want (%q, %q)", s.BaseBytes, s.RemoteRevision, proposalData, after.Revision)
	}
	if !sawBase {
		t.Fatal("proposal verifier never saw the stored base")
	}
}
