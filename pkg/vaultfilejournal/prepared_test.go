package vaultfilejournal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// preparedState is a state whose working file is exactly the prepared
// proposal's bytes and whose revision is exactly its expected revision.
func preparedState() (State, Proposal) {
	s := baseState()
	p := baseProposal()
	p.ExpectedRevision = s.RemoteRevision
	p.Bytes = bytes.Clone(s.WorkingBytes)
	return s, p
}

func mustInitialize(t *testing.T, j *Journal, s State) {
	t.Helper()
	if err := j.InitializeState(s); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
}

func mustPrepare(t *testing.T, j *Journal, gen uint64, p Proposal) {
	t.Helper()
	if err := j.Prepare(gen, p); err != nil {
		t.Fatalf("Prepare(gen %d): %v", gen, err)
	}
}

func mustLoadPrepared(t *testing.T, j *Journal) PreparedProposal {
	t.Helper()
	pp, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared: %v", err)
	}
	return pp
}

func assertPrepared(t *testing.T, got, want PreparedProposal) {
	t.Helper()
	if !samePrepared(got, want) {
		t.Fatalf("prepared mismatch:\n got gen=%d op=%q rev=%q bytes=%d\nwant gen=%d op=%q rev=%q bytes=%d",
			got.WorkingGeneration, got.Proposal.OperationID, got.Proposal.ExpectedRevision, len(got.Proposal.Bytes),
			want.WorkingGeneration, want.Proposal.OperationID, want.Proposal.ExpectedRevision, len(want.Proposal.Bytes))
	}
}

// snapshot captures every local record the prepared checkpoint may touch.
type snapshot struct {
	state       State
	proposal    Proposal
	prepared    PreparedProposal
	rawState    []byte
	rawProposal []byte
	rawPrepared []byte
}

func takeSnapshot(t *testing.T, j *Journal) snapshot {
	t.Helper()
	return snapshot{
		state:       mustLoadState(t, j),
		proposal:    mustLoad(t, j),
		prepared:    mustLoadPrepared(t, j),
		rawState:    rawKey(t, j, stateKey),
		rawProposal: rawKey(t, j, recordKey),
		rawPrepared: rawKey(t, j, preparedKey),
	}
}

func assertUnchanged(t *testing.T, j *Journal, before snapshot) {
	t.Helper()
	assertState(t, mustLoadState(t, j), before.state)
	assertProposal(t, mustLoad(t, j), before.proposal)
	assertPrepared(t, mustLoadPrepared(t, j), before.prepared)
	if !bytes.Equal(rawKey(t, j, stateKey), before.rawState) ||
		!bytes.Equal(rawKey(t, j, recordKey), before.rawProposal) ||
		!bytes.Equal(rawKey(t, j, preparedKey), before.rawPrepared) {
		t.Fatal("a rejected call changed a raw stored record")
	}
}

// TestAckLegacyOperationIDRejectedKeepsPrepared is the real-file regression
// where the legacy proposal record and the prepared proposal are different
// operations with different generations. Acking with the legacy operation ID
// and the legacy proposal bytes must be ErrPreparedMismatch and leave state,
// prepared and legacy raw bytes exactly as they were; LoadPrepared still
// returns the prepared operation and Load still returns the legacy one
// verbatim. Acknowledging the prepared operation with its own sealed bytes
// then succeeds and still leaves the legacy record untouched.
func TestAckLegacyOperationIDRejectedKeepsPrepared(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	legacy := baseProposal()
	mustSave(t, j, legacy)

	s, p := preparedState()
	p.OperationID = "op-2026-11-11:prepared.2"
	p.Generation = legacy.Generation + 5
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	if legacy.OperationID == p.OperationID || legacy.Generation == p.Generation {
		t.Fatal("fixture must keep the legacy and prepared operations distinct")
	}

	before := takeSnapshot(t, j)
	assertProposal(t, before.proposal, legacy)
	assertPrepared(t, before.prepared, PreparedProposal{WorkingGeneration: 0, Proposal: p})

	if err := j.Ack(legacy.OperationID, legacy.Bytes, `"legacy-ack"`); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(legacy op, legacy bytes) = %v, want ErrPreparedMismatch", err)
	}
	assertUnchanged(t, j, before)
	// Neither record was replaced by the other.
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: 0, Proposal: p})
	assertProposal(t, mustLoad(t, j), legacy)

	// The correct prepared operation is still acknowledged afterwards.
	newRev := vaultfilebackend.Revision(`"prepared-ack"`)
	if err := j.Ack(p.OperationID, p.Bytes, newRev); err != nil {
		t.Fatalf("Ack(prepared op, prepared bytes): %v", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after Ack = %v, want ErrEmpty", err)
	}
	got := mustLoadState(t, j)
	if !bytes.Equal(got.BaseBytes, p.Bytes) || got.RemoteRevision != newRev ||
		!bytes.Equal(got.WorkingBytes, p.Bytes) || got.Generation != 0 {
		t.Fatalf("acked state = rev %q gen %d base %d working %d",
			got.RemoteRevision, got.Generation, len(got.BaseBytes), len(got.WorkingBytes))
	}
	// The legacy record is still exactly the legacy operation on disk.
	assertProposal(t, mustLoad(t, j), legacy)
	if !bytes.Equal(rawKey(t, j, recordKey), before.rawProposal) {
		t.Fatal("Ack changed the legacy proposal record")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), got)
	if _, err := j2.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j2), legacy)
	if !bytes.Equal(rawKey(t, j2, recordKey), before.rawProposal) {
		t.Fatal("reopened legacy proposal record changed")
	}
}

// TestPreparedLifecycleLateAckKeepsNewerWorking is the main real-file story:
// a legacy LLVJ v1 proposal is saved, state is initialized, a proposal is
// prepared, the process restarts, the prepared proposal matches exactly, a
// newer working edit is written, the late ack arrives, and after another
// restart the base/revision advanced while the newer working edit and its
// generation survived and the prepared record is gone.
func TestPreparedLifecycleLateAckKeepsNewerWorking(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	legacy := baseProposal()
	mustSave(t, j, legacy)
	rawLegacy := rawKey(t, j, recordKey)

	s, p := preparedState()
	mustInitialize(t, j, s)

	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("fresh LoadPrepared = %v, want ErrEmpty", err)
	}
	mustPrepare(t, j, 0, p)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: 0, Proposal: p})
	// The legacy record is untouched and remains decodable.
	assertProposal(t, mustLoad(t, j), legacy)
	if !bytes.Equal(rawKey(t, j, recordKey), rawLegacy) {
		t.Fatal("Prepare changed the legacy proposal record")
	}

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: the exact prepared proposal is recovered.
	j2 := openAt(t, dir)
	recovered := mustLoadPrepared(t, j2)
	assertPrepared(t, recovered, PreparedProposal{WorkingGeneration: 0, Proposal: p})
	assertProposal(t, mustLoad(t, j2), legacy)

	// A newer working edit arrives before the ack.
	newer := opaque(len(p.Bytes)+13, 91)
	if err := j2.UpdateWorking(0, newer); err != nil {
		t.Fatalf("UpdateWorking: %v", err)
	}
	if err := j2.Close(); err != nil {
		t.Fatal(err)
	}

	// The ack is applied on the state loaded from disk, not on a guess.
	j3 := openAt(t, dir)
	live := mustLoadState(t, j3)
	pp := mustLoadPrepared(t, j3)
	if live.Generation != 1 || !bytes.Equal(live.WorkingBytes, newer) {
		t.Fatalf("newer edit not on disk: gen=%d", live.Generation)
	}
	newRev := vaultfilebackend.Revision(`W/"acked-8"`)
	if err := j3.Ack(pp.Proposal.OperationID, pp.Proposal.Bytes, newRev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if _, err := j3.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after Ack = %v, want ErrEmpty", err)
	}
	// Repeating the ack is refused because there is nothing prepared.
	if err := j3.Ack(pp.Proposal.OperationID, pp.Proposal.Bytes, newRev); !errors.Is(err, ErrEmpty) {
		t.Fatalf("second Ack = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j3), legacy)
	if err := j3.Close(); err != nil {
		t.Fatal(err)
	}

	j4 := openAt(t, dir)
	got := mustLoadState(t, j4)
	if !bytes.Equal(got.BaseBytes, p.Bytes) {
		t.Fatal("base was not advanced to the acked proposal bytes")
	}
	if got.RemoteRevision != newRev {
		t.Fatalf("revision = %q, want %q", got.RemoteRevision, newRev)
	}
	if !bytes.Equal(got.WorkingBytes, newer) {
		t.Fatal("the newer working edit was lost by the late ack")
	}
	if got.Generation != 1 {
		t.Fatalf("generation = %d, want 1", got.Generation)
	}
	if _, err := j4.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j4), legacy)
	if !bytes.Equal(rawKey(t, j4, recordKey), rawLegacy) {
		t.Fatal("Ack changed the legacy proposal record")
	}
}

// TestPreparedAckWithoutNewEditIsClean prepares and acks with no edit in
// between: working equals the new base and the prepared record is cleared.
func TestPreparedAckWithoutNewEditIsClean(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)

	newRev := vaultfilebackend.Revision(`"clean-1"`)
	if err := j.Ack(p.OperationID, p.Bytes, newRev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	got := mustLoadState(t, j)
	if !bytes.Equal(got.BaseBytes, p.Bytes) || !bytes.Equal(got.WorkingBytes, got.BaseBytes) {
		t.Fatal("working does not equal the new base")
	}
	if got.RemoteRevision != newRev || got.Generation != 0 {
		t.Fatalf("state = rev %q gen %d", got.RemoteRevision, got.Generation)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared = %v, want ErrEmpty", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), got)
	if _, err := j2.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j2), legacy)
}

// TestPreparedAckAfterConcurrentEditCommit forces the order with channel
// barriers. The edit transaction first holds the journal mutex and blocks (as
// earlier public calls would do between transactions) through its hook, which
// runs after the state Put and before the Bolt commit. The Ack for the older
// prepared proposal then starts and announces itself on a channel; the test
// does not wait to prove it reached the mutex, because the mutex stays held by
// the edit until release, so the Ack can only proceed after the edit commits
// and releases it. It must re-read the committed state and succeed: it
// advances base/revision, keeps the newer working bytes and generation and
// clears the prepared record. The edit committing first is the target path
// here, not a mismatch. Every wait is bounded and the release is deferred, so
// a failure cannot hang the test.
func TestPreparedAckAfterConcurrentEditCommit(t *testing.T) {
	j := openAt(t, privateDir(t))
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)

	edit := opaque(len(p.Bytes)+5, 117)
	newRev := vaultfilebackend.Revision(`"acked-after-edit"`)
	const wait = 10 * time.Second

	editPut := make(chan struct{})
	hookRelease := make(chan struct{})
	var hookReleaseOnce sync.Once
	// Deferred, so a t.Fatal after the goroutines started can never leave
	// the edit transaction blocked in its hook.
	defer hookReleaseOnce.Do(func() { close(hookRelease) })

	editDone := make(chan error, 1)
	go func() {
		editDone <- j.updateWorkingWithHook(0, edit, func() error {
			close(editPut)
			<-hookRelease
			return nil
		})
	}()

	select {
	case <-editPut:
	case <-time.After(wait):
		t.Fatal("edit never reached its state Put")
	}

	// The edit now holds the journal mutex in its hook. The Ack therefore
	// cannot re-read state until the edit has committed and released it.
	ackStarted := make(chan struct{})
	ackDone := make(chan error, 1)
	go func() {
		close(ackStarted)
		ackDone <- j.Ack(p.OperationID, p.Bytes, newRev)
	}()
	// Barrier: from the Ack start until the edit hook is released the mutex
	// stays owned by the edit, so the Ack can read state only after the edit
	// transaction commits, however long that takes.
	select {
	case <-ackStarted:
	case <-time.After(wait):
		t.Fatal("Ack goroutine never started")
	}

	// Let the edit commit and release the mutex; the Ack then proceeds.
	hookReleaseOnce.Do(func() { close(hookRelease) })
	select {
	case err := <-editDone:
		if err != nil {
			t.Fatalf("UpdateWorking: %v", err)
		}
	case <-time.After(wait):
		t.Fatal("edit did not commit after release (journal mutex still held)")
	}

	select {
	case err := <-ackDone:
		if err != nil {
			t.Fatalf("Ack after the edit committed: %v", err)
		}
	case <-time.After(wait):
		t.Fatal("Ack did not finish after the edit committed (journal mutex still held)")
	}

	got := mustLoadState(t, j)
	if !bytes.Equal(got.BaseBytes, p.Bytes) {
		t.Fatal("Ack did not advance the base to the acked proposal bytes")
	}
	if got.RemoteRevision != newRev {
		t.Fatalf("revision = %q, want %q", got.RemoteRevision, newRev)
	}
	if !bytes.Equal(got.WorkingBytes, edit) || got.Generation != 1 {
		t.Fatalf("Ack lost the newer working edit or generation: gen=%d", got.Generation)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after Ack = %v, want ErrEmpty", err)
	}
}

// TestPrepareRejectsMismatch proves generation, revision and working-byte
// disagreements are refused without changing any record.
func TestPrepareRejectsMismatch(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)

	// No state at all.
	empty := openAt(t, privateDir(t))
	if err := empty.Prepare(0, p); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Prepare without state = %v, want ErrEmpty", err)
	}

	badRev := p
	badRev.ExpectedRevision = vaultfilebackend.Revision(`"other"`)
	badBytes := p
	badBytes.Bytes = opaque(len(p.Bytes), 7)
	sameLenBadBytes := p
	sameLenBadBytes.Bytes = opaque(len(p.Bytes), 8)

	// The stored generation is 0.
	if err := j.Prepare(1, p); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Prepare(wrong generation) = %v, want ErrPreparedMismatch", err)
	}
	before := snapshotNoPrepared(t, j)
	if err := j.Prepare(0, badRev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Prepare(wrong revision) = %v, want ErrPreparedMismatch", err)
	}
	if err := j.Prepare(0, badBytes); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Prepare(wrong bytes) = %v, want ErrPreparedMismatch", err)
	}
	if err := j.Prepare(0, sameLenBadBytes); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Prepare(same-length wrong bytes) = %v, want ErrPreparedMismatch", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("rejected Prepare stored something: %v", err)
	}
	assertState(t, mustLoadState(t, j), before.state)
	assertProposal(t, mustLoad(t, j), before.proposal)

	// Malformed proposals are rejected before the transaction.
	for _, mut := range []func(*Proposal){
		func(q *Proposal) { q.Generation = 0 },
		func(q *Proposal) { q.OperationID = "" },
		func(q *Proposal) { q.OperationID = "Bad Op" },
		func(q *Proposal) { q.Bytes = nil },
		func(q *Proposal) { q.Bytes = make([]byte, MaxProposalBytes+1) },
		func(q *Proposal) {
			q.ExpectedRevision = vaultfilebackend.Revision(make([]byte, MaxExpectedRevisionBytes+1))
		},
	} {
		q := p
		q.Bytes = bytes.Clone(p.Bytes)
		mut(&q)
		if err := j.Prepare(0, q); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Prepare(malformed) = %v, want ErrInvalid", err)
		}
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("malformed Prepare stored something: %v", err)
	}

	// A matching proposal is accepted after every rejection.
	mustPrepare(t, j, 0, p)
}

// snapshotNoPrepared captures state and the legacy proposal while asserting no
// prepared record exists.
func snapshotNoPrepared(t *testing.T, j *Journal) snapshot {
	t.Helper()
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("snapshotNoPrepared: LoadPrepared = %v, want ErrEmpty", err)
	}
	return snapshot{
		state:       mustLoadState(t, j),
		proposal:    mustLoad(t, j),
		rawState:    rawKey(t, j, stateKey),
		rawProposal: rawKey(t, j, recordKey),
	}
}

// TestPrepareReplayAndConflict covers idempotent replay and refusal to
// overwrite a different outstanding proposal.
func TestPrepareReplayAndConflict(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	before := takeSnapshot(t, j)

	// Exact replay, including a rebuilt value, is a no-op.
	mustPrepare(t, j, 0, p)
	rebuilt := p
	rebuilt.Bytes = bytes.Clone(p.Bytes)
	mustPrepare(t, j, 0, rebuilt)
	assertUnchanged(t, j, before)

	// A different outstanding proposal is refused, not overwritten.
	other := p
	other.OperationID = "op-other"
	if err := j.Prepare(0, other); !errors.Is(err, ErrPreparedExists) {
		t.Fatalf("Prepare(different) = %v, want ErrPreparedExists", err)
	}
	otherGen := p
	otherGen.Generation = p.Generation + 1
	if err := j.Prepare(0, otherGen); !errors.Is(err, ErrPreparedExists) {
		t.Fatalf("Prepare(different generation) = %v, want ErrPreparedExists", err)
	}
	assertUnchanged(t, j, before)

	// After the outstanding proposal is acked and a real working edit lands,
	// the new proposal can be prepared.
	if err := j.Ack(p.OperationID, p.Bytes, `"replayed"`); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	newer := opaque(len(p.Bytes)+1, 121)
	if err := j.UpdateWorking(0, newer); err != nil {
		t.Fatal(err)
	}
	next := p
	next.OperationID = "op-next"
	next.ExpectedRevision = `"replayed"`
	next.Bytes = newer
	mustPrepare(t, j, 1, next)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: 1, Proposal: next})
	assertProposal(t, mustLoad(t, j), legacy)
}

// TestAckRejectsMismatch proves a wrong operation ID or wrong sealed proposal
// bytes (truncated, flipped, another proposal's, or the journal envelope
// instead of the file bytes), a stale expected revision, and malformed new
// revisions change no record.
func TestAckRejectsMismatch(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	before := takeSnapshot(t, j)
	exact := p.Bytes
	rev := vaultfilebackend.Revision(`"new"`)

	if err := j.Ack("op-wrong", exact, rev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(wrong op) = %v, want ErrPreparedMismatch", err)
	}
	if err := j.Ack(p.OperationID, exact[:len(exact)-1], rev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(truncated bytes) = %v, want ErrPreparedMismatch", err)
	}
	// The right operation ID and length with one flipped byte is refused.
	flipped := bytes.Clone(exact)
	flipped[len(flipped)/2] ^= 0xff
	if err := j.Ack(p.OperationID, flipped, rev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(flipped bytes) = %v, want ErrPreparedMismatch", err)
	}
	// Another proposal's sealed file bytes, of the same length, are refused.
	other := p
	other.Bytes = opaque(len(p.Bytes), 9)
	if err := j.Ack(p.OperationID, other.Bytes, rev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(other proposal bytes) = %v, want ErrPreparedMismatch", err)
	}
	// The journal's own LLVJ v1 encoding of the right proposal is not the
	// sealed file bytes the caller read, so it is refused too.
	if err := j.Ack(p.OperationID, encodeRecord(p), rev); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(record envelope instead of file bytes) = %v, want ErrPreparedMismatch", err)
	}
	if err := j.Ack(p.OperationID, exact, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Ack(empty revision) = %v, want ErrInvalid", err)
	}
	if err := j.Ack(p.OperationID, exact, vaultfilebackend.Revision(make([]byte, MaxStateRevisionBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Ack(oversize revision) = %v, want ErrInvalid", err)
	}
	assertUnchanged(t, j, before)

	// The prepared proposal was not consumed, so the right ack still works.
	if err := j.Ack(p.OperationID, exact, rev); err != nil {
		t.Fatalf("Ack after rejections: %v", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j), legacy)
}

// TestAckNoPrepared proves an ack without a prepared record changes nothing.
func TestAckNoPrepared(t *testing.T) {
	j := openAt(t, privateDir(t))
	s, p := preparedState()
	mustInitialize(t, j, s)
	before := mustLoadState(t, j)
	if err := j.Ack(p.OperationID, p.Bytes, `"r"`); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Ack without prepared = %v, want ErrEmpty", err)
	}
	assertState(t, mustLoadState(t, j), before)
}

// TestAckStalePreparedRejected proves a prepared proposal whose expected
// revision is no longer the base revision, or whose generation is newer than
// the state's, cannot be acked and changes nothing.
func TestAckStalePreparedRejected(t *testing.T) {
	j := openAt(t, privateDir(t))
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	exact := p.Bytes

	// Someone else advanced the remote base independently.
	baseMoved := s
	baseMoved.BaseBytes = opaque(128, 131)
	baseMoved.RemoteRevision = vaultfilebackend.Revision(`"moved"`)
	writeRawState(t, j, encodeState(baseMoved))
	before := mustLoadState(t, j)
	if err := j.Ack(p.OperationID, exact, `"new"`); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(stale expected revision) = %v, want ErrPreparedMismatch", err)
	}
	assertState(t, mustLoadState(t, j), before)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: 0, Proposal: p})

	// A prepared generation above the state's (planted with a raw fixture,
	// since the API cannot produce it) is refused too, even though the
	// revision matches again.
	baseMoved.Generation = 7
	writeRawState(t, j, encodeState(baseMoved))
	writeRawPrepared(t, j, encodePrepared(PreparedProposal{WorkingGeneration: 8, Proposal: p}))
	before = mustLoadState(t, j)
	if err := j.Ack(p.OperationID, exact, `"new"`); !errors.Is(err, ErrPreparedMismatch) {
		t.Fatalf("Ack(prepared newer than state) = %v, want ErrPreparedMismatch", err)
	}
	assertState(t, mustLoadState(t, j), before)
}

func writeRawPrepared(t *testing.T, j *Journal, raw []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put([]byte(preparedKey), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPrepareFaultAfterPutRollsBack fails Prepare after the prepared Put and
// before commit, then retries after reopening.
func TestPrepareFaultAfterPutRollsBack(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)

	fault := errors.New("injected prepare fault")
	ran := false
	err := j.prepareWithHook(0, p, func() error {
		ran = true
		return fault
	})
	if !ran {
		t.Fatal("fault hook never ran")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("Prepare under fault = %v, want the injected fault", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared = %v, want ErrEmpty", err)
	}
	assertState(t, mustLoadState(t, j), s)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2 := openAt(t, dir)
	if _, err := j2.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("reopened LoadPrepared = %v, want ErrEmpty", err)
	}
	assertState(t, mustLoadState(t, j2), s)
	mustPrepare(t, j2, 0, p)
	assertPrepared(t, mustLoadPrepared(t, j2), PreparedProposal{WorkingGeneration: 0, Proposal: p})
	assertProposal(t, mustLoad(t, j2), legacy)
}

// TestAckFaultAfterDeleteRollsBack fails Ack after the state Put and the
// prepared delete and before commit. The whole transaction rolls back: after
// reopening the state and prepared record are exactly as before, and the ack
// can be retried.
func TestAckFaultAfterDeleteRollsBack(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	legacy := baseProposal()
	mustSave(t, j, legacy)
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	// A newer edit, so a rollback that only half-restored state is visible.
	newer := opaque(len(p.Bytes)+3, 141)
	if err := j.UpdateWorking(0, newer); err != nil {
		t.Fatal(err)
	}
	before := takeSnapshot(t, j)
	exact := p.Bytes
	newRev := vaultfilebackend.Revision(`"acked-after-fault"`)

	fault := errors.New("injected ack fault")
	ran := false
	err := j.ackWithHook(p.OperationID, exact, newRev, func() error {
		ran = true
		return fault
	})
	if !ran {
		t.Fatal("fault hook never ran")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("Ack under fault = %v, want the injected fault", err)
	}
	assertUnchanged(t, j, before)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2 := openAt(t, dir)
	assertUnchanged(t, j2, before)

	// Retrying with the hook disabled completes the ack.
	if err := j2.Ack(p.OperationID, exact, newRev); err != nil {
		t.Fatalf("retry Ack: %v", err)
	}
	got := mustLoadState(t, j2)
	if !bytes.Equal(got.BaseBytes, p.Bytes) || got.RemoteRevision != newRev ||
		!bytes.Equal(got.WorkingBytes, newer) || got.Generation != 1 {
		t.Fatalf("retried ack state = rev %q gen %d base %d working %d",
			got.RemoteRevision, got.Generation, len(got.BaseBytes), len(got.WorkingBytes))
	}
	if _, err := j2.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared = %v, want ErrEmpty", err)
	}
	assertProposal(t, mustLoad(t, j2), legacy)
}

// TestPreparedRecordRoundTrip checks the wrapper encodes the inner LLVJ v1
// record verbatim and decodes it again exactly.
func TestPreparedRecordRoundTrip(t *testing.T) {
	_, p := preparedState()
	pp := PreparedProposal{WorkingGeneration: 42, Proposal: p}
	raw := encodePrepared(pp)
	if got := raw[preparedPrefix : len(raw)-preparedDigest]; !bytes.Equal(got, encodeRecord(p)) {
		t.Fatal("wrapper does not embed the exact LLVJ v1 record")
	}
	if got := binary.BigEndian.Uint64(raw[6:14]); got != 42 {
		t.Fatalf("embedded working generation = %d", got)
	}
	decoded, err := decodePrepared(raw)
	if err != nil {
		t.Fatal(err)
	}
	assertPrepared(t, decoded, pp)
	// WorkingGeneration is independent of Proposal.Generation.
	if decoded.WorkingGeneration == decoded.Proposal.Generation {
		t.Fatal("fixture must keep the two generations distinct")
	}
}

// encodePreparedRaw wraps an already encoded LLVJ v1 record verbatim and seals
// the outer digest, so tests can embed a deliberately malformed inner record.
func encodePreparedRaw(workingGeneration uint64, inner []byte) []byte {
	buf := make([]byte, preparedOverhead+len(inner))
	copy(buf[0:4], preparedMagic)
	binary.BigEndian.PutUint16(buf[4:6], preparedVersion)
	binary.BigEndian.PutUint64(buf[6:14], workingGeneration)
	binary.BigEndian.PutUint32(buf[14:18], uint32(len(inner)))
	copy(buf[preparedPrefix:], inner)
	sum := preparedDigestOf(buf[:preparedPrefix+len(inner)])
	copy(buf[preparedPrefix+len(inner):], sum[:])
	return buf
}

// TestPreparedRejectsCorruptRecords mutates stored wrappers and requires a
// strict ErrCorrupt from load, with no repair: the raw value stays as written.
func TestPreparedRejectsCorruptRecords(t *testing.T) {
	_, p := preparedState()
	good := encodePrepared(PreparedProposal{WorkingGeneration: 3, Proposal: p})

	cases := map[string][]byte{
		"truncated":           good[:len(good)-1],
		"trailing byte":       append(bytes.Clone(good), 0),
		"digest flipped":      flip(good, len(good)-1),
		"inner flipped":       flip(good, preparedPrefix+10),
		"bad version":         flip(good, 5),
		"bad magic":           flip(good, 0),
		"working gen changed": flip(good, 13),
		"zero length":         setPreparedLen(good, 0),
		"length over cap":     setPreparedLen(good, maxRecordLen+1),
		"length max uint32":   setPreparedLen(good, math.MaxUint32),
		"too long overall":    append(bytes.Clone(good), make([]byte, MaxPreparedRecordBytes)...),
		"empty":               {},
	}
	for name, raw := range cases {
		if _, err := decodePrepared(raw); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: decodePrepared = %v, want ErrCorrupt", name, err)
		}
	}

	// A valid wrapper whose inner record is not LLVJ v1 is corrupt too.
	badInner := encodePrepared(PreparedProposal{WorkingGeneration: 3, Proposal: p})
	badInner[preparedPrefix+4] ^= 0xff
	// Re-seal the outer digest so only the inner record is wrong.
	sum := preparedDigestOf(badInner[:len(badInner)-preparedDigest])
	copy(badInner[len(badInner)-preparedDigest:], sum[:])
	if _, err := decodePrepared(badInner); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inner mutation = %v, want ErrCorrupt", err)
	}

	// Through the real file: a corrupt stored wrapper is reported and kept.
	dir := privateDir(t)
	j := openAt(t, dir)
	corrupt := flip(bytes.Clone(good), len(good)-1)
	writeRawPrepared(t, j, corrupt)
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadPrepared(corrupt) = %v, want ErrCorrupt", err)
	}
	if !bytes.Equal(rawKey(t, j, preparedKey), corrupt) {
		t.Fatal("a corrupt prepared record was rewritten")
	}

	// A wrapper whose length, checksum and inner digest are all valid but
	// whose inner record declares proposal length math.MaxUint32 with the
	// hostile 54-byte shape must be rejected by the inner decoder.
	wrapped := encodePreparedRaw(3, hostileWrappedLengthRecord())
	pp, err := decodePrepared(bytes.Clone(wrapped))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrapped hostile inner record = %v, want ErrCorrupt", err)
	}
	if !samePrepared(pp, PreparedProposal{}) {
		t.Fatalf("wrapped hostile inner record returned a partial result: %+v", pp)
	}
}

func flip(raw []byte, i int) []byte {
	raw[i] ^= 0xff
	return raw
}

func setPreparedLen(raw []byte, n uint32) []byte {
	binary.BigEndian.PutUint32(raw[14:18], n)
	return raw
}

// TestPreparedConcurrentUse is a race-detector sanity check for the mutex.
func TestPreparedConcurrentUse(t *testing.T) {
	j := openAt(t, privateDir(t))
	s, p := preparedState()
	mustInitialize(t, j, s)
	mustPrepare(t, j, 0, p)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for k := 0; k < 10; k++ {
				_ = j.Prepare(0, p)
				_, _ = j.LoadPrepared()
				_ = j.Ack("wrong", p.Bytes, `"r"`)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// TestClosedPreparedAPI covers the prepared methods after Close.
func TestClosedPreparedAPI(t *testing.T) {
	j, err := Open(filepath.Join(privateDir(t), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, p := preparedState()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrClosed) {
		t.Fatalf("LoadPrepared = %v, want ErrClosed", err)
	}
	if err := j.Prepare(0, p); !errors.Is(err, ErrClosed) {
		t.Fatalf("Prepare = %v, want ErrClosed", err)
	}
	if err := j.Ack(p.OperationID, p.Bytes, `"r"`); !errors.Is(err, ErrClosed) {
		t.Fatalf("Ack = %v, want ErrClosed", err)
	}
}
