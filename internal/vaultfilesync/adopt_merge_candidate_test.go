package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/vaultmerge"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	bolt "go.etcd.io/bbolt"
)

// These tests adopt real BuildMergeCandidate results into a real bbolt journal
// built from real signed age/KDBX files. No fake journal substitutes for the
// authenticated file or transaction boundary.

// adoptRemark marks a synthetic operation ID byte. The protocol allows only
// [a-z0-9-_.:], so markers use the two-digit range '10'..'19'.
const adoptRemark = 0x10

// adoptOpID returns a 32-byte operation ID with the given marker bytes.
func adoptOpID(mark byte) string {
	out := bytes.Repeat([]byte{'o'}, 32)
	out[0] = '1'
	out[1] = '0' + mark%10
	return string(out)
}

// adoptFixture is one clean preview candidate over a real journal. The journal
// keeps its original B/L/old-revision/G state after the build (no rebinding),
// and the remote backend serves R, which differs from B.
type adoptFixture struct {
	f         *fixture
	journal   *vaultfilejournal.Journal
	candidate MergeCandidate
	base      []byte
	local     []byte
	remote    []byte
	// recorded is the exact original B/L/old-revision/G state that
	// RebaseAndPrepare must replace.
	recorded vaultfilejournal.State
}

// adoptBuildFixture creates a conflict-free candidate:
//
//	B (journal base) = A base, B base            seq 2
//	L (working)      = A local, B + local only   seq 3
//	R (remote)       = A base, B remote, remote  seq 4
//
// The build runs with B recorded as the journal base, and that exact state is
// left untouched afterwards. The candidate's source binding therefore names the
// original state, R differs from B, and the clean merge is
// {A local, B remote, local only, remote only}.
func adoptBuildFixture(t *testing.T) *adoptFixture {
	t.Helper()
	f := newFixture(t)
	policy, _, _ := fixtureInputs(t)
	vuk := mergeCandidateTestVUK(t)

	base := mergeCandidateSeal(t, f.pin, policy, 1, 2, adoptOpID(2), mergeCandidatePrevious(2), vuk, []vault.Item{
		mergeCandidateLogin("item-a", "A base"),
		mergeCandidateLogin("item-b", "B base"),
	})
	local := mergeCandidateSeal(t, f.pin, policy, 1, 3, adoptOpID(3), mergeCandidatePrevious(3), vuk, []vault.Item{
		mergeCandidateLogin("item-a", "A local"),
		mergeCandidateLogin("item-b", "B base"),
		mergeCandidateLogin("item-local", "Local only"),
	})
	remote := mergeCandidateSeal(t, f.pin, policy, 1, 4, adoptOpID(4), mergeCandidatePrevious(4), vuk, []vault.Item{
		mergeCandidateLogin("item-a", "A base"),
		mergeCandidateLogin("item-b", "B remote"),
		mergeCandidateLogin("item-remote", "Remote only"),
	})
	mergeCandidateUseRemote(t, f, remote)
	j := f.openJournal(t)
	recorded := vaultfilejournal.State{
		BaseBytes:      base,
		RemoteRevision: "adopt-old-rev-1",
		WorkingBytes:   local,
	}
	if err := j.InitializeState(recorded); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}

	candidate, err := BuildMergeCandidate(context.Background(), f.remote, remoteName, j, f.pin, fixtureDeviceID, f.id, fixtureInputsKey(t))
	if err != nil {
		t.Fatalf("BuildMergeCandidate: %v", err)
	}
	if candidate.MergedBytes == nil || len(candidate.Conflicts) != 0 {
		t.Fatal("fixture candidate is not a clean merge")
	}
	if bytes.Equal(recorded.BaseBytes, candidate.RemoteBytes) {
		t.Fatal("fixture needs R to differ from the journal base B")
	}
	if candidate.sourceBinding != mergeCandidateSourceBinding(recorded) {
		t.Fatal("candidate source binding does not name the original journal state")
	}
	return &adoptFixture{
		f:         f,
		journal:   j,
		candidate: candidate,
		base:      base,
		local:     local,
		remote:    remote,
		recorded:  recorded,
	}
}

// adoptReplaceState rewrites the journal's stored state record directly. The
// public API cannot produce the adoption precondition (a base whose recorded
// revision is the candidate's) without a real remote publication, so fixtures
// record it through the documented LLVS layout. The journal still validates
// every field and checksum when it next reads the record.
func adoptReplaceState(t *testing.T, fx *adoptFixture, state vaultfilejournal.State) {
	t.Helper()
	path := journalPath(t, fx.journal)
	closeNow(t, fx.journal)
	if err := openRaw(t, path, func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("journal")).Put([]byte("state"), adoptEncodeState(state))
	}); err != nil {
		t.Fatalf("rewrite state: %v", err)
	}
	adoptReopen(t, fx, path)
}

// adoptReopen swaps the fixture's open journal for a fresh handle on the same
// file at the same tracked path, so later snapshots and tests use it.
func adoptReopen(t *testing.T, fx *adoptFixture, path string) {
	t.Helper()
	reopened, err := vaultfilejournal.Open(path)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fx.journal = reopened
	journalPathsMu.Lock()
	journalPaths[reopened] = path
	journalPathsMu.Unlock()
}

// adoptFixturePolicy returns the static fixture policy for extra seals.
func adoptFixturePolicy(t *testing.T) *vaultfile.Policy {
	t.Helper()
	policy, _, _ := fixtureInputs(t)
	return policy
}

// adoptSnapshot closes the open journal, records every raw journal key (nested
// buckets included), the backend pair and a deep copy of the caller candidate,
// then reopens the journal.
func adoptSnapshot(fx *adoptFixture) func(t *testing.T) adoptJournalView {
	return func(t *testing.T) adoptJournalView {
		t.Helper()
		return adoptCapture(t, fx)
	}
}

func adoptCapture(t *testing.T, fx *adoptFixture) adoptJournalView {
	path := journalPath(t, fx.journal)
	closeNow(t, fx.journal)
	records := dumpRecords(t, path)
	adoptReopen(t, fx, path)
	backend := mergeCandidateReadBackend(t, fx.f)
	return adoptJournalView{records: records, backend: backend, candidate: adoptCloneCandidate(fx.candidate)}
}

type adoptJournalView struct {
	records   map[string]map[string][]byte
	backend   vaultfilebackend.ReadResult
	candidate MergeCandidate
}

func adoptCloneCandidate(c MergeCandidate) MergeCandidate {
	out := c
	out.RemoteBytes = bytes.Clone(c.RemoteBytes)
	out.MergedBytes = bytes.Clone(c.MergedBytes)
	return out
}

func adoptCandidateEqual(a, b MergeCandidate) bool {
	return bytes.Equal(a.RemoteBytes, b.RemoteBytes) &&
		bytes.Equal(a.MergedBytes, b.MergedBytes) &&
		a.RemoteRevision == b.RemoteRevision &&
		a.ExpectedGeneration == b.ExpectedGeneration &&
		reflect.DeepEqual(a.Conflicts, b.Conflicts) &&
		a.sourceBinding == b.sourceBinding &&
		a.resultBinding == b.resultBinding
}

func adoptAssertUnchanged(t *testing.T, fx *adoptFixture, want adoptJournalView) {
	t.Helper()
	got := adoptSnapshot(fx)(t)
	if !sameRecords(got.records, want.records) {
		t.Fatal("journal records changed on a rejected adoption")
	}
	if got.backend.Revision != want.backend.Revision || !bytes.Equal(got.backend.Bytes, want.backend.Bytes) {
		t.Fatal("backend changed on a rejected adoption")
	}
	if !adoptCandidateEqual(got.candidate, want.candidate) || !adoptCandidateEqual(got.candidate, fx.candidate) {
		t.Fatal("the caller candidate was mutated or cleared")
	}
}

func adoptAssertRejected(t *testing.T, err error, sentinel error) {
	t.Helper()
	if err == nil {
		t.Fatal("adoption returned nil for a rejection")
	}
	if sentinel != nil && !errors.Is(err, sentinel) {
		t.Fatalf("error %v does not match %v", err, sentinel)
	}
	mergeCandidateAssertNoPlaintext(t, err)
}

// adoptAssertNoPreparedOrAudit proves a rejection left no prepared record and
// no audit for the next generation.
func adoptAssertNoPreparedOrAudit(t *testing.T, fx *adoptFixture) {
	t.Helper()
	if _, err := fx.journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("prepared record exists after a rejection (err=%v, want ErrEmpty)", err)
	}
	if _, err := fx.journal.LoadRebaseAudit(fx.recorded.Generation + 1); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("audit written on a rejection (err=%v, want ErrEmpty)", err)
	}
	if state, err := fx.journal.LoadState(); err != nil || state.Generation != fx.recorded.Generation {
		t.Fatalf("state changed on a rejection (err=%v)", err)
	}
}

// adoptEncodeState produces the exact version-1 LLVS state record the journal
// stores, so a test can rewrite a state the public API cannot produce. It
// mirrors the documented layout only; it never substitutes for the journal
// decoder, which validates every rewrite on the next read.
func adoptEncodeState(s vaultfilejournal.State) []byte {
	const prefix = 4 + 2 + 8 + 4 + 2 + 4
	buf := make([]byte, prefix+len(s.BaseBytes)+len(s.RemoteRevision)+len(s.WorkingBytes)+sha256.Size)
	copy(buf[0:4], "LLVS")
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint64(buf[6:14], s.Generation)
	binary.BigEndian.PutUint32(buf[14:18], uint32(len(s.BaseBytes)))
	binary.BigEndian.PutUint16(buf[18:20], uint16(len(s.RemoteRevision)))
	binary.BigEndian.PutUint32(buf[20:24], uint32(len(s.WorkingBytes)))
	off := prefix
	off += copy(buf[off:], s.BaseBytes)
	off += copy(buf[off:], s.RemoteRevision)
	off += copy(buf[off:], s.WorkingBytes)
	h := sha256.New()
	h.Write([]byte("locklark vault-file journal state v1\x00"))
	h.Write(buf[:off])
	h.Sum(buf[off:off])
	return buf
}

// TestAdoptMergeCandidateDurableSuccess proves one nil return commits the audit,
// the rebased state and the prepared record together, with exact fields.
func TestAdoptMergeCandidateDurableSuccess(t *testing.T) {
	fx := adoptBuildFixture(t)
	c := fx.candidate
	// The original journal state is untouched B/L/old-revision/G, and R is a
	// different file, so success proves adoption targets R rather than B.
	if !bytes.Equal(fx.recorded.BaseBytes, fx.base) || !bytes.Equal(fx.recorded.WorkingBytes, fx.local) ||
		fx.recorded.RemoteRevision != "adopt-old-rev-1" || fx.recorded.Generation != c.ExpectedGeneration {
		t.Fatal("fixture journal state is not the original B/L/old revision/G state")
	}
	if bytes.Equal(c.RemoteBytes, fx.recorded.BaseBytes) {
		t.Fatal("test needs R to differ from the journal base B")
	}
	if source := mergeCandidateSourceBinding(fx.recorded); c.sourceBinding != source {
		t.Fatal("candidate source binding is not the original journal state")
	}
	before := adoptSnapshot(fx)(t)

	if err := AdoptMergeCandidate(context.Background(), fx.journal, c, fx.f.pin, fixtureDeviceID, fx.f.id); err != nil {
		t.Fatalf("AdoptMergeCandidate: %v", err)
	}
	mergeCandidateAssertBackendUnchanged(t, fx.f, before.backend)
	if !adoptCandidateEqual(fx.candidate, before.candidate) {
		t.Fatal("successful adoption mutated or cleared the caller candidate")
	}

	state, err := fx.journal.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Generation != c.ExpectedGeneration+1 {
		t.Fatalf("generation = %d, want %d", state.Generation, c.ExpectedGeneration+1)
	}
	if !bytes.Equal(state.BaseBytes, c.RemoteBytes) || state.RemoteRevision != c.RemoteRevision {
		t.Fatal("rebased state is not the exact candidate R/Rrev")
	}
	if !bytes.Equal(state.WorkingBytes, c.MergedBytes) {
		t.Fatal("rebased working bytes are not the exact candidate M")
	}

	prepared, err := fx.journal.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared: %v", err)
	}
	if prepared.WorkingGeneration != c.ExpectedGeneration+1 {
		t.Fatalf("prepared generation = %d, want %d", prepared.WorkingGeneration, c.ExpectedGeneration+1)
	}
	if prepared.Proposal.ExpectedRevision != c.RemoteRevision || !bytes.Equal(prepared.Proposal.Bytes, c.MergedBytes) {
		t.Fatal("prepared proposal is not the exact candidate Rrev/M")
	}
	mergedFile, mergedMetadata, mergedItems := openWorkingState(t, c.MergedBytes, fx.f.pin, fx.f.id)
	if prepared.Proposal.OperationID != mergedFile.Header.OpID {
		t.Fatal("prepared operation ID is not the authenticated M OpID")
	}
	// The proposal generation is the G+1 hint, independent of M's content
	// sequence; the journal generation remains a local CAS counter.
	if prepared.Proposal.Generation != c.ExpectedGeneration+1 {
		t.Fatalf("proposal generation = %d, want the G+1 hint %d", prepared.Proposal.Generation, c.ExpectedGeneration+1)
	}

	if legacy, err := fx.journal.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("legacy record after adoption = %+v, %v; want ErrEmpty", legacy, err)
	}

	audit, err := fx.journal.LoadRebaseAudit(c.ExpectedGeneration + 1)
	if err != nil {
		t.Fatalf("LoadRebaseAudit(%d): %v", c.ExpectedGeneration+1, err)
	}
	if audit.NewGeneration != c.ExpectedGeneration+1 {
		t.Fatalf("audit new generation = %d, want %d", audit.NewGeneration, c.ExpectedGeneration+1)
	}
	if !reflect.DeepEqual(audit.OldState, fx.recorded) {
		t.Fatalf("audit old state does not equal the exact pre-adoption journal state (got generation %d)", audit.OldState.Generation)
	}
	if !bytes.Equal(audit.RemoteBase, c.RemoteBytes) || audit.RemoteRevision != c.RemoteRevision {
		t.Fatal("audit remote pair is not the exact candidate R/Rrev")
	}
	if bytes.Equal(audit.RemoteBase, fx.recorded.BaseBytes) {
		t.Fatal("audit recorded B instead of the target R")
	}
	if !bytes.Equal(audit.Proposal.Bytes, c.MergedBytes) || audit.Proposal.OperationID != mergedFile.Header.OpID {
		t.Fatal("audit proposal is not the exact target M")
	}
	if !reflect.DeepEqual(audit.Proposal, prepared.Proposal) {
		t.Fatal("audit proposal differs from the prepared proposal")
	}

	wantItems := []vault.Item{
		mergeCandidateLogin("item-a", "A local"),
		mergeCandidateLogin("item-b", "B remote"),
		mergeCandidateLogin("item-local", "Local only"),
		mergeCandidateLogin("item-remote", "Remote only"),
	}
	if !reflect.DeepEqual(mergedItems, wantItems) {
		t.Fatalf("adopted items:\n got %+v\nwant %+v", mergedItems, wantItems)
	}
	_, remoteMetadata, _ := openWorkingState(t, fx.remote, fx.f.pin, fx.f.id)
	if !bytes.Equal(mergedMetadata, remoteMetadata) {
		t.Fatal("adopted metadata is not R's metadata")
	}

	// A second adoption of the same candidate is a definite rejection: the
	// journal now holds the prepared record written by the first adoption.
	after := adoptSnapshot(fx)(t)
	err = AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptPending)
	adoptAssertUnchanged(t, fx, after)
}

// TestAdoptMergeCandidateRejectsSameGenerationAck exercises a same-generation
// state change that the public API cannot produce (Ack also bumps the
// generation), by rewriting the stored state exactly as an Ack that changed
// only the base and revision would leave it: same generation, same working
// bytes, replaced base/revision. The stale candidate must be rejected.
func TestAdoptMergeCandidateRejectsSameGenerationAck(t *testing.T) {
	fx := adoptBuildFixture(t)
	c := fx.candidate
	// A newer working L2 at the same generation: an Ack that moved the base
	// and revision while the local working file changed would leave this.
	l2 := mergeCandidateSeal(t, fx.f.pin, adoptFixturePolicy(t), 1, 5, adoptOpID(5), mergeCandidatePrevious(5), mergeCandidateTestVUK(t), []vault.Item{
		mergeCandidateLogin("item-a", "A local v2"),
	})
	acked := vaultfilejournal.State{
		BaseBytes:      fx.local,
		RemoteRevision: "revision-after-ack",
		WorkingBytes:   l2,
		Generation:     c.ExpectedGeneration,
	}
	path := journalPath(t, fx.journal)
	closeNow(t, fx.journal)
	if err := openRaw(t, path, func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("journal")).Put([]byte("state"), adoptEncodeState(acked))
	}); err != nil {
		t.Fatalf("rewrite state: %v", err)
	}
	adoptReopen(t, fx, path)
	before := adoptSnapshot(fx)(t)
	state, err := fx.journal.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Generation != c.ExpectedGeneration {
		t.Fatalf("test needs the same generation: got %d want %d", state.Generation, c.ExpectedGeneration)
	}
	if bytes.Equal(state.BaseBytes, fx.recorded.BaseBytes) || bytes.Equal(state.WorkingBytes, fx.recorded.WorkingBytes) ||
		state.RemoteRevision == fx.recorded.RemoteRevision {
		t.Fatal("test needs the Ack to change the base, working file and revision")
	}
	if c.sourceBinding == mergeCandidateSourceBinding(state) {
		t.Fatal("stale candidate source binding still matches the post-Ack state")
	}

	err = AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptRejected)
	adoptAssertUnchanged(t, fx, before)
	if state, err := fx.journal.LoadState(); err != nil || !reflect.DeepEqual(state, acked) {
		t.Fatalf("post-Ack state was changed (err=%v)", err)
	}
}

// TestAdoptMergeCandidateRejectsBAndRevisionReplacement replaces the journal
// base and/or the remote revision while keeping the generation and working
// file, so the stale candidate's source binding no longer names the state.
func TestAdoptMergeCandidateRejectsBAndRevisionReplacement(t *testing.T) {
	cases := []struct {
		name     string
		base     bool
		revision bool
	}{
		{name: "base_replaced", base: true},
		{name: "revision_replaced", revision: true},
		{name: "both_replaced", base: true, revision: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := adoptBuildFixture(t)
			c := fx.candidate
			newBase := fx.recorded.BaseBytes
			if tc.base {
				newBase = fx.local
			}
			newRevision := fx.recorded.RemoteRevision
			if tc.revision {
				newRevision = "adopt-remote-rev-replaced"
			}
			path := journalPath(t, fx.journal)
			closeNow(t, fx.journal)
			replaced := vaultfilejournal.State{
				BaseBytes:      newBase,
				RemoteRevision: newRevision,
				WorkingBytes:   fx.local,
				Generation:     c.ExpectedGeneration,
			}
			if err := openRaw(t, path, func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("journal")).Put([]byte("state"), adoptEncodeState(replaced))
			}); err != nil {
				t.Fatalf("rewrite state: %v", err)
			}
			adoptReopen(t, fx, path)
			if state, err := fx.journal.LoadState(); err != nil || !reflect.DeepEqual(state, replaced) {
				t.Fatalf("rewritten state does not read back as the replacement (err=%v)", err)
			}

			before := adoptSnapshot(fx)(t)
			err := AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
			adoptAssertRejected(t, err, ErrMergeCandidateAdoptRejected)
			adoptAssertUnchanged(t, fx, before)
			if state, err := fx.journal.LoadState(); err != nil || !reflect.DeepEqual(state, replaced) {
				t.Fatalf("replaced state was changed (err=%v)", err)
			}
			if got, err := fx.journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
				t.Fatalf("prepared record written on rejection: %+v %v", got, err)
			}
			if _, err := fx.journal.LoadRebaseAudit(fx.recorded.Generation + 1); !errors.Is(err, vaultfilejournal.ErrEmpty) {
				t.Fatalf("audit written on rejection: %v", err)
			}
		})
	}
}

// TestAdoptMergeCandidateRejectsConflictAndDamagedCandidates covers a real
// conflict result, a zero candidate, missing/empty/oversized/damaged M, zero
// or oversize revisions and generations, and damaged source/result bindings.
// Every case gets its own journal so no case can observe another's writes.
func TestAdoptMergeCandidateRejectsConflictAndDamagedCandidates(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, fx *adoptFixture, c *MergeCandidate)
		sentinel error
	}{
		{name: "conflict_result", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.MergedBytes = nil
			c.Conflicts = []vaultmerge.Conflict{{ID: "item-a"}}
			c.resultBinding = mergeCandidateResultBinding(c.sourceBinding, c.RemoteBytes, nil, c.RemoteRevision, c.ExpectedGeneration)
		}},
		{name: "zero_candidate", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			*c = MergeCandidate{}
		}},
		{name: "nil_m", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.MergedBytes = nil }},
		{name: "empty_m", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.MergedBytes = []byte{} }},
		{name: "oversize_m", sentinel: ErrMergeCandidateAdoptVerify, mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.MergedBytes = append(bytes.Clone(c.MergedBytes), make([]byte, vaultfilejournal.MaxProposalBytes)...)
		}},
		{name: "unverifiable_m_content", sentinel: ErrMergeCandidateAdoptVerify, mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			// M is a parseable sealed file that the caller-pinned verifier
			// rejects (it is not R's immediate successor), with a consistent
			// result binding, so only verification can reject it.
			c.MergedBytes = bytes.Clone(c.RemoteBytes)
			c.resultBinding = mergeCandidateResultBinding(c.sourceBinding, c.RemoteBytes, c.MergedBytes, c.RemoteRevision, c.ExpectedGeneration)
		}},
		{name: "damaged_m_with_consistent_binding", sentinel: ErrMergeCandidateAdoptVerify, mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			// A tampered M whose result binding was recomputed: only the
			// caller-pinned revalidation can reject it.
			c.MergedBytes[len(c.MergedBytes)-1] ^= 0xff
			c.resultBinding = mergeCandidateResultBinding(c.sourceBinding, c.RemoteBytes, c.MergedBytes, c.RemoteRevision, c.ExpectedGeneration)
		}},
		{name: "damaged_m_bytes", sentinel: nil, mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.MergedBytes[len(c.MergedBytes)-1] ^= 0xff
		}},
		{name: "nil_conflicts", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.Conflicts = nil }},
		{name: "wrong_generation", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.ExpectedGeneration++ }},
		{name: "empty_revision", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.RemoteRevision = "" }},
		{name: "oversize_revision", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.RemoteRevision = vaultfilebackend.Revision(bytes.Repeat([]byte("r"), vaultfilebackend.MaxRevisionSize+1))
		}},
		{name: "replaced_revision", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.RemoteRevision = "another-revision" }},
		{name: "nil_remote", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.RemoteBytes = nil }},
		{name: "oversize_remote", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.RemoteBytes = append(bytes.Clone(c.RemoteBytes), make([]byte, vaultfilejournal.MaxBaseBytes)...)
		}},
		{name: "damaged_remote", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.RemoteBytes[len(c.RemoteBytes)-1] ^= 0xff
		}},
		{name: "base_substituted_for_r", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.RemoteBytes = bytes.Clone(fx.base)
		}},
		{name: "zero_source_binding", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.sourceBinding = [32]byte{} }},
		{name: "zero_result_binding", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.resultBinding = [32]byte{} }},
		{name: "damaged_source_binding", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.sourceBinding[0] ^= 1 }},
		{name: "damaged_result_binding", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) { c.resultBinding[0] ^= 1 }},
		{name: "m_swapped_for_r", mutate: func(t *testing.T, fx *adoptFixture, c *MergeCandidate) {
			c.MergedBytes = bytes.Clone(c.RemoteBytes)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := adoptBuildFixture(t)
			bad := adoptCloneCandidate(fx.candidate)
			tc.mutate(t, fx, &bad)
			fx.candidate = bad
			before := adoptCapture(t, fx)
			err := AdoptMergeCandidate(context.Background(), fx.journal, bad, fx.f.pin, fixtureDeviceID, fx.f.id)
			want := ErrMergeCandidateAdoptRejected
			if tc.sentinel != nil {
				want = tc.sentinel
			}
			adoptAssertRejected(t, err, want)
			adoptAssertUnchanged(t, fx, before)
			adoptAssertNoPreparedOrAudit(t, fx)
		})
	}
}

// TestAdoptMergeCandidateRejectsNilInputs covers nil context, journal, pin and
// identity, an empty device, and a canceled context; none may report success.
func TestAdoptMergeCandidateRejectsNilInputs(t *testing.T) {
	fx := adoptBuildFixture(t)
	before := adoptSnapshot(fx)(t)
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()

	cases := []struct {
		name     string
		ctx      context.Context
		journal  *vaultfilejournal.Journal
		pin      *vaultfile.PolicyCheckpoint
		deviceID string
		identity *age.X25519Identity
		sentinel error
	}{
		{name: "nil_context", ctx: nil, journal: fx.journal, pin: fx.f.pin, deviceID: fixtureDeviceID, identity: fx.f.id, sentinel: ErrMergeCandidateAdoptRejected},
		{name: "nil_journal", ctx: ctx, journal: nil, pin: fx.f.pin, deviceID: fixtureDeviceID, identity: fx.f.id, sentinel: ErrMergeCandidateAdoptRejected},
		{name: "nil_pin", ctx: ctx, journal: fx.journal, pin: nil, deviceID: fixtureDeviceID, identity: fx.f.id, sentinel: ErrMergeCandidateAdoptRejected},
		{name: "nil_identity", ctx: ctx, journal: fx.journal, pin: fx.f.pin, deviceID: fixtureDeviceID, sentinel: ErrMergeCandidateAdoptRejected},
		{name: "empty_device", ctx: ctx, journal: fx.journal, pin: fx.f.pin, identity: fx.f.id, sentinel: ErrMergeCandidateAdoptRejected},
		{name: "canceled_context", ctx: canceled, journal: fx.journal, pin: fx.f.pin, deviceID: fixtureDeviceID, identity: fx.f.id, sentinel: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AdoptMergeCandidate(tc.ctx, tc.journal, fx.candidate, tc.pin, tc.deviceID, tc.identity)
			adoptAssertRejected(t, err, tc.sentinel)
			adoptAssertUnchanged(t, fx, before)
			adoptAssertNoPreparedOrAudit(t, fx)
		})
	}
}

// TestAdoptMergeCandidateRejectsPendingRecords proves a legacy Load record and
// a prepared record each make the candidate non-adoptable without clearing,
// consuming or overwriting them.
func TestAdoptMergeCandidateRejectsPendingRecords(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		fx := adoptBuildFixture(t)
		legacy := vaultfilejournal.Proposal{
			Generation:       1,
			OperationID:      "op-legacy-pending",
			ExpectedRevision: "adopt-remote-rev-1",
			Bytes:            []byte("synthetic legacy sealed proposal"),
		}
		if err := fx.journal.Save(legacy); err != nil {
			t.Fatalf("Save legacy: %v", err)
		}
		before := adoptSnapshot(fx)(t)
		err := AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
		adoptAssertRejected(t, err, ErrMergeCandidateAdoptPending)
		adoptAssertUnchanged(t, fx, before)
		if got, err := fx.journal.Load(); err != nil || !reflect.DeepEqual(got, legacy) {
			t.Fatalf("legacy record changed: got %+v %v want %+v", got, err, legacy)
		}
		if state, err := fx.journal.LoadState(); err != nil || !reflect.DeepEqual(state, fx.recorded) {
			t.Fatalf("state changed on a pending legacy record (err=%v)", err)
		}
	})

	t.Run("prepared", func(t *testing.T) {
		fx := adoptBuildFixture(t)
		prepared := vaultfilejournal.Proposal{
			Generation:       1,
			OperationID:      "op-prepared-pending",
			ExpectedRevision: fx.recorded.RemoteRevision,
			Bytes:            bytes.Clone(fx.local),
		}
		if err := fx.journal.Prepare(fx.recorded.Generation, prepared); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		want, err := fx.journal.LoadPrepared()
		if err != nil {
			t.Fatalf("LoadPrepared: %v", err)
		}
		before := adoptSnapshot(fx)(t)
		err = AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
		adoptAssertRejected(t, err, ErrMergeCandidateAdoptPending)
		adoptAssertUnchanged(t, fx, before)
		if got, err := fx.journal.LoadPrepared(); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("prepared record changed: got %+v %v want %+v", got, err, want)
		}
		if _, err := fx.journal.LoadRebaseAudit(fx.recorded.Generation + 1); !errors.Is(err, vaultfilejournal.ErrEmpty) {
			t.Fatalf("audit written on a pending prepared record: %v", err)
		}
	})
}

// TestAdoptMergeCandidateRejectsCorruptPendingRecord proves a corrupt pending
// record's ErrCorrupt is propagated and never reported as adoption.
func TestAdoptMergeCandidateRejectsCorruptPendingRecord(t *testing.T) {
	for _, key := range []string{"prepared", "proposal"} {
		t.Run(key, func(t *testing.T) {
			fx := adoptBuildFixture(t)
			path := journalPath(t, fx.journal)
			closeNow(t, fx.journal)
			if err := openRaw(t, path, func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("journal")).Put([]byte(key), []byte("LLVP-corrupt"))
			}); err != nil {
				t.Fatalf("corrupt %s record: %v", key, err)
			}
			adoptReopen(t, fx, path)
			before := adoptSnapshot(fx)(t)
			err := AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
			adoptAssertRejected(t, err, nil)
			if !errors.Is(err, vaultfilejournal.ErrCorrupt) {
				t.Fatalf("corrupt pending record error = %v, want ErrCorrupt reachable", err)
			}
			if !errors.Is(err, ErrMergeCandidateAdoptPendingCorrupt) {
				t.Fatalf("corrupt pending record error = %v, want ErrMergeCandidateAdoptPendingCorrupt", err)
			}
			if errors.Is(err, ErrMergeCandidateAdoptPending) {
				t.Fatalf("corrupt pending record was classified as a plain pending record: %v", err)
			}
			adoptAssertUnchanged(t, fx, before)
		})
	}
}

// TestAdoptMergeCandidateRejectsUnverifiableM proves M and the pin decide
// adoption: a M that does not verify under the caller pin is rejected with the
// content proposal verifier's classification even when its own bindings match.
func TestAdoptMergeCandidateRejectsUnverifiableM(t *testing.T) {
	cases := []struct {
		name string
		pin  func(fx *adoptFixture) *vaultfile.PolicyCheckpoint
		m    func(fx *adoptFixture) []byte
	}{
		{
			name: "damaged_m_with_matching_binding",
			pin:  func(fx *adoptFixture) *vaultfile.PolicyCheckpoint { return fx.f.pin },
			m: func(fx *adoptFixture) []byte {
				m := bytes.Clone(fx.candidate.MergedBytes)
				m[len(m)-10] ^= 0xff
				return m
			},
		},
		{
			name: "m_without_valid_proof",
			pin:  func(fx *adoptFixture) *vaultfile.PolicyCheckpoint { return fx.f.pin },
			m: func(fx *adoptFixture) []byte {
				// Swap M for R: it parses and verifies as a file but is not
				// R's immediate successor.
				return bytes.Clone(fx.candidate.RemoteBytes)
			},
		},
		{
			name: "wrong_pin",
			pin: func(fx *adoptFixture) *vaultfile.PolicyCheckpoint {
				pin := *fx.f.pin
				pin.PolicyDigest = bytes.Clone(pin.PolicyDigest)
				pin.PolicyDigest[0] ^= 0xff
				return &pin
			},
			m: func(fx *adoptFixture) []byte { return bytes.Clone(fx.candidate.MergedBytes) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := adoptBuildFixture(t)
			m := tc.m(fx)
			forged := MergeCandidate{
				RemoteBytes:        bytes.Clone(fx.candidate.RemoteBytes),
				MergedBytes:        m,
				RemoteRevision:     fx.candidate.RemoteRevision,
				ExpectedGeneration: fx.candidate.ExpectedGeneration,
				Conflicts:          []vaultmerge.Conflict{},
			}
			// The forged binding is computed from the exact journal state the
			// fixture wrote, so only R/M verification can reject it.
			state, err := fx.journal.LoadState()
			if err != nil {
				t.Fatalf("LoadState: %v", err)
			}
			forged.sourceBinding = mergeCandidateSourceBinding(state)
			forged.resultBinding = mergeCandidateResultBinding(forged.sourceBinding, forged.RemoteBytes, forged.MergedBytes, forged.RemoteRevision, forged.ExpectedGeneration)
			if forged.sourceBinding != fx.candidate.sourceBinding {
				t.Fatal("forged candidate source binding does not match the fixture state")
			}
			fx.candidate = forged
			before := adoptSnapshot(fx)(t)

			err = AdoptMergeCandidate(context.Background(), fx.journal, forged, tc.pin(fx), fixtureDeviceID, fx.f.id)
			adoptAssertRejected(t, err, ErrMergeCandidateAdoptVerify)
			if !errors.Is(err, ErrContentProposalRejected) && !errors.Is(err, ErrMergeCandidateAdoptVerify) {
				t.Fatalf("verification error = %v, want ErrMergeCandidateAdoptVerify", err)
			}
			adoptAssertUnchanged(t, fx, before)
			adoptAssertNoPreparedOrAudit(t, fx)
		})
	}
}

// adoptSealWithDatabase seals one real file under the caller's pin from an
// explicit item database, so a fixture can vary only the inner KDBX header.
func adoptSealWithDatabase(t *testing.T, pin *vaultfile.PolicyCheckpoint, policy *vaultfile.Policy, seq uint64, opID string, vuk []byte, db *kdbx.Database) []byte {
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
			KeyEpoch:       1,
			ContentSeq:     seq,
			PrevDigest:     mergeCandidatePrevious(seq),
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
	_, _, signingKey := fixtureInputs(t)
	encoded, err := vaultfile.SealAuthenticatedFile(draft, db, pin, vuk, signingKey)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	return encoded
}

// adoptDifferentHeaderDatabase returns a real item database whose inner KDBX
// header differs from the fixture's (a different master salt), so it can only
// be decrypted under a second, incompatible VUK. Everything else matches.
func adoptDifferentHeaderDatabase(t *testing.T) (*kdbx.Database, []byte) {
	t.Helper()
	original, err := vault.NewItemDatabase(mergeCandidateMetadata(), []vault.Item{
		mergeCandidateLogin("item-a", "A local"),
		mergeCandidateLogin("item-b", "B remote"),
		mergeCandidateLogin("item-local", "Local only"),
		mergeCandidateLogin("item-remote", "Remote only"),
	})
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	defer releaseDatabase(original)
	if original.Header == nil || original.Header.FileHeaders == nil || original.Header.FileHeaders.KdfParameters == nil {
		t.Fatal("fixture database has no KDF parameters")
	}
	kdf := *original.Header.FileHeaders.KdfParameters
	for i := range kdf.Salt {
		kdf.Salt[i] ^= 0xa5
	}
	kdf.RawData = nil
	// Rebuild the header around the mutated KDF so the encoded file is
	// consistent with it.
	doc := original.Header.FileHeaders
	clone := *original.Header
	headers := *doc
	headers.KdfParameters = &kdf
	clone.FileHeaders = &headers
	modified := &kdbx.Database{
		Options:     original.Options,
		Credentials: &kdbx.DBCredentials{Key: bytes.Clone(original.Credentials.Key)},
		Header:      &clone,
		Hashes:      original.Hashes,
		Content:     original.Content,
	}
	original.Credentials = nil
	original.Content = nil
	pin := fixturePin(t, adoptFixturePolicy(t))
	encoded := adoptSealWithDatabase(t, pin, adoptFixturePolicy(t), 5, adoptOpID(5), mergeCandidateTestVUK(t), modified)
	releaseDatabase(modified)
	return modified, encoded
}

// TestAdoptMergeCandidateRejectsWrongCallerIdentity proves R and M are opened
// under exactly the caller's identity: a different identity cannot decrypt the
// candidate files and is a definite verification rejection that writes nothing.
func TestAdoptMergeCandidateRejectsWrongCallerIdentity(t *testing.T) {
	fx := adoptBuildFixture(t)
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	before := adoptSnapshot(fx)(t)
	err = AdoptMergeCandidate(context.Background(), fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, other)
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptVerify)
	adoptAssertUnchanged(t, fx, before)
	adoptAssertNoPreparedOrAudit(t, fx)
	if state, err := fx.journal.LoadState(); err != nil || !reflect.DeepEqual(state, fx.recorded) {
		t.Fatalf("journal state changed on a wrong caller identity (err=%v)", err)
	}
}

// TestAdoptMergeCandidateRejectsDifferentEpochVUK proves R and M must share one
// same-epoch VUK: an M sealed under a second, incompatible VUK that still opens
// under the caller pin is rejected on the constant-time VUK comparison.
func TestAdoptMergeCandidateRejectsDifferentEpochVUK(t *testing.T) {
	fx := adoptBuildFixture(t)
	_, foreignM := adoptDifferentHeaderDatabase(t)
	if bytes.Equal(foreignM, fx.candidate.MergedBytes) {
		t.Fatal("foreign M equals the fixture's M")
	}
	forged := adoptCloneCandidate(fx.candidate)
	forged.MergedBytes = foreignM
	forged.resultBinding = mergeCandidateResultBinding(forged.sourceBinding, forged.RemoteBytes, forged.MergedBytes, forged.RemoteRevision, forged.ExpectedGeneration)
	// The forged M must itself be fully openable under the caller pin, so the
	// rejection can come only from key continuity.
	foreignFile, foreignDB, err := vaultfile.OpenAuthenticatedFile(foreignM, fx.f.pin, fixtureDeviceID, fx.f.id)
	if err != nil {
		t.Fatalf("foreign M does not open under the caller pin: %v", err)
	}
	releaseDatabase(foreignDB)
	releaseFile(foreignFile)
	fx.candidate = forged
	before := adoptSnapshot(fx)(t)
	err = AdoptMergeCandidate(context.Background(), fx.journal, forged, fx.f.pin, fixtureDeviceID, fx.f.id)
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptVerify)
	// The forgery is openable, so the rejection must be the key-continuity
	// check rather than an earlier authentication failure.
	if !strings.Contains(err.Error(), "share one epoch VUK") {
		t.Fatalf("rejection %v is not the epoch VUK comparison", err)
	}
	adoptAssertUnchanged(t, fx, before)
	adoptAssertNoPreparedOrAudit(t, fx)
}

// TestAdoptMergeCandidateMissingState proves an uninitialized journal is a
// definite rejection.
func TestAdoptMergeCandidateMissingState(t *testing.T) {
	fx := adoptBuildFixture(t)
	j := openNewJournal(t)
	err := AdoptMergeCandidate(context.Background(), j, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
	adoptAssertRejected(t, err, ErrMergeCandidateAdoptRejected)
	wantEmptyJournal(t, j)
}

// adoptGatedContext models a host whose cancellation deadline fires after the
// pinned verifier has accepted the candidate and before the journal
// transaction: every pre-transaction check sees a live context, and the final
// check sees context.Canceled.
type adoptGatedContext struct {
	context.Context
	armed bool
}

func (c *adoptGatedContext) Err() error {
	if c.armed {
		return context.Canceled
	}
	return nil
}

// TestAdoptMergeCandidateCommitErrorIsNeverSuccess proves no RebaseAndPrepare
// error is reported as nil by the classifier.
func TestAdoptMergeCandidateCommitErrorIsNeverSuccess(t *testing.T) {
	if err := classifyAdoptCommitError(nil); err != nil {
		t.Fatalf("nil commit error classified as %v", err)
	}
	unknown := errors.New("synthetic storage failure")
	err := classifyAdoptCommitError(unknown)
	if err == nil || !errors.Is(err, ErrMergeCandidateAdoptCommitUnknown) || !errors.Is(err, unknown) {
		t.Fatalf("unknown commit error = %v, want ErrMergeCandidateAdoptCommitUnknown", err)
	}
	if errors.Is(classifyAdoptCommitError(vaultfilejournal.ErrStateMismatch), ErrMergeCandidateAdoptCommitUnknown) {
		t.Fatal("a definite state mismatch was classified as unknown")
	}
	if !errors.Is(classifyAdoptCommitError(vaultfilejournal.ErrPendingRecords), ErrMergeCandidateAdoptPending) {
		t.Fatal("a pending-record recheck failure was not classified as pending")
	}
}

// TestAdoptMergeCandidateCancellationLate proves a cancellation observed after
// the candidate has been verified and before the journal transaction returns
// the context error, writes nothing and never a false success.
func TestAdoptMergeCandidateCancellationLate(t *testing.T) {
	fx := adoptBuildFixture(t)
	before := adoptSnapshot(fx)(t)
	ctx := &adoptGatedContext{Context: context.Background()}

	ctx.armed = true
	err := AdoptMergeCandidate(ctx, fx.journal, fx.candidate, fx.f.pin, fixtureDeviceID, fx.f.id)
	adoptAssertRejected(t, err, context.Canceled)
	adoptAssertUnchanged(t, fx, before)
	adoptAssertNoPreparedOrAudit(t, fx)
}
