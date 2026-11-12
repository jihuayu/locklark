package vaultfilejournal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

func mustRebase(t *testing.T, j *Journal, expected State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, p Proposal) {
	t.Helper()
	if err := j.RebaseAndPrepare(expected, remoteBase, remoteRevision, p); err != nil {
		t.Fatalf("RebaseAndPrepare: %v", err)
	}
}

func mustLoadAudit(t *testing.T, j *Journal, generation uint64) RebaseAudit {
	t.Helper()
	a, err := j.LoadRebaseAudit(generation)
	if err != nil {
		t.Fatalf("LoadRebaseAudit(%d): %v", generation, err)
	}
	return a
}

func assertAudit(t *testing.T, got, want RebaseAudit) {
	t.Helper()
	if !sameState(got.OldState, want.OldState) ||
		!bytes.Equal(got.RemoteBase, want.RemoteBase) ||
		got.RemoteRevision != want.RemoteRevision ||
		got.NewGeneration != want.NewGeneration ||
		!sameProposal(got.Proposal, want.Proposal) {
		t.Fatalf("audit mismatch:\n got old-gen=%d new-gen=%d rev=%q base=%d prop-gen=%d prop-bytes=%d\nwant old-gen=%d new-gen=%d rev=%q base=%d prop-gen=%d prop-bytes=%d",
			got.OldState.Generation, got.NewGeneration, got.RemoteRevision, len(got.RemoteBase), got.Proposal.Generation, len(got.Proposal.Bytes),
			want.OldState.Generation, want.NewGeneration, want.RemoteRevision, len(want.RemoteBase), want.Proposal.Generation, len(want.Proposal.Bytes))
	}
}

func cloneState(s State) State {
	return State{
		BaseBytes:      bytes.Clone(s.BaseBytes),
		RemoteRevision: vaultfilebackend.Revision(bytes.Clone([]byte(s.RemoteRevision))),
		WorkingBytes:   bytes.Clone(s.WorkingBytes),
		Generation:     s.Generation,
	}
}

func cloneProposal(p Proposal) Proposal {
	return Proposal{
		Generation:       p.Generation,
		OperationID:      p.OperationID,
		ExpectedRevision: vaultfilebackend.Revision(bytes.Clone([]byte(p.ExpectedRevision))),
		Bytes:            bytes.Clone(p.Bytes),
	}
}

func rebaseProposal(expectedRevision vaultfilebackend.Revision) Proposal {
	p := baseProposal()
	p.Generation = 123
	p.OperationID = "op-rebase:atomic.1"
	p.ExpectedRevision = expectedRevision
	p.Bytes = opaque(4099, 61)
	return p
}

// rawAudit returns the raw audit value at generation, or nil.
func rawAudit(t *testing.T, j *Journal, generation uint64) []byte {
	t.Helper()
	var out []byte
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.View(func(tx *bolt.Tx) error {
		tb := tx.Bucket([]byte(bucketName))
		if tb == nil {
			return nil
		}
		ab := tb.Bucket([]byte(auditBucketName))
		if ab == nil {
			return nil
		}
		out = bytes.Clone(ab.Get(auditKey(generation)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rawAuditEntries(t *testing.T, j *Journal) map[uint64][]byte {
	t.Helper()
	out := make(map[uint64][]byte)
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.View(func(tx *bolt.Tx) error {
		tb := tx.Bucket([]byte(bucketName))
		if tb == nil {
			return nil
		}
		ab := tb.Bucket([]byte(auditBucketName))
		if ab == nil {
			return nil
		}
		return ab.ForEach(func(k, v []byte) error {
			if len(k) != 8 || v == nil {
				t.Fatalf("malformed audit entry key=%x value=%v", k, v)
			}
			out[binary.BigEndian.Uint64(k)] = bytes.Clone(v)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeRawJournalKey(t *testing.T, j *Journal, key string, raw []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return tb.Put([]byte(key), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeJournalNestedBucket(t *testing.T, j *Journal, key, child string, value []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		nb, err := tb.CreateBucket([]byte(key))
		if err != nil {
			return err
		}
		if child == "" {
			return nil
		}
		return nb.Put([]byte(child), value)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeRawAudit(t *testing.T, j *Journal, key, raw []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		ab, err := tb.CreateBucketIfNotExists([]byte(auditBucketName))
		if err != nil {
			return err
		}
		return ab.Put(key, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeAuditNestedBucket(t *testing.T, j *Journal, key []byte, child string, value []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		tb, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		ab, err := tb.CreateBucketIfNotExists([]byte(auditBucketName))
		if err != nil {
			return err
		}
		nb, err := ab.CreateBucket(key)
		if err != nil {
			return err
		}
		if child == "" {
			return nil
		}
		return nb.Put([]byte(child), value)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRebaseAndPrepareLifecycle is the real-file success story: one call
// replaces the base, makes the proposal bytes the working file, bumps the local
// generation, prepares the exact proposal and appends one audit record. Every
// value is exact after close and reopen, and the proposal's own generation is
// the original caller value, independent of the local generations.
func TestRebaseAndPrepareLifecycle(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	old := baseState()
	mustInitialize(t, j, old)

	remoteBase := opaque(4096, 201)
	remoteRev := vaultfilebackend.Revision(`"remote-base-11"`)
	p := baseProposal()
	p.Generation = 4242 // independent of the local state generation
	p.OperationID = "op-rebase:success.1"
	p.ExpectedRevision = remoteRev
	p.Bytes = opaque(5001, 202)
	if p.Generation == old.Generation || p.Generation == old.Generation+1 {
		t.Fatal("fixture must keep the proposal generation independent")
	}

	if err := j.RebaseAndPrepare(old, remoteBase, remoteRev, p); err != nil {
		t.Fatalf("RebaseAndPrepare: %v", err)
	}

	wantState := State{
		BaseBytes:      remoteBase,
		RemoteRevision: remoteRev,
		WorkingBytes:   p.Bytes,
		Generation:     old.Generation + 1,
	}
	wantPrepared := PreparedProposal{WorkingGeneration: old.Generation + 1, Proposal: p}
	wantAudit := RebaseAudit{
		OldState:       old,
		RemoteBase:     remoteBase,
		RemoteRevision: remoteRev,
		NewGeneration:  old.Generation + 1,
		Proposal:       p,
	}

	assertState(t, mustLoadState(t, j), wantState)
	assertPrepared(t, mustLoadPrepared(t, j), wantPrepared)
	assertAudit(t, mustLoadAudit(t, j, old.Generation+1), wantAudit)

	raw := rawAudit(t, j, old.Generation+1)
	if raw == nil {
		t.Fatal("audit record was not written")
	}
	if !bytes.Equal(raw, encodeRebaseAudit(wantAudit)) {
		t.Fatal("audit value is not the LLVA v1 encoding of the expected record")
	}
	if _, err := j.LoadRebaseAudit(old.Generation); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadRebaseAudit(old generation) = %v, want ErrEmpty", err)
	}
	if _, err := j.LoadRebaseAudit(old.Generation + 2); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadRebaseAudit(unused generation) = %v, want ErrEmpty", err)
	}

	mustClose(t, j)
	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), wantState)
	assertPrepared(t, mustLoadPrepared(t, j2), wantPrepared)
	assertAudit(t, mustLoadAudit(t, j2, old.Generation+1), wantAudit)
	if got := rawAudit(t, j2, old.Generation+1); !bytes.Equal(got, raw) {
		t.Fatal("reopened audit bytes differ from the committed record")
	}
}

// TestRebaseAndPrepareFullStateCAS performs a real same-generation Ack that
// changes BaseBytes and RemoteRevision, then presents the pre-Ack state to
// RebaseAndPrepare. A generation-only CAS would accept it; the full-state CAS
// must reject it and leave every record unchanged.
func TestRebaseAndPrepareFullStateCAS(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	old := baseState()
	mustInitialize(t, j, old)

	// Prepare and immediately acknowledge a proposal at the same local
	// generation, so only the base and revision move.
	prepared := baseProposal()
	prepared.ExpectedRevision = old.RemoteRevision
	prepared.Bytes = bytes.Clone(old.WorkingBytes)
	mustPrepare(t, j, old.Generation, prepared)
	ackRev := vaultfilebackend.Revision(`"acked-at-the-same-generation"`)
	if err := j.Ack(prepared.OperationID, prepared.Bytes, ackRev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	acked := mustLoadState(t, j)
	if acked.Generation != old.Generation {
		t.Fatalf("ack changed the generation from %d to %d", old.Generation, acked.Generation)
	}
	if !bytes.Equal(acked.BaseBytes, old.WorkingBytes) ||
		acked.RemoteRevision != ackRev ||
		acked.RemoteRevision == old.RemoteRevision ||
		bytes.Equal(acked.BaseBytes, old.BaseBytes) {
		t.Fatalf("fixture Ack did not change base/revision: rev=%q base=%d", acked.RemoteRevision, len(acked.BaseBytes))
	}
	rawStateBefore := rawKey(t, j, stateKey)
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after Ack = %v, want ErrEmpty", err)
	}

	remoteBase := opaque(777, 211)
	remoteRev := vaultfilebackend.Revision(`"new-remote-base"`)
	p := rebaseProposal(remoteRev)
	err := j.RebaseAndPrepare(old, remoteBase, remoteRev, p)
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("RebaseAndPrepare with a stale same-generation state = %v, want ErrStateMismatch", err)
	}

	assertState(t, mustLoadState(t, j), acked)
	if !bytes.Equal(rawKey(t, j, stateKey), rawStateBefore) {
		t.Fatal("rejected rebase rewrote the state record")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("rejected rebase stored a prepared record: %v", err)
	}
	if rawAudit(t, j, old.Generation+1) != nil {
		t.Fatal("rejected rebase wrote an audit record")
	}
	if got := rawAuditEntries(t, j); len(got) != 0 {
		t.Fatalf("rejected rebase wrote %d audit records", len(got))
	}

	mustClose(t, j)
	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), acked)
	if rawAudit(t, j2, old.Generation+1) != nil {
		t.Fatal("reopened journal contains an audit for the rejected rebase")
	}
}

// TestRebaseAndPrepareRejectsPendingRecords proves a legacy LLVJ proposal, a
// prepared LLVP proposal, and either key stored as a nested bucket are refused
// as pending work, with every existing raw byte unchanged.
func TestRebaseAndPrepareRejectsPendingRecords(t *testing.T) {
	t.Run("legacy proposal value", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		legacy := baseProposal()
		mustSave(t, j, legacy)
		rawState := rawKey(t, j, stateKey)
		rawLegacy := rawKey(t, j, recordKey)

		remoteRev := vaultfilebackend.Revision(`"pending-legacy"`)
		err := j.RebaseAndPrepare(old, opaque(128, 221), remoteRev, rebaseProposal(remoteRev))
		if !errors.Is(err, ErrPendingRecords) {
			t.Fatalf("RebaseAndPrepare with legacy record = %v, want ErrPendingRecords", err)
		}
		if !bytes.Equal(rawKey(t, j, stateKey), rawState) ||
			!bytes.Equal(rawKey(t, j, recordKey), rawLegacy) {
			t.Fatal("rejected rebase changed a raw record")
		}
		assertProposal(t, mustLoad(t, j), legacy)
		assertState(t, mustLoadState(t, j), old)
		if rawAudit(t, j, old.Generation+1) != nil {
			t.Fatal("rejected rebase wrote an audit record")
		}
	})

	t.Run("prepared proposal value", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		pending := baseProposal()
		pending.ExpectedRevision = old.RemoteRevision
		pending.Bytes = bytes.Clone(old.WorkingBytes)
		mustPrepare(t, j, old.Generation, pending)
		rawState := rawKey(t, j, stateKey)
		rawPrepared := rawKey(t, j, preparedKey)
		wantPrepared := PreparedProposal{WorkingGeneration: old.Generation, Proposal: pending}

		remoteRev := vaultfilebackend.Revision(`"pending-prepared"`)
		err := j.RebaseAndPrepare(old, opaque(128, 222), remoteRev, rebaseProposal(remoteRev))
		if !errors.Is(err, ErrPendingRecords) {
			t.Fatalf("RebaseAndPrepare with prepared record = %v, want ErrPendingRecords", err)
		}
		if !bytes.Equal(rawKey(t, j, stateKey), rawState) ||
			!bytes.Equal(rawKey(t, j, preparedKey), rawPrepared) {
			t.Fatal("rejected rebase changed a raw record")
		}
		assertState(t, mustLoadState(t, j), old)
		assertPrepared(t, mustLoadPrepared(t, j), wantPrepared)
		if rawAudit(t, j, old.Generation+1) != nil {
			t.Fatal("rejected rebase wrote an audit record")
		}
	})

	t.Run("legacy proposal nested bucket", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		marker := []byte("untouched legacy bucket child")
		writeJournalNestedBucket(t, j, recordKey, "child", marker)

		remoteRev := vaultfilebackend.Revision(`"pending-legacy-bucket"`)
		err := j.RebaseAndPrepare(old, opaque(128, 223), remoteRev, rebaseProposal(remoteRev))
		if !errors.Is(err, ErrPendingRecords) {
			t.Fatalf("RebaseAndPrepare with legacy nested bucket = %v, want ErrPendingRecords", err)
		}
		assertState(t, mustLoadState(t, j), old)
		if got := rawNested(t, j, bucketName, recordKey, "child"); !bytes.Equal(got, marker) {
			t.Fatal("rejected rebase changed the legacy nested bucket")
		}
		if rawAudit(t, j, old.Generation+1) != nil {
			t.Fatal("rejected rebase wrote an audit record")
		}
	})

	t.Run("prepared proposal nested bucket", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		marker := []byte("untouched prepared bucket child")
		writeJournalNestedBucket(t, j, preparedKey, "child", marker)

		remoteRev := vaultfilebackend.Revision(`"pending-prepared-bucket"`)
		err := j.RebaseAndPrepare(old, opaque(128, 224), remoteRev, rebaseProposal(remoteRev))
		if !errors.Is(err, ErrPendingRecords) {
			t.Fatalf("RebaseAndPrepare with prepared nested bucket = %v, want ErrPendingRecords", err)
		}
		assertState(t, mustLoadState(t, j), old)
		if got := rawNested(t, j, bucketName, preparedKey, "child"); !bytes.Equal(got, marker) {
			t.Fatal("rejected rebase changed the prepared nested bucket")
		}
		if rawAudit(t, j, old.Generation+1) != nil {
			t.Fatal("rejected rebase wrote an audit record")
		}
	})
}

func rawNested(t *testing.T, j *Journal, bucket, key, child string) []byte {
	t.Helper()
	var out []byte
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		nb := b.Bucket([]byte(key))
		if nb == nil {
			return nil
		}
		out = bytes.Clone(nb.Get([]byte(child)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRebaseAndPrepareFaultRollsBackAndAuditsAppendOnly commits generation 1,
// clears the prepared record with a real Ack, then fails a generation-2 rebase
// after all three Puts. State, prepared and the new audit roll back together
// while audit 1 survives byte for byte. A later successful generation 2
// appends audit 2 and leaves audit 1 loadable and unchanged.
func TestRebaseAndPrepareFaultRollsBackAndAuditsAppendOnly(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	old := baseState()
	mustInitialize(t, j, old)

	rev1 := vaultfilebackend.Revision(`"remote-1"`)
	p1 := baseProposal()
	p1.Generation = 501
	p1.OperationID = "op-rebase:first.1"
	p1.ExpectedRevision = rev1
	p1.Bytes = opaque(1024, 231)
	mustRebase(t, j, old, opaque(2048, 232), rev1, p1)
	next := old.Generation + 1
	audit1 := mustLoadAudit(t, j, next)
	rawAudit1 := rawAudit(t, j, next)
	if rawAudit1 == nil {
		t.Fatal("first audit was not written")
	}

	// Clear the prepared record through a real Ack at the same generation so
	// another rebase is allowed. The base becomes the prepared bytes.
	ackRev := vaultfilebackend.Revision(`"acked-between-rebases"`)
	if err := j.Ack(p1.OperationID, p1.Bytes, ackRev); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	clean := mustLoadState(t, j)
	if clean.Generation != next || !bytes.Equal(clean.BaseBytes, p1.Bytes) || clean.RemoteRevision != ackRev {
		t.Fatalf("post-Ack state = gen %d rev %q base %d", clean.Generation, clean.RemoteRevision, len(clean.BaseBytes))
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after Ack = %v, want ErrEmpty", err)
	}
	rawStateClean := rawKey(t, j, stateKey)

	rev2 := vaultfilebackend.Revision(`"remote-2"`)
	p2 := baseProposal()
	p2.Generation = 502
	p2.OperationID = "op-rebase:second.1"
	p2.ExpectedRevision = rev2
	p2.Bytes = opaque(1536, 233)

	fault := errors.New("injected rebase fault after all puts")
	ran := false
	err := j.rebaseAndPrepareWithHook(clean, opaque(3072, 234), rev2, p2, func() error {
		ran = true
		return fault
	})
	if !ran {
		t.Fatal("fault hook never ran")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("RebaseAndPrepare under fault = %v, want the injected fault", err)
	}

	// Nothing from the faulted generation was published in the still-open
	// handle, and the earlier audit is byte-for-byte unchanged.
	assertState(t, mustLoadState(t, j), clean)
	if !bytes.Equal(rawKey(t, j, stateKey), rawStateClean) {
		t.Fatal("faulted rebase changed the raw state")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("faulted rebase left a prepared record: %v", err)
	}
	if rawAudit(t, j, clean.Generation+1) != nil {
		t.Fatal("faulted rebase left an audit record")
	}
	if got := rawAudit(t, j, next); !bytes.Equal(got, rawAudit1) {
		t.Fatal("faulted rebase changed the prior audit")
	}
	assertAudit(t, mustLoadAudit(t, j, next), audit1)

	mustClose(t, j)
	j = openAt(t, dir)
	assertState(t, mustLoadState(t, j), clean)
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("reopened faulted journal has a prepared record: %v", err)
	}
	if rawAudit(t, j, clean.Generation+1) != nil {
		t.Fatal("reopened faulted journal has a new audit")
	}
	if got := rawAudit(t, j, next); !bytes.Equal(got, rawAudit1) {
		t.Fatal("reopened prior audit changed")
	}
	assertAudit(t, mustLoadAudit(t, j, next), audit1)

	// A later generation succeeds and appends only a second audit.
	mustRebase(t, j, clean, opaque(3072, 234), rev2, p2)
	want2 := State{
		BaseBytes:      opaque(3072, 234),
		RemoteRevision: rev2,
		WorkingBytes:   p2.Bytes,
		Generation:     clean.Generation + 1,
	}
	assertState(t, mustLoadState(t, j), want2)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: clean.Generation + 1, Proposal: p2})
	audit2 := RebaseAudit{
		OldState:       clean,
		RemoteBase:     opaque(3072, 234),
		RemoteRevision: rev2,
		NewGeneration:  clean.Generation + 1,
		Proposal:       p2,
	}
	assertAudit(t, mustLoadAudit(t, j, clean.Generation+1), audit2)
	if got := rawAudit(t, j, next); !bytes.Equal(got, rawAudit1) {
		t.Fatal("second rebase rewrote the first audit")
	}
	assertAudit(t, mustLoadAudit(t, j, next), audit1)

	mustClose(t, j)
	j = openAt(t, dir)
	assertAudit(t, mustLoadAudit(t, j, next), audit1)
	assertAudit(t, mustLoadAudit(t, j, clean.Generation+1), audit2)
	entries := rawAuditEntries(t, j)
	if len(entries) != 2 ||
		!bytes.Equal(entries[next], rawAudit1) ||
		!bytes.Equal(entries[clean.Generation+1], encodeRebaseAudit(audit2)) {
		t.Fatalf("audit entries after reopen = %d, want exactly the two committed generations", len(entries))
	}
}

// TestRebaseAndPrepareGenerationOverflow plants a MaxUint64 state and proves
// the existing overflow sentinel is returned without writing anything.
func TestRebaseAndPrepareGenerationOverflow(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	maxed := baseState()
	maxed.Generation = math.MaxUint64
	writeRawState(t, j, encodeState(maxed))
	rawBefore := rawKey(t, j, stateKey)

	remoteRev := vaultfilebackend.Revision(`"overflow-remote"`)
	err := j.RebaseAndPrepare(maxed, opaque(64, 241), remoteRev, rebaseProposal(remoteRev))
	var overflow *StateGenerationOverflowError
	if !errors.As(err, &overflow) || !errors.Is(err, ErrStateGenerationOverflow) {
		t.Fatalf("RebaseAndPrepare(MaxUint64) = %v, want *StateGenerationOverflowError", err)
	}
	if overflow.Generation != math.MaxUint64 {
		t.Fatalf("overflow reports generation %d", overflow.Generation)
	}
	assertState(t, mustLoadState(t, j), maxed)
	if !bytes.Equal(rawKey(t, j, stateKey), rawBefore) {
		t.Fatal("overflow rejection rewrote the state")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("overflow rejection stored prepared: %v", err)
	}
	if got := rawAuditEntries(t, j); len(got) != 0 {
		t.Fatalf("overflow rejection wrote %d audits", len(got))
	}

	mustClose(t, j)
	assertState(t, mustLoadState(t, openAt(t, dir)), maxed)
}

func sampleRebaseAudit() RebaseAudit {
	old := baseState()
	old.Generation = 5
	remoteRev := vaultfilebackend.Revision(`"audit-remote-revision"`)
	p := baseProposal()
	p.Generation = 9090
	p.OperationID = "op-audit:decode.1"
	p.ExpectedRevision = remoteRev
	p.Bytes = opaque(321, 251)
	return RebaseAudit{
		OldState:       old,
		RemoteBase:     opaque(654, 252),
		RemoteRevision: remoteRev,
		NewGeneration:  old.Generation + 1,
		Proposal:       p,
	}
}

func setAuditLengths(raw []byte, n1 uint32, n2 uint16, n3 uint32, n4 uint32, n5 uint16, n6 uint32, n7 uint16, n8 uint16) {
	binary.BigEndian.PutUint32(raw[22:26], n1)
	binary.BigEndian.PutUint16(raw[26:28], n2)
	binary.BigEndian.PutUint32(raw[28:32], n3)
	binary.BigEndian.PutUint32(raw[32:36], n4)
	binary.BigEndian.PutUint16(raw[36:38], n5)
	binary.BigEndian.PutUint32(raw[38:42], n6)
	binary.BigEndian.PutUint16(raw[42:44], n7)
	binary.BigEndian.PutUint16(raw[44:46], n8)
}

func resealAudit(raw []byte) []byte {
	body := raw[:len(raw)-auditDigest]
	sum := auditDigestOf(body)
	copy(raw[len(raw)-auditDigest:], sum[:])
	return raw
}

// TestRebaseAuditDecoderRejectsMalformed feeds every class of malformed audit
// record and requires ErrCorrupt with no partial result.
func TestRebaseAuditDecoderRejectsMalformed(t *testing.T) {
	good := encodeRebaseAudit(sampleRebaseAudit())
	decoded, err := decodeRebaseAudit(bytes.Clone(good))
	if err != nil {
		t.Fatalf("decode good audit: %v", err)
	}
	assertAudit(t, decoded, sampleRebaseAudit())

	clone := func() []byte { return bytes.Clone(good) }
	n := sampleRebaseAudit()
	n1, n2, n3 := len(n.OldState.BaseBytes), len(n.OldState.RemoteRevision), len(n.OldState.WorkingBytes)
	n4, n5, n6 := len(n.RemoteBase), len(n.RemoteRevision), len(n.Proposal.Bytes)
	n7, n8 := len(n.Proposal.OperationID), len(n.Proposal.ExpectedRevision)
	setLens := func(r []byte) []byte {
		setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
		return r
	}

	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"short":            good[:auditOverhead-1],
		"prefix-only":      good[:auditPrefix],
		"truncated-by-one": good[:len(good)-1],
		"truncated-digest": good[:len(good)-auditDigest],
		"bad-magic":        flip(clone(), 0),
		"proposal-magic": func() []byte {
			r := clone()
			copy(r[0:4], recordMagic)
			return resealAudit(r)
		}(),
		"bad-version-0": func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 0); return resealAudit(r) }(),
		"bad-version-2": func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 2); return resealAudit(r) }(),
		"zero-working-len": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), 0, uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"zero-remote-base-len": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), 0, uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"zero-remote-rev-len": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), 0, uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"zero-proposal-len": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), uint16(n5), 0, uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"zero-operation-len": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), 0, uint16(n8))
			return resealAudit(r)
		}(),
		"base-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, MaxBaseBytes+1, uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"revision-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), MaxStateRevisionBytes+1, uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"working-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), MaxWorkingBytes+1, uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"remote-base-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), MaxBaseBytes+1, uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"operation-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), MaxOperationIDBytes+1, uint16(n8))
			return resealAudit(r)
		}(),
		"expected-rev-too-long": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), MaxExpectedRevisionBytes+1)
			return resealAudit(r)
		}(),
		"base-without-rev": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), 0, uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"rev-without-base": func() []byte {
			r := clone()
			setAuditLengths(r, 0, uint16(n2), uint32(n3), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"length-past-end": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3+1), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"length-short": func() []byte {
			r := clone()
			setAuditLengths(r, uint32(n1), uint16(n2), uint32(n3-1), uint32(n4), uint16(n5), uint32(n6), uint16(n7), uint16(n8))
			return resealAudit(r)
		}(),
		"trailing-byte":  append(clone(), 0),
		"trailing-bytes": append(clone(), bytes.Repeat([]byte{0xee}, 64)...),
		"digest-bit-flip": func() []byte {
			r := clone()
			r[len(r)-1] ^= 0x01
			return r
		}(),
		"body-bit-flip": func() []byte {
			r := clone()
			r[auditPrefix] ^= 0x01
			return r
		}(),
		"length-bit-flip": func() []byte {
			r := clone()
			r[22] ^= 0x01
			return r
		}(),
		"proposal-generation-mismatch": func() []byte {
			r := setLens(clone())
			binary.BigEndian.PutUint64(r[46:54], 0)
			return resealAudit(r)
		}(),
		"expected-revision-mismatch": func() []byte {
			r := clone()
			r[len(r)-auditDigest-1] ^= 0x01
			return resealAudit(r)
		}(),
		"new-generation-wrong": func() []byte {
			r := clone()
			binary.BigEndian.PutUint64(r[14:22], n.NewGeneration+9)
			return resealAudit(r)
		}(),
		"old-generation-max": func() []byte {
			r := clone()
			binary.BigEndian.PutUint64(r[6:14], math.MaxUint64)
			return resealAudit(r)
		}(),
		// The LLVJ, LLVS and LLVP digests are not accepted for an audit.
		"proposal-domain": func() []byte {
			r := clone()
			sum := recordDigestOf(r[:len(r)-auditDigest])
			copy(r[len(r)-auditDigest:], sum[:])
			return r
		}(),
		"state-domain": func() []byte {
			r := clone()
			sum := stateDigestOf(r[:len(r)-auditDigest])
			copy(r[len(r)-auditDigest:], sum[:])
			return r
		}(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := decodeRebaseAudit(raw)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodeRebaseAudit err = %v, want ErrCorrupt", err)
			}
			if !sameRebaseAudit(a, RebaseAudit{}) {
				t.Fatalf("decodeRebaseAudit returned a partial audit: %+v", a)
			}
		})
	}
}

func sameRebaseAudit(a, b RebaseAudit) bool {
	return sameState(a.OldState, b.OldState) &&
		bytes.Equal(a.RemoteBase, b.RemoteBase) &&
		a.RemoteRevision == b.RemoteRevision &&
		a.NewGeneration == b.NewGeneration &&
		sameProposal(a.Proposal, b.Proposal)
}

// TestRebaseAuditDecoderBoundsBeforeAllocation proves hostile length headers
// are rejected from the fixed prefix and the actual length, without allocating
// from any declared length, panicking or wrapping uint32.
func TestRebaseAuditDecoderBoundsBeforeAllocation(t *testing.T) {
	good := encodeRebaseAudit(sampleRebaseAudit())
	var cal countingAllocator
	cal.stop = startAllocTracking(&cal)
	a, err := decodeRebaseAudit(bytes.Clone(good))
	got := cal.stop()
	if err != nil || got < int64(len(a.OldState.BaseBytes)+len(a.OldState.WorkingBytes)+len(a.RemoteBase)+len(a.Proposal.Bytes)) {
		t.Fatalf("valid decode allocated %d bytes (%v)", got, err)
	}

	header := func(mutate func([]byte)) []byte {
		r := bytes.Clone(good[:auditOverhead])
		mutate(r)
		return resealAudit(r)
	}
	hostile := []struct {
		name string
		raw  []byte
	}{
		{"max-uint32-all", header(func(r []byte) {
			setAuditLengths(r, math.MaxUint32, math.MaxUint16, math.MaxUint32, math.MaxUint32, math.MaxUint16, math.MaxUint32, math.MaxUint16, math.MaxUint16)
		})},
		{"max-uint32-base", header(func(r []byte) {
			setAuditLengths(r, math.MaxUint32, 0, 1, 1, 1, 1, 1, 0)
		})},
		{"max-uint32-working", header(func(r []byte) {
			setAuditLengths(r, 0, 0, math.MaxUint32, 1, 1, 1, 1, 0)
		})},
		{"max-uint32-proposal", header(func(r []byte) {
			setAuditLengths(r, 0, 0, 1, 1, 1, math.MaxUint32, 1, 0)
		})},
		// Every field is within its cap but the declared total is far larger
		// than the header: the uint64 total check rejects it.
		{"declared-past-end", header(func(r []byte) {
			setAuditLengths(r, MaxBaseBytes, MaxStateRevisionBytes, 1, 1, 1, 1, 1, 0)
		})},
	}
	for _, h := range hostile {
		for _, grow := range []int{0, 4096} {
			raw := bytes.Clone(h.raw)
			if grow > 0 {
				raw = append(raw, make([]byte, grow)...)
			}
			var alloc countingAllocator
			alloc.stop = startAllocTracking(&alloc)
			a, err := decodeRebaseAudit(raw)
			got := alloc.stop()
			if !errors.Is(err, ErrCorrupt) || !sameRebaseAudit(a, RebaseAudit{}) {
				t.Fatalf("%s: decodeRebaseAudit = %v, want ErrCorrupt and no result", h.name, err)
			}
			if got > 1024 {
				t.Fatalf("%s (len %d, +%d): corrupt audit allocated %d bytes before rejection", h.name, len(h.raw), grow, got)
			}
		}
	}
}

// TestRebaseAuditUint32WrapRejected pins the hostile header where four uint32
// lengths would wrap a 32-bit sum onto the real record length. The decoder must
// compare in uint64 and reject without panicking.
func TestRebaseAuditUint32WrapRejected(t *testing.T) {
	raw := make([]byte, auditOverhead)
	copy(raw[0:4], auditMagic)
	binary.BigEndian.PutUint16(raw[4:6], auditVersion)
	binary.BigEndian.PutUint64(raw[6:14], 0)
	binary.BigEndian.PutUint64(raw[14:22], 1)
	// old base = MaxUint32, revision = 1, working = 1, remote base = 1,
	// remote revision = 1, proposal bytes = 1, operation = 1, expected = 1.
	setAuditLengths(raw, math.MaxUint32, 1, 1, 1, 1, 1, 1, 1)
	raw = resealAudit(raw)

	for name, in := range map[string][]byte{
		"exact":    raw,
		"trailing": append(bytes.Clone(raw), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			a, err := decodeRebaseAudit(in)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodeRebaseAudit(len %d) err = %v, want ErrCorrupt", len(in), err)
			}
			if !sameRebaseAudit(a, RebaseAudit{}) {
				t.Fatalf("decodeRebaseAudit returned a partial audit: %+v", a)
			}
		})
	}
}

// TestRebaseAuditMalformedStorage proves malformed audit bucket/key shapes and
// corrupt stored audit values are ErrCorrupt through both the load and write
// paths, and nothing is repaired or overwritten.
func TestRebaseAuditMalformedStorage(t *testing.T) {
	t.Run("top-level value instead of audit bucket", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		value := []byte("not a nested audit bucket")
		writeRawJournalKey(t, j, auditBucketName, value)
		rawState := rawKey(t, j, stateKey)

		if _, err := j.LoadRebaseAudit(1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("LoadRebaseAudit = %v, want ErrCorrupt", err)
		}
		remoteRev := vaultfilebackend.Revision(`"malformed-audit-shape"`)
		if err := j.RebaseAndPrepare(old, opaque(64, 61), remoteRev, rebaseProposal(remoteRev)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("RebaseAndPrepare = %v, want ErrCorrupt", err)
		}
		if !bytes.Equal(rawKey(t, j, auditBucketName), value) || !bytes.Equal(rawKey(t, j, stateKey), rawState) {
			t.Fatal("a malformed audit shape was repaired or the state changed")
		}
	})

	t.Run("non-eight-byte audit key", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		writeRawAudit(t, j, []byte("short"), []byte("value"))
		rawBefore := rawKey(t, j, stateKey)

		// A lookup of one generation does not scan unrelated keys, but the
		// write path must reject the malformed key shape.
		if _, err := j.LoadRebaseAudit(1); !errors.Is(err, ErrEmpty) {
			t.Fatalf("LoadRebaseAudit = %v, want ErrEmpty", err)
		}
		remoteRev := vaultfilebackend.Revision(`"malformed-audit-key"`)
		if err := j.RebaseAndPrepare(old, opaque(64, 62), remoteRev, rebaseProposal(remoteRev)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("RebaseAndPrepare = %v, want ErrCorrupt", err)
		}
		if got := rawNested(t, j, bucketName, auditBucketName, "short"); !bytes.Equal(got, []byte("value")) {
			t.Fatal("malformed audit key was changed")
		}
		if !bytes.Equal(rawKey(t, j, stateKey), rawBefore) {
			t.Fatal("malformed audit key changed the state")
		}
	})

	t.Run("nested bucket at audit key", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		gen := old.Generation + 1
		writeAuditNestedBucket(t, j, auditKey(gen), "child", []byte("marker"))

		if _, err := j.LoadRebaseAudit(gen); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("LoadRebaseAudit = %v, want ErrCorrupt", err)
		}
		remoteRev := vaultfilebackend.Revision(`"nested-audit-key"`)
		if err := j.RebaseAndPrepare(old, opaque(64, 63), remoteRev, rebaseProposal(remoteRev)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("RebaseAndPrepare = %v, want ErrCorrupt", err)
		}
		assertState(t, mustLoadState(t, j), old)
	})

	t.Run("corrupt audit value", func(t *testing.T) {
		j := openAt(t, privateDir(t))
		old := baseState()
		mustInitialize(t, j, old)
		good := encodeRebaseAudit(sampleRebaseAudit())
		corrupt := flip(bytes.Clone(good), len(good)-1)
		writeRawAudit(t, j, auditKey(sampleRebaseAudit().NewGeneration), corrupt)

		if _, err := j.LoadRebaseAudit(sampleRebaseAudit().NewGeneration); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("LoadRebaseAudit = %v, want ErrCorrupt", err)
		}
		if got := rawAudit(t, j, sampleRebaseAudit().NewGeneration); !bytes.Equal(got, corrupt) {
			t.Fatal("a corrupt audit value was rewritten")
		}
		if err := j.RebaseAndPrepare(old, opaque(64, 64), `"r"`, rebaseProposal(`"r"`)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("RebaseAndPrepare next to a corrupt audit = %v, want ErrCorrupt", err)
		}
	})
}

// TestRebaseAndPrepareAuditCollision proves an existing audit at the new
// generation is never overwritten and the prior state/prepared/audit bytes stay
// exact.
func TestRebaseAndPrepareAuditCollision(t *testing.T) {
	j := openAt(t, privateDir(t))
	old := baseState()
	mustInitialize(t, j, old)
	next := old.Generation + 1
	a := sampleRebaseAudit()
	a.NewGeneration = next
	a.OldState = old
	rawOldAudit := encodeRebaseAudit(a)
	writeRawAudit(t, j, auditKey(next), rawOldAudit)
	rawState := rawKey(t, j, stateKey)

	remoteRev := vaultfilebackend.Revision(`"collision"`)
	err := j.RebaseAndPrepare(old, opaque(128, 71), remoteRev, rebaseProposal(remoteRev))
	if !errors.Is(err, ErrAuditCollision) {
		t.Fatalf("RebaseAndPrepare with audit collision = %v, want ErrAuditCollision", err)
	}
	if got := rawAudit(t, j, next); !bytes.Equal(got, rawOldAudit) {
		t.Fatal("rejected rebase overwrote the existing audit")
	}
	if !bytes.Equal(rawKey(t, j, stateKey), rawState) {
		t.Fatal("rejected rebase changed the state")
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("rejected rebase stored prepared: %v", err)
	}
}

// TestRebaseAndPrepareRejectsInvalidInputs checks every input bound before a
// transaction, and that a missing state is ErrEmpty.
func TestRebaseAndPrepareRejectsInvalidInputs(t *testing.T) {
	j := openAt(t, privateDir(t))
	old := baseState()
	mustInitialize(t, j, old)
	remoteRev := vaultfilebackend.Revision(`"valid-remote"`)
	validP := rebaseProposal(remoteRev)
	before := mustLoadState(t, j)

	badStates := map[string]State{
		"empty-working": func() State { s := old; s.WorkingBytes = nil; return s }(),
		"base-without-rev": func() State {
			s := old
			s.RemoteRevision = ""
			return s
		}(),
		"rev-without-base": func() State {
			s := old
			s.BaseBytes = nil
			return s
		}(),
		"base-too-large": func() State {
			s := old
			s.BaseBytes = make([]byte, MaxBaseBytes+1)
			return s
		}(),
	}
	for name, s := range badStates {
		t.Run("state-"+name, func(t *testing.T) {
			if err := j.RebaseAndPrepare(s, opaque(16, 81), remoteRev, validP); !errors.Is(err, ErrInvalid) {
				t.Fatalf("RebaseAndPrepare = %v, want ErrInvalid", err)
			}
		})
	}

	for name, base := range map[string][]byte{
		"nil":   nil,
		"empty": {},
		"huge":  make([]byte, MaxBaseBytes+1),
	} {
		t.Run("remote-base-"+name, func(t *testing.T) {
			if err := j.RebaseAndPrepare(old, base, remoteRev, validP); !errors.Is(err, ErrInvalid) {
				t.Fatalf("RebaseAndPrepare = %v, want ErrInvalid", err)
			}
		})
	}
	for name, rev := range map[string]vaultfilebackend.Revision{
		"empty": "",
		"huge":  vaultfilebackend.Revision(string(bytes.Repeat([]byte{'r'}, MaxStateRevisionBytes+1))),
	} {
		t.Run("remote-revision-"+name, func(t *testing.T) {
			p := validP
			p.ExpectedRevision = rev
			if err := j.RebaseAndPrepare(old, opaque(16, 82), rev, p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("RebaseAndPrepare = %v, want ErrInvalid", err)
			}
		})
	}

	badProposals := map[string]Proposal{
		"zero-generation": func() Proposal { p := validP; p.Generation = 0; return p }(),
		"empty-bytes":     func() Proposal { p := validP; p.Bytes = nil; return p }(),
		"huge-bytes":      func() Proposal { p := validP; p.Bytes = make([]byte, MaxProposalBytes+1); return p }(),
		"bad-operation":   func() Proposal { p := validP; p.OperationID = "UPPER CASE"; return p }(),
		"revision-mismatch": func() Proposal {
			p := validP
			p.ExpectedRevision = `"different"`
			return p
		}(),
	}
	for name, p := range badProposals {
		t.Run("proposal-"+name, func(t *testing.T) {
			if err := j.RebaseAndPrepare(old, opaque(16, 83), remoteRev, p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("RebaseAndPrepare = %v, want ErrInvalid", err)
			}
		})
	}
	assertState(t, mustLoadState(t, j), before)
	if got := rawAuditEntries(t, j); len(got) != 0 {
		t.Fatalf("rejected inputs wrote %d audits", len(got))
	}

	// A missing state is ErrEmpty even with otherwise valid inputs.
	emptyDir := privateDir(t)
	j2 := openAt(t, emptyDir)
	if err := j2.RebaseAndPrepare(State{WorkingBytes: opaque(8, 84)}, opaque(16, 85), remoteRev, validP); !errors.Is(err, ErrEmpty) {
		t.Fatalf("RebaseAndPrepare with no state = %v, want ErrEmpty", err)
	}
	if rawAudit(t, j2, 1) != nil {
		t.Fatal("rebase with no state wrote an audit")
	}
}

// TestRebaseAndPrepareDeepCopies proves the call retains no caller slice alias
// and that LoadState, LoadPrepared and LoadRebaseAudit return owned copies.
func TestRebaseAndPrepareDeepCopies(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)

	old := baseState()
	wantOld := cloneState(old)
	mustInitialize(t, j, old)

	remoteBase := opaque(300, 91)
	wantRemoteBase := bytes.Clone(remoteBase)
	remoteRev := vaultfilebackend.Revision(`"owned-remote"`)
	p := baseProposal()
	p.Generation = 9191
	p.OperationID = "op-copy:ownership.1"
	p.ExpectedRevision = remoteRev
	p.Bytes = opaque(700, 92)
	wantP := cloneProposal(p)

	if err := j.RebaseAndPrepare(old, remoteBase, remoteRev, p); err != nil {
		t.Fatalf("RebaseAndPrepare: %v", err)
	}

	// Mutate every caller-owned mutable input after the call.
	old.BaseBytes[0] ^= 0xff
	old.WorkingBytes[0] ^= 0xff
	remoteBase[0] ^= 0xff
	p.Bytes[0] ^= 0xff

	wantState := State{
		BaseBytes:      wantRemoteBase,
		RemoteRevision: remoteRev,
		WorkingBytes:   wantP.Bytes,
		Generation:     wantOld.Generation + 1,
	}
	wantAudit := RebaseAudit{
		OldState:       wantOld,
		RemoteBase:     wantRemoteBase,
		RemoteRevision: remoteRev,
		NewGeneration:  wantOld.Generation + 1,
		Proposal:       wantP,
	}
	assertState(t, mustLoadState(t, j), wantState)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: wantOld.Generation + 1, Proposal: wantP})
	assertAudit(t, mustLoadAudit(t, j, wantOld.Generation+1), wantAudit)

	// Mutate every slice returned by the loaders; a later load is unaffected.
	gotState := mustLoadState(t, j)
	gotState.BaseBytes[0] ^= 0xff
	gotState.WorkingBytes[0] ^= 0xff
	gotPrep := mustLoadPrepared(t, j)
	gotPrep.Proposal.Bytes[0] ^= 0xff
	gotAudit := mustLoadAudit(t, j, wantOld.Generation+1)
	gotAudit.OldState.BaseBytes[0] ^= 0xff
	gotAudit.OldState.WorkingBytes[0] ^= 0xff
	gotAudit.RemoteBase[0] ^= 0xff
	gotAudit.RemoteRevision = `"mutated"`
	gotAudit.Proposal.Bytes[0] ^= 0xff
	gotAudit.Proposal.OperationID = "mutated-operation"
	gotAudit.Proposal.ExpectedRevision = `"mutated"`

	assertState(t, mustLoadState(t, j), wantState)
	assertPrepared(t, mustLoadPrepared(t, j), PreparedProposal{WorkingGeneration: wantOld.Generation + 1, Proposal: wantP})
	assertAudit(t, mustLoadAudit(t, j, wantOld.Generation+1), wantAudit)

	// The same holds after close and reopen.
	mustClose(t, j)
	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), wantState)
	assertPrepared(t, mustLoadPrepared(t, j2), PreparedProposal{WorkingGeneration: wantOld.Generation + 1, Proposal: wantP})
	assertAudit(t, mustLoadAudit(t, j2, wantOld.Generation+1), wantAudit)
}

// TestClosedRebaseAPI covers the new methods after Close.
func TestClosedRebaseAPI(t *testing.T) {
	j, err := Open(filepath.Join(privateDir(t), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	old := baseState()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	remoteRev := vaultfilebackend.Revision(`"closed"`)
	if err := j.RebaseAndPrepare(old, opaque(8, 95), remoteRev, rebaseProposal(remoteRev)); !errors.Is(err, ErrClosed) {
		t.Fatalf("RebaseAndPrepare = %v, want ErrClosed", err)
	}
	if _, err := j.LoadRebaseAudit(1); !errors.Is(err, ErrClosed) {
		t.Fatalf("LoadRebaseAudit = %v, want ErrClosed", err)
	}
}
