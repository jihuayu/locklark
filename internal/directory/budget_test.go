package directory

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestCommitRefusesOverBudgetHistory drives the real commit transaction with a
// private per-call budget strictly between the stored History bytes and the
// History bytes the candidate would leave behind. It pins that the refusal is a
// whole-transaction preservation: the head checkpoint, the decoded head view and
// the exact stored receipt and snapshot bytes are identical before and after.
//
// The fixture is the existing legal writerFixture: one owner-signed receipt and
// its real sealed snapshot. The candidate is one valid BuildUpdate, so the
// projected History is two signed receipts and exactly one head snapshot; the
// database retains no historic snapshot.
func TestCommitRefusesOverBudgetHistory(t *testing.T) {
	f, path, first := writerFixture(t)
	if first.Proposal.Epoch != 1 {
		t.Fatalf("fixture head epoch = %d, want 1", first.Proposal.Epoch)
	}
	beforeView, history, err := ReadHistory(path, f.cfg, first.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	if beforeView.Receipt.Checkpoint() != first.Checkpoint() || len(history.Receipts) != 1 {
		t.Fatal("exported history is not the fixture head")
	}
	// storageSize bounds the head snapshot against MaxHistoryBytes, but its
	// return value is only the framing and receipt bytes, so the exact stored
	// history size is its encoding.
	if _, err := history.storageSize(); err != nil {
		t.Fatal(err)
	}
	oldSize := len(encoded(history))

	p, s, err := BuildUpdate(f.cfg, signing(10), first, f.items)
	if err != nil {
		t.Fatal(err)
	}
	if p.Parent != first.Checkpoint() || p.Epoch != 2 {
		t.Fatal("candidate is not the successor of the fixture head")
	}
	// The receipt the commit transaction itself signs, so projected is exactly
	// what a successful commit would retain: the old receipt, the new receipt
	// and the one head snapshot.
	candidate := Receipt{Proposal: p}
	candidate.Signature = ed25519.Sign(f.sequencer, candidate.proof())
	if f.cfg.verifyReceipt(candidate) != nil {
		t.Fatal("candidate receipt does not verify")
	}
	projected := History{Receipts: append(cloneReceipts(history.Receipts), candidate), Snapshot: cloneSnapshot(s)}
	projectedSize := len(encoded(projected))
	if size, err := retainedHistorySize(history.Receipts, candidate, s, MaxHistoryBytes); err != nil || size != projectedSize {
		t.Fatalf("retainedHistorySize = %d, %v; want %d", size, err, projectedSize)
	}
	if projectedSize <= oldSize {
		t.Fatalf("projected %d must exceed stored %d", projectedSize, oldSize)
	}
	budget := oldSize + (projectedSize-oldSize)/2
	if budget <= oldSize || budget >= projectedSize {
		t.Fatalf("budget %d not strictly between %d and %d", budget, oldSize, projectedSize)
	}

	before := storedHistoryBytes(t, path)
	db, err := open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := commitWithUpdate(db.Update, f.cfg, f.sequencer, p, s, false, budget)
	closeErr := db.Close()
	if err != ErrCapacity || receipt.Signature != nil {
		t.Fatalf("over-budget commit: receipt signed %v, err %v", receipt.Signature != nil, err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	if after := storedHistoryBytes(t, path); !bytes.Equal(after, before) {
		t.Fatal("refused commit changed stored history bytes")
	}
	afterView, afterHistory, err := ReadHistory(path, f.cfg, first.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	if afterView.Receipt.Checkpoint() != beforeView.Receipt.Checkpoint() || !bytes.Equal(encoded(afterView), encoded(beforeView)) {
		t.Fatal("refused commit changed the head view")
	}
	if !bytes.Equal(encoded(afterHistory), encoded(history)) || len(encoded(afterHistory)) != oldSize {
		t.Fatal("refused commit changed the stored history")
	}
}

// storedHistoryBytes returns the exact committed record and snapshot bytes, in
// version order, read from the database without any chain decoding.
func storedHistoryBytes(t *testing.T, path string) []byte {
	t.Helper()
	db, err := open(path, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []byte
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			t.Fatal("missing directory bucket")
		}
		if err := b.Bucket(recordsKey).ForEach(func(k, v []byte) error {
			out = append(out, k...)
			out = append(out, v...)
			return nil
		}); err != nil {
			return err
		}
		out = append(out, snapshotKey...)
		out = append(out, b.Get(snapshotKey)...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
