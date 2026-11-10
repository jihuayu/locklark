package directory

import (
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

// commitHistory commits n writer updates on top of the fixture's first
// receipt and returns the resulting head.
func commitHistory(t *testing.T, f fixture, path string, head Receipt, n int) Receipt {
	t.Helper()
	for i := range n {
		items := append([]vault.Item(nil), f.items...)
		items[0].Notes = string(rune('a' + i))
		p, s, e := BuildUpdate(f.cfg, signing(10), head, items)
		if e != nil {
			t.Fatal(e)
		}
		if head, e = Commit(path, f.cfg, f.sequencer, p, s); e != nil {
			t.Fatal(e)
		}
	}
	return head
}

// TestReadTrustedAdvancesEachReceiptOnce pins that one TrustedRead performs a
// single chain pass: exactly len(receipts) advance steps, and its evidence
// matches a full independent verification.
func TestReadTrustedAdvancesEachReceiptOnce(t *testing.T) {
	f, path, first := writerFixture(t)
	head := commitHistory(t, f, path, first, 2)
	var advances int
	wrapAdvance(t, &advances)
	r, e := ReadTrusted(path, f.cfg, first.Checkpoint(), head.Checkpoint())
	if e != nil {
		t.Fatal("trusted read failed", e)
	}
	h, e := r.History()
	if e != nil {
		t.Fatal(e)
	}
	if advances != len(h.Receipts) || len(h.Receipts) != int(head.Proposal.Epoch) {
		t.Fatalf("advances = %d, receipts = %d, epoch = %d", advances, len(h.Receipts), head.Proposal.Epoch)
	}
	if r.Checkpoint() != head.Checkpoint() {
		t.Fatal("trusted head differs from committed head")
	}
	if _, e = VerifyHistory(f.cfg, f.cfg.Genesis(), h); e != nil {
		t.Fatal("trusted evidence does not verify independently", e)
	}

	// A non-genesis proof anchor on the same chain is proven by that same pass.
	advances = 0
	r, e = ReadTrusted(path, f.cfg, first.Checkpoint(), first.Checkpoint())
	if e != nil {
		t.Fatal("non-genesis proof anchor refused", e)
	}
	if advances != int(head.Proposal.Epoch) {
		t.Fatalf("proof-anchor read advanced %d receipts", advances)
	}
	if v, e := r.ProvenAnchorView(first.Checkpoint()); e != nil || v.Receipt.Checkpoint() != head.Checkpoint() {
		t.Fatal("proven anchor view did not keep head authority", e)
	}
	if _, e = r.ProvenAnchorView(Checkpoint{Scope: f.cfg.Genesis().Scope, Version: 2, Hash: head.Checkpoint().Hash}); e == nil {
		t.Fatal("off-chain proof anchor selected a view")
	}
	// A plain Read has no proof-anchor constraint, genesis included.
	advances = 0
	if view, e := Read(path, f.cfg, f.cfg.Genesis()); e != nil || view.Receipt.Checkpoint() != head.Checkpoint() {
		t.Fatal("genesis Read failed", e)
	}
	if advances != int(head.Proposal.Epoch) {
		t.Fatalf("plain read advanced %d receipts", advances)
	}
	// The zero value carries no evidence.
	var zero TrustedRead
	if _, e := zero.HeadView(); e == nil {
		t.Fatal("zero TrustedRead produced a view")
	}
	if _, e := zero.History(); e == nil {
		t.Fatal("zero TrustedRead produced a history")
	}
}

// TestTrustedReadGettersReturnIndependentCopies checks no getter lends the
// sealed buffers to its caller.
func TestTrustedReadGettersReturnIndependentCopies(t *testing.T) {
	f, path, first := writerFixture(t)
	head := commitHistory(t, f, path, first, 1)
	r, e := ReadTrusted(path, f.cfg, first.Checkpoint(), first.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	want, e := Read(path, f.cfg, first.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	h, e := r.History()
	if e != nil {
		t.Fatal(e)
	}
	h.Receipts[0].Signature[0] ^= 1
	h.Receipts[0].Proposal.Members[0].Role = "reader"
	h.Receipts[len(h.Receipts)-1].Proposal.Members[0].Devices[0].ID = "altered"
	h.Snapshot.Database[0] ^= 1
	v, e := r.HeadView()
	if e != nil {
		t.Fatal(e)
	}
	v.Receipt.Signature[0] ^= 1
	v.Receipt.Proposal.Members[0].Devices[0].ID = "altered"
	v.Snapshot.Database[0] ^= 1
	v.Snapshot.Signature[0] ^= 1
	v.SnapshotSigner[0] ^= 1
	a, e := r.ProvenAnchorView(first.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	a.Receipt.Proposal.Members[0].Role = "reader"
	a.Snapshot.Envelope[0] ^= 1

	h2, e := r.History()
	if e != nil {
		t.Fatal(e)
	}
	v2, e := r.HeadView()
	if e != nil {
		t.Fatal(e)
	}
	if h2.Receipts[len(h2.Receipts)-1].Checkpoint() != head.Checkpoint() || h2.Receipts[0].Proposal.Members[0].Role != f.members[0].Role || h2.Snapshot.Database[0] != want.Snapshot.Database[0] {
		t.Fatal("History aliased sealed evidence")
	}
	if v2.Receipt.Checkpoint() != head.Checkpoint() || v2.Receipt.Proposal.Members[0].Devices[0].ID != f.members[0].Devices[0].ID || v2.Snapshot.Database[0] != want.Snapshot.Database[0] || v2.Snapshot.Signature[0] != want.Snapshot.Signature[0] || v2.SnapshotSigner[0] != want.SnapshotSigner[0] {
		t.Fatal("HeadView aliased sealed evidence")
	}
}

// wrapAdvance counts stored-chain advance steps at the reducer, the one path
// both a store pass and an untrusted history take.
func wrapAdvance(t *testing.T, n *int) {
	t.Helper()
	previous := chainAdvanceObserver
	chainAdvanceObserver = func() { *n++ }
	t.Cleanup(func() { chainAdvanceObserver = previous })
}
