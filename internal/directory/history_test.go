package directory

import (
	"crypto/ed25519"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func TestRemoteHistoryExportsEveryAuthenticatedTransition(t *testing.T) {
	f, path, parent := writerFixture(t)
	p, s, e := BuildUpdate(f.cfg, signing(10), parent, f.items)
	if e != nil {
		t.Fatal(e)
	}
	head, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Read(path, f.cfg, parent.Checkpoint()); e != nil {
		t.Fatal("baseline trusted local history unreadable")
	}
	h, e := ExportHistory(path, f.cfg, parent.Checkpoint())
	if e != nil {
		t.Fatal("remote full-history export unavailable")
	}
	if len(h.Receipts) != int(head.Proposal.Epoch) {
		t.Fatal("remote history omitted transitions")
	}
	v, e := VerifyHistory(f.cfg, parent.Checkpoint(), h)
	if e != nil || v.Receipt.Checkpoint() != head.Checkpoint() {
		t.Fatal("remote full history did not verify")
	}
}

func TestRemoteHistoryRejectsRollbackForkTamperAndACLRewrite(t *testing.T) {
	f, path, parent := writerFixture(t)
	old, e := Read(path, f.cfg, f.cfg.Genesis())
	if e != nil {
		t.Fatal(e)
	}
	p, s, e := BuildUpdate(f.cfg, signing(10), parent, f.items)
	if e != nil {
		t.Fatal(e)
	}
	head, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	h, e := ExportHistory(path, f.cfg, f.cfg.Genesis())
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*History){
		func(h *History) { h.Snapshot.Database[0] ^= 1 },
		func(h *History) { h.Receipts[0].Signature[0] ^= 1 },
		func(h *History) { h.Receipts = h.Receipts[1:] },
		func(h *History) { h.Receipts[1].Proposal.Parent.Hash = "bad" },
		func(h *History) { h.Receipts = h.Receipts[:1]; h.Snapshot = old.Snapshot },
	} {
		var altered History
		if !canonical(encoded(h), &altered) {
			t.Fatal("fixture copy failed")
		}
		change(&altered)
		if v, e := VerifyHistory(f.cfg, head.Checkpoint(), altered); e == nil || v.Receipt.Proposal.Epoch != 0 || len(v.Snapshot.Database) != 0 {
			t.Fatal("tampered/rollback history returned a view")
		}
	}
	// Every signature can be correct while a writer illegally changes roles.
	var illegal History
	_ = canonical(encoded(h), &illegal)
	r := &illegal.Receipts[1]
	r.Proposal.Members[1].Role = "writer"
	r.Proposal.Signature = ed25519.Sign(signing(10), r.Proposal.proof())
	r.Signature = ed25519.Sign(f.sequencer, r.proof())
	if f.cfg.verifyReceipt(*r) != nil {
		t.Fatal("ACL counterexample lacks valid signatures")
	}
	if _, e = VerifyHistory(f.cfg, f.cfg.Genesis(), illegal); e == nil {
		t.Fatal("signature-only remote verifier ignored writer ACL transition")
	}
	// A different fully valid signed branch cannot satisfy a retained checkpoint.
	items := []vault.Item{{ID: "login", Kind: "login", Password: "other branch"}}
	branch, snapshot, e := BuildUpdate(f.cfg, signing(10), parent, items)
	if e != nil {
		t.Fatal(e)
	}
	receipt := Receipt{Proposal: branch}
	receipt.Signature = ed25519.Sign(f.sequencer, receipt.proof())
	fork := History{Receipts: []Receipt{h.Receipts[0], receipt}, Snapshot: snapshot}
	if _, e = VerifyHistory(f.cfg, f.cfg.Genesis(), fork); e != nil {
		t.Fatal("fork counterexample is not independently valid", e)
	}
	if _, e = VerifyHistory(f.cfg, head.Checkpoint(), fork); e == nil {
		t.Fatal("retained checkpoint accepted a conflicting branch")
	}
}
