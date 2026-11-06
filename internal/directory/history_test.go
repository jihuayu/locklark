package directory

import "testing"

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
