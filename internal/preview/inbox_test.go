package preview

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUnattendedInbox(t *testing.T) {
	out := filepath.Join(t.TempDir(), "scenario")
	if err := Create(out, "init-check", "testing"); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(out, "inbox")
	b := filepath.Join(out, "clients", "B")
	a := filepath.Join(out, "clients", "A")
	reason := "review a synthetic release"
	id, err := Submit(inbox, filepath.Join(out, "agent", "approval.pub"), "job-17", reason, FixtureRef)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("missing request ID")
	}
	if _, err := Submit(inbox, filepath.Join(out, "agent", "approval.pub"), "job-18", "unrelated", FixtureRef); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(inbox, id+".request.age"))
	if err != nil || bytes.Contains(ciphertext, []byte(reason)) || bytes.Contains(ciphertext, []byte("job-17")) {
		t.Fatal("plaintext on spool or write missing")
	}
	report, err := Inbox(inbox, b, "job-17")
	got := report.Requests
	if err != nil || report.Unreadable != 0 || len(got) != 1 || got[0].ID != id || got[0].Reason != reason || got[0].State != "pending" {
		t.Fatalf("lost offline request: %+v, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(inbox, "damaged.request.age"), []byte("not ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = Inbox(inbox, b, "job-17")
	if err != nil || report.Unreadable != 1 || len(report.Requests) != 1 || report.Requests[0].ID != id {
		t.Fatal("a damaged message concealed a valid pending request", err)
	}
	if _, err := Inbox(inbox, a, "job-17"); err == nil {
		t.Fatal("A could read approval inbox")
	}
	if _, err := Submit(inbox, filepath.Join(out, "agent", "approval.pub"), "job-17", reason, "https://example.com/?token=unsafe"); err == nil {
		t.Fatal("unrestricted reference accepted")
	}
}
