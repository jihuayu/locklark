package preview

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDecisionsSurviveRestartAndDoNotTransfer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "init", "build fixture"); err != nil {
		t.Fatal(err)
	}
	inbox, b, bundle, pub := filepath.Join(root, "inbox"), filepath.Join(root, "clients", "B"), filepath.Join(root, "share", "epoch-3"), filepath.Join(root, "agent", "approval.pub")
	id, err := Submit(inbox, pub, "job", "review job", FixtureRef)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := Inbox(inbox, b, "job")
	if err != nil || len(mail.Requests) != 1 || mail.Requests[0].Review == "" {
		t.Fatal("no review handle", err)
	}
	q := mail.Requests[0]
	if _, err = Decide(inbox, b, bundle, id, "bad-digest", "approve", "OK"); err == nil {
		t.Fatal("unreviewed request accepted")
	}
	if _, err = Decide(inbox, b, filepath.Join(root, "share", "epoch-2"), id, q.Review, "approve", "OK"); err == nil {
		t.Fatal("approved for a different epoch")
	}
	var wg sync.WaitGroup
	ch := make(chan error, 2)
	for _, v := range []string{"approve", "deny"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			_, err := Decide(inbox, b, bundle, id, q.Review, v, "review decision")
			ch <- err
		}(v)
	}
	wg.Wait()
	close(ch)
	success := 0
	for err := range ch {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("expected exactly one committed decision", success)
	}
	got, err := Decisions(b, "job")
	if err != nil || len(got) != 1 || got[0].Request.Review != q.Review || got[0].Reason != "review decision" {
		t.Fatal(got, err)
	}
	mail, err = Inbox(inbox, b, "job")
	if err != nil || mail.Requests[0].State == "pending" {
		t.Fatal("committed decision not reflected", err)
	}
	q.Reason = "same ID, replaced reason"
	q.State = "pending"
	q.Review = ""
	pubText, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.ParseX25519Recipient(string(pubText))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(w).Encode(q); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(inbox, id+".request.age"), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	mail, err = Inbox(inbox, b, "job")
	if err != nil || len(mail.Requests) != 1 || mail.Requests[0].State != "conflict" {
		t.Fatal("applied decision to replaced request", err)
	}
	if _, err = Decide(inbox, b, bundle, id, got[0].Request.Review, "deny", "review decision"); err == nil {
		t.Fatal("decision accepted after request substitution")
	}
	if err = os.Remove(filepath.Join(inbox, id+".request.age")); err != nil {
		t.Fatal(err)
	}
	got, err = Decisions(b, "job")
	if err != nil || len(got) != 1 {
		t.Fatal("deleting relay message erased history", err)
	}
	raw, err := os.ReadFile(filepath.Join(b, "decisions.db"))
	if err != nil || bytes.Contains(raw, []byte("review decision")) || bytes.Contains(raw, []byte("review job")) {
		t.Fatal("plaintext in decision journal", err)
	}
}
