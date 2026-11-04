package preview

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestClockRollbackCannotShowActiveApproval(t *testing.T) {
	now := time.Now().UTC()
	end := now.Add(time.Minute)
	q := Request{Review: "same"}
	d := Decision{Request: q, At: now, Expires: &end, Result: "approved"}
	if stateAt(q, d, now.Add(-time.Second)) == "approved" || stateAt(q, d, now) != "approved" || stateAt(q, d, end) == "approved" {
		t.Fatal("displayed approval outside signed interval")
	}
}
func TestDecisionTimePolicyAndTamper(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "initial", "sample"); err != nil {
		t.Fatal(err)
	}
	inbox, b, bundle := filepath.Join(root, "inbox"), filepath.Join(root, "clients", "B"), filepath.Join(root, "share", "epoch-3")
	pubBytes, err := os.ReadFile(filepath.Join(root, "agent", "approval.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := age.ParseX25519Recipient(string(pubBytes))
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000000000000000000000000001"
	q := Request{ID: id, Session: "timer", Reason: "time test", Ref: FixtureRef, Action: FixtureAction, Epoch: 3, State: "pending"}
	keyPath := filepath.Join(t.TempDir(), "timer.sessionkey")
	public, err := NewSessionKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := changeSession(b, "timer", public, "enroll timer", false, func() time.Time { return time.Now().Add(-24*time.Hour + 30*time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	send := func(when time.Time) {
		q.Created = when.UTC().Format(time.RFC3339Nano)
		if err := signRequest(&q, seed, pub.String()); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, e := age.Encrypt(&buf, pub)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.NewEncoder(w).Encode(q); e != nil {
			t.Fatal(e)
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(inbox, id+".request.age"), buf.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, when := range []time.Time{time.Now().Add(-25 * time.Hour), time.Now().Add(time.Hour)} {
		send(when)
		if _, err = Decide(inbox, b, bundle, id, requestDigest(q), "approve", "OK"); err == nil {
			t.Fatal("approved expired or future request")
		}
	}
	send(time.Now().Add(time.Hour))
	mail, err := Inbox(inbox, b, "timer")
	if err != nil || len(mail.Requests) != 1 || mail.Requests[0].State != "not-yet-valid" {
		t.Fatal("future request misleadingly shown as actionable", err)
	}
	q.ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	id = q.ID
	send(time.Now().UTC())
	mail, err = Inbox(inbox, b, "timer")
	if err != nil || mail.Unreadable != 1 {
		t.Fatal("noncanonical request shown as actionable", err)
	}
	id = "00000000000000000000000000000001"
	q.ID = id
	send(time.Now().Add(-24*time.Hour + time.Minute))
	review := requestDigest(q)
	d, err := Decide(inbox, b, bundle, id, review, "approve", "bounded approval")
	if err != nil {
		t.Fatal(err)
	}
	created, _ := time.Parse(time.RFC3339Nano, q.Created)
	if d.Expires == nil || d.Expires.After(created.Add(24*time.Hour)) || d.Expires.After(registration.Expires) {
		t.Fatal("approval outlived original request")
	}
	retry, err := Decide(inbox, b, bundle, id, review, "approve", "bounded approval")
	if err != nil || !retry.At.Equal(d.At) {
		t.Fatal("retry regenerated approval", err)
	}
	db, err := bolt.Open(filepath.Join(b, "decisions.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(journal)
		k, v := bucket.Cursor().First()
		copyValue := append([]byte(nil), v...)
		copyValue[len(copyValue)-1] ^= 1
		return bucket.Put(k, copyValue)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if rows, err := Decisions(b, "timer"); err == nil || len(rows) != 0 {
		t.Fatal("displayed corrupted decision history")
	}
}
func TestDecisionsSurviveRestartAndDoNotTransfer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "init", "build fixture"); err != nil {
		t.Fatal(err)
	}
	inbox, b, bundle, pub := filepath.Join(root, "inbox"), filepath.Join(root, "clients", "B"), filepath.Join(root, "share", "epoch-3"), filepath.Join(root, "agent", "approval.pub")
	keyPath := filepath.Join(t.TempDir(), "job.sessionkey")
	public, err := NewSessionKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(b, "job", public, "trusted runner"); err != nil {
		t.Fatal(err)
	}
	id, err := SubmitSigned(inbox, pub, "job", "review job", FixtureRef, keyPath)
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
