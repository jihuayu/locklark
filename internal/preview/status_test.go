package preview

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatusChallengeIsReadOnlyAndBindsCurrentSession(t *testing.T) {
	f := approvedCall(t)
	c := PollConfig{Private: t.TempDir(), Exchange: t.TempDir(), Key: f.key, Recipient: f.pub, Host: f.host, Session: "job"}
	req, err := SubmitReceipt(f.inbox, f.pub, "job", "check another request", FixtureRef, f.key)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(want string) string {
		t.Helper()
		poll, e := c.Start(req.ID, req.Review)
		if e != nil {
			t.Fatal(e)
		}
		if got, e := c.Read(req.ID, req.Review, poll); e != nil || got != nil {
			t.Fatal("relay incorrectly confirmed status", got, e)
		}
		if e := AnswerStatus(f.b, f.inbox, c.Exchange, poll); e != nil {
			t.Fatal(e)
		}
		got, e := c.Read(req.ID, req.Review, poll)
		if e != nil || got == nil || got.State != want || got.ObservedAt.IsZero() {
			t.Fatal(got, e)
		}
		return poll
	}
	pending := fetch("pending")
	if _, err = Decide(f.inbox, f.b, f.bundle, req.ID, req.Review, "approve", "inspect fixture"); err != nil {
		t.Fatal(err)
	}
	approved := fetch("approved")
	if _, err = Invoke(f.b, f.bundle, filepath.Join(c.Exchange, approved+".query.age")); err == nil {
		t.Fatal("used status challenge to execute")
	}
	rows, err := Executions(f.b, "job")
	if err != nil || len(rows) != 0 {
		t.Fatal("poll consumed grant", err)
	}
	old, e := os.ReadFile(filepath.Join(c.Exchange, pending+".status.age"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(c.Exchange, approved+".status.age"), old, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(req.ID, req.Review, approved); e == nil {
		t.Fatal("old poll accepted as fresh")
	}
	if _, err = RevokeApproval(f.b, req.ID, req.Review, "finished"); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(f.inbox, req.ID+".request.age")); err != nil {
		t.Fatal(err)
	}
	fetch("approval-revoked")
	other := c
	other.Key = filepath.Join(t.TempDir(), "other.sessionkey")
	if _, err = NewSessionKey(other.Key); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Read(req.ID, req.Review, pending); err == nil {
		t.Fatal("other signing key used cached poll")
	}
	wrong, err := other.Start(req.ID, req.Review)
	if err != nil {
		t.Fatal(err)
	}
	if err = AnswerStatus(f.b, f.inbox, c.Exchange, wrong); err == nil {
		t.Fatal("impostor obtained status")
	}
	poll, err := c.Start(req.ID, req.Review)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RevokeSession(f.b, "job", "closed"); err != nil {
		t.Fatal(err)
	}
	if err = AnswerStatus(f.b, f.inbox, c.Exchange, poll); err == nil {
		t.Fatal("answered revoked session")
	}
}
