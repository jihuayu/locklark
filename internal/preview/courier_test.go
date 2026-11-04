package preview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCourierPublishesOnlyScopedProfilesAndReadOnlyStatus(t *testing.T) {
	f := approvedCall(t)
	c := PollConfig{Private: t.TempDir(), Exchange: t.TempDir(), Key: f.key, Recipient: f.pub, Host: f.host, Session: "job"}
	poll, e := c.Start(f.id, f.review)
	if e != nil {
		t.Fatal(e)
	}
	if e = ServeStatus(context.Background(), f.b, f.inbox, c.Exchange, "", "", true); e != nil {
		t.Fatal(e)
	}
	got, e := c.Read(f.id, f.review, poll)
	if e != nil || got == nil || got.State != "approved" {
		t.Fatal(got, e)
	}
	if rows, e := Executions(f.b, "job"); e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	out := filepath.Join(t.TempDir(), "foreign")
	original := []byte("do not erase")
	if e = os.WriteFile(out, original, 0600); e != nil {
		t.Fatal(e)
	}
	if e = ServeStatus(context.Background(), f.b, f.inbox, c.Exchange, "job", out, true); e == nil {
		t.Fatal("replaced unrelated file")
	}
	after, e := os.ReadFile(out)
	if e != nil || !bytes.Equal(after, original) {
		t.Fatal("clobber", e)
	}
}
