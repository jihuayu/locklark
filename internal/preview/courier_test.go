package preview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/gateway"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCourierRenewsOnlyAnActiveEnrollment(t *testing.T) {
	f := approvedCall(t)
	key := filepath.Join(t.TempDir(), "reader.sessionkey")
	pub, e := NewSessionKey(key)
	if e != nil {
		t.Fatal(e)
	}
	repo := gateway.Repository{ID: "123", Owner: "example", Name: "tools"}
	reg, e := EnrollPullSession(f.b, "reader", pub, "check PR", repo)
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "profile")
	c := PollConfig{Key: key, Host: f.host, Recipient: f.pub, Session: "reader"}
	if e = renewProfile(f.b, "reader", out); e != nil {
		t.Fatal(e)
	}
	p, e := LoadBridgeProfile(out, c)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := localSigner(f.b, "decision")
	if e != nil {
		t.Fatal(e)
	}
	defer clear(signer)
	expire := func() {
		p.Issued = time.Now().UTC().Add(-4 * time.Minute)
		p.Expires = time.Now().UTC().Add(time.Second)
		p.Sig = ed25519.Sign(signer, p.proof())
		b, _ := json.Marshal(p)
		if err := os.WriteFile(out, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	if e = renewProfile(f.b, "reader", out); e != nil {
		t.Fatal(e)
	}
	renewed, e := LoadBridgeProfile(out, c)
	if e != nil || !renewed.Expires.After(p.Expires) || renewed.Expires.After(reg.Expires) {
		t.Fatal("failed bounded renewal", e)
	}
	if _, e = RevokeSession(f.b, "reader", "finished"); e != nil {
		t.Fatal(e)
	}
	expire()
	if e = renewProfile(f.b, "reader", out); e == nil {
		t.Fatal("renewed revoked enrollment")
	}
}

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
