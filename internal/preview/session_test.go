package preview

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"filippo.io/age"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignatureBindsRequestAndRecipient(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	q := Request{ID: "00000000000000000000000000000001", Session: "worker", State: "pending", Action: FixtureAction, Epoch: 3, Ref: FixtureRef, Created: now.Format(time.RFC3339Nano), Reason: "inspect"}
	if err = signRequest(&q, priv.Seed(), id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	c := SessionChange{Session: q.Session, Public: hex.EncodeToString(pub), Action: "enrolled", Audience: id.Recipient().String(), ScopeAction: FixtureAction, ScopeRef: FixtureRef, ScopeEpoch: 3, At: now.Add(-time.Minute), Expires: now.Add(time.Hour)}
	reg := sessionRegistry{latest: map[string]SessionChange{q.Session: c}}
	if sessionStatus(q, reg, c.Audience, now) != "verified" {
		t.Fatal("control request failed")
	}
	for _, mut := range []func(*Request){func(x *Request) { x.Session = "other" }, func(x *Request) { x.Action = "other" }, func(x *Request) { x.Ref = "other" }, func(x *Request) { x.Epoch++ }, func(x *Request) { x.Reason = "changed" }, func(x *Request) { x.ID = "different" }, func(x *Request) { x.Created = now.Add(time.Minute).Format(time.RFC3339Nano) }} {
		x := q
		mut(&x)
		if sessionStatus(x, reg, c.Audience, now) == "verified" {
			t.Fatal("changed signed payload accepted")
		}
	}
	if sessionStatus(q, reg, other.Recipient().String(), now) == "verified" || sessionStatus(q, reg, c.Audience, c.Expires) == "verified" {
		t.Fatal("wrong audience or expired registration accepted")
	}
	if validPublic(strings.Repeat("00", 32)) || validPublic("01"+strings.Repeat("00", 31)) {
		t.Fatal("weak public key accepted")
	}
}
func TestAgentRegistrationAndRevocation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "init", "sample"); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "clients", "B")
	inbox := filepath.Join(root, "inbox")
	pub := filepath.Join(root, "agent", "approval.pub")
	bundle := filepath.Join(root, "share", "epoch-3")
	key := filepath.Join(t.TempDir(), "build.sessionkey")
	other := filepath.Join(t.TempDir(), "other.sessionkey")
	public, err := NewSessionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSessionKey(other); err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(device, "build", public, "known build runner"); err != nil {
		t.Fatal(err)
	}
	approve := func(id string) error {
		t.Helper()
		mail, e := Inbox(inbox, device, "build")
		if e != nil {
			t.Fatal(e)
		}
		for _, q := range mail.Requests {
			if q.ID == id {
				_, e = Decide(inbox, device, bundle, id, q.Review, "approve", "checked request")
				return e
			}
		}
		t.Fatal("missing request")
		return nil
	}
	for _, k := range []string{"", other} {
		id, e := SubmitSigned(inbox, pub, "build", "inspect target", FixtureRef, k)
		if e != nil || approve(id) == nil {
			t.Fatal("impersonator allowed", e)
		}
	}
	id, err := SubmitSigned(inbox, pub, "build", "inspect target", FixtureRef, key)
	if err != nil || approve(id) != nil {
		t.Fatal("legitimate signing key rejected", err)
	}
	next, err := SubmitSigned(inbox, pub, "build", "inspect again", FixtureRef, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RevokeSession(device, "build", "job finished"); err != nil {
		t.Fatal(err)
	}
	if approve(next) == nil {
		t.Fatal("revoked key permitted")
	}
	mail, err := Inbox(inbox, device, "build")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range mail.Requests {
		if q.ID == id && (q.SenderStatus != "revoked" || q.State == "approved") {
			t.Fatal("revoked decision displayed as active")
		}
	}
	if _, err = EnrollSession(device, "build", public, "reuse"); err == nil {
		t.Fatal("reactivated old session")
	}
}
