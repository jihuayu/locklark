package preview

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
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
func TestDeletingOnlyRevocationSuffixDoesNotReactivateKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "start", "exercise"); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(root, "clients", "B")
	pub, err := NewSessionKey(filepath.Join(t.TempDir(), "key.sessionkey"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(b, "job", pub, "start"); err != nil {
		t.Fatal(err)
	}
	if _, err = RevokeSession(b, "job", "closed"); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(b, "decisions.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket(registryBucket)
		k, _ := reg.Cursor().Last()
		return reg.Delete(k)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = SessionHistory(b, "job"); err == nil {
		t.Fatal("registry suffix deletion accepted")
	}
}
func TestSessionRevocationSerializesWithApproval(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "initial", "run fixture"); err != nil {
		t.Fatal(err)
	}
	device, inbox := filepath.Join(root, "clients", "B"), filepath.Join(root, "inbox")
	bundle, key := filepath.Join(root, "share", "epoch-3"), filepath.Join(t.TempDir(), "race.sessionkey")
	public, err := NewSessionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(device, "release", public, "runner"); err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(device, "another", public, "reuse"); err == nil {
		t.Fatal("registered same key to a second session")
	}
	id, err := SubmitSigned(inbox, filepath.Join(root, "agent", "approval.pub"), "release", "metadata", FixtureRef, key)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := Inbox(inbox, device, "release")
	if err != nil || len(mail.Requests) != 1 {
		t.Fatal("missing request", err)
	}
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		_, e := Decide(inbox, device, bundle, id, mail.Requests[0].Review, "approve", "checked")
		done <- e
	}()
	close(start)
	rev, err := RevokeSession(device, "release", "finished")
	if err != nil {
		t.Fatal(err)
	}
	approved := <-done
	records, err := Decisions(device, "release")
	if err != nil {
		t.Fatal(err)
	}
	if approved == nil {
		if len(records) != 1 || records[0].At.After(rev.At) {
			t.Fatal("approval committed after revocation")
		}
	} else if len(records) != 0 {
		t.Fatal("failed approval left a decision")
	}
	changes, err := SessionHistory(device, "release")
	if err != nil || len(changes) != 2 || changes[0].Action != "enrolled" || changes[1].Action != "revoked" {
		t.Fatal("lost registration history", err)
	}
	after, err := Inbox(inbox, device, "release")
	if err != nil || len(after.Requests) != 1 || after.Requests[0].SenderStatus != "revoked" || after.Requests[0].State == "approved" {
		t.Fatal("revoked approval displayed active", err)
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
		mail, e := Inbox(inbox, device, "build")
		if e != nil {
			t.Fatal(e)
		}
		for _, q := range mail.Requests {
			if q.ID == id {
				d, e := Decide(inbox, device, "", id, q.Review, "deny", "untrusted sender")
				if e != nil || d.Result != "denied" || d.Request.SenderStatus == "verified" {
					t.Fatal("could not deny untrusted request", e)
				}
			}
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
	if approve(id) == nil {
		t.Fatal("revoked session reused an old approval as a fresh success")
	}
	history, e := Decisions(device, "build")
	if e != nil {
		t.Fatal(e)
	}
	saved := false
	for _, d := range history {
		if d.Request.ID == id && d.Result == "approved" {
			saved = true
		}
	}
	if !saved {
		t.Fatal("historical approval erased on revoke")
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
