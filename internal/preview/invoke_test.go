package preview

import (
	"bytes"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type inviteFixture struct{ b, bundle, key, inbox, pub, host, id, review string }

func approvedCall(t *testing.T) inviteFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "boot", "fixture"); err != nil {
		t.Fatal(err)
	}
	f := inviteFixture{b: filepath.Join(root, "clients", "B"), bundle: filepath.Join(root, "share", "epoch-3"), key: filepath.Join(t.TempDir(), "job.sessionkey"), inbox: filepath.Join(root, "inbox"), pub: filepath.Join(root, "agent", "approval.pub"), host: filepath.Join(root, "clients", "B", "decision.pub")}
	key, err := NewSessionKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollSession(f.b, "job", key, "runner"); err != nil {
		t.Fatal(err)
	}
	f.id, err = SubmitSigned(f.inbox, f.pub, "job", "inspect", FixtureRef, f.key)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := Inbox(f.inbox, f.b, "job")
	if err != nil || len(mail.Requests) != 1 {
		t.Fatal(err)
	}
	f.review = mail.Requests[0].Review
	if _, err = Decide(f.inbox, f.b, f.bundle, f.id, f.review, "approve", "reviewed"); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f inviteFixture) call(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "client")
	if err := PrepareInvocation(dir, f.key, f.pub, f.host, "job", f.id, f.review); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestWrongSessionTargetAndRevocationAreNotConsumed(t *testing.T) {
	f := approvedCall(t)
	counter := 0
	fn := func(raw []byte) (FieldMetadata, error) { counter++; return inspectMetadata(raw) }
	otherKey := filepath.Join(t.TempDir(), "other.sessionkey")
	if _, err := NewSessionKey(otherKey); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "attempt")
	if err := PrepareInvocation(other, otherKey, f.pub, f.host, "job", f.id, f.review); err != nil {
		t.Fatal(err)
	}
	if _, err := runInvocation(f.b, f.bundle, filepath.Join(other, "invocation.age"), fn); err == nil {
		t.Fatal("different signer consumed grant")
	}
	client := f.call(t)
	ticket := filepath.Join(client, "invocation.age")
	if _, err := runInvocation(f.b, filepath.Join(filepath.Dir(f.bundle), "epoch-2"), ticket, fn); err == nil {
		t.Fatal("wrong snapshot")
	}
	if _, err := RevokeSession(f.b, "job", "finished"); err != nil {
		t.Fatal(err)
	}
	if _, err := runInvocation(f.b, f.bundle, ticket, fn); err == nil {
		t.Fatal("revoked signer ran")
	}
	rows, err := Executions(f.b, "job")
	if err != nil || len(rows) != 0 || counter != 0 {
		t.Fatal("failed check booked/executed action", err)
	}
}
func TestRedemptionRunsOnlyOnce(t *testing.T) {
	f := approvedCall(t)
	client := f.call(t)
	ticket := filepath.Join(client, "invocation.age")
	var calls atomic.Int32
	fn := func(raw []byte) (FieldMetadata, error) { calls.Add(1); return inspectMetadata(raw) }
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, e := runInvocation(f.b, f.bundle, ticket, fn); errs <- e }()
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-errs == nil {
			successes++
		}
	}
	if successes != 1 || calls.Load() != 1 {
		t.Fatalf("commits %d executions %d", successes, calls.Load())
	}
	reply, err := InvocationReceipt(f.b, ticket)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "reply.age")
	if err = os.WriteFile(file, reply, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := OpenInvocationResult(client, file)
	if err != nil || result.Kind != "totp" || result.Field != "otp-demo" {
		t.Fatal(result, err)
	}
	replayed, err := InvocationReceipt(f.b, ticket)
	if err != nil || !bytes.Equal(reply, replayed) {
		t.Fatal("did not recover exact sealed reply", err)
	}
	var state localAttempt
	local, err := os.ReadFile(filepath.Join(client, "attempt.private"))
	if err != nil || json.Unmarshal(local, &state) != nil {
		t.Fatal("read private test fixture", err)
	}
	attackerRecipient, err := age.ParseX25519Recipient(state.Ticket.Reply)
	if err != nil {
		t.Fatal(err)
	}
	fake, err := sealJSON(attackerRecipient, signedReply{Ticket: state.Ticket.digest(), Metadata: FieldMetadata{3, "fake", "fake"}})
	if err != nil {
		t.Fatal(err)
	}
	fakeFile := filepath.Join(t.TempDir(), "fake.age")
	if err := os.WriteFile(fakeFile, fake, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInvocationResult(client, fakeFile); err == nil {
		t.Fatal("accepted unsigned reply")
	}
	other := f.call(t)
	if _, err = OpenInvocationResult(other, file); err == nil {
		t.Fatal("different attempt decrypted response")
	}
	if _, err = runInvocation(f.b, f.bundle, filepath.Join(other, "invocation.age"), fn); err == nil || calls.Load() != 1 {
		t.Fatal("fresh attempt reused approval")
	}
}
func TestExpiredApprovalCannotReserve(t *testing.T) {
	f := approvedCall(t)
	ticket := filepath.Join(f.call(t), "invocation.age")
	_, err := runInvocationAt(f.b, f.bundle, ticket, func([]byte) (FieldMetadata, error) { t.Fatal("expired callback"); return FieldMetadata{}, nil }, func() time.Time { return time.Now().UTC().Add(3 * time.Minute) })
	if err == nil {
		t.Fatal("expired approval consumed")
	}
	rows, err := Executions(f.b, "job")
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
}
func TestIntentIsDurableBeforeFieldUnlock(t *testing.T) {
	f := approvedCall(t)
	ticket := filepath.Join(f.call(t), "invocation.age")
	if err := os.WriteFile(filepath.Join(f.b, "device.slot"), []byte("bad slot"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Invoke(f.b, f.bundle, ticket); err == nil {
		t.Fatal("locked target returned value")
	}
	uses, err := Executions(f.b, "job")
	if err != nil || len(uses) != 1 || uses[0].State != "failed" {
		t.Fatal("target unlock was attempted before durable intent", uses, err)
	}
}
func TestAbandonedClaimCannotRunAgain(t *testing.T) {
	f := approvedCall(t)
	ticket := filepath.Join(f.call(t), "invocation.age")
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("action was not reached")
			}
		}()
		_, _ = runInvocation(f.b, f.bundle, ticket, func([]byte) (FieldMetadata, error) { panic("simulated death after durable intent") })
	}()
	rows, err := Executions(f.b, "job")
	if err != nil || len(rows) != 1 || rows[0].State != "unknown" {
		t.Fatal(rows, err)
	}
	_, err = runInvocation(f.b, f.bundle, ticket, func([]byte) (FieldMetadata, error) {
		t.Fatal("ran again")
		return FieldMetadata{}, errors.New("unexpected")
	})
	if err == nil {
		t.Fatal("replay accepted")
	}
}
