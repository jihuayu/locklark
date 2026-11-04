package preview

import (
	"bytes"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/gateway"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoricalTicketMatchesDecisionAfterPluginUpgrade(t *testing.T) {
	old, err := gateway.RecordedIntent(gateway.Repository{ID: "123", Owner: "example", Name: "tools"}, 7, []byte(`{"v":1,"action":"github.pulls.get","repo":"123","number":7}`))
	if err != nil {
		t.Fatal(err)
	}
	old.Digest = "removed-version"
	now := time.Now()
	q := Request{ID: "abc", Session: "job", Review: "signed-review", Action: gateway.PullAction, Ref: gateway.PullSlot, Epoch: 3, Pull: &old, Auth: &SessionProof{Public: "signer", Audience: "owner"}, SenderStatus: "verified"}
	h := history{decisions: []Decision{{Request: q, Result: "approved", Expires: &now}}}
	if supportedAction(q) {
		t.Fatal("retired module remained executable")
	}
	if _, err := authorization(h, invocation{ID: q.ID, Session: q.Session, Review: q.Review, Public: "signer", Audience: "owner"}); err != nil {
		t.Fatal("matching known historical approval rejected", err)
	}
}

func TestSignedPullApprovalToSingleRecordedReply(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := Create(root, "boot", "fixture"); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "clients", "B")
	inbox := filepath.Join(root, "inbox")
	bundle := filepath.Join(root, "share", "epoch-3")
	pub := filepath.Join(root, "agent", "approval.pub")
	key := filepath.Join(t.TempDir(), "job.sessionkey")
	identity, err := NewSessionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	repo := gateway.Repository{ID: "123", Owner: "example", Name: "tools"}
	if _, err := EnrollPullSession(device, "job", identity, "read PR", repo); err != nil {
		t.Fatal(err)
	}
	plan := []byte(`{"v":1,"action":"github.pulls.get","repo":"123","number":7}`)
	s, err := SubmitPullReceipt(inbox, pub, "job", "check merge", key, repo, 7, plan)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := Inbox(inbox, device, "job")
	if err != nil || len(mail.Requests) != 1 {
		t.Fatal(err)
	}
	q := mail.Requests[0]
	if q.SenderStatus != "verified" || q.Review != s.Review || q.Pull.Number != 7 || q.Ref != gateway.PullSlot || !q.Pull.Valid() {
		t.Fatal("invalid reviewed target", q)
	}
	for _, change := range []func(*gateway.PullIntent){func(p *gateway.PullIntent) { p.Number++ }, func(p *gateway.PullIntent) { p.Repo.ID = "987" }, func(p *gateway.PullIntent) { p.Repo.Name = "renamed" }, func(p *gateway.PullIntent) { p.Digest = "other" }, func(p *gateway.PullIntent) { p.Slot = "other" }} {
		x := q
		v := *q.Pull
		change(&v)
		x.Pull = &v
		if requestDigest(x) == s.Review || bytes.Equal(proofMessage(q), proofMessage(x)) {
			t.Fatal("changed target preserved proof")
		}
	}
	certPath := filepath.Join(device, "pull-target.age")
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	inboxKey, err := mailIdentity(device)
	if err != nil {
		t.Fatal(err)
	}
	var cert pullTarget
	if err = unsealJSON(inboxKey, certBytes, 2048, &cert); err != nil {
		t.Fatal(err)
	}
	cert.Archive = string(bytes.Repeat([]byte("0"), 64))
	forged, err := sealJSON(inboxKey.Recipient(), cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Decide(inbox, device, bundle, s.ID, s.Review, "approve", "forged metadata"); err == nil {
		t.Fatal("accepted forged slot descriptor")
	}
	if err = os.WriteFile(certPath, certBytes, 0600); err != nil {
		t.Fatal(err)
	}
	slotPath := filepath.Join(device, "device.slot")
	slotBytes, err := os.ReadFile(slotPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slotPath, []byte("vault locked"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Decide(inbox, device, bundle, s.ID, s.Review, "approve", "owner verified"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slotPath, slotBytes, 0600); err != nil {
		t.Fatal(err)
	}
	attempt := filepath.Join(t.TempDir(), "attempt")
	if err := PrepareInvocation(attempt, key, pub, filepath.Join(root, "agent", "host-sign.pub"), "job", s.ID, s.Review); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(attempt, "invocation.age")
	if _, err := Invoke(device, bundle, ticket); err == nil {
		t.Fatal("metadata command consumed PR approval")
	}
	fixture := filepath.Join(t.TempDir(), "response.json")
	if err := os.WriteFile(fixture, []byte(`{"base":{"repo":{"id":123}},"number":7,"state":"open","merged_at":null,"title":"not public"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cipher, err := InvokeRecordedPull(device, bundle, ticket, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InvokeRecordedPull(device, bundle, ticket, fixture); err == nil {
		t.Fatal("ran twice")
	}
	reply := filepath.Join(t.TempDir(), "reply.age")
	if err := os.WriteFile(reply, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := InvocationResult(attempt, reply)
	raw, _ := json.Marshal(result)
	if err != nil || string(raw) != `{"source":"recorded-response/v1","pull":{"number":7,"state":"open","merged_at":null}}` {
		t.Fatal(string(raw), err)
	}
	history, err := Executions(device, "job")
	if err != nil || len(history) != 1 || history[0].Pull == nil || *history[0].Pull != *q.Pull || history[0].State != "succeeded" {
		t.Fatal("audit lost executed target", err)
	}
	tamper, err := SubmitPullReceipt(inbox, pub, "job", "review another", key, repo, 7, plan)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := mailIdentity(device)
	if err != nil {
		t.Fatal(err)
	}
	name := tamper.ID + ".request.age"
	modified, ok := openRequest(inbox, name, owner)
	if !ok {
		t.Fatal("missing submitted request")
	}
	modified.Pull.Number = 8
	modified.Review = ""
	modified.SenderStatus = ""
	wire, err := sealJSON(owner.Recipient(), modified)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(inbox, name), wire, 0600); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{tamper.Review, requestDigest(modified)} {
		if _, err := Decide(inbox, device, bundle, tamper.ID, digest, "approve", "wrong PR"); err == nil {
			t.Fatal("modified PR gained approval")
		}
	}
	other := repo
	other.ID = "456"
	bad, err := SubmitPullReceipt(inbox, pub, "job", "another repo", key, other, 7, bytes.Replace(plan, []byte("123"), []byte("456"), 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decide(inbox, device, bundle, bad.ID, bad.Review, "approve", "try outside"); err == nil {
		t.Fatal("out of scope approval")
	}
	if _, err := SubmitPullReceipt(inbox, pub, "job", "substitute PR", key, repo, 8, plan); err == nil {
		t.Fatal("accepted substituted plan")
	}
}
