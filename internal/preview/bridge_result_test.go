package preview

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/gateway"
)

func TestBridgeCollectRequiresOriginalRecipient(t *testing.T) {
	f := approvedCall(t)
	key := filepath.Join(t.TempDir(), "reader.sessionkey")
	public, err := NewSessionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	repo := gateway.Repository{ID: "123", Owner: "example", Name: "tools"}
	if _, err = EnrollPullSession(f.b, "reader", public, "test result", repo); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "launch.profile")
	if err = ExportBridgeProfile(f.b, "reader", profile); err != nil {
		t.Fatal(err)
	}
	c := PollConfig{Session: "reader", Key: key, Host: f.host, Recipient: f.pub, Private: t.TempDir(), Exchange: t.TempDir()}
	p, err := LoadBridgeProfile(profile, c)
	if err != nil {
		t.Fatal(err)
	}
	plan := []byte(`{"v":1,"repo":"123","number":7,"action":"github.pulls.get"}`)
	var wg sync.WaitGroup
	var rec [2]Submitted
	var es [2]error
	for i := range rec {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec[i], es[i] = SubmitBridgeAction(c, f.inbox, p, strings.Repeat("ab", 16), "review pull", 7, plan)
		}(i)
	}
	wg.Wait()
	if es[0] != nil || es[1] != nil || rec[0] != rec[1] {
		t.Fatal("competing submit returned different outcomes", es)
	}
	id, review := rec[0].ID, rec[0].Review
	sealedPath := filepath.Join(c.Private, id+".replykey")
	sealed, err := os.ReadFile(sealedPath)
	if err != nil || bytes.Contains(sealed, []byte("AGE-SECRET-KEY")) {
		t.Fatal("private recipient not sealed")
	}
	other := c
	other.Key = f.key
	if _, err := CollectBridgeResult(other, p, id, review); err == nil {
		t.Fatal("wrong session key")
	}
	if _, err := CollectBridgeResult(c, p, id, strings.Repeat("a", 64)); err == nil {
		t.Fatal("unrelated review")
	}
	if _, err = Decide(f.inbox, f.b, f.bundle, id, review, "approve", "reviewed result"); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(c.Exchange, id+".invoke.age")
	recording := filepath.Join(t.TempDir(), "rec.json")
	if err = os.WriteFile(recording, []byte(`{"base":{"repo":{"id":123}},"number":7,"state":"open","merged_at":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	encrypted, err := InvokeRecordedPull(f.b, f.bundle, ticket, recording)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(c.Exchange, id+".result.age")
	if err = WriteReply(out, []byte("relay replacement")); err != nil {
		t.Fatal(err)
	}
	if _, err = CollectBridgeResult(c, p, id, review); err == nil {
		t.Fatal("accepted relay replacement")
	}
	if err = os.Remove(out); err != nil {
		t.Fatal(err)
	}
	if _, err = RevokeSession(f.b, "reader", "finished"); err != nil {
		t.Fatal(err)
	}
	holder, e := mailIdentity(f.b)
	if e != nil {
		t.Fatal(e)
	}
	if err = forwardReceipt(holder, f.b, c.Exchange, id, out); err == nil {
		t.Fatal("delivered cached reply after revocation")
	}
	if err = WriteReply(out, encrypted); err != nil {
		t.Fatal(err)
	} // already delivered independently; cannot be recalled
	if got, e := CollectBridgeResult(c, p, id, review); e != nil || got.Result.Pull.Number != 7 {
		t.Fatal(got, e)
	}
	if err = os.Remove(sealedPath); err != nil {
		t.Fatal(err)
	}
	if _, err = CollectBridgeResult(c, p, id, review); err == nil {
		t.Fatal("recreated missing local identity on collect")
	}
	if _, err = os.Stat(sealedPath); !os.IsNotExist(err) {
		t.Fatal("collect wrote identity file")
	}
}
func TestRetiredModuleProfileStillPermitsReceiptRecovery(t *testing.T) {
	f := approvedCall(t)
	key := filepath.Join(t.TempDir(), "old.sessionkey")
	pub, e := NewSessionKey(key)
	if e != nil {
		t.Fatal(e)
	}
	scope, e := gateway.RecordedScope(gateway.Repository{ID: "123", Owner: "example", Name: "tools"})
	if e != nil {
		t.Fatal(e)
	}
	scope.Digest = strings.Repeat("1", 64)
	if _, e = changeScopedSession(f.b, "old", pub, "issued before upgrade", false, time.Now, &scope); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "retired.profile")
	if e = ExportBridgeProfile(f.b, "old", out); e != nil {
		t.Fatal("active historical enrollment cannot recover", e)
	}
	p, e := LoadBridgeProfile(out, PollConfig{Session: "old", Host: f.host, Key: key, Recipient: f.pub})
	if e != nil || p.Scope != scope {
		t.Fatal("retired profile unreadable", e)
	}
	if (gateway.PullIntent{PullScope: scope, Number: 7}).Valid() {
		t.Fatal("retired module enabled execution")
	}
}
