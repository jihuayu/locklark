package preview

import (
	"bytes"
	"github.com/jihuayu/locklark/internal/gateway"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOutboxCoalescesConcurrentCallsAndRestoresLostPublication(t *testing.T) {
	f := approvedCall(t)
	c := PollConfig{Private: t.TempDir(), Key: f.key, Recipient: f.pub, Host: f.host, Session: "job"}
	repo := gateway.Repository{ID: "123", Owner: "example", Name: "tools"}
	scope, e := gateway.RecordedScope(repo)
	if e != nil {
		t.Fatal(e)
	}
	p := BridgeProfile{Session: "job", Scope: scope, Issued: time.Now(), Expires: time.Now().Add(time.Minute)}
	key := "0123456789abcdef0123456789abcdef"
	plan := []byte(`{"v":1,"action":"github.pulls.get","repo":"123","number":7}`)
	dir := t.TempDir()
	var wg sync.WaitGroup
	var r [2]Submitted
	var errs [2]error
	for i := range r {
		wg.Add(1)
		go func(i int) { defer wg.Done(); r[i], errs[i] = SubmitBridgePull(c, dir, p, key, "check merge", 7, plan) }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || r[0] != r[1] {
		t.Fatal(r, errs)
	}
	path := filepath.Join(dir, r[0].ID+".request.age")
	orig, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if _, e = SubmitBridgePull(c, dir, p, key, "check merge", 7, plan); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(orig, got) {
		t.Fatal("lost stable ciphertext", e)
	}
	if e = os.WriteFile(path, []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = SubmitBridgePull(c, dir, p, key, "check merge", 7, plan); e == nil {
		t.Fatal("accepted conflicting relay file")
	}
}
