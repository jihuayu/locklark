package browserhost

import (
	"bytes"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/passkey"
	"runtime"
	"strings"
	"testing"
	"time"
)

func waitPasskey(t *testing.T, c *Connection) *PasskeyView {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		v := c.Snapshot()
		if v.Passkey != nil && !v.Passkey.Working {
			return v.Passkey
		}
		time.Sleep(time.Millisecond * 5)
	}
	t.Fatal("passkey review timed out")
	return nil
}
func TestPasskeyNativeApprovalPersistenceAndSign(t *testing.T) {
	c, s, out, r := paired(t)
	defer c.Close()
	r.Type = "passkey-create"
	r.Revision = ""
	r.Options = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"userVerification":"required"}}`
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	p := waitPasskey(t, c)
	if len(out.responses(t)) != 1 || len(p.Choices) != 1 {
		t.Fatal("must await approval with attach choice")
	}
	if e := c.ApprovePasskey(r.ID, p.Choices[0].ID, []byte("fixture"), bytes.Repeat([]byte{7}, 16)); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	if all[len(all)-1].Type != "passkey-result" {
		t.Fatal("missing credential")
	}
	var credential passkey.Response
	if json.Unmarshal([]byte(all[len(all)-1].Credential), &credential) != nil {
		t.Fatal("invalid response")
	}
	if _, e := s.List("active"); e != nil {
		t.Fatal("created audit not readable", e)
	}
	r.ID = reqID(50)
	r.Type = "passkey-get"
	r.Options = `{"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2","allowCredentials":[{"type":"public-key","id":"` + credential.ID + `"}]}`
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	p = waitPasskey(t, c)
	if len(p.Choices) != 1 {
		t.Fatal("credential missing after encrypted reopen")
	}
	if e := c.ApprovePasskey(r.ID, p.Choices[0].ID, nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, e := s.List("active"); e != nil {
		t.Fatal("signed audit not readable", e)
	}
}
func TestPasskeyCancellationBeforeApproval(t *testing.T) {
	c, _, out, r := paired(t)
	defer c.Close()
	r.Type = "passkey-create"
	r.Revision = ""
	r.Options = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	waitPasskey(t, c)
	if e := c.Handle(Request{V: 1, ID: reqID(40), Type: "cancel", Capability: r.Capability}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApprovePasskey(r.ID, "", nil, nil); e == nil {
		t.Fatal("cancelled approval")
	}
	for _, m := range out.responses(t) {
		if m.Type == "passkey-result" {
			t.Fatal("cancelled credential escaped")
		}
	}
}

func TestQuickPairRequiresNativeChoiceAndLockRevokesIt(t *testing.T) {
	_, s, _, r := paired(t)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	defer c.Close()
	if e := c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if c.Snapshot().QuickFill {
		t.Fatal("browser enabled quick mode")
	}
	if e := c.ApproveQuickPair(s); e != nil {
		t.Fatal(e)
	}
	paired := out.responses(t)[0]
	if !paired.QuickFill {
		t.Fatal("native quick choice missing")
	}
	r.Capability = paired.Capability
	matchAndFill(t, c, out, r)
	until := time.Now().Add(3 * time.Second)
	filled := false
	for time.Now().Before(until) {
		for _, m := range out.responses(t) {
			if m.Type == "fill" {
				filled = true
			}
		}
		if filled {
			break
		}
		time.Sleep(time.Millisecond * 5)
	}
	if !filled {
		t.Fatal("native-authorized quick fill did not run")
	}
	c.Invalidate()
	if c.Snapshot().QuickFill || s.Unlocked() {
		t.Fatal("lock retained quick authority")
	}
}

func TestPasskeyQueuedOutputRefusesAfterLock(t *testing.T) {
	c, _, out, r := paired(t)
	defer c.Close()
	r.Type = "passkey-create"
	r.Revision = ""
	r.Options = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	waitPasskey(t, c)
	release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.ApprovePasskey(r.ID, "", nil, nil) }()
	until := time.Now().Add(time.Second)
	waiting := false
	for time.Now().Before(until) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		for _, g := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(g, "(*Connection).ApprovePasskey") && strings.Contains(g, "(*Writer).acquire") {
				waiting = true
			}
		}
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		release()
		t.Fatal("passkey never queued for output")
	}
	c.Invalidate()
	release()
	if e = <-done; e == nil {
		t.Fatal("revoked assertion delivered")
	}
	for _, m := range out.responses(t) {
		if m.Type == "passkey-result" {
			t.Fatal("revoked credential escaped")
		}
	}
}
