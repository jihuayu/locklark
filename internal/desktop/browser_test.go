package desktop

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

type browserPipe struct {
	sync.Mutex
	bytes.Buffer
}

func (p *browserPipe) Write(b []byte) (int, error) {
	p.Lock()
	defer p.Unlock()
	return p.Buffer.Write(b)
}
func (p *browserPipe) Close() error { return nil }

func TestBrowserV2StageAndCommitReviewControlsAreDistinct(t *testing.T) {
	for _, test := range []struct {
		kind, heading, detail, approve, reject, absent string
	}{
		{"stage-save", "确认暂存浏览器登录", "仅暂存这次登录信息供后续确认；不会提交金库变更。", "批准本次暂存", "拒绝本次暂存", "批准本次保存"},
		{"commit-staged-save", "确认浏览器保存登录", "仅在本窗口批准后，才会提交这次登录保存。", "批准本次保存", "拒绝本次保存", "批准本次暂存"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			a := &App{}
			tester := ui.NewTester(func(c *ui.Context) {
				a.browserV2ApprovalView(c, nil, browserhost.V2ApprovalView{Type: test.kind})
			}, 1000, 780)
			for _, text := range []string{test.heading, test.detail, test.approve, test.reject} {
				if !tester.HasText(text) {
					t.Fatal("typed browser save review omitted its fixed presentation")
				}
			}
			if tester.HasText(test.absent) {
				t.Fatal("staging and commit must not offer the other operation's approval")
			}
		})
	}
}

func TestNativeBrowserLockDropsLateApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser.ll")
	key := bytes.Repeat([]byte{4}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	id, e := s.AddLogin("Native fixture", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test"})
	if e != nil {
		t.Fatal(e)
	}
	out := &browserPipe{}
	connection := browserhost.NewConnection(browserhost.NewWriter(out, time.Second), nil)
	rid := func(n int) string { return fmt.Sprintf("%032x", n) }
	if connection.Handle(browserhost.Request{V: 1, ID: rid(1), Type: "hello"}) != nil || connection.ApprovePair(s) != nil {
		t.Fatal("pair")
	}
	// Capability is protocol metadata, never exposed through a product renderer.
	out.Lock()
	raw := out.String()
	out.Unlock()
	marker := `"capability":"`
	start := strings.Index(raw, marker) + len(marker)
	capability := raw[start : start+32]
	match := browserhost.Request{V: 1, ID: rid(2), Type: "match", Capability: capability, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"}
	if connection.Handle(match) != nil {
		t.Fatal("match")
	}
	fill := match
	fill.ID = rid(3)
	fill.Type = "fill"
	fill.ItemID = id
	fill.Revision = rev
	if connection.Handle(fill) != nil {
		t.Fatal("fill")
	}
	a := New()
	a.session = s
	a.browser = connection
	a.browserLabel = "fixed development extension"
	tester := ui.NewTester(a.View, 1000, 780)
	if !tester.HasText("HTTPS 来源：https://example.test") || !tester.HasText("批准本次填充") {
		t.Fatal("missing native exact confirmation")
	}
	var worker, completion func()
	a.launch = func(fn func()) { worker = fn }
	a.dispatch = func(fn func()) { completion = fn }
	a.run(func() outcome { return outcome{err: connection.ApproveFill(fill.ID)} })
	approve := worker
	a.Lock()
	approve()
	completion()
	out.Lock()
	protocol := out.String()
	out.Unlock()
	if strings.Contains(protocol, "fixture-password") || strings.Contains(protocol, `"type":"fill"`) || a.session != nil || a.busy {
		t.Fatal("late approval survived UI lock")
	}
	tester = ui.NewTester(a.View, 1000, 780)
	if tester.HasText("批准本次填充") {
		t.Fatal("approval survived locked view")
	}
}
