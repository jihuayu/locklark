package desktop

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
)

// desktopKnowledgeStore implements only the quick-unlock adapter contract; it
// deliberately has no per-operation user-verification method.
type desktopKnowledgeStore struct {
	values map[string][]byte
	calls  int
}

func (s *desktopKnowledgeStore) Store(id string, b []byte) error {
	if s.values == nil {
		s.values = map[string][]byte{}
	}
	s.values[id] = bytes.Clone(b)
	return nil
}

func (s *desktopKnowledgeStore) Load(id string) ([]byte, error) {
	return bytes.Clone(s.values[id]), nil
}

func (s *desktopKnowledgeStore) Delete(id string) error {
	delete(s.values, id)
	return nil
}

// desktopVerificationStore is a structural trusted-adapter stand-in: it adds the
// fresh verification call. It is not hardware and returns a refusal, so the test
// proves only that the native UI asks the adapter asynchronously and fails
// closed.
type desktopVerificationStore struct {
	desktopKnowledgeStore
	verifications int
}

func (s *desktopVerificationStore) LoadForPasskeyVerification(string) ([]byte, error) {
	s.verifications++
	return nil, errors.New("not enrolled")
}

// desktopPasskeyFixture pairs a connection with an unlocked session and a
// reviewed passkey-create request, exactly like the native confirmation window.
func desktopPasskeyFixture(t *testing.T) (*App, *browserhost.Connection, *personal.Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passkey-system.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Desktop login", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	out := &browserPipe{}
	c := browserhost.NewConnection(browserhost.NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e = c.Handle(browserhost.Request{V: 1, ID: fmt.Sprintf("%032x", 1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e = c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	out.Lock()
	raw := out.String()
	out.Unlock()
	marker := `"capability":"`
	start := strings.Index(raw, marker)
	if start < 0 {
		t.Fatal("pairing did not deliver a capability")
	}
	start += len(marker)
	if len(raw) < start+32 {
		t.Fatal("short capability")
	}
	request := browserhost.Request{V: 1, ID: fmt.Sprintf("%032x", 2), Type: "passkey-create", Capability: raw[start : start+32], Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"userVerification":"required"}}`}
	if e = c.Handle(request); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		view := c.Snapshot()
		if view.Passkey != nil && !view.Passkey.Working && len(view.Passkey.Choices) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("passkey review timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
	a := New()
	a.session = s
	a.browser = c
	return a, c, s
}

func desktopTextWithPrefix(t *testing.T, tester *ui.Tester, prefix string) string {
	t.Helper()
	for _, text := range tester.Texts() {
		if strings.HasPrefix(text, prefix) {
			return text
		}
	}
	t.Fatalf("no native element starts with %q", prefix)
	return ""
}

// TestNativePasskeySystemFactorIsStructuralAndAsync proves that the system
// factor button exists only for a structurally trusted native adapter, never
// prompts while rendering, clears stale factor inputs before the OS prompt and
// runs the approval asynchronously through a.run.
func TestNativePasskeySystemFactorIsStructuralAndAsync(t *testing.T) {
	label := "使用" + osunlock.Label() + "保存到："
	t.Run("knowledge-only-adapter", func(t *testing.T) {
		a, _, _ := desktopPasskeyFixture(t)
		a.systemStore = &desktopKnowledgeStore{}
		tester := ui.NewTester(a.View, 1000, 2000)
		if !tester.HasText("验证主密码") || !tester.HasText("创建新登录并保存 Passkey") {
			t.Fatal("existing knowledge factors disappeared")
		}
		if tester.HasText(label) {
			t.Fatal("system factor offered without a trusted verification adapter")
		}
	})
	t.Run("verification-adapter", func(t *testing.T) {
		a, _, _ := desktopPasskeyFixture(t)
		store := &desktopVerificationStore{}
		a.systemStore = store
		tester := ui.NewTester(a.View, 1000, 2000)
		if !tester.HasText("验证主密码") || !tester.HasText("创建新登录并保存 Passkey") {
			t.Fatal("existing knowledge factors disappeared")
		}
		button := desktopTextWithPrefix(t, tester, label)
		if store.verifications != 0 {
			t.Fatal("rendering asked the OS adapter for user verification")
		}
		var worker, completion func()
		a.launch = func(fn func()) { worker = fn }
		a.dispatch = func(fn func()) { completion = fn }
		a.password = "stale-password"
		a.secret = "stale-secret"
		if e := tester.Click(button); e != nil {
			t.Fatal(e)
		}
		if a.password != "" || a.secret != "" {
			t.Fatal("stale factor inputs survived an OS approval")
		}
		if store.verifications != 0 {
			t.Fatal("OS prompt ran during render or click handling")
		}
		if worker == nil {
			t.Fatal("system approval did not run asynchronously through a.run")
		}
		worker()
		if store.verifications != 1 {
			t.Fatalf("expected exactly one fresh OS verification, got %d", store.verifications)
		}
		if completion == nil {
			t.Fatal("missing async completion")
		}
		completion()
		if a.busy {
			t.Fatal("app stayed busy after the refused verification")
		}
	})
}
