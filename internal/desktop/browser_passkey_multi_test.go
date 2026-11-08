package desktop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

const desktopPasskeyCreateOptions = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`

type desktopCredential struct {
	id  string
	pub string
}

func desktopRevision(t *testing.T, s *personal.Session, id string) string {
	t.Helper()
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == id {
			return row.Revision
		}
	}
	t.Fatal("desktop passkey item missing")
	return ""
}

func desktopFrameResponses(t *testing.T, out *browserPipe) []browserhost.Response {
	t.Helper()
	out.Lock()
	raw := bytes.Clone(out.Bytes())
	out.Unlock()
	var responses []browserhost.Response
	for len(raw) >= 4 {
		n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16 | int(raw[3])<<24
		raw = raw[4:]
		if n < 0 || n > len(raw) {
			t.Fatal("bad native frame")
		}
		var response browserhost.Response
		if e := json.Unmarshal(raw[:n], &response); e != nil {
			t.Fatal(e)
		}
		responses = append(responses, response)
		raw = raw[n:]
	}
	return responses
}

// desktopMultiPasskeyFixture unlocks a login that owns two credentials and
// exposes an unpinned assertion review, exactly like a real passkey-get with an
// empty allowCredentials list.
func desktopMultiPasskeyFixture(t *testing.T) (*App, *browserhost.Connection, *browserPipe, []desktopCredential) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passkey-multi.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	itemID, e := s.AddLogin("Desktop login", "alice", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Edit(personal.Edit{ID: itemID, Revision: desktopRevision(t, s, itemID), Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	credentials := []desktopCredential{}
	for n := 0; n < 2; n++ {
		gate := personal.NewMutationGate(time.Now().Add(time.Minute))
		if e := s.RegisterMutation(gate); e != nil {
			t.Fatal(e)
		}
		created, e := s.PerformPasskey(personal.PasskeyTarget{
			Context:  personal.BrowserContext{RequestID: fmt.Sprintf("%032x", 200+n), Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"},
			Create:   true,
			ID:       itemID,
			Revision: desktopRevision(t, s, itemID),
			Options:  []byte(desktopPasskeyCreateOptions),
		}, false, gate)
		if e != nil {
			t.Fatalf("credential %d: %v", n, e)
		}
		credentials = append(credentials, desktopCredential{id: created.ID, pub: created.Response.PublicKey})
	}
	out := &browserPipe{}
	c := browserhost.NewConnection(browserhost.NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e := c.Handle(browserhost.Request{V: 1, ID: fmt.Sprintf("%032x", 1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	capability := ""
	for _, response := range desktopFrameResponses(t, out) {
		if response.Type == "paired" {
			capability = response.Capability
		}
	}
	if capability == "" {
		t.Fatal("pairing did not deliver a capability")
	}
	get := browserhost.Request{
		V: 1, ID: fmt.Sprintf("%032x", 300), Type: "passkey-get", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2"}`,
	}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		view := c.Snapshot().Passkey
		if view != nil && !view.Working && len(view.Choices) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("two-credential review timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
	a := New()
	a.session = s
	a.browser = c
	return a, c, out, credentials
}

func desktopTextsWithPrefix(tester *ui.Tester, prefix string) []string {
	out := []string{}
	for _, text := range tester.Texts() {
		if strings.HasPrefix(text, prefix) {
			out = append(out, text)
		}
	}
	return out
}

func desktopSignatureValid(t *testing.T, credential passkey.Response, publicKey string) bool {
	t.Helper()
	pubDER, e := base64.RawURLEncoding.DecodeString(publicKey)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.ParsePKIXPublicKey(pubDER)
	if e != nil {
		t.Fatal(e)
	}
	client, _ := base64.RawURLEncoding.DecodeString(credential.Response.ClientDataJSON)
	auth, _ := base64.RawURLEncoding.DecodeString(credential.Response.AuthenticatorData)
	signature, _ := base64.RawURLEncoding.DecodeString(credential.Response.Signature)
	h := sha256.Sum256(client)
	digest := sha256.Sum256(append(auth, h[:]...))
	return ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], signature)
}

// TestNativePasskeyMultipleChoicesBindExactCredential clicks one of two buttons
// that share a parent login and proves the delivered assertion was produced by
// that exact credential, not by the first record.
func TestNativePasskeyMultipleChoicesBindExactCredential(t *testing.T) {
	a, c, out, credentials := desktopMultiPasskeyFixture(t)
	tester := ui.NewTester(a.View, 1000, 2000)
	labels := desktopTextsWithPrefix(tester, "登录：")
	if len(labels) != 2 || labels[0] == labels[1] {
		t.Fatalf("per-credential buttons: %#v", labels)
	}
	short := credentials[1].id[:8]
	selected := ""
	for _, label := range labels {
		if !strings.Contains(label, "example.test") || !strings.Contains(label, "Desktop login") {
			t.Fatalf("label lost RP/account context: %q", label)
		}
		if strings.Contains(label, short) {
			selected = label
		}
	}
	if selected == "" {
		t.Fatalf("second credential has no distinct button: %#v", labels)
	}
	a.launch = func(fn func()) { fn() }
	a.dispatch = func(fn func()) { fn() }
	if e := tester.Click(selected); e != nil {
		t.Fatal(e)
	}
	if a.busy {
		t.Fatal("native selection left the app busy")
	}
	var result *passkey.Response
	for _, response := range desktopFrameResponses(t, out) {
		if response.Type != "passkey-result" {
			continue
		}
		var credential passkey.Response
		if e := json.Unmarshal([]byte(response.Credential), &credential); e != nil {
			t.Fatal(e)
		}
		result = &credential
	}
	if result == nil {
		t.Fatal("no passkey-result after native selection")
	}
	if result.ID != credentials[1].id {
		t.Fatalf("signed %q, clicked %q", result.ID, credentials[1].id)
	}
	if !desktopSignatureValid(t, *result, credentials[1].pub) {
		t.Fatal("signature does not match the selected credential")
	}
	if desktopSignatureValid(t, *result, credentials[0].pub) {
		t.Fatal("signature also verifies under the sibling credential")
	}
	if c.Snapshot().Passkey != nil {
		t.Fatal("approval surface survived the completed selection")
	}
}

// TestNativePasskeyCreationWarnsFormatUpgrade proves the creation selector shows
// the existing credential count and the explicit encrypted-format upgrade
// warning before the owner can approve appending a second credential.
func TestNativePasskeyCreationWarnsFormatUpgrade(t *testing.T) {
	a, c, out, _ := desktopMultiPasskeyFixture(t)
	pending := c.Snapshot().Passkey
	if pending == nil {
		t.Fatal("missing review")
	}
	if e := c.RejectPasskey(pending.ID); e != nil {
		t.Fatal(e)
	}
	capability := ""
	for _, response := range desktopFrameResponses(t, out) {
		if response.Type == "paired" {
			capability = response.Capability
		}
	}
	create := browserhost.Request{
		V: 1, ID: fmt.Sprintf("%032x", 400), Type: "passkey-create", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", Options: desktopPasskeyCreateOptions,
	}
	if e := c.Handle(create); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		view := c.Snapshot().Passkey
		if view != nil && view.Create && !view.Working && len(view.Choices) == 1 {
			if len(view.ChoicePasskeys) != 1 || view.ChoicePasskeys[0] != 2 {
				t.Fatalf("creation counts: %#v", view.ChoicePasskeys)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("creation review timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
	tester := ui.NewTester(a.View, 1000, 2000)
	if !tester.HasText("添加第二个 Passkey 会升级该登录的加密格式；旧客户端将拒绝打开金库。请仅在核对账号后明确批准。") {
		t.Fatal("missing explicit upgrade warning")
	}
	labels := desktopTextsWithPrefix(tester, "保存到：")
	if len(labels) != 1 || !strings.Contains(labels[0], "已有 2 个 Passkey") || !strings.Contains(labels[0], "旧客户端将拒绝该金库") {
		t.Fatalf("creation label: %#v", labels)
	}
}
