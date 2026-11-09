package personal

import (
	"testing"
	"time"
)

func exportTestSource(t *testing.T) (*Session, PasskeyTarget, string, []byte) {
	t.Helper()
	path, key, fill := revealFixture(t)
	revision, err := EditLogin(path, "fixture", key, Edit{ID: fill.ID, Revision: fill.Revision, Field: "url", Value: "https://example.test/login"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	target := PasskeyTarget{
		Context:  BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "document-1"},
		Create:   true,
		ID:       fill.ID,
		Revision: revision,
		Options:  []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`),
	}
	return s, target, path, key
}
