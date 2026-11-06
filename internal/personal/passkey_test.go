package personal

import (
	"bytes"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/passkey"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func passkeyTarget(t *testing.T) (*Session, PasskeyTarget) {
	t.Helper()
	s, fill := browserFixture(t)
	return s, PasskeyTarget{Context: fill.Context, Create: true, ID: fill.ID, Revision: fill.Revision, Options: []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)}
}
func TestPasskeyBackupRestoreAndNoPlaintext(t *testing.T) {
	s, target := passkeyTarget(t)
	created, e := s.PerformPasskey(target, false, dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	var recordRaw []byte
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		t.Fatal(e)
	}
	e = db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, passkeyGetAction, s)
		if e != nil {
			return e
		}
		defer a.clear()
		for _, item := range a.items {
			if item.ID == target.ID {
				recordRaw = bytes.Clone(item.Passkey)
			}
		}
		return nil
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	record, e := passkey.Load(recordRaw)
	if e != nil {
		t.Fatal(e)
	}
	defer record.Clear()
	defer clear(recordRaw)
	disk, e := os.ReadFile(s.path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(disk, record.PrivateKey) || bytes.Contains(disk, recordRaw) || bytes.Contains(disk, []byte("passkey-fixture-user")) {
		t.Fatal("plaintext persisted")
	}
	key := bytes.Repeat([]byte{4}, 16)
	defer clear(key)
	archive, restored := filepath.Join(t.TempDir(), "backup.llb"), filepath.Join(t.TempDir(), "restored.ll")
	kit, e := Backup(s.path, archive, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	nextKey := bytes.Repeat([]byte{6}, 16)
	defer clear(nextKey)
	if e = Restore(archive, restored, "fixture", key, kit, nextKey); e != nil {
		t.Fatal("passkey history restore", e)
	}
	next, e := UnlockSession(restored, []byte("fixture"), nextKey, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Lock()
	get := PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + created.ID + `"}]}`)}
	choices, e := next.ReviewPasskey(get)
	if e != nil || len(choices) != 1 {
		t.Fatal("restored key not discoverable", e)
	}
	get.ID = choices[0].ID
	get.Revision = choices[0].Revision
	signed, e := next.PerformPasskey(get, false, dailyGate(t, next))
	if e != nil || signed.ID != created.ID {
		t.Fatal("restored key cannot sign", e)
	}
	if _, e = next.List("active"); e != nil {
		t.Fatal("restored assertion audit", e)
	}
}
func TestPasskeyStaleCancellationUVAndNoOverwrite(t *testing.T) {
	s, target := passkeyTarget(t)
	g := dailyGate(t, s)
	g.Cancel()
	if _, e := s.PerformPasskey(target, false, g); e == nil {
		t.Fatal("cancel ignored")
	}
	bad := target
	bad.Revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, e := s.PerformPasskey(bad, false, dailyGate(t, s)); e == nil {
		t.Fatal("stale revision")
	}
	if e := s.VerifyPasskeyUser([]byte("wrong"), bytes.Repeat([]byte{4}, 16)); e == nil {
		t.Fatal("bad factors")
	}
	created, e := s.PerformPasskey(target, false, dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	target.Revision = rows[0].Revision
	if _, e = s.PerformPasskey(target, false, dailyGate(t, s)); e == nil {
		t.Fatal("overwrote existing credential")
	}
	var options map[string]any
	json.Unmarshal(target.Options, &options)
	options["excludeCredentials"] = []map[string]string{{"type": "public-key", "id": created.ID}}
	target.Options, _ = json.Marshal(options)
	target.ID = ""
	target.Revision = ""
	if _, e = s.PerformPasskey(target, false, dailyGate(t, s)); e == nil {
		t.Fatal("excluded credential recreated")
	}
	g = dailyGate(t, s)
	s.RequestLock()
	if _, e = s.PerformPasskey(target, false, g); e == nil {
		t.Fatal("locked operation")
	}
}
