package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"github.com/jihuayu/locklark/internal/passkey"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
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
func TestMixedSSHAndPasskeyVaultReplayAndBackupRestore(t *testing.T) {
	s, target := passkeyTarget(t)
	genSSH, e := s.GenerateSSHKey("Mixed Generated SSH", dailyGate(t, s))
	if e != nil || genSSH.ID == "" {
		t.Fatal("generated SSH key", e)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	defer clear(priv)
	block, e := ssh.MarshalPrivateKey(priv, "")
	if e != nil {
		t.Fatal("marshal imported SSH key", e)
	}
	input := pem.EncodeToMemory(block)
	impSSH, e := s.ImportSSHKey("Mixed Imported SSH", input, dailyGate(t, s))
	if e != nil {
		t.Fatal("imported SSH key", e)
	}
	pk1, e := s.PerformPasskey(target, false, dailyGate(t, s))
	if e != nil {
		t.Fatal("attached passkey", e)
	}
	target2 := target
	target2.ID = ""
	target2.Revision = ""
	target2.Options = []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjI","name":"second-user","displayName":"Second"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
	pk2, e := s.PerformPasskey(target2, false, dailyGate(t, s))
	if e != nil || pk2.ID == pk1.ID {
		t.Fatal("second passkey login", e)
	}
	intent := preparedSSH(t, s, impSSH)
	out, e := s.ApproveSSHSign(intent)
	if e != nil {
		t.Fatal("mixed SSH approve", e)
	}
	wire, e := s.ConsumeSSHSignature(out)
	if e != nil {
		t.Fatal("mixed SSH consume", e)
	}
	var sig ssh.Signature
	if e = ssh.Unmarshal(wire, &sig); e != nil {
		t.Fatal("mixed SSH signature encoding", e)
	}
	pub, _, _, _, e := ssh.ParseAuthorizedKey([]byte(impSSH.PublicKey))
	if e != nil {
		t.Fatal("mixed SSH public key", e)
	}
	if e = pub.Verify([]byte("exact SSH client message"), &sig); e != nil {
		t.Fatal("mixed SSH signature", e)
	}
	get := PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + pk1.ID + `"}]}`)}
	choices, e := s.ReviewPasskey(get)
	if e != nil || len(choices) != 1 {
		t.Fatal("mixed passkey review", e)
	}
	get.ID = choices[0].ID
	get.Revision = choices[0].Revision
	signed, e := s.PerformPasskey(get, false, dailyGate(t, s))
	if e != nil || signed.ID != pk1.ID {
		t.Fatal("mixed passkey assertion", e)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal("mixed audit", e)
	}
	active, e := s.List("active")
	if e != nil {
		t.Fatal("mixed active items", e)
	}
	// The shared fixture has unrelated pre-existing rows, so count the two
	// passkey logins owned by this test rather than every active SSH key too.
	passkeyLogins := 0
	for _, row := range active {
		if row.Kind == "login" && (row.ID == target.ID || row.Title == "example.test · second-user") {
			passkeyLogins++
		}
	}
	if passkeyLogins != 2 {
		t.Fatalf("mixed active passkey logins: got %d want 2", passkeyLogins)
	}
	sshKeys, e := s.ListSSHKeys()
	if e != nil || len(sshKeys) != 2 {
		t.Fatal("mixed SSH keys", e)
	}
	for _, action := range []string{sshGenerateAction, sshImportAction, passkeyCreateAction, sshSignAction, passkeyGetAction} {
		found := false
		for _, event := range events {
			if event.Action == action {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mixed audit missing %s", action)
		}
	}
	key := bytes.Repeat([]byte{4}, 16)
	defer clear(key)
	archive, restored := filepath.Join(t.TempDir(), "backup.llb"), filepath.Join(t.TempDir(), "restored.ll")
	kit, e := Backup(s.path, archive, "fixture", key)
	if e != nil {
		t.Fatal("mixed backup", e)
	}
	nextKey := bytes.Repeat([]byte{6}, 16)
	defer clear(nextKey)
	if e = Restore(archive, restored, "fixture", key, kit, nextKey); e != nil {
		t.Fatal("mixed restore", e)
	}
	next, e := UnlockSession(restored, []byte("fixture"), nextKey, time.Minute)
	if e != nil {
		t.Fatal("mixed restored unlock", e)
	}
	defer next.Lock()
	restoredKeys, e := next.ListSSHKeys()
	if e != nil || len(restoredKeys) != 2 {
		t.Fatal("restored SSH keys", e)
	}
	var restoredImp SSHKeyRow
	for _, row := range restoredKeys {
		if row.ID == impSSH.ID {
			restoredImp = row
		}
	}
	if restoredImp.ID == "" {
		t.Fatal("restored imported SSH key")
	}
	intent = preparedSSH(t, next, restoredImp)
	out, e = next.ApproveSSHSign(intent)
	if e != nil {
		t.Fatal("restored SSH approve", e)
	}
	wire, e = next.ConsumeSSHSignature(out)
	if e != nil {
		t.Fatal("restored SSH consume", e)
	}
	if e = ssh.Unmarshal(wire, &sig); e != nil {
		t.Fatal("restored SSH signature encoding", e)
	}
	if e = pub.Verify([]byte("exact SSH client message"), &sig); e != nil {
		t.Fatal("restored SSH signature", e)
	}
	// A restore re-chains the journal hashes, so the pre-restore exact-revision
	// pin is intentionally stale; re-review the restored vault, then re-pin.
	get.ID, get.Revision = "", ""
	choices, e = next.ReviewPasskey(get)
	if e != nil || len(choices) != 1 {
		t.Fatal("restored passkey review", e)
	}
	get.ID = choices[0].ID
	get.Revision = choices[0].Revision
	signed, e = next.PerformPasskey(get, false, dailyGate(t, next))
	if e != nil || signed.ID != pk1.ID {
		t.Fatal("restored passkey assertion", e)
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
