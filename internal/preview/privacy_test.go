package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"filippo.io/age"
	"time"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamedCredentialAssignments(t *testing.T) {
	for _, s := range []string{"GITHUB_TOKEN=synthetic-canary", "DATABASE_" + "PASSWORD" + "=synthetic-canary", `{"password":"synthetic-canary"}`, `'client_secret': 'synthetic-canary'`} {
		if validRequest("release", s, FixtureRef) || displayedEvent(Event{Reason: s}).Reason != "[redacted]" {
			t.Fatal("named assignment escaped privacy check")
		}
	}
}
func TestTaskNamesAreOrdinaryIdentifiers(t *testing.T) {
	for _, id := range []string{"task-rotate-passwords", "risk-assessment-2026", "desk-release-20261104"} {
		if !validSession(id) || !validReason(id) {
			t.Fatal("ordinary task blocked", id)
		}
	}
}
func TestPrivacyOnLegacyRead(t *testing.T) {
	sensitive := "Authorization: Bearer demo-example"
	old := Event{Session: "release", Reason: sensitive}
	visible := displayedEvent(old)
	if visible.Reason != "[redacted]" || old.Reason != sensitive {
		t.Fatal("unsafe legacy display or mutation")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	client, bundle := filepath.Join(root, "client"), filepath.Join(root, "bundle")
	if err := saveDevice(client, device, pub, make([]byte, 16), make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if err := saveEpoch(bundle, payload{Events: []Event{old}}, 1, []*age.X25519Recipient{device.Recipient()}, key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundle, "vault.kdbx")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := Audit(bundle, client, 1, "release")
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy query changed signed snapshot")
	}
	if err != nil || len(events) != 1 || events[0].Reason != "[redacted]" {
		t.Fatal("legacy secret escaped audit query", err)
	}
	if validRequest("release", sensitive, FixtureRef) {
		t.Fatal("external sender could replay a credential-bearing reason")
	}
}
func TestRejectedSecretsNeverReachNewArtifacts(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "control")
	if err := Create(client, "bootstrap", "检查令牌轮换流程"); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(client, "inbox")
	recipient := filepath.Join(client, "agent", "approval.pub")
	for _, reason := range []string{"Authorization: Bearer synthetic-example", "password=fixture-value", "otpauth://totp/test?secret=ABCD", "https://bot:fixture@example.invalid", "-----BEGIN OPENSSH PRIVATE KEY-----", "GitHub token: ghp_" + strings.Repeat("A", 36)} {
		if _, err := Submit(inbox, recipient, "release", reason, FixtureRef); err == nil || strings.Contains(err.Error(), reason) {
			t.Fatal("submission accepted or reflected a sensitive reason")
		}
		out := filepath.Join(root, "never-created")
		if err := Create(out, "release", reason); err == nil {
			t.Fatal("demo persisted a sensitive reason")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("rejection created files")
		}
	}
	if _, err := Submit(inbox, recipient, "ghp_"+strings.Repeat("A", 36), "check release", FixtureRef); err == nil {
		t.Fatal("token accepted as session")
	}
	files, err := os.ReadDir(inbox)
	if err != nil || len(files) != 0 {
		t.Fatal("rejection wrote inbox data")
	}
	forgedID := strings.Repeat("a", 32)
	pub, err := os.ReadFile(recipient)
	if err != nil {
		t.Fatal(err)
	}
	key, err := age.ParseX25519Recipient(strings.TrimSpace(string(pub)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	forged := Request{ID: forgedID, Session: "release", Reason: "Authorization: Bearer synthetic-forged", Ref: FixtureRef, State: "pending", Created: time.Now().UTC().Format(time.RFC3339Nano)}
	if err = json.NewEncoder(w).Encode(forged); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(inbox, forgedID+".request.age"), buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Inbox(inbox, filepath.Join(client, "clients", "B"), "release")
	if err != nil || report.Unreadable != 1 || len(report.Requests) != 0 {
		t.Fatal("untrusted encrypted request leaked", err)
	}
	if _, err := Submit(inbox, recipient, "release-42", "核对 password rotation 和 GitHub token 的到期时间", FixtureRef); err != nil {
		t.Fatal("ordinary business reason blocked", err)
	}
}
