package preview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivacyOnLegacyRead(t *testing.T) {
	sensitive := "Authorization: Bearer demo-example"
	old := Event{Session: "release", Reason: sensitive}
	visible := displayedEvent(old)
	if visible.Reason != "[redacted]" || old.Reason != sensitive {
		t.Fatal("unsafe legacy display or mutation")
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
	if _, err := Submit(inbox, recipient, "release-42", "核对 password rotation 和 GitHub token 的到期时间", FixtureRef); err != nil {
		t.Fatal("ordinary business reason blocked", err)
	}
}
