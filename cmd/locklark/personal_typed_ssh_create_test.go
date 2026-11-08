package main

// End-to-end typed ssh_key creation: one explicit owner-private Ed25519 key file
// becomes a real Session.AddItem mutation whose public half is read back from
// the reopened encrypted vault. Receipts and prompts must never echo the path,
// key bytes or fingerprint.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func typedSSHCreateDocument(t *testing.T, keyPath string) string {
	t.Helper()
	return fmt.Sprintf(`{"category":"ssh_key","title":"Typed SSH private title","ssh_private_key_file":%q,"tags":["infra"],"sections":[{"id":"ops","title":"Ops","fields":[{"id":"note","label":"Note","value":"owner-visible"}]}]}`, keyPath)
}

func TestCreateTypedPersonalSSHKeyWritesEd25519Material(t *testing.T) {
	private := ed25519.NewKeyFromSeed(typedSSHFixtureSeed())
	keyPath := writeTypedSSHKeyFile(t, private, nil)
	vaultPath, inputPath, pw, key := typedCreateFixture(t, typedSSHCreateDocument(t, keyPath))

	var prompt bytes.Buffer
	response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(question string) ([]byte, error) {
		if question != "输入 SAVE 确认新增条目" {
			t.Fatalf("unexpected consent prompt %q", question)
		}
		return []byte("SAVE"), nil
	}, &prompt)
	if err != nil {
		t.Fatalf("create typed ssh item: %v", err)
	}
	if len(response) != 3 || response["status"] != "created" || response["id"] == "" || response["revision"] == "" {
		t.Fatalf("receipt must contain only status/id/revision: %+v", response)
	}
	receipt, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	for _, secret := range []string{keyPath, "BEGIN OPENSSH PRIVATE KEY", base64.StdEncoding.EncodeToString(typedSSHFixtureSeed()), ssh.FingerprintSHA256(public), "Typed SSH private title"} {
		if bytes.Contains(receipt, []byte(secret)) || bytes.Contains(prompt.Bytes(), []byte(secret)) {
			t.Fatalf("receipt or prompt echoed protected key material")
		}
	}

	session, err := personal.UnlockSession(vaultPath, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("reopen encrypted vault: %v", err)
	}
	defer session.Lock()
	detail, err := session.GetItemDetail(response["id"], response["revision"], true)
	if err != nil {
		t.Fatalf("read created ssh item: %v", err)
	}
	if detail.Category != vault.CategorySSHKey || detail.SSHPublicKey == "" || !strings.HasPrefix(detail.SSHFingerprint, "SHA256:") {
		t.Fatalf("ssh material was not persisted: %+v", detail)
	}
	if want := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(public)), "\n"); detail.SSHPublicKey != want {
		t.Fatalf("persisted public key does not match the private key file")
	}
	if detail.Username != "" || detail.Password != "" || detail.Notes != "" || detail.OTP != "" || detail.URL != "" {
		t.Fatalf("ssh item unexpectedly carried scalar credentials: %+v", detail)
	}
	if len(detail.Sections) != 1 || len(detail.Sections[0].Fields) != 1 || detail.Sections[0].Fields[0].Value != "owner-visible" || len(detail.Tags) != 1 {
		t.Fatalf("remaining typed fields were dropped: %+v", detail)
	}
}

func TestCreateTypedPersonalSSHKeyWrongConsentDoesNotMutate(t *testing.T) {
	keyPath := writeTypedSSHKeyFile(t, ed25519.NewKeyFromSeed(typedSSHFixtureSeed()), nil)
	vaultPath, inputPath, pw, key := typedCreateFixture(t, typedSSHCreateDocument(t, keyPath))
	response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
		return []byte("NOPE"), nil
	}, &bytes.Buffer{})
	if !errors.Is(err, errTypedCreateCancelled) || response != nil {
		t.Fatalf("wrong consent must cancel with the fixed error: response=%+v err=%v", response, err)
	}
	if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
		t.Fatalf("wrong consent mutated the vault: %d items", count)
	}
}
