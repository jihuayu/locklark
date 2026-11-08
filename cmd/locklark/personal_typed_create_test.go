package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func typedCreateFixture(t *testing.T, document string) (vaultPath, inputPath string, pw, key []byte) {
	t.Helper()
	dir := t.TempDir()
	vaultPath = filepath.Join(dir, "two-factor.ll")
	inputPath = filepath.Join(dir, "item.json")
	pw = []byte("two-factor-master")
	key = bytes.Repeat([]byte{0x5a}, 16)
	if err := personal.Create(vaultPath, string(pw), key); err != nil {
		t.Fatalf("create fixture vault: %v", err)
	}
	writePrivateTypedFixture(t, inputPath, []byte(document))
	return vaultPath, inputPath, pw, key
}

func typedCreateActiveCount(t *testing.T, path string, pw, key []byte) int {
	t.Helper()
	rows, err := personal.ListState(path, string(pw), key, "all")
	if err != nil {
		t.Fatalf("list vault after add-item: %v", err)
	}
	return len(rows)
}

const typedCreateIdentityDocument = `{
	"category": "identity",
	"title": "Typed identity private title",
	"username": "typed-username-secret",
	"password": "typed-password-secret",
	"identity": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.test", "country": "GB"},
	"sections": [{"id": "api", "title": "API", "fields": [
		{"id": "token", "label": "Token", "type": "concealed", "value": "concealed-token-secret"},
		{"id": "owner", "label": "Owner", "value": "owner-visible"}
	]}]
}`

func TestCreateTypedPersonalWritesIdentityAndConcealedSection(t *testing.T) {
	vaultPath, inputPath, pw, key := typedCreateFixture(t, typedCreateIdentityDocument)
	questions := 0
	var prompt bytes.Buffer
	response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(question string) ([]byte, error) {
		questions++
		if question != "输入 SAVE 确认新增条目" {
			t.Fatalf("unexpected consent prompt %q", question)
		}
		return []byte("SAVE"), nil
	}, &prompt)
	if err != nil {
		t.Fatalf("create typed item: %v", err)
	}
	if questions != 1 {
		t.Fatalf("expected exactly one consent prompt, got %d", questions)
	}
	if len(response) != 3 || response["status"] != "created" || response["id"] == "" || response["revision"] == "" {
		t.Fatalf("receipt must contain only status/id/revision: %+v", response)
	}
	receipt, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	for _, secret := range []string{"concealed-token-secret", "typed-password-secret", "typed-username-secret", "Typed identity private title", "owner-visible"} {
		if bytes.Contains(receipt, []byte(secret)) {
			t.Fatalf("receipt echoed item data %q: %s", secret, receipt)
		}
		if bytes.Contains(prompt.Bytes(), []byte(secret)) {
			t.Fatalf("confirmation prompt echoed item data %q: %s", secret, prompt.String())
		}
	}
	if !bytes.Contains(prompt.Bytes(), []byte("identity")) || !bytes.Contains(prompt.Bytes(), []byte("1 个分区")) || !bytes.Contains(prompt.Bytes(), []byte("2 个自定义字段")) {
		t.Fatalf("confirmation did not show category and field counts: %s", prompt.String())
	}

	session, err := personal.UnlockSession(vaultPath, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("reopen encrypted vault: %v", err)
	}
	defer session.Lock()
	detail, err := session.GetItemDetail(response["id"], response["revision"], true)
	if err != nil {
		t.Fatalf("read created item detail: %v", err)
	}
	if detail.Category != vault.CategoryIdentity || detail.Identity == nil || detail.Identity.FirstName != "Ada" || detail.Identity.Country != "GB" {
		t.Fatalf("identity was not persisted: %+v", detail)
	}
	if detail.Username != "typed-username-secret" || detail.Password != "typed-password-secret" {
		t.Fatalf("credential fields were not persisted: %+v", detail)
	}
	if len(detail.Sections) != 1 || len(detail.Sections[0].Fields) != 2 {
		t.Fatalf("section was not persisted: %+v", detail.Sections)
	}
	concealed := detail.Sections[0].Fields[0]
	if concealed.ID != "token" || concealed.Value != "concealed-token-secret" || concealed.Type != vault.FieldTypeConcealed || !concealed.Protected {
		t.Fatalf("concealed field was not persisted: %+v", concealed)
	}

	index, err := personal.References(vaultPath, string(pw), key)
	if err != nil {
		t.Fatalf("read references: %v", err)
	}
	if len(index.Items) != 1 {
		t.Fatalf("expected one active reference row, got %+v", index.Items)
	}
	ref := index.Items[0].References["api/token"]
	if !strings.HasPrefix(ref, "op://") || !strings.HasSuffix(ref, "/api/token") {
		t.Fatalf("concealed section field reference missing: %+v", index.Items[0].References)
	}
}

func TestCreateTypedPersonalWrongConsentAndBadFactorsDoNotMutate(t *testing.T) {
	t.Run("wrong-save", func(t *testing.T) {
		vaultPath, inputPath, pw, key := typedCreateFixture(t, typedCreateIdentityDocument)
		response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
			return []byte("NOPE"), nil
		}, &bytes.Buffer{})
		if !errors.Is(err, errTypedCreateCancelled) || response != nil {
			t.Fatalf("wrong consent must cancel with the fixed error: response=%+v err=%v", response, err)
		}
		if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
			t.Fatalf("wrong consent mutated the vault: %d items", count)
		}
	})

	for _, tc := range []struct {
		name string
		pw   []byte
		key  []byte
	}{
		{"bad-password", []byte("wrong-master-password"), nil},
		{"bad-key", nil, bytes.Repeat([]byte{0x11}, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vaultPath, inputPath, pw, key := typedCreateFixture(t, typedCreateIdentityDocument)
			factorPW, factorKey := tc.pw, tc.key
			if factorPW == nil {
				factorPW = pw
			}
			if factorKey == nil {
				factorKey = key
			}
			asked := 0
			_, err := createTypedPersonal(vaultPath, inputPath, factorPW, factorKey, func(string) ([]byte, error) {
				asked++
				return []byte("SAVE"), nil
			}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("bad factors unexpectedly unlocked the vault")
			}
			if asked != 0 {
				t.Fatalf("bad factors reached consent prompt %d times", asked)
			}
			if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
				t.Fatalf("bad factors mutated the vault: %d items", count)
			}
		})
	}
}

func TestAddItemCLIArgumentAndTerminalBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"add-item", "--file", "vault.ll"},
		{"add-item", "--file", "vault.ll", "--input", ""},
		{"add-item", "--file", "", "--input", "item.json"},
		{"add-item", "--file", "vault.ll", "--input", "item.json", "--extra", "value"},
		{"add-item", "--file", "vault.ll", "--input", "item.json", "--input", "other.json"},
	} {
		if err := runPersonal(args, &bytes.Buffer{}); err != personalUsage {
			t.Fatalf("invalid add-item shape accepted: %v args=%v", err, args)
		}
	}
	var out bytes.Buffer
	err := runPersonal([]string{"add-item", "--file", "unused.ll", "--input", "unused.json"}, &out)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") || out.Len() != 0 {
		t.Fatalf("add-item did not stop at the terminal boundary: err=%v out=%q", err, out.String())
	}
}
