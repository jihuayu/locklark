package personal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/password"
)

func TestGeneratedPasswordEncryptedRoundTripAndAudit(t *testing.T) {
	secret, err := password.Generate(password.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	path, master, key := filepath.Join(t.TempDir(), "generated.ll"), "synthetic-master", bytes.Repeat([]byte{6}, 16)
	if err = Create(path, master, key); err != nil {
		t.Fatal(err)
	}
	id, err := AddLogin(path, master, key, "Generated synthetic login", "synthetic-user", secret.Value())
	if err != nil {
		t.Fatal(err)
	}
	items := readStoredItems(t, path, master, key)
	if len(items) != 1 || items[0].ID != id || items[0].Password != secret.Value() {
		t.Fatal("generated password did not survive encrypted reopen")
	}
	disk, err := os.ReadFile(path)
	if err != nil || bytes.Contains(disk, []byte(secret.Value())) {
		t.Fatal("generated password appeared in the database outside encryption", err)
	}
	events, err := Audit(path, master, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.add" && event.Item == id && event.Result == "succeeded" {
			found = true
		}
	}
	if !found {
		t.Fatal("generated login not present in the verified signed journal")
	}
	raw, err := json.Marshal([]any{events, secret, secret.Profile()})
	if err != nil || bytes.Contains(raw, []byte(secret.Value())) || bytes.Contains(raw, []byte("synthetic-user")) {
		t.Fatal("journal or ordinary serialization exposed generated value")
	}
}
