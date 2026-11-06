package vault

import (
	"bytes"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/passkey"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"testing"
)

func TestPasskeyProtectedKDBXAndLegacyOmission(t *testing.T) {
	r, e := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"user"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, _, e := passkey.Create(r, false)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	if e = writeItems(db, nil, []Item{{ID: "login", Kind: "login", Passkey: raw}}); e != nil {
		t.Fatal(e)
	}
	group := db.Content.Root.Groups[0]
	_, items, e := readItems(db, group)
	if e != nil || len(items) != 1 || !bytes.Equal(items[0].Passkey, raw) {
		t.Fatal("round trip", e)
	}
	found := false
	for n := range group.Entries[1].Values {
		v := &group.Entries[1].Values[n]
		if v.Key == "Locklark.Passkey" {
			found = true
			if !v.Value.Protected.Bool {
				t.Fatal("unprotected")
			}
			v.Value.Protected.Bool = false
		}
	}
	if !found {
		t.Fatal("missing field")
	}
	if _, _, e = readItems(db, group); e == nil {
		t.Fatal("accepted unprotected key")
	}
	legacy, _ := json.Marshal(Item{ID: "old", Kind: "login"})
	if bytes.Contains(legacy, []byte("Passkey")) {
		t.Fatal("changed legacy digest")
	}
	if ValidateItems(nil, []Item{{ID: "bad", Kind: "login", Passkey: []byte("invalid")}}) == nil {
		t.Fatal("malformed credential")
	}
}
