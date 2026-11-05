package vault

import (
	"bytes"
	"encoding/json"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"testing"
)

func TestNativeWebsite(t *testing.T) {
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	if err := writeItems(db, nil, []Item{{ID: "site", Kind: "login", URL: "https://example.com/login"}}); err != nil {
		t.Fatal(err)
	}
	group := db.Content.Root.Groups[0]
	_, items, err := readItems(db, group)
	if err != nil || len(items) != 1 || items[0].URL != "https://example.com/login" {
		t.Fatal("URL roundtrip", err)
	}
	for _, v := range []kdbx.ValueData{slot("URL", "https://example.com", false), slot("URL", "", true), slot("URL", "https://example.com?token=value", true)} {
		group.Entries[1].Values[3] = v
		if _, _, err := readItems(db, group); err == nil {
			t.Fatal("unsupported URL accepted")
		}
	}
	raw, err := json.Marshal(Item{ID: "legacy", Kind: "login"})
	if err != nil || bytes.Contains(raw, []byte("URL")) {
		t.Fatal("legacy backup encoding changed", err)
	}
	if ValidateItems(nil, []Item{{ID: "doc", Kind: "document", Filename: "example", URL: "https://example.com"}}) == nil {
		t.Fatal("document URL accepted")
	}
}
