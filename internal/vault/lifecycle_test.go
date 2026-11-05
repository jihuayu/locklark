package vault

import (
	"bytes"
	"encoding/json"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"testing"
)

func TestNativeArchiveState(t *testing.T) {
	for _, kind := range []string{"login", "document"} {
		item := Item{ID: kind, Kind: kind, Title: "same", State: "archived"}
		if kind == "document" {
			item.Filename = "example.bin"
			item.Attachment = []byte{0, 255}
		}
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if err := writeItems(db, nil, []Item{item}); err != nil {
			t.Fatal(err)
		}
		_, got, err := readItems(db, db.Content.Root.Groups[0])
		if err != nil || len(got) != 1 || got[0].State != "archived" {
			t.Fatal("state roundtrip", err)
		}
		for _, bad := range []string{"active", "deleted", ""} {
			db.Content.Root.Groups[0].Entries[1].Values[3] = slot("Locklark.State", bad, false)
			if _, _, err := readItems(db, db.Content.Root.Groups[0]); err == nil {
				t.Fatal("unsupported stored state", bad)
			}
		}
	}
	if ValidateItems(nil, []Item{{ID: "a", Kind: "login", State: "active"}}) == nil {
		t.Fatal("noncanonical active")
	}
	raw, err := json.Marshal(Item{ID: "a", Kind: "login"})
	if err != nil || bytes.Contains(raw, []byte("State")) {
		t.Fatal("legacy backup serialization changed", err)
	}
}
