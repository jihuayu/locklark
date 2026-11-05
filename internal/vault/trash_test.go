package vault

import (
	"bytes"
	"encoding/json"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"testing"
)

func TestNativeTrashState(t *testing.T) {
	for _, kind := range []string{"login", "document"} {
		for _, previous := range []string{"", "archived"} {
			it := Item{ID: kind, Kind: kind, State: "trashed", PreviousState: previous}
			if kind == "document" {
				it.Filename = "example.bin"
				it.Attachment = []byte{0, 255}
			}
			db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
			if err := writeItems(db, nil, []Item{it}); err != nil {
				t.Fatal(err)
			}
			_, items, err := readItems(db, db.Content.Root.Groups[0])
			if err != nil || len(items) != 1 || items[0].State != it.State || items[0].PreviousState != previous {
				t.Fatal("native trash roundtrip", err)
			}
		}
	}
	for _, it := range []Item{{ID: "bad", Kind: "login", PreviousState: "archived"}, {ID: "bad", Kind: "login", State: "archived", PreviousState: "archived"}, {ID: "bad", Kind: "login", State: "trashed", PreviousState: "active"}, {ID: "bad", Kind: "login", State: "trashed", PreviousState: "trashed"}} {
		if ValidateItems(nil, []Item{it}) == nil {
			t.Fatal("invalid trash combination")
		}
	}
	for _, value := range []kdbx.ValueData{slot("Locklark.PreviousState", "", false), slot("Locklark.PreviousState", "active", false), slot("Locklark.PreviousState", "archived", true)} {
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if err := writeItems(db, nil, []Item{{ID: "test", Kind: "login", State: "trashed", PreviousState: "archived"}}); err != nil {
			t.Fatal(err)
		}
		db.Content.Root.Groups[0].Entries[1].Values[4] = value
		if _, _, err := readItems(db, db.Content.Root.Groups[0]); err == nil {
			t.Fatal("invalid native previous state")
		}
	}
	raw, err := json.Marshal(Item{ID: "legacy", Kind: "login"})
	if err != nil || bytes.Contains(raw, []byte("PreviousState")) {
		t.Fatal("legacy backup encoding changed", err)
	}
}
