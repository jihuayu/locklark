package vault

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

func TestLoginNotesProtectedRoundtripAndLegacyOmission(t *testing.T) {
	notes := " first\r\nsecond\n\t备注🙂  "
	for _, body := range []string{"", notes, strings.Repeat("x", MaxNotes)} {
		item := Item{ID: "login", Kind: "login", Notes: body}
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if e := writeItems(db, []byte("metadata"), []Item{item}); e != nil {
			t.Fatal(e)
		}
		present := false
		for _, v := range db.Content.Root.Groups[0].Entries[1].Values {
			if v.Key == "Notes" {
				present = true
				if !v.Value.Protected.Bool || v.Value.Content != body {
					t.Fatal("notes not protected or preserved")
				}
			}
		}
		if present != (body != "") {
			t.Fatal("empty notes changed old KDBX schema")
		}
		_, items, e := readItems(db, db.Content.Root.Groups[0])
		if e != nil || !reflect.DeepEqual(items, []Item{item}) {
			t.Fatal("notes read was lossy")
		}
	}
	raw, _ := json.Marshal(Item{ID: "old", Kind: "login"})
	if bytes.Contains(raw, []byte("Notes")) {
		t.Fatal("empty notes changed old item digest")
	}
}

func TestLoginNotesValidationAndProtectedReader(t *testing.T) {
	for _, notes := range []string{strings.Repeat("x", MaxNotes+1), "nul\x00value", "\xff", "\ufffe", "\x01"} {
		if ValidNotes(notes) || ValidateItems(nil, []Item{{ID: "login", Kind: "login", Notes: notes}}) == nil {
			t.Fatal("invalid notes accepted")
		}
	}
	if ValidateItems(nil, []Item{{ID: "doc", Kind: "document", Filename: "file", Notes: "not a login"}}) == nil {
		t.Fatal("document notes accepted")
	}
	for _, alter := range []func(*kdbx.Entry){
		func(e *kdbx.Entry) { e.Values = append(e.Values, slot("Notes", "value", false)) },
		func(e *kdbx.Entry) { e.Values = append(e.Values, slot("Notes", strings.Repeat("x", MaxNotes+1), true)) },
		func(e *kdbx.Entry) { e.Values = append(e.Values, slot("Notes", "", true)) },
		func(e *kdbx.Entry) {
			e.Values = append(e.Values, slot("Notes", "value", true), slot("Notes", "other", true))
		},
	} {
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if e := writeItems(db, nil, []Item{{ID: "login", Kind: "login"}}); e != nil {
			t.Fatal(e)
		}
		g := db.Content.Root.Groups[0]
		alter(&g.Entries[1])
		if _, _, e := readItems(db, g); e == nil {
			t.Fatal("unsupported Notes field accepted")
		}
	}
}
