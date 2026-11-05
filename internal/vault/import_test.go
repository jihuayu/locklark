package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
)

func TestImportProvenanceNativeRoundtrip(t *testing.T) {
	device, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	items := []Item{{ID: "source", Kind: "login", Title: "title", Password: "new", ImportSource: []byte(`{"password":"old"}`)}}
	snapshot, e := SealItems([]byte("metadata"), items, 1, []*age.X25519Recipient{device.Recipient()}, priv)
	if e != nil {
		t.Fatal(e)
	}
	meta, got, e := OpenItems(snapshot, device, pub, 1)
	if e != nil || !reflect.DeepEqual(got, items) || !bytes.Equal(meta, []byte("metadata")) {
		t.Fatal("source provenance lost", e)
	}
	items[0].ImportSource = make([]byte, MaxPayload)
	if ValidateItems(nil, items) == nil {
		t.Fatal("provenance bypassed capacity")
	}
}

func TestImportProvenanceRejectsUnprotectedOrNoncanonicalField(t *testing.T) {
	for _, value := range []string{"", "not-base64", "e30=\n", "e31="} {
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if e := writeItems(db, nil, []Item{{ID: "source", Kind: "login", ImportSource: []byte("{}")}}); e != nil {
			t.Fatal(e)
		}
		group := db.Content.Root.Groups[0]
		for j := range group.Entries[1].Values {
			v := &group.Entries[1].Values[j]
			if v.Key == "Locklark.ImportSource" {
				v.Value.Content = value
			}
		}
		if _, _, e := readItems(db, group); e == nil {
			t.Fatal("invalid source encoding accepted")
		}
	}
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	if e := writeItems(db, nil, []Item{{ID: "source", Kind: "login", ImportSource: []byte("{}")}}); e != nil {
		t.Fatal(e)
	}
	group := db.Content.Root.Groups[0]
	for j := range group.Entries[1].Values {
		v := &group.Entries[1].Values[j]
		if v.Key == "Locklark.ImportSource" {
			v.Value.Protected = wrappers.NewBoolWrapper(false)
		}
	}
	if _, _, e := readItems(db, group); e == nil {
		t.Fatal("unprotected source accepted")
	}
}
