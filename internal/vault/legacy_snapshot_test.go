package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// legacyControlText is valid UTF-8 but not KDBX/XML plain text.
const legacyControlText = "ctrl\x01\x02\ttext"

// pastSealItems seals items with the validation the previous release applied,
// which let control characters inside the JSON-only v2 values reach KDBX. It
// also returns the plaintext database so the fixture can be checked.
func pastSealItems(t *testing.T, metadata []byte, items []Item, epoch uint64, recipients []*age.X25519Recipient, signer ed25519.PrivateKey) (Snapshot, *kdbx.Database) {
	t.Helper()
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters.UUID = kdbx.KdfArgon2id
	db.Header.FileHeaders.KdfParameters.Memory = 16 << 20
	db.Header.FileHeaders.KdfParameters.Iterations = 3
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	creds, err := kdbx.NewKeyDataCredentials(key)
	if err != nil {
		t.Fatal(err)
	}
	db.Credentials = creds
	if err := writeItems(db, metadata, items); err != nil {
		t.Fatal(err)
	}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	var data, env bytes.Buffer
	if err := kdbx.NewEncoder(&data).Encode(db); err != nil {
		t.Fatal(err)
	}
	allowed := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		allowed = append(allowed, r)
	}
	w, err := age.Encrypt(&env, allowed...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(key); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Epoch: epoch, Database: data.Bytes(), Envelope: env.Bytes()}
	s.Signature = ed25519.Sign(signer, s.signed())
	return s, db
}

func legacyControlItem(id, kind string) Item {
	it := Item{
		ID:         id,
		Kind:       kind,
		Title:      "Legacy",
		Username:   "user",
		Password:   "pw",
		URLs:       []ItemURL{{URL: "https://legacy.example.test", MatchMode: "host"}},
		Sections:   []ItemSection{{ID: "s1", Title: "Section", Fields: []CustomField{{ID: "f1", Label: "Field", Type: FieldTypeText, Value: legacyControlText}}}},
		CreditCard: &CreditCardDetails{CardholderName: legacyControlText, Number: "4111111111111111"},
		Identity:   &IdentityDetails{Title: "Dr", FirstName: legacyControlText, Email: "a@example.test"},
		History: []ItemHistoryEntry{{
			Timestamp: 1700000000,
			Action:    "edit",
			Title:     legacyControlText,
			Notes:     legacyControlText,
			Sections:  []ItemSection{{ID: "h1", Title: "Old", Fields: []CustomField{{ID: "hf1", Label: "Old field", Type: FieldTypeText, Value: legacyControlText}}}},
		}},
	}
	if kind != "login" {
		// Only login items may carry URLs.
		it.URLs, it.Username, it.Password = nil, "", ""
	}
	return it
}

func TestLegacySnapshotControlCharactersReadable(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	want := legacyControlItem("legacy-ctrl", "login")
	snapshot, db := pastSealItems(t, []byte("legacy"), []Item{want}, 1, []*age.X25519Recipient{device.Recipient()}, signer)

	// Sanity-check that the legacy blob really carries the control characters
	// inside the JSON v2 envelope.
	raw, err := base64.StdEncoding.DecodeString(legacyV2Slot(t, db, "legacy-ctrl"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope itemV2Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`\u0001`)) {
		t.Fatal("legacy fixture lost its serialized control characters")
	}
	if envelope.Sections[0].Fields[0].Value != legacyControlText || envelope.CreditCard.CardholderName != legacyControlText || envelope.Identity.FirstName != legacyControlText || envelope.History[0].Title != legacyControlText || envelope.History[0].Sections[0].Fields[0].Value != legacyControlText {
		t.Fatal("legacy fixture lost its control characters")
	}

	metadata, got, err := OpenItems(snapshot, device, pub, 1)
	if err != nil {
		t.Fatalf("legacy snapshot rejected: %v", err)
	}
	if string(metadata) != "legacy" || len(got) != 1 {
		t.Fatalf("unexpected legacy read %q %d", metadata, len(got))
	}
	if g := got[0]; g.Sections[0].Fields[0].Value != legacyControlText || g.CreditCard.CardholderName != legacyControlText || g.Identity.FirstName != legacyControlText || g.History[0].Title != legacyControlText || g.History[0].Notes != legacyControlText || g.History[0].Sections[0].Fields[0].Value != legacyControlText {
		t.Fatalf("legacy control characters not preserved: %+v", g)
	}
}

func TestNewWriteRejectsControlCharacters(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Item){
		"section value": func(it *Item) {
			it.Sections = []ItemSection{{ID: "s1", Title: "S", Fields: []CustomField{{ID: "f1", Label: "F", Type: FieldTypeText, Value: legacyControlText}}}}
		},
		"credit card": func(it *Item) { it.CreditCard = &CreditCardDetails{CardholderName: legacyControlText} },
		"identity":    func(it *Item) { it.Identity = &IdentityDetails{FirstName: legacyControlText} },
		"history title": func(it *Item) {
			it.History = []ItemHistoryEntry{{Timestamp: 1, Action: "edit", Title: legacyControlText}}
		},
		"history notes": func(it *Item) {
			it.History = []ItemHistoryEntry{{Timestamp: 1, Action: "edit", Notes: legacyControlText}}
		},
		"history section": func(it *Item) {
			it.History = []ItemHistoryEntry{{Timestamp: 1, Action: "edit", Sections: []ItemSection{{ID: "h1", Title: "H", Fields: []CustomField{{ID: "hf1", Label: "F", Type: FieldTypeText, Value: legacyControlText}}}}}}
		},
		"direct XML notes": func(it *Item) { it.Notes = legacyControlText },
		"direct XML title": func(it *Item) { it.Title = legacyControlText },
		"direct XML url ": func(it *Item) {
			it.URLs = []ItemURL{{URL: "https://example.test", MatchMode: "host", Label: legacyControlText}}
		},
		"invalid UTF-8": func(it *Item) {
			it.Sections = []ItemSection{{ID: "s1", Title: "S", Fields: []CustomField{{ID: "f1", Label: "F", Type: FieldTypeText, Value: "\xff"}}}}
		},
	}
	for name, mutate := range bad {
		it := Item{ID: "strict", Kind: "login", Title: "Strict", Username: "u", Password: "p"}
		mutate(&it)

		if err := ValidateItems(nil, []Item{it}); !errors.Is(err, ErrSnapshot) {
			t.Fatalf("%s: ValidateItems = %v, want ErrSnapshot", name, err)
		}
		if _, err := SealItems([]byte("new"), []Item{it}, 1, []*age.X25519Recipient{device.Recipient()}, signer); !errors.Is(err, ErrSnapshot) {
			t.Fatalf("%s: SealItems = %v, want ErrSnapshot", name, err)
		}
		// The read-mode validator must not relax the JSON-only field rule for
		// anything other than valid UTF-8: invalid bytes stay rejected.
		if name == "invalid UTF-8" && validLegacyItems([]Item{it}, 0) {
			t.Fatalf("%s: legacy validator accepted invalid UTF-8", name)
		}
	}
	// Invalid UTF-8 in direct XML fields is rejected on the read path as well.
	if validLegacyItems([]Item{{ID: "x", Kind: "login", Title: "\xff"}}, 0) {
		t.Fatal("legacy validator accepted invalid UTF-8 in XML text")
	}
}

// legacyV2Slot reads a protected v2 slot from the fixture's plaintext database.
func legacyV2Slot(t *testing.T, db *kdbx.Database, id string) string {
	t.Helper()
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	for _, e := range db.Content.Root.Groups[0].Entries {
		if e.GetContent("Locklark.ID") == id {
			return e.GetContent(itemV2Slot)
		}
	}
	t.Fatalf("fixture database has no item %q", id)
	return ""
}
