package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

func testPasskeyRecord(t *testing.T) []byte {
	t.Helper()
	req, err := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"user"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if err != nil {
		t.Fatal("passkey fixture", err)
	}
	raw, _, err := passkey.Create(req, false)
	if err != nil || !passkey.ValidRecord(raw) {
		t.Fatal("passkey fixture", err)
	}
	return raw
}

func TestPasskeyCollectionKDBXAndEncryptedRoundTrip(t *testing.T) {
	a, b := testPasskeyRecord(t), testPasskeyRecord(t)
	item := Item{ID: "login-1", Kind: "login", Title: "Multi", Passkeys: [][]byte{a, b}}
	legacy := Item{ID: "old", Kind: "login", Title: "Legacy", Passkey: a}
	if err := ValidateItems(nil, []Item{item, legacy}); err != nil {
		t.Fatal("valid collection refused", err)
	}
	if err := ValidateItems(nil, []Item{{ID: "one", Kind: "login", Passkeys: [][]byte{b}}}); err != nil {
		t.Fatal("single-record collection refused", err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	snap, err := SealItems(nil, []Item{item, legacy}, 1, []*age.X25519Recipient{identity.Recipient()}, signer)
	if err != nil {
		t.Fatal("seal", err)
	}
	_, got, err := OpenItems(snap, identity, signer.Public().(ed25519.PublicKey), 1)
	if err != nil || len(got) != 2 || len(got[0].Passkeys) != 2 || !bytes.Equal(got[0].Passkeys[1], b) || !bytes.Equal(got[1].Passkey, a) {
		t.Fatal("encrypted round trip", err)
	}
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	if err = writeItems(db, nil, []Item{item, legacy}); err != nil {
		t.Fatal(err)
	}
	g := db.Content.Root.Groups[0]
	_, items, err := readItems(db, g)
	if err != nil || len(items) != 2 || len(items[0].Passkeys) != 2 || !bytes.Equal(items[0].Passkeys[0], a) {
		t.Fatal("kdbx round trip", err)
	}
	slotIdx := -1
	for n, v := range g.Entries[1].Values {
		if v.Key == itemPasskeysSlot {
			slotIdx = n
			if !v.Value.Protected.Bool {
				t.Fatal("unprotected collection")
			}
			raw, dec := base64.StdEncoding.Strict().DecodeString(v.Value.Content)
			var env itemPasskeyCollection
			if dec != nil || json.Unmarshal(raw, &env) != nil || env.Version != 1 || len(env.Records) != 2 {
				t.Fatal("non-canonical envelope")
			}
		}
	}
	for _, v := range g.Entries[2].Values {
		if v.Key == itemPasskeysSlot {
			t.Fatal("collection written for legacy-only item")
		}
	}
	if slotIdx < 0 {
		t.Fatal("missing collection slot")
	}
	g.Entries[1].Values = append(g.Entries[1].Values, slot("Locklark.PasskeysNext", "x", true))
	if _, _, err = readItems(db, g); err == nil {
		t.Fatal("accepted unknown protected slot")
	}
	g.Entries[1].Values = g.Entries[1].Values[:len(g.Entries[1].Values)-1]
	g.Entries[1].Values[slotIdx].Value.Protected.Bool = false
	if _, _, err = readItems(db, g); err == nil {
		t.Fatal("accepted unprotected collection")
	}
	plain, _ := json.Marshal(Item{ID: "old", Kind: "login"})
	if bytes.Contains(plain, []byte("Passkeys")) || bytes.Contains(plain, []byte("Passkey")) {
		t.Fatal("legacy digest changed")
	}
}

func TestPasskeyCollectionStrictValidationAndClone(t *testing.T) {
	a, b := testPasskeyRecord(t), testPasskeyRecord(t)
	enc := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	envelope := func(v int, recs [][]byte) []byte {
		raw, err := json.Marshal(itemPasskeyCollection{Version: v, Records: recs})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if recs, err := decodePasskeyCollection(enc(envelope(1, [][]byte{a, b}))); err != nil || len(recs) != 2 {
		t.Fatal("canonical collection refused", err)
	}
	unknown := map[string]any{}
	if json.Unmarshal(envelope(1, [][]byte{a}), &unknown) != nil {
		t.Fatal("envelope")
	}
	unknown["extra"] = true
	unknownRaw, _ := json.Marshal(unknown)
	bad := map[string]string{
		"version":   enc(envelope(2, [][]byte{a})),
		"trailing":  enc(append(envelope(1, [][]byte{a}), '{', '}')),
		"unknown":   enc(unknownRaw),
		"duplicate": enc(envelope(1, [][]byte{a, a})),
		"empty":     enc(envelope(1, nil)),
		"nonb64":    "!!!",
	}
	for name, content := range bad {
		if _, err := decodePasskeyCollection(content); err == nil {
			t.Fatal("accepted invalid collection", name)
		}
	}
	if ValidateItems(nil, []Item{{ID: "mixed", Kind: "login", Passkey: a, Passkeys: [][]byte{b}}}) == nil {
		t.Fatal("accepted mixed legacy and collection forms")
	}
	if ValidateItems(nil, []Item{{ID: "doc", Kind: "document", Filename: "a.txt", Passkeys: [][]byte{a}}}) == nil {
		t.Fatal("accepted non-login collection")
	}
	if ValidateItems(nil, []Item{{ID: "dup", Kind: "login", Passkeys: [][]byte{a, a}}}) == nil {
		t.Fatal("accepted duplicate credential")
	}
	seventeen := make([][]byte, 0, MaxPasskeys+1)
	for i := 0; i <= MaxPasskeys; i++ {
		seventeen = append(seventeen, testPasskeyRecord(t))
	}
	if ValidateItems(nil, []Item{{ID: "big", Kind: "login", Passkeys: seventeen}}) == nil {
		t.Fatal("accepted oversized collection")
	}

	src := Item{ID: "c", Kind: "login", Passkeys: [][]byte{a, b}}
	cp := CloneItem(src)
	cp.Passkeys[0][0] ^= 0xff
	if bytes.Equal(cp.Passkeys[0], src.Passkeys[0]) || !bytes.Equal(src.Passkeys[1], b) {
		t.Fatal("clone shares passkey buffers")
	}
	if recs := src.PasskeyRecords(); len(recs) != 2 || &recs[1][0] != &src.Passkeys[1][0] {
		t.Fatal("PasskeyRecords must borrow native slices")
	}
	if recs := (Item{Passkey: a}).PasskeyRecords(); len(recs) != 1 || &recs[0][0] != &a[0] {
		t.Fatal("legacy borrow")
	}
	c := testPasskeyRecord(t)
	var target Item
	if err := target.SetPasskeyRecords([][]byte{c}); err != nil {
		t.Fatal(err)
	}
	c[0] ^= 0xff
	if bytes.Equal(target.Passkeys[0], c) {
		t.Fatal("setter did not deep copy")
	}
	buf := target.Passkeys[0]
	target.Passkey = a
	target.ClearPasskeys()
	if target.Passkeys != nil || target.Passkey != nil || !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatal("clear left passkey bytes")
	}
}
