package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"golang.org/x/crypto/ssh"
)

func TestSSHKeyProtectedSeedRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{71}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal("public key")
	}
	raw, _ := json.Marshal(map[string]any{"ID": "ssh-key", "Kind": "ssh-key", "Title": "test key", "SSHSeed": seed, "SSHPublicKey": public.Marshal()})
	var item Item
	if json.Unmarshal(raw, &item) != nil {
		t.Fatal("item input")
	}
	if err := ValidateItems(nil, []Item{item}); err != nil {
		t.Fatal("explicit SSH key schema is missing")
	}
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	if writeItems(db, []byte("metadata"), []Item{item}) != nil {
		t.Fatal("SSH write")
	}
	found := false
	for _, v := range db.Content.Root.Groups[0].Entries[1].Values {
		if v.Key == "Locklark.SSHSeed" {
			found = v.Value.Protected.Bool
		}
	}
	if !found {
		t.Fatal("seed is not a protected KDBX field")
	}
	_, got, err := readItems(db, db.Content.Root.Groups[0])
	if err != nil || !reflect.DeepEqual(got, []Item{item}) {
		t.Fatal("SSH protected round trip")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("identity")
	}
	snapshot, err := SealItems([]byte("metadata"), []Item{item}, 1, []*age.X25519Recipient{identity.Recipient()}, private)
	if err != nil {
		t.Fatal("SSH seal")
	}
	_, got, err = OpenItems(snapshot, identity, private.Public().(ed25519.PublicKey), 1)
	if err != nil || !reflect.DeepEqual(got, []Item{item}) {
		t.Fatal("encrypted SSH round trip")
	}
}

func TestSSHKeyRejectsHybridAndUnprotectedShapes(t *testing.T) {
	seed := bytes.Repeat([]byte{41}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		t.Fatal("SSH fixture")
	}
	base := Item{ID: "ssh", Kind: "ssh-key", Title: "key", SSHSeed: seed, SSHPublicKey: public.Marshal()}
	pkRequest, e := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"user"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if e != nil {
		t.Fatal("passkey fixture")
	}
	pkRaw, _, e := passkey.Create(pkRequest, false)
	if e != nil {
		t.Fatal("passkey fixture")
	}
	defer clear(pkRaw)
	for _, change := range []func(*Item){func(i *Item) { i.Kind = "login" }, func(i *Item) { i.Kind = "document"; i.Filename = "file" }, func(i *Item) { i.Password = "not a key" }, func(i *Item) { i.Username = "user" }, func(i *Item) { i.Notes = "notes" }, func(i *Item) { i.OTP = "seed" }, func(i *Item) { i.URL = "https://example.test" }, func(i *Item) { i.Attachment = []byte{1} }, func(i *Item) { i.ImportSource = []byte("old") }, func(i *Item) { i.SSHSeed = make([]byte, 31) }, func(i *Item) { i.SSHPublicKey = bytes.Repeat([]byte{1}, 51) }, func(i *Item) { i.Passkey = pkRaw }, func(i *Item) { i.Kind = "login"; i.Passkey = pkRaw }} {
		item := base
		change(&item)
		if ValidateItems(nil, []Item{item}) == nil {
			t.Fatal("hybrid or inconsistent SSH key accepted")
		}
	}
	for _, change := range []func(*kdbx.Entry){func(e *kdbx.Entry) {
		for n := range e.Values {
			if e.Values[n].Key == "Locklark.SSHSeed" {
				e.Values[n] = slot("Locklark.SSHSeed", base64.StdEncoding.EncodeToString(seed), false)
			}
		}
	}, func(e *kdbx.Entry) { e.Values = append(e.Values, slot("Password", "hybrid", true)) }, func(e *kdbx.Entry) {
		for n := range e.Values {
			if e.Values[n].Key == "Locklark.SSHPublicKey" {
				e.Values[n] = slot("Locklark.SSHPublicKey", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 51)), false)
			}
		}
	}} {
		db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
		if writeItems(db, nil, []Item{base}) != nil {
			t.Fatal("SSH fixture write")
		}
		group := db.Content.Root.Groups[0]
		change(&group.Entries[1])
		if _, _, e := readItems(db, group); e == nil {
			t.Fatal("unsupported SSH KDBX fields accepted")
		}
	}
}

func TestSSHKeyEncryptedExportPreservesProtectedSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{51}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		t.Fatal("SSH export fixture")
	}
	item := Item{ID: "ssh", Kind: "ssh-key", Title: "key", SSHSeed: seed, SSHPublicKey: public.Marshal()}
	const password = "independent export password"
	raw, e := ExportKDBX([]Item{item}, password)
	if e != nil {
		t.Fatal("SSH export")
	}
	db := kdbx.NewDatabase()
	db.Credentials = kdbx.NewPasswordCredentials(password)
	if kdbx.NewDecoder(bytes.NewReader(raw)).Decode(db) != nil || db.UnlockProtectedEntries() != nil {
		t.Fatal("SSH exported KDBX decrypt")
	}
	if len(db.Content.Root.Groups) != 1 || len(db.Content.Root.Groups[0].Entries) != 1 {
		t.Fatal("SSH export schema")
	}
	found := false
	for _, v := range db.Content.Root.Groups[0].Entries[0].Values {
		if v.Key == "Locklark.SSHSeed" {
			found = true
			decoded, e := base64.StdEncoding.Strict().DecodeString(v.Value.Content)
			if e != nil || !bytes.Equal(decoded, seed) || !v.Value.Protected.Bool {
				t.Fatal("SSH export lost protected seed")
			}
		}
	}
	if !found {
		t.Fatal("SSH seed omitted from encrypted export")
	}
}
