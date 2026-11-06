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

func TestMixedSSHKeyAndPasskeyVaultRoundTripAndKDBX(t *testing.T) {
	seed := bytes.Repeat([]byte{72}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		t.Fatal("SSH fixture")
	}
	request, e := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"user"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if e != nil {
		t.Fatal("passkey fixture")
	}
	raw, _, e := passkey.Create(request, false)
	if e != nil {
		t.Fatal("passkey fixture")
	}
	defer clear(raw)
	mixed := []Item{
		{ID: "ssh-1", Kind: "ssh-key", Title: "SSH Key", SSHSeed: seed, SSHPublicKey: public.Marshal()},
		{ID: "login-1", Kind: "login", Title: "Passkey Login", Username: "alice", URL: "https://example.test", Passkey: raw},
	}
	if e = ValidateItems([]byte("meta"), mixed); e != nil {
		t.Fatal("mixed vault validation", e)
	}
	identity, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal("identity")
	}
	snapshot, e := SealItems([]byte("meta"), mixed, 1, []*age.X25519Recipient{identity.Recipient()}, private)
	if e != nil {
		t.Fatal("mixed vault seal", e)
	}
	_, got, e := OpenItems(snapshot, identity, private.Public().(ed25519.PublicKey), 1)
	if e != nil || !reflect.DeepEqual(got, mixed) {
		t.Fatal("mixed vault encrypted round trip", e)
	}
	rawDB, e := ExportKDBX(mixed, "export-password")
	if e != nil {
		t.Fatal("mixed vault export", e)
	}
	db := kdbx.NewDatabase()
	db.Credentials = kdbx.NewPasswordCredentials("export-password")
	if e = kdbx.NewDecoder(bytes.NewReader(rawDB)).Decode(db); e != nil {
		t.Fatal("mixed export decode", e)
	}
	if e = db.UnlockProtectedEntries(); e != nil {
		t.Fatal("mixed export decrypt", e)
	}
	if len(db.Content.Root.Groups) != 1 || len(db.Content.Root.Groups[0].Entries) != 2 {
		t.Fatal("mixed export schema")
	}
	foundSeed, foundPasskey := false, false
	for _, entry := range db.Content.Root.Groups[0].Entries {
		for _, v := range entry.Values {
			switch v.Key {
			case "Locklark.SSHSeed":
				decoded, err := base64.StdEncoding.Strict().DecodeString(v.Value.Content)
				if err != nil || !v.Value.Protected.Bool || !bytes.Equal(decoded, seed) {
					t.Fatal("export lost protected SSH seed")
				}
				foundSeed = true
			case "Locklark.Passkey":
				decoded, err := base64.StdEncoding.Strict().DecodeString(v.Value.Content)
				if err != nil || !v.Value.Protected.Bool || !bytes.Equal(decoded, raw) {
					t.Fatal("export lost protected passkey")
				}
				foundPasskey = true
			}
		}
	}
	if !foundSeed || !foundPasskey {
		t.Fatal("mixed export omitted SSH or passkey material")
	}
}
