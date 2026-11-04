package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIndependentNativeEditor(t *testing.T) {
	python := os.Getenv("LOCKLARK_TEST_PYKEEPASS")
	if python == "" {
		t.Skip("set LOCKLARK_TEST_PYKEEPASS for independent reader/writer")
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	items := []Item{{ID: "login", Kind: "login", Title: "same", Password: "fixture password", OTP: "otpauth://totp/example?secret=AAAA"}, {ID: "doc", Kind: "document", Title: "same", Filename: "demo.bin", Attachment: []byte("QUJD")}}
	s, err := SealItems([]byte("layout"), items, 1, []*age.X25519Recipient{device.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := unwrap(s.Envelope, device)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "source.kdbx"), filepath.Join(dir, "peer.kdbx")
	if err = os.WriteFile(src, s.Database, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-I", "testdata/item_peer.py", src, dst)
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("peer: %v: %s", err, out)
	}
	s.Database, err = os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = OpenItems(s, device, pub, 1); err == nil {
		t.Fatal("unsigned edits accepted")
	}
	s.Signature = ed25519.Sign(signer, s.signed())
	meta, got, err := OpenItems(s, device, pub, 1)
	if err != nil || string(meta) != "layout" || len(got) != 2 {
		t.Fatal("could not read peer edits", err)
	}
	found := map[string]Item{}
	for _, it := range got {
		found[it.ID] = it
	}
	if found["login"].Title != "renamed via independent editor" || found["login"].Password != "changed fixture" || found["login"].OTP != "otpauth://totp/edited?secret=BBBB" || found["doc"].Title != "same" || found["doc"].Filename != "edited.bin" || string(found["doc"].Attachment) != "RUZH" {
		t.Fatal("peer changes lost or applied to the wrong item")
	}
}

func TestNativeRejectsLossyReads(t *testing.T) {
	for name, alter := range map[string]func(*kdbx.Entry){
		"password no longer protected":              func(e *kdbx.Entry) { e.Values[3].Value.Protected.Bool = false },
		"protected title would lose its protection": func(e *kdbx.Entry) { e.Values[0].Value.Protected.Bool = true },
		"extra field would be lost":                 func(e *kdbx.Entry) { e.Values = append(e.Values, slot("Custom", "data", true)) },
		"duplicate field":                           func(e *kdbx.Entry) { e.Values = append(e.Values, e.Values[3]) },
		"mismatched source ID":                      func(e *kdbx.Entry) { e.Values[1].Value.Content = "another-id" },
	} {
		t.Run(name, func(t *testing.T) {
			db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
			if err := writeItems(db, nil, []Item{{ID: "login", Kind: "login"}}); err != nil {
				t.Fatal(err)
			}
			g := db.Content.Root.Groups[0]
			alter(&g.Entries[1])
			if _, _, err := readItems(db, g); err == nil {
				t.Fatal("silently accepted unsupported mutation")
			}
		})
	}
}

func TestNativeItemsRoundTrip(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	items := []Item{{ID: "login", Kind: "login", Title: "same", Password: "fixture password", OTP: "otpauth://totp/example?secret=AAAA"}, {ID: "doc", Kind: "document", Title: "same", Filename: "demo.bin", Attachment: []byte{0, 255, 1}}}
	recipients := []*age.X25519Recipient{device.Recipient()}
	s, err := SealItems([]byte("layout"), items, 1, recipients, signer)
	if err != nil {
		t.Fatal(err)
	}
	metadata, got, err := OpenItems(s, device, pub, 1)
	if err != nil || string(metadata) != "layout" || len(got) != 2 || got[0].Password != items[0].Password || got[0].OTP != items[0].OTP || got[1].ID != "doc" || !bytes.Equal(got[1].Attachment, items[1].Attachment) {
		t.Fatal("native fields did not survive reopen", err)
	}
	if _, err = Open(s, device, pub, 1); err == nil {
		t.Fatal("legacy API discarded native items")
	}
	items[1].ID = items[0].ID
	if _, err := SealItems(nil, items, 2, recipients, signer); err == nil {
		t.Fatal("duplicate source item ID accepted")
	}
}
