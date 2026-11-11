package vault

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// TestVaultfileKDBXPayloadItemsRoundTrip exercises the public
// vaultfile.SealKDBXPayload / OpenKDBXPayload pair on the production item
// layout: native items written by writeItems, sealed from the natural
// unlocked state without prelocking, then opened under the CEK and read back
// with readItems.
func TestVaultfileKDBXPayloadItemsRoundTrip(t *testing.T) {
	metadata := []byte(`{"layout":"fixture","note":"\u0000\u00ff"}`)
	attachment := []byte{'a', 0x00, 0xff, 'b', 0xc3, 0x28, 0x00}
	items := []Item{
		{
			ID: "login", Kind: "login", Title: "Example login",
			URL: "https://example.com/login", Username: "synthetic-user",
			Password: "synthetic-password", OTP: "otpauth://totp/example?secret=AAAA",
		},
		{
			ID: "document", Kind: "document", Title: "Binary document",
			Filename: "fixture.bin", Attachment: attachment, AttachmentProtected: true,
		},
	}
	if err := ValidateItems(metadata, items); err != nil {
		t.Fatalf("fixture items are invalid: %v", err)
	}

	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	prior := kdbx.NewPasswordCredentials("prior password")
	db.Credentials = prior
	if err := writeItems(db, metadata, items); err != nil {
		t.Fatal(err)
	}
	// writeItems leaves protected values in plaintext. The public Seal API
	// owns locking, so the database is not prelocked here.
	for _, e := range db.Content.Root.Groups[0].Entries {
		for _, v := range e.Values {
			if v.Key == "Password" && v.Value.Content != items[0].Password {
				t.Fatal("writeItems did not leave protected values unlocked")
			}
		}
	}

	cek := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	cekCopy := bytes.Clone(cek)
	sealed, err := vaultfile.SealKDBXPayload(db, cek)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if db.Credentials != prior {
		t.Fatal("Seal did not restore the prior credentials pointer")
	}
	if len(sealed) == 0 || int64(len(sealed)) > vaultfile.MaxKDBXCiphertextBytes {
		t.Fatalf("sealed payload has %d bytes", len(sealed))
	}
	if !bytes.Equal(cek, cekCopy) {
		t.Fatal("Seal modified the caller's CEK")
	}
	if bytes.Contains(sealed, attachment) || bytes.Contains(sealed, []byte(items[0].Password)) {
		t.Fatal("sealed payload carries plaintext item data or binary bytes")
	}

	wrong := bytes.Clone(cek)
	wrong[0] ^= 0x01
	if got, err := vaultfile.OpenKDBXPayload(sealed, wrong); err == nil || got != nil {
		t.Fatal("payload opened under a wrong CEK")
	}

	opened, err := vaultfile.OpenKDBXPayload(sealed, cek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Content == nil || opened.Content.Root == nil || len(opened.Content.Root.Groups) != 1 {
		t.Fatal("opened database has no single item group")
	}
	gotMetadata, gotItems, err := readItems(opened, opened.Content.Root.Groups[0])
	if err != nil {
		t.Fatalf("readItems: %v", err)
	}
	if !bytes.Equal(gotMetadata, metadata) {
		t.Fatalf("metadata = %q, want %q", gotMetadata, metadata)
	}
	if len(gotItems) != len(items) {
		t.Fatalf("read %d items, want %d", len(gotItems), len(items))
	}
	login, doc := gotItems[0], gotItems[1]
	if login.ID != "login" || login.Title != items[0].Title || login.URL != items[0].URL ||
		login.Username != items[0].Username || login.Password != items[0].Password ||
		login.OTP != items[0].OTP || login.Attachment != nil {
		t.Fatalf("login item changed: %+v", login)
	}
	if doc.ID != "document" || doc.Title != items[1].Title || doc.Filename != "fixture.bin" ||
		!bytes.Equal(doc.Attachment, attachment) || !doc.AttachmentProtected {
		t.Fatalf("document item changed: %+v", doc)
	}

	// Open never returns the CEK or any other credential with the database.
	if c := opened.Credentials; c == nil || c.Passphrase != nil || c.Key != nil || c.Windows != nil {
		t.Fatal("opened database retains credentials")
	}
}
