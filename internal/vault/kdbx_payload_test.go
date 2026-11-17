package vault

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

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
	attContent := []byte{'s', 'y', 'n', 0x00, 0xff, 't', 'h'}
	history := ItemHistoryEntry{
		Timestamp: 1_700_000_000, Action: "password-change",
		Title: "Example login (old)", Username: "synthetic-old-user",
		Password: "synthetic-old-password", Notes: "synthetic old notes",
		Sections: []ItemSection{{
			ID: "credentials", Title: "Credentials",
			Fields: []CustomField{{
				ID: "recovery-pin", Label: "Recovery PIN", Type: FieldTypeConcealed,
				Value: "4821", Protected: true,
			}},
		}},
	}
	att := AttachmentMeta{
		ID: "recovery-file", FileName: "recovery.txt", Size: int64(len(attContent)),
		MIMEType: "text/plain", SHA256: AttachmentSHA256(attContent),
		Protected: true, Content: attContent,
	}
	trashedAt := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	trashedUser, trashedPassword, trashedOTP := "synthetic-trashed-user", "synthetic-trashed-password", "otpauth://totp/trashed?secret=BBBB"
	items := []Item{
		{
			ID: "login", Kind: "login", Title: "Example login",
			URL: "https://example.com/login", Username: "synthetic-user",
			Password: "synthetic-password", OTP: "otpauth://totp/example?secret=AAAA",
			History: []ItemHistoryEntry{history}, Attachments: []AttachmentMeta{att},
		},
		{
			ID: "document", Kind: "document", Title: "Binary document",
			Filename: "fixture.bin", Attachment: attachment, AttachmentProtected: true,
		},
		{
			ID: "trashed-login", Kind: "login", Title: "Trashed login",
			Username: trashedUser, Password: trashedPassword, OTP: trashedOTP,
			State: "trashed", PreviousState: "archived", TrashedAt: &trashedAt,
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
		if e.UUID != itemUUID(items[0].ID) {
			continue
		}
		for _, v := range e.Values {
			switch v.Key {
			case "Password":
				if v.Value.Content != items[0].Password {
					t.Fatal("writeItems did not leave protected values unlocked")
				}
			case "otp":
				if v.Value.Content != items[0].OTP {
					t.Fatal("writeItems did not leave protected values unlocked")
				}
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
	if bytes.Contains(sealed, attachment) || bytes.Contains(sealed, []byte(items[0].Password)) ||
		bytes.Contains(sealed, attContent) || bytes.Contains(sealed, []byte(history.Password)) {
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

	// Item history survives the v2 envelope exactly.
	if len(login.History) != 1 {
		t.Fatalf("login history len = %d, want 1", len(login.History))
	}
	gotH := login.History[0]
	if gotH.Timestamp != history.Timestamp || gotH.Action != history.Action ||
		gotH.Title != history.Title || gotH.Username != history.Username ||
		gotH.Password != history.Password || gotH.Notes != history.Notes {
		t.Fatalf("history entry = %+v, want %+v", gotH, history)
	}
	if len(gotH.Sections) != 1 {
		t.Fatalf("history sections len = %d, want 1", len(gotH.Sections))
	}
	gotSec, wantSec := gotH.Sections[0], history.Sections[0]
	if gotSec.ID != wantSec.ID || gotSec.Title != wantSec.Title || len(gotSec.Fields) != 1 {
		t.Fatalf("history section = %+v, want %+v", gotSec, wantSec)
	}
	gotF, wantF := gotSec.Fields[0], wantSec.Fields[0]
	if gotF.ID != wantF.ID || gotF.Label != wantF.Label || gotF.Type != wantF.Type ||
		gotF.Type != FieldTypeConcealed || gotF.Value != wantF.Value || gotF.Protected != wantF.Protected || !gotF.Protected {
		t.Fatalf("history section field = %+v, want %+v", gotF, wantF)
	}

	// v2 attachment metadata and bytes survive the KDBX Binary round trip.
	if len(login.Attachments) != 1 {
		t.Fatalf("login attachments len = %d, want 1", len(login.Attachments))
	}
	gotAtt := login.Attachments[0]
	if gotAtt.ID != att.ID || gotAtt.FileName != att.FileName || gotAtt.Size != att.Size ||
		gotAtt.MIMEType != att.MIMEType || gotAtt.SHA256 != att.SHA256 || gotAtt.Protected != att.Protected {
		t.Fatalf("attachment meta = %+v, want %+v", gotAtt, att)
	}
	if !bytes.Equal(gotAtt.Content, attContent) {
		t.Fatalf("attachment content = %x, want %x", gotAtt.Content, attContent)
	}
	if gotAtt.SHA256 != AttachmentSHA256(gotAtt.Content) || gotAtt.Size != int64(len(gotAtt.Content)) {
		t.Fatalf("attachment summary inconsistent after round trip: size %d sha256 %q content %x", gotAtt.Size, gotAtt.SHA256, gotAtt.Content)
	}

	// Soft-trash fields (TrashedAt travels inside the v2 envelope).
	trashed := gotItems[2]
	if trashed.ID != "trashed-login" || trashed.State != "trashed" || trashed.PreviousState != "archived" {
		t.Fatalf("trashed item = %+v, want state trashed previous archived", trashed)
	}
	if trashed.TrashedAt == nil || !trashed.TrashedAt.Equal(trashedAt) {
		t.Fatalf("trashed item TrashedAt = %v, want %v", trashed.TrashedAt, trashedAt)
	}
	if trashed.Username != trashedUser || trashed.Password != trashedPassword || trashed.OTP != trashedOTP {
		t.Fatalf("trashed item credentials = %q/%q/%q, want %q/%q/%q",
			trashed.Username, trashed.Password, trashed.OTP, trashedUser, trashedPassword, trashedOTP)
	}
	if trashed.Attachment != nil || len(trashed.Attachments) != 0 {
		t.Fatalf("trashed item carries unexpected attachment: legacy %d bytes, v2 %d entries", len(trashed.Attachment), len(trashed.Attachments))
	}
	if doc.Attachment == nil || len(doc.Attachments) != 0 {
		t.Fatalf("document item attachment layout changed: legacy %d bytes, v2 %d entries", len(doc.Attachment), len(doc.Attachments))
	}

	// Open never returns the CEK or any other credential with the database.
	if c := opened.Credentials; c == nil || c.Passphrase != nil || c.Key != nil || c.Windows != nil {
		t.Fatal("opened database retains credentials")
	}
}
