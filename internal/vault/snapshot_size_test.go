package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"
)

// A snapshot above the old 8 MiB ceiling but below the vault bounds must seal,
// verify, export and reopen; a payload above MaxPayload and an artifact above
// the stored bound are both refused by every entry point.
func TestSnapshotSizeBoundsFollowMaxPayload(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := []*age.X25519Recipient{id.Recipient()}
	authority := signer.Public().(ed25519.PublicKey)

	// Synthetic random v2 attachments: five full 2 MiB attachments (the per-item
	// bound) push the sealed KDBX above the legacy 8 MiB bound while the
	// plaintext stays below MaxPayload.
	items := make([]Item, 0, 5)
	for n := 0; n < 5; n++ {
		content := make([]byte, MaxAttachmentSize)
		if _, err := rand.Read(content); err != nil {
			t.Fatal(err)
		}
		items = append(items, Item{
			ID: "item-synthetic-" + string(rune('a'+n)), Kind: "document", Category: CategoryDocument, Title: "synthetic large",
			Attachments: []AttachmentMeta{{ID: "attachment", FileName: "synthetic.bin", Size: int64(len(content)), SHA256: AttachmentSHA256(content), Content: content, Protected: true}},
		})
	}
	t.Cleanup(func() {
		for n := range items {
			clear(items[n].Attachments[0].Content)
		}
	})
	s, err := SealItems([]byte("size fixture"), items, 1, recipients, signer)
	if err != nil {
		t.Fatalf("seal refused a snapshot below MaxPayload: %v", err)
	}
	if len(s.Database) <= 8<<20 || len(s.Database) > maxStoredSnapshot {
		t.Fatalf("database=%d MaxStoredSnapshot()=%d", len(s.Database), MaxStoredSnapshot())
	}
	if err := VerifySnapshot(s, authority, 1); err != nil {
		t.Fatalf("VerifySnapshot refused a %d-byte database: %v", len(s.Database), err)
	}
	data, got, err := OpenItems(s, id, authority, 1)
	if err != nil {
		t.Fatalf("open of a large snapshot failed: %v", err)
	}
	clear(data)
	if len(got) != len(items) {
		clearJoined(got)
		t.Fatal("large snapshot did not round-trip the synthetic items")
	}
	defer clearJoined(got)
	for n := range items {
		if len(got[n].Attachments) != 1 || !bytes.Equal(got[n].Attachments[0].Content, items[n].Attachments[0].Content) {
			t.Fatal("large snapshot did not round-trip the synthetic attachment")
		}
	}

	exported, err := ExportKDBX(items, "synthetic-export-password")
	if err != nil {
		t.Fatalf("export refused a database below MaxStoredSnapshot: %v", err)
	}
	clear(exported)

	// A payload over MaxPayload still fails, and so do oversized artifacts
	// regardless of signature, using the same bound as seal.
	if _, err := Seal(make([]byte, MaxPayload+1), 2, recipients, signer); err == nil {
		t.Fatal("seal accepted a payload above MaxPayload")
	}
	oversized := s
	oversized.Database = bytes.Repeat([]byte{1}, maxStoredSnapshot+1)
	oversized.Signature = ed25519.Sign(signer, oversized.signed())
	if err := VerifySnapshot(oversized, authority, 1); err == nil {
		t.Fatal("VerifySnapshot accepted a database above the seal bound")
	}
}

func clearJoined(items []Item) {
	for n := range items {
		for m := range items[n].Attachments {
			clear(items[n].Attachments[m].Content)
		}
	}
}

// A schema-valid item whose encoded KDBX exceeds the stored bound must fail
// at the size check with the distinct capacity error, not the generic
// invalid/corrupt ErrSnapshot, for both write and export paths.
func TestSnapshotCapacityBeyondStoredBoundIsDistinct(t *testing.T) {
	item := syntheticCapacityItem()
	if err := ValidateItems(nil, []Item{item}); err != nil {
		t.Fatalf("capacity fixture is not schema-valid: %v", err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := SealItems(nil, []Item{item}, 1, []*age.X25519Recipient{id.Recipient()}, signer)
	if !errors.Is(err, ErrSnapshotCapacity) || errors.Is(err, ErrSnapshot) {
		t.Fatalf("SealItems = %v, want only ErrSnapshotCapacity", err)
	}
	if len(s.Database) != 0 || len(s.Signature) != 0 {
		t.Fatal("refused seal returned snapshot material")
	}
	if _, err := ExportKDBX([]Item{item}, "synthetic-export-password"); !errors.Is(err, ErrSnapshotCapacity) || errors.Is(err, ErrSnapshot) {
		t.Fatalf("ExportKDBX = %v, want only ErrSnapshotCapacity", err)
	}
}
