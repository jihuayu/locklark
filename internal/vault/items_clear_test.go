package vault

import (
	"bytes"
	"testing"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

func TestClearSensitiveItemBuffersZeroesAttachmentsAndProvenance(t *testing.T) {
	legacy := []byte("synthetic-legacy-attachment")
	attached := []byte("synthetic-v2-attachment")
	source := []byte("synthetic-import-source")
	item := &Item{
		Attachment:   legacy,
		Attachments:  []AttachmentMeta{{Content: attached}},
		ImportSource: source,
	}

	clearSensitiveItemBuffers(item)

	for name, value := range map[string][]byte{
		"attachment": legacy,
		"content":    attached,
		"source":     source,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("%s retained %q", name, value)
		}
	}
	if len(item.Attachment) != len(legacy) || len(item.Attachments) != 1 || len(item.Attachments[0].Content) != len(attached) || len(item.ImportSource) != len(source) {
		t.Fatal("cleanup dropped slice presence")
	}
}

func TestReadItemsFailureZeroesDecodedAttachment(t *testing.T) {
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	marker := []byte("synthetic-decoded-attachment")
	if err := writeItems(db, nil, []Item{
		{ID: "doc", Kind: "document", Title: "Doc", Filename: "synthetic.bin", Attachment: marker},
		{ID: "bad", Kind: "login", Title: "Bad"},
	}); err != nil {
		t.Fatal(err)
	}
	group := db.Content.Root.Groups[0]
	// Corrupting the cached source ID makes the second entry fail after the
	// first document has already been decoded and appended.
	group.Entries[2].Values[1].Value.Content = "another-id"

	metadata, items, err := readItems(db, group)
	if err != ErrSnapshot || metadata != nil || items != nil {
		t.Fatalf("readItems = %v, %v, %v", metadata, items, err)
	}
	// The decoded item owns a private copy of the attachment, so failure
	// cleanup may zero only that copy. The database binary and the caller's
	// original bytes must stay intact: a read must never mutate its source.
	if !bytes.Equal(marker, []byte("synthetic-decoded-attachment")) {
		t.Fatalf("caller attachment mutated by failure cleanup: %q", marker)
	}
	if b := db.FindBinary(group.Entries[1].Binaries[0].Value.ID); b == nil || !bytes.Equal(b.Content, marker) {
		t.Fatal("source database binary mutated by failure cleanup")
	}
}
