package personal

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

func TestAuthenticatedStateClearZeroesAttachmentAndProvenanceBuffers(t *testing.T) {
	legacy := []byte("synthetic-legacy-attachment")
	attached := []byte("synthetic-v2-attachment")
	source := []byte("synthetic-import-source")
	state := &authenticatedState{items: []vault.Item{{
		Attachment:   legacy,
		Attachments:  []vault.AttachmentMeta{{Content: attached}},
		ImportSource: source,
	}}}

	state.clear()

	for name, value := range map[string][]byte{
		"attachment": legacy,
		"content":    attached,
		"source":     source,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("%s retained %q", name, value)
		}
	}
	if len(state.items[0].Attachment) != len(legacy) || len(state.items[0].Attachments) != 1 || len(state.items[0].Attachments[0].Content) != len(attached) || len(state.items[0].ImportSource) != len(source) {
		t.Fatal("cleanup dropped slice presence")
	}
}

func TestCommandCloseZeroesAttachmentBytes(t *testing.T) {
	attachmentBytes := []byte("synthetic-attachment-bytes")
	got, err := commandWithClose(func() (result, error) {
		return result{attachmentBytes: attachmentBytes}, nil
	}, func() error {
		return errors.New("synthetic close failure")
	})

	if !errors.Is(err, ErrCommandClose) {
		t.Fatalf("close error = %v", err)
	}
	if !bytes.Equal(attachmentBytes, make([]byte, len(attachmentBytes))) {
		t.Fatalf("attachment bytes retained %q", attachmentBytes)
	}
	if got.attachmentBytes != nil {
		t.Fatal("failed close returned the attachment buffer")
	}
}

func TestReadAuthenticatedItemsZeroesDecodedAttachmentBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	marker := []byte("synthetic-document-body")
	if _, err := AddDocument(path, "fixture", key, "Synthetic document", "synthetic.bin", marker); err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()

	items, _, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Kind != "document" {
			continue
		}
		if len(item.Attachment) != len(marker) || !bytes.Equal(item.Attachment, make([]byte, len(marker))) {
			t.Fatalf("metadata read retained attachment %q", item.Attachment)
		}
		return
	}
	t.Fatal("document item missing from authenticated read")
}
