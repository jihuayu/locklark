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

// The origin shallow copy keeps pre-transaction item structs (and their byte
// buffers) reachable after CloneItem replacements, while the transaction's
// final buffers survive until commit.
func TestAuthenticatedStateClearZeroesOriginAndFinalItems(t *testing.T) {
	originalAttachment := []byte("synthetic-origin-attachment")
	originalSource := []byte("synthetic-origin-provenance")
	nextAttachment := []byte("synthetic-cloned-attachment")
	source := []byte("synthetic-import-source")
	state := &authenticatedState{
		items: []vault.Item{
			{ImportSource: source},
			{Attachments: []vault.AttachmentMeta{{Content: nextAttachment}}},
		},
		origin: []vault.Item{{Attachment: originalAttachment, ImportSource: originalSource}},
	}

	state.clear()

	for name, value := range map[string][]byte{
		"origin attachment": originalAttachment,
		"origin provenance": originalSource,
		"import source":     source,
		"replacement body":  nextAttachment,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("%s retained %q", name, value)
		}
	}
	if state.origin != nil {
		t.Fatal("origin lifetime root retained")
	}
	if len(state.items) != 2 || len(state.items[1].Attachments) != 1 {
		t.Fatal("cleanup dropped final slice presence")
	}
}

// AddAttachment must not modify the caller's slice and the new attachment must
// reopen byte-exact from the encrypted snapshot.
func TestAddAttachmentKeepsCallerBufferAndReopensNewValue(t *testing.T) {
	s, path, key := v2Session(t)
	baseID, baseRev, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	existing := []byte("reopened-existing-bytes")
	if _, baseRev, err = s.AddAttachment(baseID, baseRev, "existing.txt", "text/plain", existing, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}

	content := []byte("synthetic-added-body")
	attID, attRev, err := s.AddAttachment(baseID, baseRev, "added.txt", "text/plain", content, v2Gate(t, s))
	if err != nil {
		t.Fatalf("attachment add failed: %v", err)
	}
	if !bytes.Equal(content, []byte("synthetic-added-body")) {
		t.Fatalf("caller buffer modified: %q", content)
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	meta, reopenedBytes, err := reopened.GetAttachment(baseID, attRev, attID)
	if err != nil || meta.FileName != "added.txt" || meta.SHA256 != vault.AttachmentSHA256(content) || !bytes.Equal(reopenedBytes, content) {
		t.Fatalf("new attachment did not reopen byte-exact: %+v %q %v", meta, reopenedBytes, err)
	}
	items, _, err := reopened.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.ID == baseID {
			if len(it.Attachments) != 2 || it.Attachments[1].FileName != "added.txt" {
				t.Fatalf("new attachment metadata lost: %+v", it.Attachments)
			}
			return
		}
	}
	t.Fatal("login item missing after reopen")
}

// After CloneItem replacements, the pre-transaction structs are reachable only
// through the origin shallow copy; clear must zero theirs and the final items'
// buffers while leaving the final pending value intact until commit.
func TestClearZeroesReplacedOriginBuffersKeepsFinalValue(t *testing.T) {
	existing := []byte("reopened-existing-bytes")
	importSource := []byte("reopened-existing-provenance")
	pending := []byte("synthetic-pending-body")
	decrypted := []vault.Item{{ID: "item-one", ImportSource: importSource, Attachments: []vault.AttachmentMeta{{Content: existing}}}}
	auth := &authenticatedState{items: decrypted, origin: append([]vault.Item(nil), decrypted...)}

	// Keep direct references to the backing buffers the origin structs own.
	originAttachment := auth.origin[0].Attachments[0].Content
	originProvenance := auth.origin[0].ImportSource
	// The transaction replaces every item, exactly as CloneItem mutations do.
	next := make([]vault.Item, len(auth.items))
	for n := range auth.items {
		next[n] = vault.CloneItem(auth.items[n])
		next[n].Attachments = append(next[n].Attachments, vault.AttachmentMeta{Content: append([]byte(nil), pending...)})
	}
	auth.items = next
	finalPending := auth.items[0].Attachments[len(auth.items[0].Attachments)-1].Content
	finalExisting := auth.items[0].Attachments[0].Content

	auth.clear()

	for name, value := range map[string][]byte{
		"origin attachment": originAttachment,
		"origin provenance": originProvenance,
		"final existing":    finalExisting,
		"final pending":     finalPending,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("%s retained %q", name, value)
		}
	}
	if auth.origin != nil {
		t.Fatal("origin lifetime root retained after clear")
	}
}

// Favorite and tag edits also replace the item with a CloneItem copy; the
// caller's buffers must be left untouched and the new values must reopen from
// the encrypted snapshot.
func TestFavoriteAndTagsKeepCallerBuffersAndReopen(t *testing.T) {
	s, path, key := v2Session(t)
	id, rev, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	existing := []byte("reopened-existing-bytes")
	if _, rev, err = s.AddAttachment(id, rev, "existing.txt", "text/plain", existing, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	if rev, err = s.SetFavorite(id, rev, true, v2Gate(t, s)); err != nil {
		t.Fatalf("favorite failed: %v", err)
	}
	if !bytes.Equal(existing, []byte("reopened-existing-bytes")) {
		t.Fatalf("favorite modified the attachment buffer: %q", existing)
	}
	tags := []string{"synthetic-tag"}
	if rev, err = s.SetTags(id, rev, tags, v2Gate(t, s)); err != nil {
		t.Fatalf("tags failed: %v", err)
	}
	if len(tags) != 1 || tags[0] != "synthetic-tag" {
		t.Fatalf("tags modified the caller slice: %q", tags)
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	items, revisions, err := reopened.ReadAuthenticatedItems(true)
	if err != nil {
		t.Fatal(err)
	}
	if revisions[id] != rev {
		t.Fatalf("reopened revision mismatch: %s != %s", revisions[id], rev)
	}
	for _, it := range items {
		if it.ID != id {
			continue
		}
		if !it.Favorite || len(it.Tags) != 1 || it.Tags[0] != "synthetic-tag" || len(it.Attachments) != 1 {
			t.Fatalf("new favorite/tags value lost: favorite=%v tags=%v attachments=%d", it.Favorite, it.Tags, len(it.Attachments))
		}
		return
	}
	t.Fatal("login item missing after reopen")
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
