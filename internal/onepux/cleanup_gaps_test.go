package onepux

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

// TestMapArchiveItemRejectsAttachmentBeforeClone covers every attachment
// rejection the mapper can raise on its own. Each check runs before the
// buffered entry is cloned: a rejection returns the zero item, and the caller's
// buffered entry is neither wiped nor retained by a stray copy.
func TestMapArchiveItemRejectsAttachmentBeforeClone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		path    string
		doc     map[string]any
		want    error
	}{
		{"invalid name", []byte(clearSource), "files/a:b", map[string]any{"decryptedSize": len(clearSource)}, ErrUnsupported},
		{"size mismatch", []byte(clearSource), "files/body.txt", map[string]any{"fileName": "body.txt", "decryptedSize": len(clearSource) + 1}, ErrUnsupported},
		// The oversize check runs before the name check, so the document
		// fallback name is never consulted for the limit path.
		{"oversize", make([]byte, vault.MaxAttachmentSize+1), "files/body.txt", map[string]any{"fileName": "body.txt"}, ErrLimit},
	} {
		content := bytes.Clone(tc.content)
		files := map[string][]byte{tc.path: content}
		item := onepuxItem(t, "doc", "114", "active", map[string]any{"title": "doc"}, map[string]any{"documentAttributes": tc.doc})
		item["file"] = map[string]any{"path": tc.path}
		got, err := mapArchiveItem(item, files)
		if err != tc.want || !reflect.DeepEqual(got, vault.Item{}) || got.Attachment != nil || got.Attachments != nil {
			t.Fatalf("%s: rejected mapping escaped an item clone: %v", tc.name, err)
		}
		if !bytes.Equal(files[tc.path], tc.content) {
			t.Fatalf("%s: rejected mapping touched the caller's buffered entry", tc.name)
		}
	}
}

// TestMapArchiveV2OuterFailureWipesCurrentItem maps a document item that takes
// its attachment copy and then fails with a limit error (password history
// carrying a character the vault's XML text rejects). An earlier document
// already owns a handed-off attachment. The call returns only an empty
// mapping, and the current item, its attachment copy, every appended item and
// the buffered entries are released.
func TestMapArchiveV2OuterFailureWipesCurrentItem(t *testing.T) {
	login := func(uuid string) map[string]any {
		return onepuxItem(t, uuid, "001", "active",
			map[string]any{"title": uuid, "url": "https://example.test/"},
			map[string]any{
				"loginFields": []any{map[string]any{"designation": "password", "fieldType": "P", "value": clearPlaceholder}},
				"notesPlain":  clearPlaceholder,
			})
	}
	attachment := []byte(clearPlaceholder)
	document := func() map[string]any {
		item := onepuxItem(t, "doc", "114", "active",
			map[string]any{"title": "doc"},
			map[string]any{"documentAttributes": map[string]any{"fileName": "body.txt", "decryptedSize": len(attachment)}})
		item["file"] = map[string]any{"path": "files/body.txt"}
		return item
	}
	overflow := document()
	overflow["uuid"] = "doc-overflow"
	history := make([]any, 101)
	for n := range history {
		history[n] = map[string]any{"value": clearPlaceholder}
	}
	// U+0085 is valid UTF-8 and not a valid 1PUX source control character, so
	// only the outer vault validator rejects it.
	history[0] = map[string]any{"value": "\u0085"}
	overflow["details"].(map[string]any)["passwordHistory"] = history
	items := []map[string]any{login("login-first"), document(), overflow, login("login-last")}
	files := map[string][]byte{"files/body.txt": attachment}
	raw := onepuxArchive(t, items, files)
	before := bytes.Clone(raw)
	mapped, err := MapArchiveV2(raw)
	if err == nil || !reflect.DeepEqual(mapped, MappedLogins{}) || mapped.Items != nil {
		t.Fatal("item rejected after mapping escaped a partial result")
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("failed MapArchiveV2 modified the caller's archive")
	}

	// Without the rejected login the same attachment survives handoff intact,
	// so the failure cleanup never reaches a successful result.
	raw = onepuxArchive(t, []map[string]any{login("login-first"), document()}, map[string][]byte{"files/body.txt": attachment})
	mapped, err = MapArchiveV2(raw)
	if err != nil || len(mapped.Items) != 2 {
		t.Fatalf("sanity mapping failed: %v", err)
	}
	defer releaseMappedItems(&mapped)
	doc := mapped.Items[1]
	if doc.Title != "doc" || len(doc.Attachments) != 1 || !bytes.Equal(doc.Attachments[0].Content, attachment) || !bytes.Equal(doc.Attachment, attachment) {
		t.Fatal("handed-off attachment content was wiped")
	}
}

// TestMapArchiveItemRejectWipesOwnedClone rejects an SSH key item after it has
// allocated byte buffers: the mapper stores the decoded SSH seed and then the
// password history exceeds its limit. The failure cleanup clears what the item
// owns, the caller receives the zero item, and the caller's input maps and
// buffers stay untouched.
func TestMapArchiveItemRejectWipesOwnedClone(t *testing.T) {
	seed := bytes.Repeat([]byte{33}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(block)
	if privatePEM == nil {
		t.Fatal("private key encoding failed")
	}
	// The mapper reads sections as []any, so the fixture is shaped like a
	// decoded archive instead of typedSection's []map[string]any.
	section := map[string]any{"name": "ssh", "title": "SSH", "fields": []any{typedField("key", "Private Key", map[string]any{"sshKey": string(privatePEM)})}}
	item := onepuxItem(t, "ssh", "115", "active", map[string]any{"title": "SSH Key"}, map[string]any{"sections": []any{section}})
	seeded, err := mapArchiveItem(item, map[string][]byte{})
	if err != nil || len(seeded.SSHSeed) != ed25519.SeedSize {
		t.Fatalf("fixture never decoded the SSH seed: %v", err)
	}
	wipeItem(&seeded)
	// Each entry is purchased after the SSH seed, so the oversize history
	// rejects the item with ErrLimit once it already owns that buffer.
	history := make([]any, 101)
	for n := range history {
		history[n] = map[string]any{"value": clearPlaceholder}
	}
	item["details"].(map[string]any)["passwordHistory"] = history
	files := map[string][]byte{}
	bytesBefore := bytes.Clone([]byte(string(privatePEM)))
	dataBefore := mustJSON(t, item)

	owned, err := mapArchiveItem(item, files)
	if err != ErrLimit || !reflect.DeepEqual(owned, vault.Item{}) {
		t.Fatalf("failed mapping escaped an item: %v", err)
	}
	if string(privatePEM) != string(bytesBefore) {
		t.Fatal("failed mapping wiped the caller's private key bytes")
	}
	if dataBefore != mustJSON(t, item) || len(files) != 0 {
		t.Fatal("failed mapping modified the caller's input")
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestReleaseFailedItemWipesEveryOwnedBuffer builds an item that still owns an
// attachment clone and a second copy of it, plus mapped credential buffers,
// then runs the failure cleanup directly: every byte buffer is zeroed and the
// item collapses to the zero value. Buffers outside the item are untouched.
func TestReleaseFailedItemWipesEveryOwnedBuffer(t *testing.T) {
	caller := []byte(clearSource)
	content := bytes.Clone(caller)
	item := vault.Item{
		ID: "doc", Kind: "document", Title: "doc", Notes: clearPlaceholder,
		Password: clearPlaceholder, Attachment: content,
		Attachments: []vault.AttachmentMeta{{ID: "att", FileName: "body.txt", Content: content}},
	}
	releaseFailedItem(&item)
	if !reflect.DeepEqual(item, vault.Item{}) {
		t.Fatalf("failure cleanup left an item behind: %+v", item)
	}
	if !bytes.Equal(content, make([]byte, len(caller))) {
		t.Fatal("failure cleanup left the owned attachment clone uncleared")
	}
	if !bytes.Equal(caller, []byte(clearSource)) {
		t.Fatal("failure cleanup touched a caller-owned buffer")
	}
}
