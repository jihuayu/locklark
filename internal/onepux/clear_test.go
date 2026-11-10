package onepux

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

// Failure messages render as public entity names, so a leak assertion never
// echoes the secret bytes it is testing for.
const (
	clearPlaceholder = "PlaceholderForTest"
	clearMarker      = "SensitiveMarker"
)

var clearSource = `{"format":"locklark/1pux-source/v1","account":"` + clearMarker + `"}`

// strictV2Items lists logins accepted by both mappers: one URL and a password
// field without the optional field metadata the narrow login profile refuses.
func strictV2Items(t testing.TB, states ...string) []map[string]any {
	items := make([]map[string]any, len(states))
	for n, state := range states {
		uuid := "login-" + string(rune('0'+n))
		items[n] = onepuxItem(t, uuid, "001", state,
			map[string]any{"title": uuid, "url": "https://example.test/"},
			map[string]any{"loginFields": []any{
				map[string]any{"designation": "username", "fieldType": "T", "value": clearPlaceholder},
				map[string]any{"designation": "password", "fieldType": "P", "value": clearPlaceholder},
			}, "notesPlain": clearPlaceholder})
	}
	return items
}

// releaseProbe drives the mapper's failure-time release with a result buffer
// of the mapper's shape. Slots that are written keep the marker; the release
// must hand back an empty mapping and leave the discarded result with no secret.
func releaseProbe(t *testing.T, size int) {
	t.Helper()
	out := MappedLogins{Report: MappingReport{Profile: FullProfileV2, Items: size}, Items: make([]vault.Item, 0, size)}
	for range size {
		out.Items = append(out.Items, vault.Item{Title: clearMarker, Username: clearMarker, Password: clearMarker, Notes: clearMarker, ImportSource: []byte(clearSource)})
	}
	if got := releaseMappedItems(&out); !reflect.DeepEqual(got, MappedLogins{}) || out.Items != nil {
		t.Fatalf("release did not reset the mapping: %+v", got)
	}
}

func documentItemFor(t testing.TB, uuid, title, fileName string, size int) map[string]any {
	item := onepuxItem(t, uuid, "114", "active", map[string]any{"title": title}, map[string]any{
		"documentAttributes": map[string]any{"fileName": fileName, "decryptedSize": size},
	})
	item["file"] = map[string]any{"path": "files/" + fileName}
	return item
}

func assertEmptyMapping(t *testing.T, mapped MappedLogins, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(mapped, MappedLogins{}) || mapped.Items != nil {
		t.Fatalf("partial mapping escaped on failure: %+v %v", mapped, err)
	}
}

func assertHandedOff(t *testing.T, item vault.Item) {
	t.Helper()
	if item.Title == "" || item.Username != clearPlaceholder || item.Password != clearPlaceholder || item.Notes != clearPlaceholder || bytes.Count(item.ImportSource, []byte("locklark/1pux-source/v1")) != 1 {
		t.Fatalf("handed-off item was wiped or lost: %+v", item)
	}
}

// TestMapLoginsFailureWipesAppendedItems maps two logins into the result and
// fails on a third. The call returns an empty mapping without touching the
// caller's archive, and a later successful mapping still hands over intact
// items.
func TestMapLoginsFailureWipesAppendedItems(t *testing.T) {
	items := strictV2Items(t, "active", "archived", "future")
	raw := onepuxArchive(t, items, nil)
	before := bytes.Clone(raw)
	mapped, err := MapLogins(raw)
	assertEmptyMapping(t, mapped, err)
	if !bytes.Equal(raw, before) {
		t.Fatal("failed MapLogins modified the caller's archive")
	}

	good, err := MapLogins(onepuxArchive(t, items[:2], nil))
	if err != nil || len(good.Items) != 2 {
		t.Fatalf("sanity mapping failed: %v", err)
	}
	for _, item := range good.Items {
		assertHandedOff(t, item)
	}
}

// TestMapArchiveV2FailureWipesItemsAndOwnedFiles fails after a document with an
// attachment was mapped. The partial item, its attachment body and every
// buffered archive entry are wiped, while the success path keeps the
// attachment body it hands to the caller.
func TestMapArchiveV2FailureWipesItemsAndOwnedFiles(t *testing.T) {
	body := []byte(clearSource)
	files := map[string][]byte{"files/body.txt": bytes.Clone(body), "files/extra.txt": bytes.Clone(body)}
	items := append([]map[string]any{documentItemFor(t, "doc", "doc", "body.txt", len(body))}, strictV2Items(t, "active", "future")...)
	raw := onepuxArchive(t, items, files)
	before := bytes.Clone(raw)
	mapped, err := MapArchiveV2(raw)
	assertEmptyMapping(t, mapped, err)
	if !bytes.Equal(raw, before) {
		t.Fatal("failed MapArchiveV2 modified the caller's archive")
	}

	good, err := MapArchiveV2(onepuxArchive(t, items[:2], files))
	if err != nil || len(good.Items) != 2 {
		t.Fatalf("successful mapping failed: %v", err)
	}
	doc := good.Items[0]
	if string(doc.Attachment) != clearSource || doc.Filename != "body.txt" || len(doc.Attachments) != 1 || string(doc.Attachments[0].Content) != clearSource || doc.Attachments[0].SHA256 != vault.AttachmentSHA256(body) {
		t.Fatalf("handed-off attachment body was wiped or altered: %+v", doc.Attachments)
	}
	assertHandedOff(t, good.Items[1])
}

// TestReleaseWipesPartialItemsAndSourceFiles checks the failure cleanup
// directly: every secret an unfinished item holds is zeroed before release, and
// each buffered archive entry is wiped and dropped, referenced or not.
func TestReleaseWipesPartialItemsAndSourceFiles(t *testing.T) {
	attachment := []byte(clearSource)
	seed := []byte(clearSource)
	item := vault.Item{
		Title: clearMarker, Username: clearMarker, Password: clearMarker, Notes: clearMarker, Filename: clearMarker,
		Attachment:   attachment,
		Attachments:  []vault.AttachmentMeta{{ID: "a", FileName: "a.bin", Content: attachment}},
		ImportSource: []byte(clearSource),
		CreditCard:   &vault.CreditCardDetails{Number: clearMarker},
		Identity:     &vault.IdentityDetails{Email: clearMarker},
		SSHSeed:      seed,
		History:      []vault.ItemHistoryEntry{{Password: clearMarker}},
		Sections:     []vault.ItemSection{{Fields: []vault.CustomField{{Value: clearMarker}}}},
	}
	card, identity, source := item.CreditCard, item.Identity, item.ImportSource
	out := &MappedLogins{Report: MappingReport{Profile: FullProfileV2, Items: 1, Archived: 1}, Items: []vault.Item{item}}
	if got := releaseMappedItems(out); !reflect.DeepEqual(got, MappedLogins{}) || out.Items != nil {
		t.Fatalf("release did not reset the mapping: %+v", got)
	}
	zeroed := make([]byte, len(clearSource))
	for name, value := range map[string][]byte{"attachment": attachment, "attachment meta": attachment, "import source": source, "ssh seed": seed} {
		if !bytes.Equal(value, zeroed) {
			t.Fatalf("%s buffer retained %s bytes", name, clearMarker)
		}
	}
	for name, value := range map[string]*string{"history": &item.History[0].Password, "field": &item.Sections[0].Fields[0].Value} {
		if *value != "" {
			t.Fatalf("%s string survived release", name)
		}
	}
	if !reflect.DeepEqual(*card, vault.CreditCardDetails{}) || !reflect.DeepEqual(*identity, vault.IdentityDetails{}) {
		t.Fatalf("released credit card or identity retained data: %+v %+v", *card, *identity)
	}
	if !bytes.Equal(item.ImportSource, zeroed) || item.Attachment[0] != 0 {
		t.Fatalf("released item retained %s bytes", clearMarker)
	}

	linked, unlinked := bytes.Clone([]byte(clearSource)), bytes.Clone([]byte(clearSource))
	files := map[string][]byte{"files/linked": linked, "files/unlinked": unlinked}
	releaseSourceFiles(files)
	if len(files) != 0 || !bytes.Equal(linked, zeroed) || !bytes.Equal(unlinked, zeroed) {
		t.Fatal("releaseSourceFiles left owned entries or bytes")
	}
}

// failingReader yields one chunk and then fails, standing in for a corrupt
// entry whose copy aborts midway.
type failingReader struct{ data []byte }

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("copy failed")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestReadEntryWipesPartialBuffer checks that a copy error and an oversize
// entry both wipe what was already copied. A complete read hands the bytes
// out untouched.
func TestReadEntryWipesPartialBuffer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader io.Reader
		size   uint64
		limit  int64
		want   error
	}{
		{"copy error", &failingReader{data: []byte(clearSource)}, uint64(len(clearSource)), MaxEntry, ErrInvalid},
		{"oversize copy error", &failingReader{data: []byte(clearSource + clearSource)}, uint64(len(clearSource) + 1), int64(len(clearSource)) + 1, ErrLimit},
		{"oversize", strings.NewReader(clearSource + clearSource), uint64(2 * len(clearSource)), int64(len(clearSource)), ErrLimit},
		{"short entry", strings.NewReader(clearSource[:1]), uint64(len(clearSource)), MaxEntry, ErrInvalid},
	} {
		var out bytes.Buffer
		out.WriteString(clearSource[:1])
		if data, _, err := readEntryBytes(tc.reader, &out, &out, tc.size, tc.limit); err != tc.want || data != nil {
			t.Fatalf("%s: returned %v", tc.name, err)
		}
		if out.Len() != 0 || bytes.Contains(out.Bytes()[:cap(out.Bytes())], []byte(clearMarker)) {
			t.Fatalf("%s: kept partial %s bytes", tc.name, clearMarker)
		}
	}
	var out bytes.Buffer
	data, n, err := readEntryBytes(strings.NewReader(clearSource), &out, &out, uint64(len(clearSource)), MaxEntry)
	if err != nil || n != int64(len(clearSource)) || string(data) != clearSource || string(out.Bytes()) != clearSource {
		t.Fatalf("complete read altered the entry: %d %v", n, err)
	}
}

// TestMapArchiveV2PreAppendFailureWipesCurrentItem maps one login, then fails
// while mapping the next item before it is appended. Only an empty mapping is
// returned, so the caller never receives the partially built item.
func TestMapArchiveV2PreAppendFailureWipesCurrentItem(t *testing.T) {
	items := append(strictV2Items(t, "active"), onepuxItem(t, "bad", "001", "active",
		map[string]any{"title": "bad"},
		map[string]any{"loginFields": []any{
			map[string]any{"designation": "password", "fieldType": "P", "value": clearPlaceholder},
			map[string]any{"designation": "password", "fieldType": "P", "value": clearPlaceholder},
		}, "notesPlain": clearPlaceholder}))
	raw := onepuxArchive(t, items, nil)
	before := bytes.Clone(raw)
	mapped, err := MapArchiveV2(raw)
	assertEmptyMapping(t, mapped, err)
	if !bytes.Equal(raw, before) {
		t.Fatal("failed MapArchiveV2 modified the caller's archive")
	}
}

// TestMapArchiveItemFailureWipesAttachments fails after the attachment body
// was attached: the returned item is the zero value and the clone it owned is
// wiped, while the buffered archive entry stays owned by the caller.
func TestMapArchiveItemFailureWipesAttachments(t *testing.T) {
	buffered := []byte(clearSource)
	files := map[string][]byte{"files/body.txt": buffered}
	item := documentItemFor(t, "doc", "doc", "body.txt", len(buffered))
	item["details"] = map[string]any{
		"documentAttributes": map[string]any{"fileName": "body.txt", "decryptedSize": len(buffered)},
		"notesPlain":         "\x00",
	}
	got, err := mapArchiveItem(item, files)
	if err != ErrUnsupported || !reflect.DeepEqual(got, vault.Item{}) {
		t.Fatalf("failed mapping escaped an item: %v", err)
	}
	if string(buffered) != clearSource || string(files["files/body.txt"]) != clearSource {
		t.Fatal("failed mapping wiped the caller's buffered entry")
	}
}
