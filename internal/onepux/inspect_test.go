package onepux

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

const attributes = `{"version":3,"description":"1Password Unencrypted Export","createdAt":0}`
const inventoryData = `{"accounts":[{"attrs":{"uuid":"a1","name":"private-account-marker"},"vaults":[{"attrs":{"uuid":"v1","name":"private-vault-marker","type":"P"},"items":[{"uuid":"i1","categoryUuid":"001","state":"active","overview":{"title":"private-title-marker"},"details":{"sections":[{"name":"s","fields":[{"id":"repeated","value":{"concealed":"private-value-marker"}},{"id":"repeated","value":{"string":"private-value-marker"}}]}]}},{"uuid":"i2","categoryUuid":"114","state":"archived","overview":{},"details":{"documentAttributes":{"documentId":"private-document-id","fileName":"private-file-marker","decryptedSize":4}}},{"uuid":"i3","categoryUuid":"777","state":"future-state-marker","overview":{},"details":{"passwordHistory":[{"value":"private-old-password"}]}}]}]}]}`

type entry struct{ name, data string }

func pack(t testing.TB, attrs, data string, extras ...entry) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, e := range append([]entry{{"export.attributes", attrs}, {"export.data", data}}, extras...) {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		if e.name == "files/" {
			h.SetMode(os.ModeDir | 0700)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestInventoryCountsAndPrivacy(t *testing.T) {
	raw := pack(t, attributes, inventoryData, entry{"files/", ""}, entry{"files/private-file-marker", "\x00\x01\x02\xff"})
	before := append([]byte(nil), raw...)
	report, err := Inspect(raw)
	want := Report{SectionInventory: SectionReport{Sections: 1, Fields: 2, RepeatedFieldIDs: 1, ObjectValues: 2}, Version: 3, Accounts: 1, Vaults: 1, Items: 3, Active: 1, Archived: 1, OtherStates: 1, Files: 1, FileBytes: 4, FileReferences: FileReferenceReport{FilesWithoutExplicitLinks: 1, ItemsWithoutExplicitPath: 1}, Categories: []Category{{"001", 1}, {"114", 1}, {"777", 1}}, UnmappedItems: 3, ReviewReasons: []string{"field-value-semantics-unverified", "file-linkage-unverified", "file-path-not-provided", "files-without-explicit-links", "mapping-not-implemented", "password-history-unmapped", "repeated-field-id", "sections-unmapped", "unknown-category", "unknown-state"}}
	if err != nil || !reflect.DeepEqual(report, want) {
		t.Fatal("inventory counts or unverified mapping changed", report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"private-", "future-state-marker", "a1", "i1", "v1"} {
		if bytes.Contains(encoded, []byte(marker)) || strings.Contains(fmt.Sprintf("%+v", report), marker) {
			t.Fatal("inventory echoed private metadata or values")
		}
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("inventory modified its source")
	}
}

func TestInventoryScopesAndUnknownMetadata(t *testing.T) {
	// Source item UUIDs are only unique within a vault. Repeated field IDs in
	// inventoryData are legal source data and never become stable target IDs.
	data := `{"future":"private-extra-marker","accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v1"},"items":[{"uuid":"same","categoryUuid":"001","state":"active"}]},{"attrs":{"uuid":"v2"},"items":[{"uuid":"same","categoryUuid":"001","state":"active"}]}]}]}`
	report, err := Inspect(pack(t, attributes, data))
	if err != nil || report.Items != 2 || report.Vaults != 2 || report.MappingVerified || !contains(report.ReviewReasons, "additional-metadata") {
		t.Fatal("source scope or unknown metadata was silently relabelled", err)
	}
	empty, err := Inspect(pack(t, attributes, `{"accounts":[]}`))
	if err != nil || empty.Items != 0 || empty.MappingVerified || !contains(empty.ReviewReasons, "mapping-not-implemented") {
		t.Fatal("empty inventory was confused with import authorization", err)
	}
	for _, change := range []struct{ old, new string }{{`"uuid":"i2"`, `"uuid":"i1"`}, {`"uuid":"a1"`, `"uuid":"bad/private-identifier"`}} {
		refuse(t, pack(t, attributes, strings.Replace(inventoryData, change.old, change.new, 1)), ErrInvalid)
	}
}

func contains(all []string, want string) bool {
	for _, value := range all {
		if value == want {
			return true
		}
	}
	return false
}

func refuse(t testing.TB, raw []byte, want error) {
	t.Helper()
	report, err := Inspect(raw)
	if !errors.Is(err, want) || !reflect.DeepEqual(report, Report{}) {
		t.Fatal("failed inventory returned partial state or wrong error", err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("inventory error echoed private input")
	}
}

func TestInventoryRejectsArchiveAmbiguityAndCorruption(t *testing.T) {
	for _, name := range []string{"../private-traversal", "/private-absolute", "files/../private-traversal", "files\\private-path", "files/C:private-path", "files/a/private-nested", "files/private-trailing.", "files/private\x00name"} {
		refuse(t, pack(t, attributes, inventoryData, entry{name, "private-bytes"}), ErrInvalid)
	}
	for _, extras := range [][]entry{
		{{"export.data", "private-duplicate"}},
		{{"files/Case", "a"}, {"files/case", "b"}},
	} {
		refuse(t, pack(t, attributes, inventoryData, extras...), ErrInvalid)
	}
	refuse(t, pack(t, attributes, inventoryData, entry{"private-unknown-root", "data"}), ErrUnsupported)
	corrupt := pack(t, attributes, inventoryData, entry{"files/blob", "private-attachment-bytes"})
	i := bytes.Index(corrupt, []byte("private-attachment-bytes"))
	if i < 0 {
		t.Fatal("invalid corruption fixture")
	}
	corrupt[i] ^= 1
	refuse(t, corrupt, ErrInvalid)
	for _, mode := range []os.FileMode{os.ModeSymlink | 0777, os.ModeNamedPipe | 0600} {
		var out bytes.Buffer
		w := zip.NewWriter(&out)
		h := &zip.FileHeader{Name: "files/private-special", Method: zip.Store}
		h.SetMode(mode)
		if _, err := w.CreateHeader(h); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		refuse(t, out.Bytes(), ErrInvalid)
	}
	// Central-directory declarations must be bounded before decompression.
	for _, mutation := range []struct {
		offset int
		value  uint32
		want   error
	}{{24, MaxEntry + 1, ErrLimit}, {20, MaxArchive + 1, ErrInvalid}} {
		raw := pack(t, attributes, inventoryData)
		at := bytes.Index(raw, []byte{'P', 'K', 1, 2})
		binary.LittleEndian.PutUint32(raw[at+mutation.offset:], mutation.value)
		refuse(t, raw, mutation.want)
	}
}

func TestInventoryStrictJSONAndLimits(t *testing.T) {
	for _, data := range []string{
		`{"accounts":[],"accounts":[]}`, `{"accounts":[],"Accounts":[]}`, `{"\u0061ccounts":[],"accounts":[]}`,
		`{"accounts":null}`, `{"accounts":{}}`, `{"accounts":[]} {}`, `{"accounts":[],"private":"\ud800"}`,
		`{"accounts":[],"private":"\udc00"}`, "{\"accounts\":[],\"private\":\"\xff\"}",
		strings.Replace(inventoryData, `"categoryUuid":"001"`, `"categoryUuid":"private-category"`, 1),
		strings.Replace(inventoryData, `"items":[`, `"items":[null,`, 1),
	} {
		refuse(t, pack(t, attributes, data), ErrInvalid)
	}
	valid, err := Inspect(pack(t, attributes, `{"accounts":[],"future":"\ud83d\ude00"}`))
	if err != nil || !contains(valid.ReviewReasons, "additional-metadata") {
		t.Fatal("valid surrogate pair rejected", err)
	}
	refuse(t, pack(t, strings.Replace(attributes, `"version":3`, `"version":4`, 1), inventoryData), ErrUnsupported)
	refuse(t, pack(t, attributes, strings.Repeat(" ", MaxJSON+1)), ErrLimit)
	refuse(t, bytes.Repeat([]byte{0}, MaxArchive+1), ErrLimit)
	refuse(t, pack(t, attributes, `{"accounts":[],"private":`+strings.Repeat("[", MaxDepth+2)+`0`+strings.Repeat("]", MaxDepth+2)+`}`), ErrLimit)
	refuse(t, pack(t, attributes, `{"accounts":[],"private":[`+strings.Repeat(`0,`, MaxNodes)+`0]}`), ErrLimit)
	extras := make([]entry, MaxEntries)
	for i := range extras {
		extras[i] = entry{fmt.Sprintf("files/%d", i), ""}
	}
	refuse(t, pack(t, attributes, inventoryData, extras...), ErrLimit)
}

func TestDirectoryBudgetAndArchiveBoundary(t *testing.T) {
	extras := make([]entry, MaxEntries)
	for i := range extras {
		extras[i] = entry{fmt.Sprintf("files/%d", i), ""}
	}
	raw := pack(t, attributes, inventoryData, extras...)
	end := bytes.LastIndex(raw, []byte{'P', 'K', 5, 6})
	// Do not let a lying EOCD defer the object limit until zip.NewReader has
	// allocated every central-directory file and rejected the count mismatch.
	binary.LittleEndian.PutUint16(raw[end+8:], 0)
	binary.LittleEndian.PutUint16(raw[end+10:], 0)
	t.Run("lying-count", func(t *testing.T) { refuse(t, raw, ErrLimit) })
	t.Run("trailing", func(t *testing.T) {
		refuse(t, append(pack(t, attributes, inventoryData), []byte("private-trailing-payload")...), ErrInvalid)
	})
	t.Run("entry-on-other-disk", func(t *testing.T) {
		raw := pack(t, attributes, inventoryData)
		at := bytes.Index(raw, []byte{'P', 'K', 1, 2})
		binary.LittleEndian.PutUint16(raw[at+34:], 1)
		refuse(t, raw, ErrUnsupported)
	})
}

func TestInventoryTotalBudgetsAndZipFeatures(t *testing.T) {
	var items strings.Builder
	for i := 0; i < MaxObjects; i++ {
		if i > 0 {
			items.WriteByte(',')
		}
		fmt.Fprintf(&items, `{"uuid":"i%d","categoryUuid":"001","state":"active"}`, i)
	}
	data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[` + items.String() + `]}]}]}`
	refuse(t, pack(t, attributes, data), ErrLimit)
	raw := pack(t, attributes, inventoryData, entry{"files/a", "a"}, entry{"files/b", "b"})
	at := bytes.Index(raw, []byte{'P', 'K', 1, 2})
	for bytes.Equal(raw[at:at+4], []byte{'P', 'K', 1, 2}) {
		n := int(binary.LittleEndian.Uint16(raw[at+28:]))
		e := int(binary.LittleEndian.Uint16(raw[at+30:]))
		c := int(binary.LittleEndian.Uint16(raw[at+32:]))
		if strings.HasPrefix(string(raw[at+46:at+46+n]), "files/") {
			binary.LittleEndian.PutUint32(raw[at+24:], MaxEntry)
		}
		at += 46 + n + e + c
	}
	refuse(t, raw, ErrLimit)
	for _, mutation := range []struct {
		offset int
		value  uint16
	}{{8, 1}, {10, 99}} {
		raw := pack(t, attributes, inventoryData)
		at := bytes.Index(raw, []byte{'P', 'K', 1, 2})
		binary.LittleEndian.PutUint16(raw[at+mutation.offset:], mutation.value)
		refuse(t, raw, ErrUnsupported)
	}
	refuse(t, pack(t, attributes, inventoryData, entry{"files/" + strings.Repeat("x", 1024), ""}), ErrLimit)
}

func TestInventoryRejectsSymlinkWithDirectorySuffix(t *testing.T) {
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, e := range []entry{{"export.attributes", attributes}, {"export.data", inventoryData}, {"files/", ""}} {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		if e.name == "files/" {
			h.SetMode(os.ModeSymlink | 0777)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	refuse(t, out.Bytes(), ErrInvalid)
}

func TestDirectoryBudgetMatchesLastEOCD(t *testing.T) {
	raw := pack(t, attributes, inventoryData)
	end := bytes.LastIndex(raw, []byte{'P', 'K', 5, 6})
	comment := make([]byte, 23)
	copy(comment, []byte{'P', 'K', 5, 6})
	// Go selects the last EOCD-looking signature even when bytes trail its
	// declared comment. The guard must reject it, not inspect an earlier EOCD
	// and leave archive/zip free to allocate from a different directory view.
	binary.LittleEndian.PutUint16(raw[end+20:], uint16(len(comment)))
	raw = append(raw, comment...)
	if err := directoryBudget(raw); !errors.Is(err, ErrInvalid) {
		t.Fatal("directory budget and ZIP reader could select different EOCDs", err)
	}
}

func FuzzInventory(f *testing.F) {
	f.Add(pack(f, attributes, inventoryData, entry{"files/blob", "private-bytes"}))
	f.Add(pack(f, attributes, `{"accounts":[]}`))
	f.Add(pack(f, attributes, fileData(f, fileItem("i", "files/private-target", 4)), entry{"files/private-target", "data"}))
	f.Add([]byte("not a zip"))
	f.Fuzz(checkInventory)
}

// Repack mutated export.data with a valid CRC so fuzzing reaches the JSON
// and hierarchy checks instead of stopping at the ZIP checksum boundary.
func FuzzInventoryJSON(f *testing.F) {
	f.Add([]byte(inventoryData))
	f.Add([]byte(`{"accounts":[]}`))
	f.Add([]byte(`{"accounts":[],"accounts":null}`))
	f.Add([]byte(fileData(f, fileItem("i", "files/private-target", 4))))
	f.Add([]byte(fileData(f, fileItem("i", "files/private-missing", 0))))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxJSON {
			return
		}
		checkInventory(t, pack(t, attributes, string(data), entry{"files/private-target", "data"}))
	})
}

func checkInventory(t *testing.T, data []byte) {
	before := append([]byte(nil), data...)
	report, err := Inspect(data)
	if !bytes.Equal(before, data) {
		t.Fatal("inventory changed source bytes")
	}
	if err != nil {
		if err != ErrInvalid && err != ErrUnsupported && err != ErrLimit || !reflect.DeepEqual(report, Report{}) {
			t.Fatal("inventory returned partial state or input-bearing error")
		}
		return
	}
	if report.Version != 3 || report.MappingVerified || report.UnmappedItems != report.Items || report.Active+report.Archived+report.OtherStates != report.Items || report.Accounts+report.Vaults+report.Items > MaxObjects || !contains(report.ReviewReasons, "mapping-not-implemented") {
		t.Fatal("inventory escaped its bounds or granted migration")
	}
	count := 0
	for _, category := range report.Categories {
		count += category.Items
	}
	if count != report.Items || report.FileBytes > MaxExpanded {
		t.Fatal("inventory category or attachment accounting inconsistent")
	}
	refs := report.FileReferences
	if refs.Explicit != refs.Matched+refs.Missing || refs.LinkedFiles+refs.FilesWithoutExplicitLinks != report.Files || refs.LinkedFiles > refs.Matched || refs.Repeated > refs.Explicit || refs.SizeMismatches > refs.Matched || refs.Explicit+refs.ItemsWithoutExplicitPath > report.Items {
		t.Fatal("file reference accounting inconsistent")
	}
}
