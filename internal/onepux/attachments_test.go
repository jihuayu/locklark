package onepux

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func fileItem(id string, sourcePath any, size any) map[string]any {
	return map[string]any{
		"uuid": id, "categoryUuid": "114", "state": "active",
		"overview": map[string]any{"title": "private-title-marker"},
		"file":     map[string]any{"path": sourcePath, "attrs": map[string]any{}},
		"details":  map[string]any{"documentAttributes": map[string]any{"documentId": "private-document-marker", "fileName": "private-name-marker", "decryptedSize": size}},
	}
}

func fileData(t testing.TB, items ...map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"accounts": []any{map[string]any{"attrs": map[string]any{"uuid": "a"}, "vaults": []any{map[string]any{"attrs": map[string]any{"uuid": "v"}, "items": items}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFileReferencesMatchMissingAndPrivacy(t *testing.T) {
	data := fileData(t, fileItem("i1", "files/private-a", 4), fileItem("i2", "files/private-b", 0), fileItem("i3", "files/private-missing", 4))
	raw := pack(t, attributes, data, entry{"files/private-a", "data"}, entry{"files/private-b", ""}, entry{"files/private-unused", "x"})
	before := append([]byte(nil), raw...)
	report, err := Inspect(raw)
	want := FileReferenceReport{Explicit: 3, Matched: 2, Missing: 1, LinkedFiles: 2, FilesWithoutExplicitLinks: 1}
	if err != nil || report.FileReferences != want || report.MappingVerified || report.UnmappedItems != 3 {
		t.Fatal("explicit reference counts or unverified mapping changed", report.FileReferences, err)
	}
	for _, code := range []string{"missing-referenced-file", "files-without-explicit-links", "file-linkage-unverified", "mapping-not-implemented"} {
		if !contains(report.ReviewReasons, code) {
			t.Fatal("missing file review reason")
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil || bytes.Contains(encoded, []byte("private-")) || strings.Contains(fmt.Sprintf("%+v", report), "private-") || !bytes.Equal(before, raw) {
		t.Fatal("file reconciliation leaked metadata or changed source", err)
	}
}

func TestFileReferencesRepeatAndSizeMismatch(t *testing.T) {
	data := fileData(t, fileItem("i1", "files/private-target", 4), fileItem("i2", "files/private-target", 5))
	report, err := Inspect(pack(t, attributes, data, entry{"files/private-target", "data"}))
	want := FileReferenceReport{Explicit: 2, Matched: 2, Repeated: 1, LinkedFiles: 1, SizeMismatches: 1}
	if err != nil || report.FileReferences != want || !contains(report.ReviewReasons, "repeated-file-reference") || !contains(report.ReviewReasons, "file-size-mismatch") || report.MappingVerified {
		t.Fatal("shared reference or declared length mismatch hidden", report.FileReferences, err)
	}
}

func TestFileReferencesRespectItemScopes(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal([]byte(fileData(t, fileItem("same", "files/private-a", 4))), &root); err != nil {
		t.Fatal(err)
	}
	account := root["accounts"].([]any)[0].(map[string]any)
	vaults := account["vaults"].([]any)
	account["vaults"] = append(vaults, map[string]any{"attrs": map[string]any{"uuid": "v2"}, "items": []any{fileItem("same", "files/private-b", 4)}})
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(pack(t, attributes, string(raw), entry{"files/private-a", "data"}, entry{"files/private-b", "data"}))
	want := FileReferenceReport{Explicit: 2, Matched: 2, LinkedFiles: 2}
	if err != nil || report.FileReferences != want || report.Items != 2 {
		t.Fatal("same item ID in separate vaults merged attachment references", err)
	}
}

func TestFileReferencesNeverGuessNamesOrNormalizePaths(t *testing.T) {
	item := fileItem("i", "files/unused", 4)
	delete(item, "file")
	report, err := Inspect(pack(t, attributes, fileData(t, item), entry{"files/private-document-marker___private-name-marker", "data"}))
	want := FileReferenceReport{FilesWithoutExplicitLinks: 1, ItemsWithoutExplicitPath: 1}
	if err != nil || report.FileReferences != want || !contains(report.ReviewReasons, "file-path-not-provided") {
		t.Fatal("implicit metadata lost its unresolved status", report.FileReferences, err)
	}
	item["file"] = map[string]any{"attrs": map[string]any{}}
	report, err = Inspect(pack(t, attributes, fileData(t, item)))
	if err != nil || report.FileReferences.ItemsWithoutExplicitPath != 1 || report.FileReferences.Explicit != 0 {
		t.Fatal("missing path silently acquired a default", err)
	}
	for _, path := range []string{"files/PRIVATE-target", "files/private%2dtarget", "files/e\u0301"} {
		item := fileItem("i", path, 4)
		report, err := Inspect(pack(t, attributes, fileData(t, item), entry{"files/private-target", "data"}, entry{"files/é", "data"}))
		if err != nil || report.FileReferences.Missing != 1 || report.FileReferences.Matched != 0 || report.FileReferences.FilesWithoutExplicitLinks != 2 {
			t.Fatal("path case/encoding/Unicode was normalized", err)
		}
	}
	item = fileItem("i", "files/%2e%2e", 4)
	report, err = Inspect(pack(t, attributes, fileData(t, item), entry{"files/%2e%2e", "data"}))
	if err != nil || report.FileReferences.Matched != 1 {
		t.Fatal("literal percent filename was URL-decoded", err)
	}
}

func TestFileReferencesRejectMalformedDeclarations(t *testing.T) {
	for _, path := range []any{nil, 17, "", "files/", "export.data", "export.attributes", "../private-name", "/files/private-name", "files/../private-name", "files/private/nested", "files\\private-name", "https://private.invalid/blob", "files/private\nname"} {
		refuse(t, pack(t, attributes, fileData(t, fileItem("i", path, 4))), ErrInvalid)
	}
	refuse(t, pack(t, attributes, fileData(t, fileItem("i", "private-basename", 4))), ErrUnsupported)
	refuse(t, pack(t, attributes, fileData(t, fileItem("i", "files/"+strings.Repeat("x", 1024), 4))), ErrLimit)
	for _, size := range []any{nil, "4", -1, json.Number("4.0"), json.Number("4e0"), json.Number("18446744073709551616")} {
		refuse(t, pack(t, attributes, fileData(t, fileItem("i", "files/private-target", size))), ErrInvalid)
	}
	for _, problem := range []string{"file-null", "attrs-null", "document-null"} {
		item := fileItem("i", "files/private-target", 4)
		switch problem {
		case "file-null":
			item["file"] = nil
		case "attrs-null":
			item["file"].(map[string]any)["attrs"] = nil
		case "document-null":
			item["details"].(map[string]any)["documentAttributes"] = nil
		}
		refuse(t, pack(t, attributes, fileData(t, item)), ErrInvalid)
	}
}

func TestFileReferencesSizeOptionalAndUnknownAttributes(t *testing.T) {
	item := fileItem("i", "files/private-target", 4)
	doc := item["details"].(map[string]any)["documentAttributes"].(map[string]any)
	delete(doc, "decryptedSize")
	item["file"].(map[string]any)["attrs"] = map[string]any{"future": "private-attrs-marker"}
	report, err := Inspect(pack(t, attributes, fileData(t, item), entry{"files/private-target", "data"}))
	if err != nil || report.FileReferences.Matched != 1 || report.FileReferences.SizeMismatches != 0 || !contains(report.ReviewReasons, "file-attributes-unmapped") {
		t.Fatal("optional size or unknown file attributes silently relabelled", err)
	}
	doc["decryptedSize"] = json.Number("18446744073709551615")
	report, err = Inspect(pack(t, attributes, fileData(t, item), entry{"files/private-target", "data"}))
	if err != nil || report.FileReferences.SizeMismatches != 1 {
		t.Fatal("uint64 metadata size wrapped or allocated a payload", err)
	}
	if report.MappingVerified || !contains(report.ReviewReasons, "mapping-not-implemented") {
		t.Fatal("file match granted migration")
	}
}
