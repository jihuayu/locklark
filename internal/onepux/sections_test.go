package onepux

import (
	"encoding/json"
	"strings"
	"testing"
)

func sectionItem(id string, sections any) map[string]any {
	return map[string]any{"uuid": id, "categoryUuid": "001", "state": "active", "details": map[string]any{"sections": sections}}
}
func TestSectionInventoryScopesAndPrivacy(t *testing.T) {
	field := func(id string, value any) any { return map[string]any{"id": id, "value": value} }
	sections := []any{
		map[string]any{"name": "private-section", "fields": []any{field("private-id", map[string]any{"concealed": "private-secret"}), field("private-id", "private-string"), field("other", nil)}},
		map[string]any{"name": "private-section", "fields": []any{field("private-id", true), field("", []any{}), map[string]any{"value": 12}}},
	}
	report, err := Inspect(pack(t, attributes, fileData(t, sectionItem("i1", sections), sectionItem("i2", sections))))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(report)
	var decoded map[string]any
	json.Unmarshal(raw, &decoded)
	got, ok := decoded["section_inventory"].(map[string]any)
	if !ok {
		t.Fatal("section inventory missing")
	}
	want := map[string]int{"sections": 4, "fields": 12, "repeated_section_names": 2, "repeated_field_ids": 2, "unidentified_fields": 4, "object_values": 2, "string_values": 2, "null_values": 2, "boolean_values": 2, "array_values": 2, "number_values": 2, "missing_values": 0}
	for key, n := range want {
		if got[key] != float64(n) {
			t.Fatalf("%s count: %v want %d", key, got[key], n)
		}
	}
	if strings.Contains(string(raw), "private-") || report.MappingVerified {
		t.Fatal("private data or mapping claim in report")
	}
}
func TestSectionInventoryRejectsMalformedStructure(t *testing.T) {
	for _, section := range []any{
		map[string]any{"fields": nil}, map[string]any{"fields": "private-invalid"}, map[string]any{"fields": []any{nil}},
		map[string]any{"name": 12, "fields": []any{}}, map[string]any{"fields": []any{map[string]any{"id": true}}},
	} {
		refuse(t, pack(t, attributes, fileData(t, sectionItem("i", []any{section}))), ErrInvalid)
	}
}
func TestSectionInventoryBounded(t *testing.T) {
	fields := make([]any, MaxObjects)
	for i := range fields {
		fields[i] = map[string]any{}
	}
	refuse(t, pack(t, attributes, fileData(t, sectionItem("i", []any{map[string]any{"fields": fields}}))), ErrLimit)
}

func TestSectionInventoryMissingAndLiteralIdentifiers(t *testing.T) {
	sections := []any{map[string]any{}, map[string]any{"name": "", "fields": []any{map[string]any{}, map[string]any{"id": "x", "value": nil}, map[string]any{"id": "X", "value": json.Number("9007199254740993")}}}}
	report, err := Inspect(pack(t, attributes, fileData(t, sectionItem("i", sections))))
	if err != nil || report.SectionInventory != (SectionReport{Sections: 2, Fields: 3, UnidentifiedSections: 2, UnidentifiedFields: 1, MissingValues: 1, NullValues: 1, NumberValues: 1}) {
		t.Fatal("missing/empty IDs or values were conflated", err, report.SectionInventory)
	}
	for _, reason := range []string{"section-fields-missing", "source-identifiers-missing", "field-value-semantics-unverified"} {
		if !contains(report.ReviewReasons, reason) {
			t.Fatal("missing review reason", reason)
		}
	}
}

func FuzzSectionInventory(f *testing.F) {
	f.Add([]byte(`[{"name":"a","fields":[{"id":"x","value":{"concealed":"private-value"}},{"id":"x"}]}]`))
	f.Add([]byte(`[{}, {"fields":null}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		// Keep the hierarchy/ZIP valid so mutations reach the nested inventory.
		data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"i","categoryUuid":"001","state":"active","details":{"sections":` + string(raw) + `}}]}]}]}`
		report, err := Inspect(pack(t, attributes, data))
		if err != nil {
			if report.Version != 0 {
				t.Fatal("partial report")
			}
			return
		}
		r := report.SectionInventory
		if r.Fields != r.MissingValues+r.NullValues+r.ObjectValues+r.ArrayValues+r.StringValues+r.NumberValues+r.BooleanValues || r.RepeatedFieldIDs+r.UnidentifiedFields > r.Fields || r.RepeatedSectionNames+r.UnidentifiedSections > r.Sections || r.Fields+r.Sections > MaxObjects || report.MappingVerified {
			t.Fatal("invalid inventory invariants")
		}
	})
}
