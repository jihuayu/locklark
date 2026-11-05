package onepux

import (
	"encoding/json"
	"strings"
	"testing"
)

func loginItem(id string, fields any) map[string]any {
	return map[string]any{"uuid": id, "categoryUuid": "001", "state": "active", "details": map[string]any{"loginFields": fields}}
}

func TestLoginFieldsInventoryScopesAndPrivacy(t *testing.T) {
	fields := []any{
		map[string]any{"id": "private-id", "name": "private-name", "designation": "username", "type": "T", "value": "private-user"},
		map[string]any{"id": "private-id", "name": "private-name", "designation": "password", "fieldType": "P", "value": "private-password"},
		map[string]any{"id": "other", "name": "other", "designation": "password", "type": "T", "fieldType": "P", "value": nil},
		map[string]any{"designation": "private-unknown", "type": "private-type", "value": json.Number("9007199254740993")},
		map[string]any{"id": "", "name": "", "designation": "", "value": []any{}},
		map[string]any{"value": map[string]any{"private-key": "private-value"}},
		map[string]any{"designation": "USERNAME", "value": true},
		map[string]any{},
	}
	report, err := Inspect(pack(t, attributes, fileData(t, loginItem("i1", fields), loginItem("i2", fields))))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(report)
	var decoded map[string]any
	json.Unmarshal(raw, &decoded)
	got, ok := decoded["login_field_inventory"].(map[string]any)
	if !ok {
		t.Fatal("login field inventory missing")
	}
	want := map[string]int{"fields": 16, "repeated_names": 2, "repeated_ids": 2, "unnamed_fields": 10, "unidentified_fields": 10, "username_designations": 2, "password_designations": 4, "unknown_designations": 4, "empty_designations": 2, "missing_designations": 4, "repeated_designations": 2, "type_attributes": 6, "field_type_attributes": 4, "both_type_attributes": 2, "different_type_attributes": 2, "missing_types": 8, "string_values": 4, "null_values": 2, "number_values": 2, "array_values": 2, "object_values": 2, "boolean_values": 2, "missing_values": 2}
	for key, n := range want {
		if got[key] != float64(n) {
			t.Fatalf("%s count: %v want %d", key, got[key], n)
		}
	}
	if strings.Contains(string(raw), "private-") || report.MappingVerified || report.UnmappedItems != 2 {
		t.Fatal("private data or mapping claim in report")
	}
	for _, reason := range []string{"login-fields-unmapped", "login-field-semantics-unverified", "repeated-login-designation", "unknown-login-designation", "login-type-attributes-differ"} {
		if !contains(report.ReviewReasons, reason) {
			t.Fatal("missing review reason", reason)
		}
	}
}

func TestLoginFieldsRejectMalformed(t *testing.T) {
	for _, fields := range []any{nil, "private-value", []any{nil}, []any{3}, []any{map[string]any{"designation": nil}}, []any{map[string]any{"designation": 1}}, []any{map[string]any{"name": false}}, []any{map[string]any{"id": []any{}}}, []any{map[string]any{"type": nil}}, []any{map[string]any{"fieldType": map[string]any{}}}} {
		refuse(t, pack(t, attributes, fileData(t, loginItem("valid", []any{map[string]any{"value": "private-secret"}}), loginItem("i", fields))), ErrInvalid)
	}
}

func TestLoginFieldsLiteralMetadataAndEmptyLists(t *testing.T) {
	fields := []any{
		map[string]any{"id": "x", "name": "X", "designation": "private-unknown", "type": "private-type", "fieldType": "private-type", "value": ""},
		map[string]any{"id": "X", "name": "x", "designation": "private-unknown", "type": "", "fieldType": "", "value": false},
		map[string]any{"id": "x", "name": "X", "designation": "private-unknown", "type": "P", "fieldType": "p"},
		map[string]any{"designation": " username ", "type": "TEL"},
		map[string]any{"designation": ""}, map[string]any{"designation": ""}, map[string]any{}, map[string]any{},
	}
	report, err := Inspect(pack(t, attributes, fileData(t, loginItem("i", fields))))
	if err != nil {
		t.Fatal(err)
	}
	r := report.LoginFieldInventory
	if r.Fields != 8 || r.RepeatedNames != 1 || r.RepeatedIDs != 1 || r.UnknownDesignations != 4 || r.RepeatedDesignations != 2 || r.EmptyDesignations != 2 || r.MissingDesignations != 2 || r.UsernameDesignations != 0 || r.BothTypeAttributes != 3 || r.DifferentTypeAttributes != 1 || r.TypeAttributes != 4 || r.FieldTypeAttributes != 3 || r.MissingTypes != 4 {
		t.Fatal("literal metadata was normalized or merged", r)
	}
	for _, item := range []map[string]any{loginItem("i", []any{}), sectionItem("i", []any{})} {
		report, err := Inspect(pack(t, attributes, fileData(t, item)))
		if err != nil || report.LoginFieldInventory != (LoginFieldReport{}) || contains(report.ReviewReasons, "login-fields-unmapped") {
			t.Fatal("missing/empty login list invented fields", err)
		}
	}
}

func TestLoginFieldsSharedBudget(t *testing.T) {
	fields := make([]any, MaxObjects)
	for i := range fields {
		fields[i] = map[string]any{}
	}
	if _, err := Inspect(pack(t, attributes, fileData(t, loginItem("i", fields)))); err != nil {
		t.Fatal("exact limit rejected", err)
	}
	refuse(t, pack(t, attributes, fileData(t, loginItem("i", append(fields, map[string]any{})))), ErrLimit)
	// Cross-item order must not let either structure evade the shared budget.
	section := sectionItem("s", []any{map[string]any{"fields": []any{}}})
	for _, items := range [][]map[string]any{{loginItem("i", fields), section}, {section, loginItem("i", fields)}} {
		refuse(t, pack(t, attributes, fileData(t, items...)), ErrLimit)
	}
	// Count actual section fields too, and accept the exact combined boundary.
	section = sectionItem("s", []any{map[string]any{"fields": []any{map[string]any{}}}})
	for _, items := range [][]map[string]any{{loginItem("i", fields[:MaxObjects-2]), section}, {section, loginItem("i", fields[:MaxObjects-2])}} {
		if _, err := Inspect(pack(t, attributes, fileData(t, items...))); err != nil {
			t.Fatal("combined exact limit rejected", err)
		}
	}
	refuse(t, pack(t, attributes, fileData(t, loginItem("i", fields[:MaxObjects-1]), section)), ErrLimit)
}

func FuzzLoginFieldsInventory(f *testing.F) {
	f.Add([]byte(`[{"designation":"username","type":"T","value":"private-value"},{"designation":"username","fieldType":"P"}]`))
	f.Add([]byte(`[{}, {"designation":null}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"i","categoryUuid":"001","state":"active","details":{"loginFields":` + string(raw) + `}}]}]}]}`
		report, err := Inspect(pack(t, attributes, data))
		if err != nil {
			if report.Version != 0 {
				t.Fatal("partial report")
			}
			return
		}
		r := report.LoginFieldInventory
		if r.Fields != r.MissingValues+r.NullValues+r.ObjectValues+r.ArrayValues+r.StringValues+r.NumberValues+r.BooleanValues || r.Fields != r.UsernameDesignations+r.PasswordDesignations+r.UnknownDesignations+r.EmptyDesignations+r.MissingDesignations || r.TypeAttributes+r.FieldTypeAttributes-r.BothTypeAttributes+r.MissingTypes != r.Fields || r.RepeatedDesignations > r.UsernameDesignations+r.PasswordDesignations+r.UnknownDesignations || r.RepeatedNames+r.UnnamedFields > r.Fields || r.RepeatedIDs+r.UnidentifiedFields > r.Fields || r.DifferentTypeAttributes > r.BothTypeAttributes || r.Fields+report.SectionInventory.Fields+report.SectionInventory.Sections > MaxObjects || report.MappingVerified {
			t.Fatal("invalid login field invariants")
		}
	})
}
