package browserhost

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestConcealedFieldHasValueFlag asserts the popup can tell an empty concealed
// field from a stored-but-masked one over real native frames, without the
// secret ever entering the response.
func TestConcealedFieldHasValueFlag(t *testing.T) {
	d, _, _ := attachmentFixture(t)
	created := d.call(map[string]any{"type": "item-create", "item_json": `{"category":"login","title":"Flag host","username":"flag-user","password":"flag-pass","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Code","type":"concealed","value":"top-secret"},{"id":"f-empty","label":"Empty code","type":"concealed","value":""},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`})
	if created.Type != "item-saved" {
		t.Fatalf("create: %#v", created)
	}
	itemID, rev := created.ItemID, created.Revision
	get := func() (BrowserItemDetail, map[string]any) {
		t.Helper()
		detail := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": rev})
		if detail.Type != "item-detail" || detail.Item == nil {
			t.Fatalf("item-get: %#v", detail)
		}
		raw, e := json.Marshal(detail.Item)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("top-secret")) {
			t.Fatal("item detail leaked the concealed value")
		}
		var wire map[string]any
		if e := json.Unmarshal(raw, &wire); e != nil {
			t.Fatal(e)
		}
		return *detail.Item, wire
	}
	detail, wire := get()
	fields := map[string]BrowserCustomField{}
	for _, f := range detail.Sections[0].Fields {
		fields[f.ID] = f
		if f.ID != "f-plain" && f.Value != "" {
			t.Fatalf("concealed field %s carried a value", f.ID)
		}
	}
	if f := fields["f-secret"]; !f.HasValue || !f.Concealed || f.Value != "" {
		t.Fatalf("stored concealed field flag: %#v", f)
	}
	if f := fields["f-empty"]; f.HasValue || !f.Concealed {
		t.Fatalf("empty concealed field flag: %#v", f)
	}
	if f := fields["f-plain"]; !f.HasValue || f.Concealed || f.Value != "visible" {
		t.Fatalf("plain field flag: %#v", f)
	}
	// The wire shape hides the empty field's flag entirely.
	rawFields := wire["sections"].([]any)[0].(map[string]any)["fields"].([]any)
	for _, entry := range rawFields {
		field := entry.(map[string]any)
		if field["id"] == "f-secret" && field["has_value"] != true {
			t.Fatalf("has_value missing on the stored secret: %v", field)
		}
		if field["id"] == "f-empty" {
			if _, ok := field["has_value"]; ok {
				t.Fatalf("empty concealed field advertised has_value: %v", field)
			}
		}
	}

	// An explicit clear drops the flag on the next read.
	cleared := d.call(map[string]any{"type": "item-edit", "item_id": itemID, "revision": rev, "item_json": `{"category":"login","title":"Flag host","clear_fields":["section:sec1:f-secret"],"sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Code","type":"concealed"},{"id":"f-empty","label":"Empty code","type":"concealed"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`})
	if cleared.Type != "item-saved" {
		t.Fatalf("clear: %#v", cleared)
	}
	rev = cleared.Revision
	detail, _ = get()
	for _, f := range detail.Sections[0].Fields {
		if f.ID == "f-secret" && f.HasValue {
			t.Fatalf("cleared concealed field still reports has_value: %#v", f)
		}
	}
}
