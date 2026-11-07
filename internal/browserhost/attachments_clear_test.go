package browserhost

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestExplicitClearAndMaskedSectionPreservation(t *testing.T) {
	d, _, _ := attachmentFixture(t)
	createJSON := `{"category":"login","title":"Clear host","username":"clear-user","password":"clear-pass","notes":"saved note","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Recovery code","type":"concealed","value":"top-secret"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`
	created := d.call(map[string]any{"type": "item-create", "item_json": createJSON})
	if created.Type != "item-saved" || created.ItemID == "" {
		t.Fatalf("create: %#v", created)
	}
	itemID, rev := created.ItemID, created.Revision
	field := func(name string) string {
		t.Helper()
		resp := d.call(map[string]any{"type": "item-copy-field", "item_id": itemID, "revision": rev, "field": name})
		if resp.Type != "field-value" {
			t.Fatalf("copy %s: %#v", name, resp)
		}
		return resp.FieldValue
	}
	edit := func(item string) Response {
		return d.call(map[string]any{"type": "item-edit", "item_id": itemID, "revision": rev, "item_json": item})
	}
	if field("notes") != "saved note" || field("section:sec1:f-secret") != "top-secret" || field("section:sec1:f-plain") != "visible" {
		t.Fatal("create did not store notes and masked sections")
	}

	// A metadata-only edit preserves notes and both custom fields.
	edited := edit(`{"category":"login","title":"Clear host renamed"}`)
	if edited.Type != "item-saved" || edited.Revision == rev {
		t.Fatalf("metadata edit: %#v", edited)
	}
	rev = edited.Revision
	if field("notes") != "saved note" || field("section:sec1:f-secret") != "top-secret" || field("section:sec1:f-plain") != "visible" {
		t.Fatal("metadata-only edit lost durable data")
	}

	// Reclassifying a concealed field as plaintext is refused without mutating.
	downgrade := edit(`{"category":"login","title":"Clear host renamed","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Recovery code","type":"text"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`)
	if downgrade.Type != "error" {
		t.Fatalf("concealed to text reclassification accepted: %#v", downgrade)
	}
	detail := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": rev})
	if detail.Item == nil || len(detail.Item.Sections) != 1 || len(detail.Item.Sections[0].Fields) != 2 {
		t.Fatalf("refused downgrade mutated the sections: %#v", detail.Item)
	}
	dump, e := json.Marshal(detail.Item)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(dump, []byte("top-secret")) {
		t.Fatal("item detail disclosed the concealed value")
	}
	if field("section:sec1:f-secret") != "top-secret" {
		t.Fatal("refused downgrade changed the concealed value")
	}
	// Dropping the concealed flag implicitly is the same downgrade.
	implicit := edit(`{"category":"login","title":"Clear host renamed","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Recovery code"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`)
	if implicit.Type != "error" {
		t.Fatalf("implicit concealed downgrade accepted: %#v", implicit)
	}

	// OTP/TOTP typed fields may not be downgraded to plaintext either.
	otpCreated := d.call(map[string]any{"type": "item-create", "item_json": `{"category":"login","title":"OTP host","username":"otp-user","password":"otp-pass","sections":[{"id":"sec2","title":"Seeds","fields":[{"id":"f-otp","label":"Seed","type":"otp","value":"JBSWY3DPEHPK3PXP"}]}]}`})
	if otpCreated.Type != "item-saved" {
		t.Fatalf("otp create: %#v", otpCreated)
	}
	if refused := d.call(map[string]any{"type": "item-edit", "item_id": otpCreated.ItemID, "revision": otpCreated.Revision, "item_json": `{"category":"login","title":"OTP host","sections":[{"id":"sec2","title":"Seeds","fields":[{"id":"f-otp","label":"Seed","type":"text","value":""}]}]}`}); refused.Type != "error" {
		t.Fatalf("otp to text downgrade accepted: %#v", refused)
	}
	// An omitted value for a stable id that exists nowhere is refused.
	if unknown := edit(`{"category":"login","title":"Clear host renamed","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-new","label":"New"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`); unknown.Type != "error" {
		t.Fatalf("omitted value for an unknown field accepted: %#v", unknown)
	}

	// Explicit clears land in the same whole-item transaction.
	clearJSON := `{"category":"login","title":"Clear host renamed","clear_fields":["notes","section:sec1:f-secret"],"sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f-secret","label":"Recovery code","type":"concealed"},{"id":"f-plain","label":"Hint","type":"text","value":"visible"}]}]}`
	cleared := edit(clearJSON)
	if cleared.Type != "item-saved" || cleared.Revision == rev {
		t.Fatalf("clear: %#v", cleared)
	}
	rev = cleared.Revision
	if field("notes") != "" || field("section:sec1:f-secret") != "" {
		t.Fatal("explicit clear did not empty the targets")
	}
	if field("section:sec1:f-plain") != "visible" {
		t.Fatal("explicit clear blanked an unrelated visible field")
	}
	// Clearing notes that are already empty still preserves the rest.
	again := edit(`{"category":"login","title":"Clear host renamed","clear_fields":["notes"]}`)
	if again.Type != "item-saved" {
		t.Fatalf("second notes clear: %#v", again)
	}
	rev = again.Revision

	// Refusals: stale revision, unknown and non-concealed targets, contradictory
	// notes, duplicate keys.
	if stale := d.call(map[string]any{"type": "item-edit", "item_id": itemID, "revision": created.Revision, "item_json": `{"category":"login","title":"stale","clear_fields":["notes"]}`}); stale.Type != "error" {
		t.Fatalf("stale clear accepted: %#v", stale)
	}
	for _, key := range []string{"section:sec1:missing", "section:sec1:f-plain", "unknown"} {
		if refused := edit(`{"category":"login","title":"Clear host renamed","clear_fields":["` + key + `"]}`); refused.Type != "error" {
			t.Fatalf("clear target %q accepted: %#v", key, refused)
		}
	}
	if contradictory := edit(`{"category":"login","title":"Clear host renamed","notes":"new note","clear_fields":["notes"]}`); contradictory.Type != "error" {
		t.Fatalf("contradictory notes clear accepted: %#v", contradictory)
	}
	if duplicate := edit(`{"category":"login","title":"Clear host renamed","clear_fields":["notes","notes"]}`); duplicate.Type != "error" {
		t.Fatalf("duplicate clear keys accepted: %#v", duplicate)
	}
	final := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": rev})
	if final.Item == nil || final.Item.Title != "Clear host renamed" || len(final.Item.Sections) != 1 || len(final.Item.Sections[0].Fields) != 2 {
		t.Fatalf("refused clears mutated the item: %#v", final.Item)
	}
}
