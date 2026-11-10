package browserhost

import "testing"

// The two-factor setup capture writes through item-save with an OTP-only
// mutation. This pins the native contract the extension depends on: the OTP is
// parsed before scheduling, every other field of the targeted login is carried
// over, and the signed revision advances.
func TestItemSaveOTPOnlyMutationPreservesLogin(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	revision := revisions[id]
	config := "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	response := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(20), "type": "item-save", "capability": capability,
		"item_id": id, "revision": revision,
		"item_json": `{"title":"Existing","category":"login","otp":"` + config + `"}`,
	})
	if response.Type != "item-saved" || response.ItemID != id || response.Revision == "" || response.Revision == revision {
		t.Fatalf("response: %+v", response)
	}
	detail, err := s.GetItemDetail(id, response.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if detail.OTP != config {
		t.Fatalf("otp not stored: %q", detail.OTP)
	}
	if detail.Username != "alice" || detail.Password != "old-password" {
		t.Fatalf("credentials were not preserved: %q %q", detail.Username, detail.Password)
	}
	if detail.Title != "Existing" || detail.URL != "https://example.test/login" {
		t.Fatalf("metadata was not preserved: %q %q", detail.Title, detail.URL)
	}
}

// An invalid or unsupported otpauth configuration must be refused before any
// write, leaving the revision unchanged.
func TestItemSaveRefusesInvalidOTPWithoutWriting(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	revision := revisions[id]
	response := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(21), "type": "item-save", "capability": capability,
		"item_id": id, "revision": revision,
		"item_json": `{"title":"Existing","category":"login","otp":"otpauth://hotp/ACME:john?secret=JBSWY3DPEHPK3PXP"}`,
	})
	if response.Type != "error" {
		t.Fatalf("response: %+v", response)
	}
	detail, err := s.GetItemDetail(id, revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if detail.OTP != "" {
		t.Fatalf("refused edit still wrote otp: %q", detail.OTP)
	}
}

// Custom sections survive an OTP-only mutation: the browser sends no sections,
// so the native merge must carry the encrypted section array over unchanged.
func TestItemSaveOTPOnlyKeepsCustomSections(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	created := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(22), "type": "item-save", "capability": capability,
		"item_json": `{"title":"With sections","category":"login","password":"secret-password","sections":[{"id":"sec1","title":"Extra","fields":[{"id":"f1","label":"Recovery","type":"text","value":"visible"}]}]}`,
	})
	if created.Type != "item-saved" || created.ItemID == "" {
		t.Fatalf("create: %+v", created)
	}
	config := "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	edited := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(23), "type": "item-save", "capability": capability,
		"item_id": created.ItemID, "revision": created.Revision,
		"item_json": `{"title":"With sections","category":"login","otp":"` + config + `"}`,
	})
	if edited.Type != "item-saved" {
		t.Fatalf("edit: %+v", edited)
	}
	detail, err := s.GetItemDetail(created.ItemID, edited.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if detail.OTP != config || detail.Password != "secret-password" {
		t.Fatalf("otp/password: %q %q", detail.OTP, detail.Password)
	}
	if len(detail.Sections) != 1 || len(detail.Sections[0].Fields) != 1 {
		t.Fatalf("sections: %+v", detail.Sections)
	}
	field := detail.Sections[0].Fields[0]
	if field.ID != "f1" || field.Value != "visible" {
		t.Fatalf("custom field: %+v", field)
	}
}

// A stale revision cannot save a captured TOTP over a newer edit.
func TestItemSaveOTPRefusesStaleRevision(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	stale := revisions[id]
	config := "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	first := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(24), "type": "item-save", "capability": capability,
		"item_id": id, "revision": stale,
		"item_json": `{"title":"Existing","category":"login","otp":"` + config + `"}`,
	})
	if first.Type != "item-saved" {
		t.Fatalf("first: %+v", first)
	}
	again := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(25), "type": "item-save", "capability": capability,
		"item_id": id, "revision": stale,
		"item_json": `{"title":"Existing","category":"login","otp":"` + config + `"}`,
	})
	if again.Type != "error" {
		t.Fatalf("stale edit accepted: %+v", again)
	}
}
