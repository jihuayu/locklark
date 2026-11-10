package browserhost

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func v2Fixture(t *testing.T) (*Connection, *memoryPipe, *personal.Session, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2.ll")
	key := bytes.Repeat([]byte{5}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Existing", "alice", "old-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e := c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApproveQuickPair(s); e != nil {
		t.Fatal(e)
	}
	cap := out.responses(t)[0].Capability
	return c, out, s, cap
}

func mustReadRequest(t *testing.T, value map[string]any) Request {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	r, e := ReadRequest(bytes.NewReader(frame(string(raw))))
	if e != nil {
		t.Fatalf("read request %s: %v", raw, e)
	}
	return r
}

func v2Handle(t *testing.T, c *Connection, out *memoryPipe, value map[string]any) Response {
	t.Helper()
	v2Send(t, c, value)
	return v2Last(t, out)
}

func v2Send(t *testing.T, c *Connection, value map[string]any) {
	t.Helper()
	r := mustReadRequest(t, value)
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
}

func v2Last(t *testing.T, out *memoryPipe) Response {
	t.Helper()
	all := out.responses(t)
	if len(all) == 0 {
		t.Fatal("no response")
	}
	return all[len(all)-1]
}

func TestGenerateModesAndRedaction(t *testing.T) {
	c, out, _, cap := v2Fixture(t)
	random := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(10), "type": "generate", "capability": cap, "mode": "random", "length": 24, "digits": true, "symbols": true})
	if random.Type != "generated" || len(random.GeneratedPassword) != 24 || random.PasswordProfile == nil || random.PasswordProfile.Mode != "random" || random.HistoryID == "" {
		t.Fatalf("random: %#v", random)
	}
	if token.MatchString(random.HistoryID) == false {
		t.Fatal("history id")
	}
	optionsJSON := `{"mode":"random","length":18,"digits":true,"symbols":false}`
	options := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(11), "type": "generate", "capability": cap, "options": optionsJSON})
	if options.Type != "generated" || len(options.GeneratedPassword) != 18 || options.PasswordProfile == nil || options.PasswordProfile.Length != 18 {
		t.Fatalf("options random: %#v", options)
	}
	memorable := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(12), "type": "generate", "capability": cap, "options": `{"mode":"memorable","length":5,"capitalize":true}`})
	if memorable.Type != "generated" || strings.Count(memorable.GeneratedPassword, "-") != 4 || memorable.PasswordProfile.Mode != "memorable" {
		t.Fatalf("memorable: %#v", memorable)
	}
	pin := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(13), "type": "generate", "capability": cap, "mode": "pin", "length": 6, "save_history": false})
	if pin.Type != "generated" || len(pin.GeneratedPassword) != 6 || pin.PasswordProfile.Mode != "pin" || pin.HistoryID != "" {
		t.Fatalf("pin: %#v", pin)
	}
	for _, r := range []Response{random, options, memorable, pin} {
		if strings.Contains(r.String(), r.GeneratedPassword) {
			t.Fatal("response formatting exposed a generated password")
		}
	}
	raw, e := json.Marshal(Response{V: 1, Type: "status", GeneratedPassword: "must-not-serialize"})
	if e != nil || bytes.Contains(raw, []byte("must-not-serialize")) || bytes.Contains(raw, []byte("generated_password")) {
		t.Fatal("non-generated response leaked generated_password")
	}
}

func TestStageSaveAcrossNavigationAndNeverSave(t *testing.T) {
	c, out, s, cap := v2Fixture(t)
	staged := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(20), "type": "stage-save", "capability": cap, "origin": "https://new.example.test", "tab_id": 1, "window_id": 1, "document_id": "doc-1", "username": "new-user", "password": "new-secret", "title": "New Site"})
	if staged.Type != "save-staged" || staged.StagedSave == nil || staged.StagedSave.Mode != "new" {
		t.Fatalf("stage new: %#v", staged)
	}
	stageID := staged.StagedSave.StageID
	pending := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(21), "type": "pending-save", "capability": cap, "origin": "https://new.example.test", "tab_id": 1, "window_id": 1})
	if pending.Type != "save-pending" || pending.StagedSave == nil || pending.StagedSave.StageID != stageID {
		t.Fatalf("pending: %#v", pending)
	}
	pendingRaw, _ := json.Marshal(pending)
	if bytes.Contains(pendingRaw, []byte("new-secret")) || bytes.Contains(pendingRaw, []byte(`"password"`)) {
		t.Fatal("pending save echoed the password")
	}
	saved := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(22), "type": "commit-staged-save", "capability": cap, "stage_id": stageID, "origin": "https://new.example.test", "tab_id": 1, "window_id": 1, "document_id": "doc-2"})
	if saved.Type != "saved" || saved.ItemID == "" || saved.Revision == "" {
		t.Fatalf("commit new: %#v", saved)
	}
	items, _, e := s.ActiveItems()
	if e != nil {
		t.Fatal(e)
	}
	foundNew := false
	for _, it := range items {
		if it.ID == saved.ItemID && it.Password == "new-secret" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Fatal("new login not persisted")
	}
	existingRow := items[0]
	for _, it := range items {
		if it.Username == "alice" {
			existingRow = it
		}
	}
	update := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(23), "type": "stage-save", "capability": cap, "origin": "https://example.test", "tab_id": 2, "window_id": 1, "document_id": "doc-3", "username": "alice", "password": "updated-secret"})
	if update.Type != "save-staged" || update.StagedSave.Mode != "update" || update.StagedSave.ExistingItemID != existingRow.ID {
		t.Fatalf("stage update: %#v", update)
	}
	updated := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(24), "type": "commit-staged-save", "capability": cap, "stage_id": update.StagedSave.StageID, "origin": "https://example.test", "tab_id": 2, "window_id": 1, "document_id": "doc-4"})
	if updated.Type != "saved" || updated.ItemID != existingRow.ID {
		t.Fatalf("commit update: %#v", updated)
	}
	items, _, e = s.ActiveItems()
	if e != nil {
		t.Fatal(e)
	}
	for _, it := range items {
		if it.ID == existingRow.ID && it.Password != "updated-secret" {
			t.Fatal("update did not persist")
		}
	}
	unchanged := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(25), "type": "stage-save", "capability": cap, "origin": "https://example.test", "tab_id": 3, "window_id": 1, "document_id": "doc-5", "username": "alice", "password": "updated-secret"})
	if unchanged.Type != "save-staged" || unchanged.StagedSave.Mode != "unchanged" {
		t.Fatalf("unchanged: %#v", unchanged)
	}
	dismissed := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(26), "type": "dismiss-save", "capability": cap, "origin": "https://never.example.test", "never_for_origin": true})
	if dismissed.Type != "save-dismissed" || len(dismissed.NeverOrigins) != 1 || dismissed.NeverOrigins[0] != "https://never.example.test" {
		t.Fatalf("dismiss: %#v", dismissed)
	}
	never := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(27), "type": "stage-save", "capability": cap, "origin": "https://never.example.test", "tab_id": 4, "window_id": 1, "document_id": "doc-6", "username": "blocked", "password": "blocked-secret"})
	if never.Type != "save-staged" || never.StagedSave.Mode != "never" {
		t.Fatalf("never: %#v", never)
	}
}

func TestPopupVaultCRUDAndProfileFill(t *testing.T) {
	c, out, s, cap := v2Fixture(t)
	loginJSON := `{"category":"login","title":"Popup Login","username":"popup-user","password":"popup-pass","url":"https://popup.example.test","otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f1","label":"Code","type":"concealed","value":"secret-code"}]}]}`
	created := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(30), "type": "item-create", "capability": cap, "item_json": loginJSON})
	if created.Type != "item-saved" || created.ItemID == "" || created.Revision == "" || created.ItemSummary == nil {
		t.Fatalf("create login: %#v", created)
	}
	loginID, loginRev := created.ItemID, created.Revision
	identityJSON := `{"category":"identity","title":"Alice Home","identity":{"first_name":"Alice","last_name":"Smith","email":"alice@example.com","phone":"+15551234567","address_line1":"1 Main St","city":"Springfield","state":"CA","postal_code":"90210","country":"US","birth_date":"1990-01-02"}}`
	identity := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(31), "type": "item-create", "capability": cap, "item_json": identityJSON})
	if identity.Type != "item-saved" {
		t.Fatalf("create identity: %#v", identity)
	}
	cardJSON := `{"category":"credit_card","title":"Personal Visa","credit_card":{"cardholder_name":"Alice Smith","type":"visa","number":"4242424242424242","verification":"123","expiry_date":"2028-12","pin":"4321","issuing_bank":"Example Bank"}}`
	card := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(32), "type": "item-create", "capability": cap, "item_json": cardJSON})
	if card.Type != "item-saved" {
		t.Fatalf("create card: %#v", card)
	}
	for _, kind := range []string{"search", "list", "vault-search", "vault-list"} {
		list := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(33 + len(kind)), "type": kind, "capability": cap, "query": "", "category": "all", "vault_id": "all"})
		if list.Type != "items" || len(list.Items) < 4 {
			t.Fatalf("%s: %#v", kind, list)
		}
	}
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(40), "type": "item-get", "capability": cap, "item_id": loginID, "revision": loginRev})
	if detail.Type != "item-detail" || detail.Item == nil {
		t.Fatalf("item-get: %#v", detail)
	}
	if detail.Item.Username != "popup-user" || !detail.Item.HasPassword || !detail.Item.HasOTP {
		t.Fatalf("detail fields: %#v", detail.Item)
	}
	if len(detail.Item.Sections) != 1 || len(detail.Item.Sections[0].Fields) != 1 || detail.Item.Sections[0].Fields[0].Value != "" || !detail.Item.Sections[0].Fields[0].Concealed {
		t.Fatalf("concealed section: %#v", detail.Item.Sections)
	}
	cardDetail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(41), "type": "item-get", "capability": cap, "item_id": card.ItemID, "revision": card.Revision})
	if cardDetail.Item == nil || cardDetail.Item.CreditCard == nil || cardDetail.Item.CreditCard.Last4 != "4242" {
		t.Fatalf("card detail: %#v", cardDetail.Item)
	}
	cardRaw, _ := json.Marshal(cardDetail.Item)
	if bytes.Contains(cardRaw, []byte("4242424242424242")) || bytes.Contains(cardRaw, []byte(`"123"`)) || bytes.Contains(cardRaw, []byte(`"pin":`)) {
		t.Fatal("item-get leaked full PAN, CVV or PIN")
	}
	if !strings.Contains(cardDetail.Item.CreditCard.MaskedNumber, "4242") || strings.Contains(cardDetail.Item.CreditCard.MaskedNumber, "4242424242424242") {
		t.Fatal("masked number")
	}
	for n, tc := range []struct {
		field  string
		want   string
		action string
	}{
		{"password", "popup-pass", "copy"},
		{"username", "popup-user", "reveal"},
		{"notes", "", "copy"},
		{"section:sec1:f1", "secret-code", "copy"},
	} {
		resp := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(100 + n), "type": "item-copy-field", "capability": cap, "item_id": loginID, "revision": loginRev, "field": tc.field, "action": tc.action})
		if resp.Type != "field-value" || resp.FieldValue != tc.want || resp.Field != tc.field {
			t.Fatalf("field %s: %#v", tc.field, resp)
		}
	}
	otp := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(50), "type": "item-reveal-field", "capability": cap, "item_id": loginID, "revision": loginRev, "field": "otp"})
	if otp.Type != "field-value" || len(otp.FieldValue) != 6 || otp.ExpiresInSeconds < 0 || otp.ExpiresInSeconds > 30 {
		t.Fatalf("otp field: %#v", otp)
	}
	ccNumber := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(51), "type": "item-copy-field", "capability": cap, "item_id": card.ItemID, "revision": card.Revision, "field": "cc-number"})
	if ccNumber.FieldValue != "4242424242424242" || !ccNumber.Copied {
		t.Fatalf("cc-number: %#v", ccNumber)
	}
	csc := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(52), "type": "item-copy-field", "capability": cap, "item_id": card.ItemID, "revision": card.Revision, "field": "cc-csc"})
	if csc.FieldValue != "123" {
		t.Fatalf("cc-csc: %#v", csc)
	}
	pin := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(53), "type": "item-copy-field", "capability": cap, "item_id": card.ItemID, "revision": card.Revision, "field": "cc-pin"})
	if pin.FieldValue != "4321" {
		t.Fatalf("cc-pin: %#v", pin)
	}

	editJSON := `{"category":"login","title":"Popup Login Renamed","username":"popup-user"}`
	edited := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(54), "type": "item-edit", "capability": cap, "item_id": loginID, "revision": loginRev, "item_json": editJSON})
	if edited.Type != "item-saved" || edited.Revision == loginRev {
		t.Fatalf("edit: %#v", edited)
	}
	loginRev = edited.Revision
	state := `{"v":1,"id":"` + reqID(55) + `","type":"item-state","capability":"` + cap + `","item_id":"` + loginID + `","revision":"` + loginRev + `","state_action":"favorite"}`
	favorite, e := ReadRequest(bytes.NewReader(frame(state)))
	if e != nil {
		t.Fatal(e)
	}
	if e := c.Handle(favorite); e != nil {
		t.Fatal(e)
	}
	fav := out.responses(t)
	if fav[len(fav)-1].Type != "item-saved" || !fav[len(fav)-1].Favorite {
		t.Fatalf("favorite: %#v", fav[len(fav)-1])
	}
	// Favorites are a durable whole-item mutation, so they advance the revision.
	loginRev = fav[len(fav)-1].Revision
	archived := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(56), "type": "item-state", "capability": cap, "item_id": loginID, "revision": loginRev, "state_action": "archive"})
	if archived.Type != "item-saved" || archived.State != "archived" {
		t.Fatalf("archive: %#v", archived)
	}

	profiles := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(57), "type": "match-profiles", "capability": cap, "origin": "https://shop.example.test", "tab_id": 7, "document_id": "doc-9", "profile_kind": "all"})
	if profiles.Type != "profiles" || len(profiles.Profiles) != 2 {
		t.Fatalf("profiles: %#v", profiles)
	}
	var ccProfile, identityProfile BrowserProfileSummary
	for _, p := range profiles.Profiles {
		if p.Category == "credit_card" {
			ccProfile = p
		}
		if p.Category == "identity" {
			identityProfile = p
		}
	}
	before := len(out.responses(t))
	v2Send(t, c, map[string]any{"v": 1, "id": reqID(58), "type": "fill-profile", "capability": cap, "origin": "https://shop.example.test", "tab_id": 7, "document_id": "doc-9", "item_id": ccProfile.ID, "revision": ccProfile.Revision})
	// A profile fill is public metadata until the native owner explicitly
	// approves this exact request; no private response may be written first.
	if len(out.responses(t)) != before {
		t.Fatal("profile fill answered before native approval")
	}
	view := c.Snapshot()
	if view.Profile == nil || view.Profile.ID != reqID(58) || view.Profile.ItemID != ccProfile.ID || view.Profile.Revision != ccProfile.Revision || view.Profile.Category != "credit_card" || view.Profile.Origin != "https://shop.example.test" {
		t.Fatalf("profile review: %#v", view.Profile)
	}
	if e := c.ApproveProfile(reqID(58)); e != nil {
		t.Fatal(e)
	}
	ccFill := v2Last(t, out)
	if ccFill.Type != "profile-fill" || ccFill.ProfileFill == nil {
		t.Fatalf("cc fill: %#v", ccFill)
	}
	for _, key := range []string{"cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-exp-year-short", "cc-csc", "cc-type"} {
		if ccFill.ProfileFill.Fields[key] == "" {
			t.Fatalf("cc fill missing %s: %#v", key, ccFill.ProfileFill.Fields)
		}
	}
	if ccFill.ProfileFill.Fields["cc-exp-month"] != "12" || ccFill.ProfileFill.Fields["cc-exp-year-short"] != "28" {
		t.Fatalf("cc expiry mapping: %#v", ccFill.ProfileFill.Fields)
	}
	if _, _, e := s.ActiveItems(); e != nil {
		t.Fatal(e)
	}
	v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(59), "type": "match-profiles", "capability": cap, "origin": "https://shop.example.test", "tab_id": 8, "document_id": "doc-10", "profile_kind": "identity"})
	before = len(out.responses(t))
	v2Send(t, c, map[string]any{"v": 1, "id": reqID(60), "type": "fill-profile", "capability": cap, "origin": "https://shop.example.test", "tab_id": 8, "document_id": "doc-10", "item_id": identityProfile.ID, "revision": identityProfile.Revision})
	if len(out.responses(t)) != before {
		t.Fatal("identity profile fill answered before native approval")
	}
	if e := c.ApproveProfile(reqID(60)); e != nil {
		t.Fatal(e)
	}
	idFill := v2Last(t, out)
	if idFill.Type != "profile-fill" || idFill.ProfileFill == nil {
		t.Fatalf("identity fill: %#v", idFill)
	}
	for _, key := range []string{"given-name", "family-name", "name", "email", "tel", "street-address", "address-level2", "postal-code", "country", "bday"} {
		if idFill.ProfileFill.Fields[key] == "" {
			t.Fatalf("identity fill missing %s: %#v", key, idFill.ProfileFill.Fields)
		}
	}
	if idFill.ProfileFill.Fields["given-name"] != "Alice" || idFill.ProfileFill.Fields["family-name"] != "Smith" {
		t.Fatalf("identity mapping: %#v", idFill.ProfileFill.Fields)
	}
	for _, kind := range []string{"watchtower", "watchtower-summary"} {
		watch := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(61 + len(kind)), "type": kind, "capability": cap, "origin": "https://popup.example.test"})
		if watch.Type != kind || watch.Watchtower == nil || watch.Watchtower.OverallScore < 0 || watch.Watchtower.OverallScore > 100 {
			t.Fatalf("%s: %#v", kind, watch)
		}
	}
}
