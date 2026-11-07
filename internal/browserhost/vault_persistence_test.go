package browserhost

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// These tests pin the durable browser data model: every item-create /
// item-edit / item-state call must land in the same vault.Item records the
// desktop vault reads, with no process-local metadata overlay.

func browserPersistenceFixture(t *testing.T) (*Connection, *memoryPipe, *personal.Session, string, []byte, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2-persist.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if e := personal.Create(path, "persistence", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("persistence"), key, 2*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e := c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	return c, out, s, path, key, out.responses(t)[0].Capability
}

func reopenBrowserPersistence(t *testing.T, path string, key []byte) (*Connection, *memoryPipe, *personal.Session, string) {
	t.Helper()
	s, e := personal.UnlockSession(path, []byte("persistence"), key, 2*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if e := c.Handle(Request{V: 1, ID: reqID(2), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	return c, out, s, out.responses(t)[0].Capability
}

func createV2ThroughBrowser(t *testing.T, c *Connection, out *memoryPipe, cap string, seq int, itemJSON string) Response {
	t.Helper()
	created := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(seq), "type": "item-create", "capability": cap, "item_json": itemJSON})
	if created.Type != "item-saved" || created.ItemID == "" || created.Revision == "" {
		t.Fatalf("item-create refused: %#v", created)
	}
	return created
}

func editV2ThroughBrowser(t *testing.T, c *Connection, out *memoryPipe, cap string, seq int, id, revision, itemJSON string) Response {
	t.Helper()
	return v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(seq), "type": "item-edit", "capability": cap, "item_id": id, "revision": revision, "item_json": itemJSON})
}

func TestBrowserCreatePersistsWholeDurableItem(t *testing.T) {
	c, out, s, path, key, cap := browserPersistenceFixture(t)
	loginJSON := `{"category":"login","title":"Popup Login","username":"popup-user","password":"popup-pass","url":"https://popup.example.test","otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","tags":["work"],"sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f1","label":"Code","type":"concealed","value":"secret-code"}]}]}`
	login := createV2ThroughBrowser(t, c, out, cap, 10, loginJSON)
	loginDetail, e := s.GetItemDetail(login.ItemID, login.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if loginDetail.Kind != "login" || loginDetail.Category != vault.CategoryLogin || loginDetail.Password != "popup-pass" || loginDetail.OTP == "" {
		t.Fatalf("durable login lost fields: %#v", loginDetail)
	}
	if len(loginDetail.Tags) != 1 || loginDetail.Tags[0] != "work" {
		t.Fatalf("durable login tags: %#v", loginDetail.Tags)
	}
	if len(loginDetail.Sections) != 1 || len(loginDetail.Sections[0].Fields) != 1 || loginDetail.Sections[0].Fields[0].Value != "secret-code" || !loginDetail.Sections[0].Fields[0].Protected {
		t.Fatalf("durable login sections: %#v", loginDetail.Sections)
	}

	// The extension form uses short category aliases; they must land as the
	// canonical durable category, with no placeholder password.
	cardJSON := `{"category":"card","title":"Personal Visa","credit_card":{"cardholder_name":"Alice Smith","type":"visa","number":"4242424242424242","verification":"123","expiry_date":"2028-12","pin":"4321","issuing_bank":"Example Bank"}}`
	card := createV2ThroughBrowser(t, c, out, cap, 11, cardJSON)
	cardDetail, e := s.GetItemDetail(card.ItemID, card.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if cardDetail.Category != vault.CategoryCreditCard || cardDetail.Kind != string(vault.CategoryCreditCard) {
		t.Fatalf("durable card category: %#v", cardDetail)
	}
	if cardDetail.Password != "" {
		t.Fatal("non-login category stored a random password placeholder")
	}
	if cardDetail.CreditCard == nil || cardDetail.CreditCard.Number != "4242424242424242" || cardDetail.CreditCard.Verification != "123" || cardDetail.CreditCard.PIN != "4321" || cardDetail.CreditCard.CardholderName != "Alice Smith" {
		t.Fatalf("durable card fields: %#v", cardDetail.CreditCard)
	}

	identityJSON := `{"category":"identity","title":"Alice Home","identity":{"first_name":"Alice","last_name":"Smith","email":"alice@example.com","city":"Springfield"}}`
	identity := createV2ThroughBrowser(t, c, out, cap, 12, identityJSON)
	identityDetail, e := s.GetItemDetail(identity.ItemID, identity.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if identityDetail.Identity == nil || identityDetail.Identity.Email != "alice@example.com" || identityDetail.Identity.FirstName != "Alice" {
		t.Fatalf("durable identity fields: %#v", identityDetail.Identity)
	}

	// Desktop listing reads the same durable model, not a browser overlay.
	all, e := s.ListByFilter(personal.ItemFilter{State: "all"})
	if e != nil {
		t.Fatal(e)
	}
	categories := map[vault.ItemCategory]bool{}
	for _, row := range all {
		categories[row.Category] = true
	}
	for _, want := range []vault.ItemCategory{vault.CategoryLogin, vault.CategoryCreditCard, vault.CategoryIdentity} {
		if !categories[want] {
			t.Fatalf("durable list missing %s: %#v", want, all)
		}
	}

	// Reopen: durable rich fields and masking must survive a restart.
	s.Lock()
	c2, out2, s2, cap2 := reopenBrowserPersistence(t, path, key)
	_ = s2
	loginAfter := v2Handle(t, c2, out2, map[string]any{"v": 1, "id": reqID(13), "type": "item-get", "capability": cap2, "item_id": login.ItemID, "revision": login.Revision})
	if loginAfter.Item == nil || loginAfter.Item.Category != "login" || !loginAfter.Item.HasPassword || !loginAfter.Item.HasOTP {
		t.Fatalf("reopened login detail: %#v", loginAfter.Item)
	}
	if len(loginAfter.Item.Sections) != 1 || loginAfter.Item.Sections[0].Fields[0].Value != "" || !loginAfter.Item.Sections[0].Fields[0].Concealed {
		t.Fatalf("concealed custom field not masked after reopen: %#v", loginAfter.Item.Sections)
	}
	cardAfter := v2Handle(t, c2, out2, map[string]any{"v": 1, "id": reqID(14), "type": "item-get", "capability": cap2, "item_id": card.ItemID, "revision": card.Revision})
	if cardAfter.Item == nil || cardAfter.Item.CreditCard == nil || cardAfter.Item.CreditCard.Last4 != "4242" || !cardAfter.Item.CreditCard.HasCVV || !cardAfter.Item.CreditCard.HasPIN {
		t.Fatalf("reopened card detail: %#v", cardAfter.Item)
	}
	raw, _ := json.Marshal(cardAfter.Item)
	for _, secret := range []string{"4242424242424242", `"123"`, "4321"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("reopened card detail leaked %q", secret)
		}
	}
}

func TestBrowserEditPreservesProtectedFieldsAndRefusesPartialWrites(t *testing.T) {
	c, out, s, _, _, cap := browserPersistenceFixture(t)
	cardJSON := `{"category":"credit_card","title":"Personal Visa","credit_card":{"cardholder_name":"Alice Smith","type":"visa","number":"4242424242424242","verification":"123","expiry_date":"2028-12","pin":"4321"}}`
	card := createV2ThroughBrowser(t, c, out, cap, 20, cardJSON)
	editJSON := `{"category":"credit_card","title":"Personal Visa Renamed","credit_card":{"cardholder_name":"Alice B Smith"}}`
	edited := editV2ThroughBrowser(t, c, out, cap, 21, card.ItemID, card.Revision, editJSON)
	if edited.Type != "item-saved" || edited.Revision == card.Revision {
		t.Fatalf("card edit: %#v", edited)
	}
	cardDetail, e := s.GetItemDetail(card.ItemID, edited.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if cardDetail.Title != "Personal Visa Renamed" {
		t.Fatalf("card title not edited: %#v", cardDetail)
	}
	if cardDetail.CreditCard == nil || cardDetail.CreditCard.CardholderName != "Alice B Smith" || cardDetail.CreditCard.Number != "4242424242424242" || cardDetail.CreditCard.Verification != "123" || cardDetail.CreditCard.PIN != "4321" {
		t.Fatalf("card edit dropped protected fields: %#v", cardDetail.CreditCard)
	}

	// A stale revision must not partially apply.
	stale := editV2ThroughBrowser(t, c, out, cap, 22, card.ItemID, card.Revision, editJSON)
	if stale.Type != "error" || stale.Error != "refused" {
		t.Fatalf("stale edit not refused: %#v", stale)
	}
	afterStale, e := s.GetItemDetail(card.ItemID, edited.Revision, true)
	if e != nil || afterStale.Title != "Personal Visa Renamed" {
		t.Fatalf("stale edit mutated the item: %#v %v", afterStale, e)
	}

	// A masked concealed section value echoed by the client keeps the durable
	// secret instead of clearing it.
	loginJSON := `{"category":"login","title":"Popup Login","username":"popup-user","password":"popup-pass","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f1","label":"Code","type":"concealed","value":"secret-code"}]}]}`
	login := createV2ThroughBrowser(t, c, out, cap, 23, loginJSON)
	echoJSON := `{"category":"login","title":"Popup Login Renamed","sections":[{"id":"sec1","title":"Recovery","fields":[{"id":"f1","label":"Code","type":"concealed","value":""}]}]}`
	loginEdited := editV2ThroughBrowser(t, c, out, cap, 24, login.ItemID, login.Revision, echoJSON)
	if loginEdited.Type != "item-saved" {
		t.Fatalf("login edit: %#v", loginEdited)
	}
	loginDetail, e := s.GetItemDetail(login.ItemID, loginEdited.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if loginDetail.Password != "popup-pass" {
		t.Fatalf("login edit dropped the stored password: %#v", loginDetail)
	}
	if len(loginDetail.Sections) != 1 || len(loginDetail.Sections[0].Fields) != 1 || loginDetail.Sections[0].Fields[0].Value != "secret-code" {
		t.Fatalf("masked round-trip cleared a concealed field: %#v", loginDetail.Sections)
	}

	// Invalid OTP and notes are refused before any mutation lands.
	badOTP := `{"category":"login","title":"Popup Login Renamed","otp":"not-a-totp-seed"}`
	if refused := editV2ThroughBrowser(t, c, out, cap, 25, login.ItemID, loginEdited.Revision, badOTP); refused.Type != "error" {
		t.Fatalf("invalid otp accepted: %#v", refused)
	}
	badNotes := `{"category":"login","title":"Popup Login Renamed","notes":"bad\u0000notes"}`
	if refused := editV2ThroughBrowser(t, c, out, cap, 26, login.ItemID, loginEdited.Revision, badNotes); refused.Type != "error" {
		t.Fatalf("invalid notes accepted: %#v", refused)
	}
	afterRefusals, e := s.GetItemDetail(login.ItemID, loginEdited.Revision, true)
	if e != nil {
		t.Fatalf("refused edits changed the revision: %v", e)
	}
	if afterRefusals.OTP != "" || afterRefusals.Notes != "" || afterRefusals.Title != "Popup Login Renamed" {
		t.Fatalf("refused edits partially mutated: %#v", afterRefusals)
	}

	// An explicit empty OTP clears the stored seed.
	otpJSON := `{"category":"login","title":"Popup Login Renamed","otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}`
	withOTP := editV2ThroughBrowser(t, c, out, cap, 27, login.ItemID, loginEdited.Revision, otpJSON)
	if withOTP.Type != "item-saved" {
		t.Fatalf("otp set: %#v", withOTP)
	}
	clearOTP := `{"category":"login","title":"Popup Login Renamed","otp":""}`
	cleared := editV2ThroughBrowser(t, c, out, cap, 28, login.ItemID, withOTP.Revision, clearOTP)
	if cleared.Type != "item-saved" {
		t.Fatalf("otp clear: %#v", cleared)
	}
	clearedDetail, e := s.GetItemDetail(login.ItemID, cleared.Revision, true)
	if e != nil || clearedDetail.OTP != "" {
		t.Fatalf("explicit empty otp did not clear: %#v %v", clearedDetail, e)
	}
}

func TestBrowserFavoritePersistsAcrossReopen(t *testing.T) {
	c, out, s, path, key, cap := browserPersistenceFixture(t)
	login := createV2ThroughBrowser(t, c, out, cap, 30, `{"category":"login","title":"Fav Login","username":"fav","password":"fav-pass"}`)
	favorite := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(31), "type": "item-state", "capability": cap, "item_id": login.ItemID, "revision": login.Revision, "state_action": "favorite"})
	if favorite.Type != "item-saved" || !favorite.Favorite || favorite.Revision == "" || favorite.Revision == login.Revision {
		t.Fatalf("favorite: %#v", favorite)
	}
	detail, e := s.GetItemDetail(login.ItemID, favorite.Revision, true)
	if e != nil || !detail.Favorite {
		t.Fatalf("favorite not durable: %#v %v", detail, e)
	}
	want := true
	rows, e := s.ListByFilter(personal.ItemFilter{State: "all", Favorite: &want})
	if e != nil || len(rows) != 1 || rows[0].ID != login.ItemID {
		t.Fatalf("favorite filter: %#v %v", rows, e)
	}

	s.Lock()
	c2, out2, s2, cap2 := reopenBrowserPersistence(t, path, key)
	after := v2Handle(t, c2, out2, map[string]any{"v": 1, "id": reqID(32), "type": "item-get", "capability": cap2, "item_id": login.ItemID, "revision": favorite.Revision})
	if after.Item == nil || !after.Item.Favorite {
		t.Fatalf("favorite lost on reopen: %#v", after.Item)
	}

	unfavorite := v2Handle(t, c2, out2, map[string]any{"v": 1, "id": reqID(33), "type": "item-state", "capability": cap2, "item_id": login.ItemID, "revision": favorite.Revision, "state_action": "unfavorite"})
	if unfavorite.Type != "item-saved" || unfavorite.Favorite || unfavorite.Revision == favorite.Revision {
		t.Fatalf("unfavorite: %#v", unfavorite)
	}
	reopenedDetail, e := s2.GetItemDetail(login.ItemID, unfavorite.Revision, true)
	if e != nil || reopenedDetail.Favorite {
		t.Fatalf("unfavorite not durable: %#v %v", reopenedDetail, e)
	}
}
