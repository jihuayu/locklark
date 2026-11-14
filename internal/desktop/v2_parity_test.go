package desktop

import (
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// v2ParityQueue captures the launched worker and the dispatched receipt so a
// test can hold a read in flight while the user changes the query.
type v2ParityQueue struct {
	work     []func()
	complete []func()
}

func v2ParityBusyApp(t *testing.T) (*App, *v2ParityQueue) {
	t.Helper()
	a := dailyAppFixture(t)
	a.EnableV2()
	q := &v2ParityQueue{}
	a.launch = func(fn func()) { q.work = append(q.work, fn) }
	a.dispatch = func(fn func()) { q.complete = append(q.complete, fn) }
	return a, q
}

func v2ParityRun(t *testing.T, q *v2ParityQueue, index int) {
	t.Helper()
	if index >= len(q.work) || index >= len(q.complete) {
		t.Fatalf("missing queued work at %d (work=%d complete=%d)", index, len(q.work), len(q.complete))
	}
	q.work[index]()
	q.complete[index]()
}

func v2ParityTitles(a *App) []string {
	out := make([]string, 0, len(a.v2.rows))
	for _, row := range a.v2.rows {
		out = append(out, row.Title)
	}
	return out
}

// TestV2SelectVaultReloadsList pins the sidebar contract: the public
// SelectVault refreshes the list for the new vault, the private helper alone
// does not (which is why the sidebar must call the public one).
func TestV2SelectVaultReloadsList(t *testing.T) {
	a := dailyAppFixture(t)
	a.EnableV2()
	bugfixAddLogin(t, a, "Alpha", "alpha-user", "alpha-password")

	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := a.session.RegisterMutation(g); err != nil {
		t.Fatal(err)
	}
	work, err := a.session.CreateVault("Work", "", "", g)
	a.session.ReleaseMutation(g)
	if err != nil {
		t.Fatal(err)
	}

	var launched int
	a.launch = func(fn func()) { launched++; fn() }
	a.dispatch = func(fn func()) { fn() }

	a.v2.vaultID = "all"
	a.selectVault(work.ID)
	if launched != 0 {
		t.Fatal("private selectVault reloaded the list; sidebar must call SelectVault")
	}

	a.SelectVault("all")
	if launched != 1 {
		t.Fatalf("SelectVault(all) launched %d reloads, want 1", launched)
	}
	if got := v2ParityTitles(a); len(got) != 1 || got[0] != "Alpha" {
		t.Fatalf("rows after SelectVault(all) = %v", got)
	}

	a.SelectVault(work.ID)
	if launched != 2 {
		t.Fatalf("SelectVault(vault) launched %d reloads, want 2", launched)
	}
	if got := v2ParityTitles(a); len(got) != 0 {
		t.Fatalf("rows after switching to empty vault = %v", got)
	}
}

// TestV2QueryChangeDuringBusyRejectsStaleSnapshotAndReplaysReload covers the
// stale-list finding: a reload requested while a read is in flight is kept
// (not dropped) and the snapshot started under the old filter is rejected.
func TestV2QueryChangeDuringBusyRejectsStaleSnapshotAndReplaysReload(t *testing.T) {
	a, q := v2ParityBusyApp(t)
	bugfixAddLogin(t, a, "Alpha", "user", "password")
	bugfixAddLogin(t, a, "Beta", "user", "password")

	a.reloadV2(false)
	if len(q.work) != 1 {
		t.Fatalf("reload queued %d workers, want 1", len(q.work))
	}
	if !a.busy {
		t.Fatal("reload did not mark the UI busy")
	}

	// The user types a search term while the unfiltered read is in flight.
	a.SetSearchQuery("Alpha")
	if !a.v2.pendingReload {
		t.Fatal("reload requested while busy was dropped instead of deferred")
	}
	if len(q.work) != 1 {
		t.Fatalf("a second read started while one was in flight (%d)", len(q.work))
	}

	// The stale (unfiltered) snapshot arrives on the UI goroutine. It must be
	// rejected, and the deferred reload must be replayed from that receipt.
	q.work[0]()
	q.complete[0]()
	if len(q.work) != 2 {
		t.Fatalf("deferred reload was not replayed (workers=%d)", len(q.work))
	}
	if a.v2.rows != nil {
		t.Fatalf("stale snapshot populated rows: %v", v2ParityTitles(a))
	}
	if a.rows != nil {
		t.Fatalf("stale snapshot leaked into legacy rows: %v", a.rows)
	}
	if a.v2.pendingReload {
		t.Fatal("deferred reload was neither replayed nor kept")
	}

	// Applying the replayed read yields only the filtered rows.
	q.work[1]()
	q.complete[1]()
	if got := v2ParityTitles(a); len(got) != 1 || got[0] != "Alpha" {
		t.Fatalf("rows after replay = %v, want [Alpha]", got)
	}
	if !strings.Contains(a.status, "1 个条目") {
		t.Fatalf("status after replay = %q", a.status)
	}
}

// TestV2SnapshotRejectedWithoutPendingReload checks the guard alone: an old
// snapshot cannot win against a newer filter even when nothing else is queued.
func TestV2SnapshotRejectedWithoutPendingReload(t *testing.T) {
	a := dailyAppFixture(t)
	a.EnableV2()
	bugfixAddLogin(t, a, "Alpha", "user", "password")

	var snap v2Snapshot
	query := a.currentV2Query()
	snap = a.captureV2(a.session, a.currentFilter())
	snap.query = query

	// A different query is now requested.
	a.v2.nav = navAllItems
	a.SetSearchQuery("Alpha")
	a.v2.querySeq++

	if a.applyV2Snapshot(snap, false) {
		t.Fatal("snapshot captured before the query change was accepted")
	}
	if a.v2.rows != nil {
		t.Fatalf("rejected snapshot still set rows: %v", v2ParityTitles(a))
	}
	if !strings.Contains(a.status, "搜索条件已变更") {
		t.Fatalf("stale rejection status = %q", a.status)
	}
}

// TestV2ConcealedValuesMaskedBeforeEmptiness covers the detail-pane masking
// finding: GetItemDetail(false) clears protected values, so an empty masked
// password/OTP must render as masked rather than "no value".
func TestV2ConcealedValuesMaskedBeforeEmptiness(t *testing.T) {
	masked := &personal.ItemDetail{
		ID:       "item-1",
		Title:    "Login",
		Category: vault.CategoryLogin,
		Username: "user",
		// A masked read returns empty strings for concealed values.
		Password: "",
		OTP:      "",
		Notes:    "",
		Sections: []vault.ItemSection{{
			ID:    "extra",
			Title: "Extra",
			Fields: []vault.CustomField{{
				ID: "pin", Label: "PIN", Type: vault.FieldTypeConcealed, Protected: true,
			}},
		}},
	}
	if got := v2FieldDisplay(masked, nil, "password", false); got != v2MaskedValue {
		t.Fatalf("masked password = %q, want %q", got, v2MaskedValue)
	}
	if got := v2FieldDisplay(masked, nil, "otp", false); got != v2MaskedValue {
		t.Fatalf("masked OTP = %q, want %q", got, v2MaskedValue)
	}
	if got := v2FieldDisplay(masked, nil, "notes", false); got != v2MaskedValue {
		t.Fatalf("masked notes = %q, want %q", got, v2MaskedValue)
	}
	if got := v2FieldDisplay(masked, nil, "extra/pin", false); got != v2MaskedValue {
		t.Fatalf("masked custom field = %q, want %q", got, v2MaskedValue)
	}
	// Non-secret values still render, and genuinely absent fields stay empty.
	if got := v2FieldDisplay(masked, nil, "username", false); got != "user" {
		t.Fatalf("username = %q", got)
	}
	if got := v2FieldDisplay(masked, nil, "url", false); got != v2EmptyValue {
		t.Fatalf("absent url = %q, want %q", got, v2EmptyValue)
	}

	// An implicit view never exposes an unmasked value even if one is cached,
	// and an explicit reveal uses the unmasked detail.
	plain := &personal.ItemDetail{ID: "item-1", Password: "secret", OTP: "otpauth://x", Sections: masked.Sections}
	plain.Sections[0].Fields[0].Value = "9999"
	if got := v2FieldDisplay(masked, plain, "password", false); got != v2MaskedValue {
		t.Fatalf("implicit view of cached plain password = %q", got)
	}
	if got := v2FieldDisplay(masked, plain, "password", true); got != "secret" {
		t.Fatalf("revealed password = %q", got)
	}
	if got := v2FieldDisplay(masked, plain, "extra/pin", true); got != "9999" {
		t.Fatalf("revealed custom field = %q", got)
	}
	// A revealed-but-empty field is empty, not masked.
	if got := v2FieldDisplay(masked, &personal.ItemDetail{ID: "item-1"}, "password", true); got != v2EmptyValue {
		t.Fatalf("revealed empty password = %q, want %q", got, v2EmptyValue)
	}
}

// TestV2DetailFieldMapping pins the detail rendering map: rich ItemModelV2
// values are rendered through the stable keys understood by fieldValue,
// revealField and copyField, and concealed keys are flagged.
func TestV2DetailFieldMapping(t *testing.T) {
	detail := &personal.ItemDetail{
		ID:       "item-2",
		Title:    "Card",
		Category: vault.CategoryCreditCard,
		URL:      "https://primary.example",
		URLs: []vault.ItemURL{
			{URL: "https://secondary.example", Label: "secondary", MatchMode: vault.URLMatchHost},
		},
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Ada Lovelace",
			Type:           "visa",
			Number:         "4111111111111111",
			Verification:   "123",
			ExpiryDate:     "2030-01",
			PIN:            "9999",
			IssuingBank:    "Bank",
		},
		Identity: &vault.IdentityDetails{FirstName: "Ada", Email: "ada@example.com"},
		Sections: []vault.ItemSection{{
			ID:    "extra",
			Title: "Extra",
			Fields: []vault.CustomField{
				{ID: "recovery", Label: "Recovery", Type: vault.FieldTypeString, Value: "code"},
				{ID: "seed", Label: "Seed", Type: vault.FieldTypeOTP, Value: "JBSWY3DPEHPK3PXP", Protected: true},
			},
		}},
	}

	fields := v2DetailFields(detail)
	index := map[string]v2DetailField{}
	for _, f := range fields {
		if _, dup := index[f.Key]; dup {
			t.Fatalf("duplicate detail key %q", f.Key)
		}
		index[f.Key] = f
	}
	for _, key := range []string{
		"url:0", "url:1",
		"credit_card.name", "credit_card.number", "credit_card.verification", "credit_card.pin", "credit_card.expiry",
		"identity.first_name", "identity.email",
		"extra/recovery", "extra/seed",
	} {
		if _, ok := index[key]; !ok {
			t.Fatalf("missing detail key %q in %v", key, fields)
		}
	}
	if !index["credit_card.number"].Concealed || !index["credit_card.verification"].Concealed || !index["credit_card.pin"].Concealed {
		t.Fatal("card secrets are not flagged concealed")
	}
	if index["credit_card.name"].Concealed {
		t.Fatal("cardholder name flagged concealed")
	}
	if !index["extra/seed"].Concealed {
		t.Fatal("OTP custom field is not flagged concealed")
	}
	if index["url:0"].Concealed {
		t.Fatal("URL flagged concealed")
	}

	// Every mapped key must resolve through the shared fieldValue helper.
	for key, want := range map[string]string{
		"url:0":              "https://primary.example",
		"url:1":              "https://secondary.example",
		"credit_card.name":   "Ada Lovelace",
		"credit_card.number": "4111111111111111",
		"identity.email":     "ada@example.com",
		"extra/recovery":     "code",
	} {
		if got, ok := fieldValue(detail, key); !ok || got != want {
			t.Fatalf("fieldValue(%q) = %q,%v want %q", key, got, ok, want)
		}
	}

	// Detail rows never show stored secrets in clear text.
	if got := v2FieldDisplay(detail, nil, "credit_card.number", false); got != v2MaskedValue {
		t.Fatalf("card number rendered as %q", got)
	}
	if got := v2FieldDisplay(detail, nil, "extra/recovery", false); got != "code" {
		t.Fatalf("plain custom field rendered as %q", got)
	}
}

// TestV2EditorHelpersBuildRichDraft pins the editor control mapping: the view
// calls the existing draft helpers, so exercising them here keeps the sections,
// concealed field types, URLs and tags reachable from the UI honest.
func TestV2EditorHelpersBuildRichDraft(t *testing.T) {
	a := New()
	a.EnableV2()
	a.v2.draft = newItemDraft(vault.CategoryLogin)

	a.setDraftCategory(vault.CategoryCreditCard)
	draft := a.v2.draft
	if draft.Category != vault.CategoryCreditCard {
		t.Fatalf("draft category = %q", draft.Category)
	}
	if len(draft.Sections) == 0 {
		t.Fatal("credit card template not provisioned on a new draft")
	}

	a.addSection("Extra")
	sectionIndex := len(draft.Sections) - 1
	a.addField(sectionIndex, "Recovery Code", "concealed", "abc-123")
	added := draft.Sections[sectionIndex].Fields
	if len(added) != 1 {
		t.Fatalf("addField added %d fields", len(added))
	}
	if added[0].Value != "abc-123" || !added[0].Protected || !v2FieldTypeConcealed(added[0]) {
		t.Fatalf("concealed field not stored protected: %+v", added[0])
	}
	if v2FieldTypeConcealed(vault.CustomField{Type: vault.FieldTypeString}) {
		t.Fatal("plain string field flagged concealed")
	}

	a.addURL("https://example.com", "Example", vault.URLMatchHost)
	a.addURL("https://second.example", "", "")
	if len(draft.URLs) != 2 || !draft.URLs[0].Primary || draft.URLs[1].Primary {
		t.Fatalf("URL list = %+v", draft.URLs)
	}
	a.setPrimaryURL(1)
	if draft.URLs[0].Primary || !draft.URLs[1].Primary || draft.URL != "https://second.example" {
		t.Fatalf("primary URL not switched: %+v url=%q", draft.URLs, draft.URL)
	}
	a.cycleURLMatchMode(1)
	if draft.URLs[1].MatchMode != vault.URLMatchOrigin {
		t.Fatalf("match mode after cycle = %q", draft.URLs[1].MatchMode)
	}
	a.removeURL(1)
	if len(draft.URLs) != 1 || !draft.URLs[0].Primary {
		t.Fatalf("removeURL left %+v", draft.URLs)
	}

	a.addTag("recover")
	a.addTag("recover")
	a.addTag("work")
	if len(draft.Tags) != 2 {
		t.Fatalf("tags = %v, want de-duplicated 2", draft.Tags)
	}
	a.removeTag("work")
	if len(draft.Tags) != 1 || draft.Tags[0] != "recover" {
		t.Fatalf("tags after remove = %v", draft.Tags)
	}

	// Type and section pickers stay inside their option sets.
	seen := map[vault.FieldType]bool{}
	for i := 0; i < len(v2FieldTypes); i++ {
		seen[draft.NewFieldType] = true
		a.cycleDraftFieldType()
	}
	if len(seen) != len(v2FieldTypes) {
		t.Fatalf("type cycle covered %d of %d types", len(seen), len(v2FieldTypes))
	}
	if _, ok := normalizeFieldType(string(draft.NewFieldType)); !ok {
		t.Fatalf("cycled field type %q is not a supported field type", draft.NewFieldType)
	}
	for i := 0; i < len(draft.Sections)+2; i++ {
		a.cycleDraftFieldSection()
		if draft.NewFieldSection < 0 || draft.NewFieldSection >= len(draft.Sections) {
			t.Fatalf("section picker out of range: %d", draft.NewFieldSection)
		}
	}

	// The composed field lands in the chosen section with its chosen type.
	a.cycleDraftFieldType()
	draft.NewFieldSection = 0
	draft.NewFieldLabel = "Seed"
	draft.NewFieldValue = "JBSWY3DPEHPK3PXP"
	a.addField(draft.NewFieldSection, draft.NewFieldLabel, string(vault.FieldTypeOTP), draft.NewFieldValue)
	first := draft.Sections[0].Fields
	last := first[len(first)-1]
	if last.Label != "Seed" || last.Type != vault.FieldTypeOTP || !v2FieldTypeConcealed(last) {
		t.Fatalf("composed OTP field = %+v", last)
	}
}

// TestV2DetailAndEditorViewsRenderRichItem renders the new detail and editor
// panes so the rich controls are exercised end to end: custom sections and
// concealed fields are reachable, and a cached plain detail is never shown
// without an explicit reveal.
func TestV2DetailAndEditorViewsRenderRichItem(t *testing.T) {
	a := dailyAppFixture(t)
	a.EnableV2()
	a.launch = func(fn func()) { fn() }
	a.dispatch = func(fn func()) { fn() }
	a.v2.detail = &personal.ItemDetail{
		ID:       "item-rich",
		Revision: "rev-1",
		Title:    "Rich card",
		Category: vault.CategoryCreditCard,
		Username: "holder",
		State:    "active",
		URLs:     []vault.ItemURL{{URL: "https://bank.example", Label: "Bank", Primary: true, MatchMode: vault.URLMatchOrigin}},
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Ada Lovelace",
		},
		Sections: []vault.ItemSection{{
			ID:    "extra",
			Title: "Extra",
			Fields: []vault.CustomField{
				{ID: "recovery", Label: "Recovery", Type: vault.FieldTypeString, Value: "code-123"},
				{ID: "pin", Label: "Card PIN", Type: vault.FieldTypeOTP, Value: "", Protected: true},
			},
		}},
	}
	a.v2.detailPlain = &personal.ItemDetail{
		ID:       "item-rich",
		Revision: "rev-1",
		Title:    "Rich card",
		Password: "swordfish-secret",
		Sections: a.v2.detail.Sections,
	}

	view := ui.NewTester(a.View, 1200, 1800)
	for _, label := range []string{
		"用户名", "密码", "一次性验证码",
		"Bank（主）", "持卡人", "卡号",
		"Extra · Recovery", "Extra · Card PIN",
		"显示", "复制",
	} {
		if !view.HasText(label) {
			t.Fatalf("detail pane missing %q", label)
		}
	}
	if view.HasText("swordfish-secret") {
		t.Fatal("detail pane exposed an unrevealed password")
	}
	if !view.HasText("code-123") {
		t.Fatal("detail pane hid a plain custom field value")
	}

	// The editor exposes the same sections, plus tags, URLs and category.
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryLogin)
	a.v2.draft.Tags = []string{"work"}
	a.v2.draft.URLs = []vault.ItemURL{{URL: "https://example.com", Label: "Example", Primary: true}}
	editor := ui.NewTester(a.View, 1200, 2400)
	for _, label := range []string{
		"编辑条目", "分区与自定义字段", "添加字段", "添加分区", "添加网址", "添加标签",
		"自动填充匹配", "默认", "标签", "网址",
	} {
		if !editor.HasText(label) {
			t.Fatalf("editor pane missing %q", label)
		}
	}
}

func v2ParityField(t *testing.T, d *ItemDraft, sectionID, fieldID string) *string {
	t.Helper()
	ptr := v2DraftFieldValue(d, sectionID, fieldID)
	if ptr == nil {
		t.Fatalf("no draft input for %s/%s", sectionID, fieldID)
	}
	return ptr
}

func v2ParitySectionValue(sections []vault.ItemSection, sectionID, fieldID string) (string, bool) {
	for _, s := range sections {
		// Match either the section id or its title; addSection assigns ids.
		if s.ID != sectionID && s.Title != sectionID {
			continue
		}
		for _, f := range s.Fields {
			if f.ID == fieldID {
				return f.Value, true
			}
		}
	}
	return "", false
}

func v2ParitySaveApp(t *testing.T) *App {
	t.Helper()
	a := dailyAppFixture(t)
	a.EnableV2()
	a.launch = func(fn func()) { fn() }
	a.dispatch = func(fn func()) { fn() }
	return a
}

// TestV2CardTypedEditorInputsPersistAndReopen drives the real editor path:
// pointer bound to the typed draft struct -> draft.item -> Session.AddItem ->
// detail/autofill, then edit and reopen. PAN/CVV/PIN stay masked in the plain
// detail read.
func TestV2CardTypedEditorInputsPersistAndReopen(t *testing.T) {
	a := v2ParitySaveApp(t)
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryCreditCard)
	draft := a.v2.draft
	draft.Title = "My Card"
	*v2ParityField(t, draft, "card", "cardholder") = "Ada Lovelace"
	*v2ParityField(t, draft, "card", "number") = "4111111111111111"
	*v2ParityField(t, draft, "card", "verification") = "123"
	*v2ParityField(t, draft, "card", "expiry") = "2030-01"
	*v2ParityField(t, draft, "details", "pin") = "9999"
	*v2ParityField(t, draft, "details", "issuing_bank") = "Bank"

	// Unrelated user custom section must survive the save untouched.
	a.addSection("Notes")
	notesIndex := len(draft.Sections) - 1
	a.addField(notesIndex, "Recovery", "string", "rec-1")

	if err := a.saveDraft(); err != nil {
		t.Fatalf("saveDraft: %v", err)
	}
	detail := a.v2.detail
	if detail == nil || detail.CreditCard == nil {
		t.Fatal("saved detail lost the typed credit card")
	}
	if detail.CreditCard.CardholderName != "Ada Lovelace" || detail.CreditCard.ExpiryDate != "2030-01" || detail.CreditCard.IssuingBank != "Bank" {
		t.Fatalf("typed card fields lost: %+v", detail.CreditCard)
	}
	if detail.CreditCard.Number == "4111111111111111" || detail.CreditCard.Verification == "123" || detail.CreditCard.PIN == "9999" {
		t.Fatalf("masked detail exposed card secrets: %+v", detail.CreditCard)
	}

	plain, err := a.session.GetItemDetail(detail.ID, detail.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.CreditCard == nil || plain.CreditCard.Number != "4111111111111111" || plain.CreditCard.Verification != "123" || plain.CreditCard.PIN != "9999" {
		t.Fatalf("inspect read lost typed card secrets: %+v", plain.CreditCard)
	}
	// The persisted default-section duplicates mirror the typed struct.
	if got, ok := v2ParitySectionValue(plain.Sections, "card", "number"); !ok || got != "4111111111111111" {
		t.Fatalf("template card/number = %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "card", "cardholder"); !ok || got != "Ada Lovelace" {
		t.Fatalf("template card/cardholder = %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "details", "pin"); !ok || got != "9999" {
		t.Fatalf("template details/pin = %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "Notes", "field-1"); !ok || got != "rec-1" {
		t.Fatalf("custom section field = %q,%v", got, ok)
	}
	// Autofill reads the normalized typed struct, not the section copy.
	normalized := vault.Item{Category: vault.CategoryCreditCard, Sections: plain.Sections, CreditCard: plain.CreditCard}.NormalizedCreditCard()
	if normalized == nil || normalized.Number != "4111111111111111" || normalized.Verification != "123" {
		t.Fatalf("normalized/autofill card = %+v", normalized)
	}

	// Re-open the editor: typed inputs show the stored values again.
	if err := a.beginEdit(); err != nil {
		t.Fatalf("beginEdit: %v", err)
	}
	reopened := a.v2.draft
	if reopened == nil {
		t.Fatal("editor did not reopen")
	}
	if got := *v2ParityField(t, reopened, "card", "number"); got != "4111111111111111" {
		t.Fatalf("reopened card number = %q", got)
	}
	if got := *v2ParityField(t, reopened, "card", "verification"); got != "123" {
		t.Fatalf("reopened CVV = %q", got)
	}
	if got, ok := v2ParitySectionValue(reopened.Sections, "Notes", "field-1"); !ok || got != "rec-1" {
		t.Fatalf("reopened custom section = %q,%v", got, ok)
	}
}

// TestV2IdentityTypedEditorInputsPersistAndReopen covers the identity category
// the same way.
func TestV2IdentityTypedEditorInputsPersistAndReopen(t *testing.T) {
	a := v2ParitySaveApp(t)
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryIdentity)
	draft := a.v2.draft
	draft.Title = "Me"
	*v2ParityField(t, draft, "identification", "first_name") = "Ada"
	*v2ParityField(t, draft, "identification", "last_name") = "Lovelace"
	*v2ParityField(t, draft, "identification", "job_title") = "Mathematician"
	*v2ParityField(t, draft, "contact", "email") = "ada@example.com"
	*v2ParityField(t, draft, "contact", "city") = "London"
	*v2ParityField(t, draft, "contact", "website") = "https://ada.example"
	a.addSection("Extra")
	extraIndex := len(draft.Sections) - 1
	a.addField(extraIndex, "Code", "concealed", "secret-code")

	if err := a.saveDraft(); err != nil {
		t.Fatalf("saveDraft: %v", err)
	}
	detail := a.v2.detail
	if detail == nil || detail.Identity == nil {
		t.Fatal("saved detail lost the typed identity")
	}
	if detail.Identity.FirstName != "Ada" || detail.Identity.LastName != "Lovelace" || detail.Identity.Email != "ada@example.com" || detail.Identity.City != "London" || detail.Identity.Website != "https://ada.example" {
		t.Fatalf("typed identity fields lost: %+v", detail.Identity)
	}
	plain, err := a.session.GetItemDetail(detail.ID, detail.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "identification", "first_name"); !ok || got != "Ada" {
		t.Fatalf("template identification/first_name = %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "contact", "email"); !ok || got != "ada@example.com" {
		t.Fatalf("template contact/email = %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "Extra", "field-1"); !ok || got != "secret-code" {
		t.Fatalf("custom identity section = %q,%v", got, ok)
	}

	if err := a.beginEdit(); err != nil {
		t.Fatalf("beginEdit: %v", err)
	}
	reopened := a.v2.draft
	if reopened == nil || reopened.Category != vault.CategoryIdentity {
		t.Fatalf("reopened identity draft = %+v", reopened)
	}
	if got := *v2ParityField(t, reopened, "identification", "last_name"); got != "Lovelace" {
		t.Fatalf("reopened last name = %q", got)
	}
	if got := *v2ParityField(t, reopened, "contact", "website"); got != "https://ada.example" {
		t.Fatalf("reopened website = %q", got)
	}
	if got, ok := v2ParitySectionValue(reopened.Sections, "Extra", "field-1"); !ok || got != "secret-code" {
		t.Fatalf("reopened custom identity section = %q,%v", got, ok)
	}
}

// TestV2TypedEditOverridesDivergedSectionCopy proves the typed input wins and
// the persisted duplicate template field is re-synced from it on save.
func TestV2TypedEditOverridesDivergedSectionCopy(t *testing.T) {
	a := v2ParitySaveApp(t)
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryCreditCard)
	draft := a.v2.draft
	draft.Title = "Card"
	*v2ParityField(t, draft, "card", "cardholder") = "Ada"
	*v2ParityField(t, draft, "card", "number") = "4111"
	a.addSection("Custom")
	a.addField(len(draft.Sections)-1, "Label", "string", "keep-me")
	if err := a.saveDraft(); err != nil {
		t.Fatal(err)
	}
	if err := a.beginEdit(); err != nil {
		t.Fatal(err)
	}
	draft = a.v2.draft
	// Simulate a persisted template copy that diverged from the typed struct.
	for i := range draft.Sections {
		if draft.Sections[i].ID != "card" {
			continue
		}
		for j := range draft.Sections[i].Fields {
			if draft.Sections[i].Fields[j].ID == "cardholder" {
				draft.Sections[i].Fields[j].Value = "stale duplicate"
			}
		}
	}
	*v2ParityField(t, draft, "card", "cardholder") = "Grace Hopper"
	if err := a.saveDraft(); err != nil {
		t.Fatal(err)
	}
	plain, err := a.session.GetItemDetail(a.v2.detail.ID, a.v2.detail.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.CreditCard == nil || plain.CreditCard.CardholderName != "Grace Hopper" {
		t.Fatalf("typed edit lost: %+v", plain.CreditCard)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "card", "cardholder"); !ok || got != "Grace Hopper" {
		t.Fatalf("diverged duplicate not resynced: %q,%v", got, ok)
	}
	if got, ok := v2ParitySectionValue(plain.Sections, "Custom", "field-1"); !ok || got != "keep-me" {
		t.Fatalf("unrelated custom section lost: %q,%v", got, ok)
	}
}

func TestV2DraftFieldValueFallsBackToSectionValue(t *testing.T) {
	draft := newItemDraft(vault.CategoryLogin)
	if ptr := v2DraftFieldValue(draft, "missing", "missing"); ptr != nil {
		t.Fatal("unknown field returned a pointer")
	}
	draft.Sections = append(draft.Sections, vault.ItemSection{ID: "custom", Title: "Custom", Fields: []vault.CustomField{{ID: "f1", Label: "F", Type: vault.FieldTypeString, Value: "v"}}})
	ptr := v2DraftFieldValue(draft, "custom", "f1")
	if ptr == nil || *ptr != "v" {
		t.Fatalf("custom field pointer = %v", ptr)
	}
	*ptr = "changed"
	if draft.Sections[0].Fields[0].Value != "changed" {
		t.Fatal("custom field pointer is not live")
	}
	if _, ok := v2DraftCanonicalField(draft, "card", vault.CustomField{ID: "number", Purpose: "cc-number"}); ok {
		t.Fatal("login draft treated card fields as canonical")
	}
}
