package browserhost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// nonQuickFixture is a real manual pairing: the owner approved the extension
// but did not grant quick fill, so every sensitive V2 operation must return to
// the native approval surface.
func nonQuickFixture(t *testing.T) (*Connection, *memoryPipe, *personal.Session, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approval.ll")
	key := bytes.Repeat([]byte{11}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Approval login", "approval-user", "approval-secret")
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
	if e := c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	cap := out.responses(t)[0].Capability
	if c.Snapshot().QuickFill {
		t.Fatal("manual pairing enabled quick fill")
	}
	return c, out, s, cap
}

func TestV2SecretDisclosureRequiresNativeApproval(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	reveal := Request{V: 1, ID: reqID(20), Type: "item-reveal-field", Capability: cap, ItemID: rows[0].ID, Revision: rows[0].Revision, Field: "password"}
	if e := c.Handle(reveal); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot()
	if view.V2 == nil || view.V2.Type != "item-reveal-field" || view.V2.ItemID != rows[0].ID {
		t.Fatalf("missing native review: %#v", view)
	}
	if view.V2.Field != "password" || view.V2.Action != "显示字段" || view.V2.Summary == "" {
		t.Fatalf("public field review selectors: %#v", view.V2)
	}
	if got := len(out.responses(t)); got != 1 {
		t.Fatalf("secret escaped before approval: %d frames", got)
	}
	if e := c.ApproveV2(reveal.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "field-value" || last.FieldValue != "approval-secret" {
		t.Fatalf("approved disclosure: %#v", last)
	}
}

func TestV2MutationRejectionWritesNothingAndClearsRequest(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	before, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	create := mustReadRequest(t, map[string]any{
		"v": 1, "id": reqID(30), "type": "item-create", "capability": cap,
		"item_json": `{"category":"login","title":"Should not exist","username":"native-gate","password":"synthetic-secret"}`,
	})
	if e := c.Handle(create); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot()
	if view.V2 == nil || view.V2.Type != "item-create" {
		t.Fatalf("missing mutation review: %#v", view)
	}
	if e := c.RejectV2(create.ID); e != nil {
		t.Fatal(e)
	}
	last := out.responses(t)
	if last[len(last)-1].Type != "error" {
		t.Fatal("rejection was not sent to the browser")
	}
	after, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if len(after) != len(before) {
		t.Fatal("rejected mutation wrote an item")
	}
	if c.Snapshot().V2 != nil {
		t.Fatal("rejected review survived")
	}
}

func TestV2StagedSavePayloadSurvivesApproval(t *testing.T) {
	c, out, _, cap := nonQuickFixture(t)
	defer c.Close()
	stage := mustReadRequest(t, map[string]any{
		"v": 1, "id": reqID(40), "type": "stage-save", "capability": cap,
		"origin": "https://new.example.test", "tab_id": 1, "window_id": 1,
		"document_id": "doc-1", "username": "new-user", "password": "synthetic-stage-secret",
		"title": "New Site",
	})
	if e := c.Handle(stage); e != nil {
		t.Fatal(e)
	}
	if v := c.Snapshot().V2; v == nil || v.Type != "stage-save" {
		t.Fatalf("missing staged-save review: %#v", v)
	}
	if e := c.ApproveV2(stage.ID); e != nil {
		t.Fatal(e)
	}
	last := out.responses(t)
	if last[len(last)-1].Type != "save-staged" || last[len(last)-1].Staged == nil {
		t.Fatalf("staged save after approval: %#v", last[len(last)-1])
	}
}

func addApprovalIdentity(t *testing.T, s *personal.Session) (string, string) {
	t.Helper()
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	id, rev, e := s.AddItem(vault.Item{
		Kind:     "identity",
		Category: vault.CategoryIdentity,
		Title:    "Approval identity",
		Identity: &vault.IdentityDetails{FirstName: "Ada", LastName: "Lovelace", Email: "ada@example.test"},
		Sections: []vault.Section{{ID: "public", Title: "Public", Fields: []vault.CustomField{
			{ID: "visible", Label: "Visible", Type: vault.FieldTypeText, Value: "public-hint"},
			{ID: "concealed", Label: "Concealed", Type: vault.FieldTypeConcealed, Value: "concealed-hint"},
		}}},
	}, gate)
	if e != nil {
		t.Fatal(e)
	}
	return id, rev
}

func TestV2ItemGetRequiresNativeApprovalForIdentityAndPublicFields(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	id, rev := addApprovalIdentity(t, s)
	get := Request{V: 1, ID: reqID(60), Type: "item-get", Capability: cap, ItemID: id, Revision: rev}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot()
	if view.V2 == nil || view.V2.Type != "item-get" || view.V2.Action != "读取条目详情" || view.V2.Summary == "" {
		t.Fatalf("missing item-get native review: %#v", view)
	}
	if got := len(out.responses(t)); got != 1 {
		t.Fatalf("item detail escaped before approval: %d frames", got)
	}
	if e := c.ApproveV2(get.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "item-detail" || last.Item == nil || last.Item.Identity == nil || last.Item.Identity.FirstName != "Ada" {
		t.Fatalf("approved item detail: %#v", last)
	}
	if len(last.Item.Sections) != 1 {
		t.Fatalf("item sections: %#v", last.Item.Sections)
	}
	if last.Item.Sections[0].Fields[0].Value != "public-hint" || last.Item.Sections[0].Fields[1].Value != "" {
		t.Fatalf("public/concealed projection: %#v", last.Item.Sections[0].Fields)
	}
}

func TestV2QuickPathKeepsItemGetDirectAndNeverShowsReview(t *testing.T) {
	c, out, s, cap := v2Fixture(t)
	defer c.Close()
	id, rev := addApprovalIdentity(t, s)
	get := Request{V: 1, ID: reqID(70), Type: "item-get", Capability: cap, ItemID: id, Revision: rev}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	if c.Snapshot().V2 != nil {
		t.Fatal("quick-fill item-get created a native review")
	}
	last := out.responses(t)
	if len(last) == 0 || last[len(last)-1].Type != "item-detail" {
		t.Fatalf("quick item-get did not execute directly: %#v", last)
	}
}

// v2ApprovalSentinel is the single synthetic secret every approval-lane test
// writes as a field value. No view, snapshot or frame may ever contain it.
const v2ApprovalSentinel = "SYNTHETIC-SECRET-SENTINEL-7f3c"

// v2SentinelItem is a real durable login whose values are all the sentinel. It
// also carries a card and identity block and custom sections so the anchor
// projection must choose names without reading any of them.
func v2SentinelItem(t *testing.T, s *personal.Session) (string, string) {
	t.Helper()
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	sentinel := v2ApprovalSentinel
	id, rev, e := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Stored Anchor Login",
		Username: sentinel,
		Password: sentinel,
		OTP:      "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		URL:      "https://stored.example.test",
		Notes:    sentinel,
		CreditCard: &vault.CreditCardDetails{
			CardholderName: sentinel, Type: "visa", Number: "4242424242424242",
			Verification: "987", ExpiryDate: "2030-01", PIN: "1357", IssuingBank: sentinel,
		},
		Identity: &vault.IdentityDetails{FirstName: sentinel, LastName: sentinel, Email: "stored@example.test"},
		Sections: []vault.Section{{ID: "stored-sec", Title: "Stored", Fields: []vault.CustomField{
			{ID: "stored-hidden", Label: "Stored Hidden", Type: vault.FieldTypeConcealed, Value: sentinel},
			{ID: "stored-note", Label: "Stored Hint", Type: vault.FieldTypeText, Value: sentinel},
		}}},
	}, gate)
	if e != nil {
		t.Fatal(e)
	}
	return id, rev
}

func v2ApprovalJSON(t *testing.T, view *V2ApprovalView) string {
	t.Helper()
	raw, e := json.Marshal(view)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

func v2ViewHas(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

func TestV2ItemGetWithoutRevisionPinsExactCurrentRevision(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	id, rev := addApprovalIdentity(t, s)
	get := Request{V: 1, ID: reqID(80), Type: "item-get", Capability: cap, ItemID: id}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot().V2
	if view == nil || view.Type != "item-get" || view.Revision != rev || !view.RevisionPinned {
		t.Fatalf("missing pinned item-get review: %#v", view)
	}
	c.mu.Lock()
	stored := c.v2pending.request.Revision
	c.mu.Unlock()
	if stored != rev {
		t.Fatalf("pending request revision = %q, want %q", stored, rev)
	}
	if view.StoredTitle != "Approval identity" || view.StoredCategory != "identity" || !v2ViewHas(view.StoredFields, "身份·名") || !v2ViewHas(view.StoredFields, "自定义字段：Concealed") {
		t.Fatalf("stored anchor names: %#v", view)
	}
	if got := len(out.responses(t)); got != 1 {
		t.Fatalf("detail leaked into %d frames before approval", got)
	}
	// The approval runs the unchanged handleItemGet path for the pinned
	// revision.
	if e := c.ApproveV2(get.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "item-detail" || last.Item == nil || last.Item.Revision != rev {
		t.Fatalf("approved item-get: %#v", last)
	}
}

func TestV2ItemGetApprovalRefusesRevisionThatMoved(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	// Read the fixture anchor before touching the idle clock below.
	if len(out.responses(t)) != 1 {
		t.Fatal("pairing frame missing")
	}
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	id, rev := rows[0].ID, rows[0].Revision
	if e := c.Handle(Request{V: 1, ID: reqID(81), Type: "item-get", Capability: cap, ItemID: id}); e != nil {
		t.Fatal(e)
	}
	if v := c.Snapshot().V2; v == nil || v.Revision != rev || !v.RevisionPinned {
		t.Fatalf("pinned review: %#v", v)
	}
	// Keep the connection's grant clock alive across the concurrent edit; the
	// edit refreshes the session's idle clock so only the revision moved.
	c.mu.Lock()
	c.until = time.Now().Add(time.Minute)
	c.mu.Unlock()
	if _, e := s.Edit(personal.Edit{ID: id, Revision: rev, Field: "notes", Value: "changed after approval opened"}); e != nil {
		t.Fatal(e)
	}
	if e := c.ApproveV2(reqID(81)); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	if last := all[len(all)-1]; last.Type != "error" {
		t.Fatalf("moved revision was not refused by the original path: %#v", last)
	}
	for _, r := range all {
		if r.Type == "item-detail" || r.Item != nil {
			t.Fatalf("moved revision disclosed detail: %#v", r)
		}
	}
	if c.Snapshot().V2 != nil {
		t.Fatal("refused review remained pending")
	}
}

func TestV2MutationSummaryNamesPublicFieldsWithoutValues(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	id, rev := v2SentinelItem(t, s)

	// The identity DTO only accepts its published members; an identity number
	// (ssn) is not writable through the browser channel and is never named.
	createJSON := `{"category":"card","title":"Requested Card","username":"` + v2ApprovalSentinel + `","password":"` + v2ApprovalSentinel + `","otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","url":"https://requested.example.test/` + v2ApprovalSentinel + `","notes":"` + v2ApprovalSentinel + `","favorite":true,"tags":["` + v2ApprovalSentinel + `"],"credit_card":{"cardholder_name":"` + v2ApprovalSentinel + `","type":"visa","number":"4242424242424242","verification":"987","expiry_date":"2030-01","pin":"1357","issuing_bank":"` + v2ApprovalSentinel + `"},"identity":{"first_name":"` + v2ApprovalSentinel + `","last_name":"` + v2ApprovalSentinel + `","email":"requested@example.test"},"sections":[{"id":"requested-sec","title":"Requested","fields":[{"id":"requested-hidden","label":"Requested Recovery","type":"concealed","value":"` + v2ApprovalSentinel + `"}]}]}`
	create := mustReadRequest(t, map[string]any{"v": 1, "id": reqID(90), "type": "item-create", "capability": cap, "item_json": createJSON})
	if e := c.Handle(create); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot().V2
	if view == nil || view.Type != "item-create" {
		t.Fatalf("missing create review: %#v", view)
	}
	if view.RequestedTitle != "Requested Card" || view.RequestedCategory != "credit_card" || view.StoredTitle != "" {
		t.Fatalf("requested anchor: %#v", view)
	}
	for _, want := range []string{
		"标题", "用户名", "密码", "验证码", "网址", "备注", "收藏", "标签",
		"信用卡·持卡人", "信用卡·卡类型", "信用卡·卡号", "信用卡·安全码", "信用卡·有效期", "信用卡·PIN", "信用卡·发卡银行",
		"身份·名", "身份·姓", "身份·邮箱",
		"自定义字段：Requested Recovery",
	} {
		if !v2ViewHas(view.RequestedFields, want) {
			t.Fatalf("create summary missing %q: %#v", want, view.RequestedFields)
		}
	}
	for _, raw := range []string{v2ApprovalJSON(t, view), fmt.Sprint(out.responses(t))} {
		if strings.Contains(raw, v2ApprovalSentinel) || strings.Contains(raw, "4242424242424242") || strings.Contains(raw, "JBSWY3DPEHPK3PXP") || strings.Contains(raw, "987") && strings.Contains(raw, "verification") {
			t.Fatalf("sentinel leaked into approval view or frames: %s", raw)
		}
	}
	if len(out.responses(t)) != 1 {
		t.Fatal("request answered before approval")
	}
	if e := c.RejectV2(create.ID); e != nil {
		t.Fatal(e)
	}

	editJSON := `{"category":"identity","title":"Requested Rename","notes":"` + v2ApprovalSentinel + `","username":"` + v2ApprovalSentinel + `","url":"https://edited.example.test","clear_fields":["notes","section:stored-sec:stored-hidden"],"identity":{"first_name":"` + v2ApprovalSentinel + `","email":"edited@example.test"},"sections":[{"id":"stored-sec","title":"Stored","fields":[{"id":"stored-hidden","label":"Stored Hidden","type":"concealed"},{"id":"stored-note","label":"Stored Hint","type":"text","value":"` + v2ApprovalSentinel + `"}]}]}`
	edit := mustReadRequest(t, map[string]any{"v": 1, "id": reqID(91), "type": "item-edit", "capability": cap, "item_id": id, "revision": rev, "item_json": editJSON})
	if e := c.Handle(edit); e != nil {
		t.Fatal(e)
	}
	view = c.Snapshot().V2
	if view == nil || view.Type != "item-edit" || view.ItemID != id || view.Revision != rev {
		t.Fatalf("missing edit review: %#v", view)
	}
	// Stored anchor and request metadata stay distinguishable.
	if view.StoredTitle != "Stored Anchor Login" || view.StoredCategory != "login" || view.RequestedTitle != "Requested Rename" || view.RequestedCategory != "identity" {
		t.Fatalf("anchors not distinct: stored=%q/%q requested=%q/%q", view.StoredTitle, view.StoredCategory, view.RequestedTitle, view.RequestedCategory)
	}
	if !v2ViewHas(view.StoredFields, "信用卡·卡号") || !v2ViewHas(view.StoredFields, "身份·邮箱") || !v2ViewHas(view.StoredFields, "自定义字段：Stored Hidden") {
		t.Fatalf("stored anchor names: %#v", view.StoredFields)
	}
	for _, want := range []string{
		"标题", "用户名", "网址", "备注",
		"身份·名", "身份·邮箱",
		"自定义字段：Stored Hidden", "自定义字段：Stored Hint",
		"清除：备注", "清除：自定义隐藏字段：Stored Hidden",
	} {
		if !v2ViewHas(view.RequestedFields, want) {
			t.Fatalf("edit summary missing %q: %#v", want, view.RequestedFields)
		}
	}
	if v2ViewHas(view.RequestedFields, "密码") || v2ViewHas(view.RequestedFields, "标签") || v2ViewHas(view.RequestedFields, "收藏") {
		t.Fatalf("edit summary named members the payload never writes: %#v", view.RequestedFields)
	}
	for _, raw := range []string{v2ApprovalJSON(t, view), fmt.Sprint(out.responses(t))} {
		if strings.Contains(raw, v2ApprovalSentinel) || strings.Contains(raw, "4242424242424242") {
			t.Fatalf("sentinel leaked into approval view or frames: %s", raw)
		}
	}
	if e := c.RejectV2(edit.ID); e != nil {
		t.Fatal(e)
	}
}

func TestV2EditSummaryRequiresExactStoredRevision(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	id, rev := addApprovalIdentity(t, s)
	stale := strings.Repeat("ab", 32)
	if stale == rev {
		t.Fatal("fixture revision collision")
	}
	edit := mustReadRequest(t, map[string]any{"v": 1, "id": reqID(95), "type": "item-edit", "capability": cap, "item_id": id, "revision": stale,
		"item_json": `{"category":"identity","title":"Stale Edit","identity":{"first_name":"Requested"}}`})
	if e := c.Handle(edit); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot().V2
	if view == nil || view.StoredTitle != "" || len(view.StoredFields) != 0 || view.RequestedTitle != "Stale Edit" {
		t.Fatalf("stale edit anchored an item it does not target: %#v", view)
	}
	if e := c.ApproveV2(edit.ID); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	if last := all[len(all)-1]; last.Type != "error" {
		t.Fatalf("stale edit was not refused by the original path: %#v", last)
	}
	after, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	changed := false
	for _, row := range after {
		if row.ID == id && row.Revision != rev {
			changed = true
		}
	}
	if changed {
		t.Fatal("stale edit changed the vault")
	}
}

func TestV2ApprovalFieldLabelsAreSnapshottedAndBounded(t *testing.T) {
	c, _, s, cap := nonQuickFixture(t)
	defer c.Close()
	id, rev := addApprovalIdentity(t, s)
	get := Request{V: 1, ID: reqID(96), Type: "item-get", Capability: cap, ItemID: id, Revision: rev}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	first := c.Snapshot().V2
	if first == nil || len(first.StoredFields) == 0 {
		t.Fatalf("missing stored names: %#v", first)
	}
	want := first.StoredFields[0]
	first.StoredFields[0] = "mutated by the caller\n"
	second := c.Snapshot().V2
	if second == nil || len(second.StoredFields) == 0 || second.StoredFields[0] != want {
		t.Fatalf("snapshot slice aliased the pending review: %#v", second)
	}
	second.StoredFields[0] = "mutated again"
	if third := c.Snapshot().V2; third.StoredFields[0] != want {
		t.Fatal("snapshot leaked a mutation between calls")
	}
	// The review pins the revision it reserved, so it reports the pin even
	// for an explicit request; the pin never substitutes a different one.
	if !first.RevisionPinned || first.Revision != rev {
		t.Fatal("explicit revision reported as pinned")
	}

	// Bounds: de-duplicate, cap the list, cap and escape each label while
	// dropping control characters from named custom fields.
	oldList := projectionListLen
	projectionListLen = 3
	defer func() { projectionListLen = oldList }()
	labels := v2BoundedLabels([]string{"same", "same", "two", "three", "four"})
	if len(labels) != 3 || labels[0] != "same" || labels[1] != "two" || labels[2] != "three" {
		t.Fatalf("bounded labels: %#v", labels)
	}
	long := strings.Repeat("界", v2AnchorMaxLabel+20)
	if got := v2PublicLabel(long); len([]rune(got)) != v2AnchorMaxLabel {
		t.Fatalf("label not clipped: %d runes", len([]rune(got)))
	}
	escaped := v2PublicLabel("line\nbreak\u2028and\r\tbell\x07")
	if strings.ContainsAny(escaped, "\n\r\t\x07\u2028") {
		t.Fatalf("control characters survived: %q", escaped)
	}
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	inject := []vault.Section{{ID: "inject", Title: "Inject", Fields: []vault.CustomField{
		{ID: "a", Label: "Plain", Type: vault.FieldTypeText, Value: "x"},
		{ID: "b", Label: "行\n注入", Type: vault.FieldTypeText, Value: "x"},
		{ID: "c", Label: "Plain", Type: vault.FieldTypeText, Value: "x"},
	}}}
	injectedID, _, e := s.AddItem(vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Injected", Sections: inject}, gate)
	if e != nil {
		t.Fatal(e)
	}
	injectGet := Request{V: 1, ID: reqID(102), Type: "item-get", Capability: cap, ItemID: injectedID}
	if e := c.Handle(injectGet); e != nil {
		t.Fatal(e)
	}
	injected := c.Snapshot().V2
	if injected == nil || !injected.RevisionPinned {
		t.Fatalf("injected review: %#v", injected)
	}
	custom := 0
	for _, label := range injected.StoredFields {
		if !strings.HasPrefix(label, "自定义字段：") {
			continue
		}
		custom++
		if strings.ContainsAny(label, "\n\r\t") {
			t.Fatalf("custom label kept a control character: %q", label)
		}
	}
	if custom != 2 {
		t.Fatalf("duplicate custom labels were not de-duplicated: %#v", injected.StoredFields)
	}
}

func TestV2HistoryAndPasskeySelectorsStayVisible(t *testing.T) {
	c, out, s, cap := nonQuickFixture(t)
	defer c.Close()
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("rows", e)
	}
	// History index 0 is a real selector and must reach the review.
	restore := mustReadRequest(t, map[string]any{"v": 1, "id": reqID(97), "type": "item-restore-history", "capability": cap,
		"item_id": rows[0].ID, "revision": rows[0].Revision, "history_index": 0})
	if e := c.Handle(restore); e != nil {
		t.Fatal(e)
	}
	view := c.Snapshot().V2
	if view == nil || view.Type != "item-restore-history" || view.ItemID != rows[0].ID || view.Revision != rows[0].Revision {
		t.Fatalf("restore review: %#v", view)
	}
	c.mu.Lock()
	if c.v2pending.request.HistoryIndex != 0 || !c.v2pending.request.historyIndexSet {
		t.Fatal("history index 0 was lost from the pending request")
	}
	c.mu.Unlock()
	if e := c.RejectV2(restore.ID); e != nil {
		t.Fatal(e)
	}

	// passkey-remove keeps its exact credential selector and parent revision.
	credential := strings.Repeat("01", 32)
	// passkey-remove keeps its exact credential selector and parent revision
	// on the private pending request; the review never renders key material.
	remove := Request{V: 1, ID: reqID(98), Type: "passkey-remove", Capability: cap, ItemID: rows[0].ID, Revision: rows[0].Revision, CredentialID: credential}
	c.mu.Lock()
	field, action, summary := v2ApprovalReview(remove)
	c.v2pending = &pendingV2{request: remove, field: field, action: action, summary: summary, deadline: c.now().Add(30 * time.Second), epoch: c.epoch, cancelEpoch: c.cancelEpoch.Load()}
	c.mu.Unlock()
	view = c.Snapshot().V2
	if view == nil || view.Type != "passkey-remove" || view.ItemID != rows[0].ID || view.Revision != rows[0].Revision {
		t.Fatalf("passkey-remove review: %#v", view)
	}
	c.mu.Lock()
	stored := c.v2pending.request
	c.mu.Unlock()
	if stored.CredentialID != credential || stored.Revision != rows[0].Revision {
		t.Fatalf("passkey selector lost: %#v", stored)
	}
	if strings.Contains(v2ApprovalJSON(t, view), credential) {
		t.Fatal("passkey credential material entered the V2 approval view")
	}
	if e := c.RejectV2(remove.ID); e != nil {
		t.Fatal(e)
	}
	_ = out
}
