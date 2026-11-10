package browserhost

import (
	"bytes"
	"path/filepath"
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
