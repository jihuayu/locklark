package browserhost

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func historyEdit(t *testing.T, c *Connection, out *memoryPipe, capability, id, revision, itemJSON string) Response {
	t.Helper()
	return v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(31), "type": "item-save", "capability": capability,
		"item_id": id, "revision": revision, "item_json": itemJSON,
	})
}

// The history list is metadata only: it must never serialize the previous
// password or hidden section snapshot.
func TestItemHistoryReturnsMetadataOnly(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	saved := historyEdit(t, c, out, capability, id, revisions[id],
		`{"title":"Existing","category":"login","password":"new-password"}`)
	if saved.Type != "item-saved" {
		t.Fatalf("edit: %+v", saved)
	}
	response := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(32), "type": "item-history", "capability": capability,
		"item_id": id, "revision": saved.Revision,
	})
	if response.Type != "item-history" || len(response.History) != 1 {
		t.Fatalf("history: %+v", response)
	}
	entry := response.History[0]
	if entry.Index != 0 || !entry.HasPassword || entry.Username != "alice" {
		t.Fatalf("entry: %+v", entry)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-password", "new-password", `"password"`, `"sections"`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("history response leaked %s: %s", secret, raw)
		}
	}
}

// A restore is a normal authenticated mutation: it advances the revision, puts
// the retained password back, and refuses a stale revision afterwards.
func TestItemRestoreHistoryRestoresOldPassword(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	saved := historyEdit(t, c, out, capability, id, revisions[id],
		`{"title":"Existing","category":"login","password":"new-password"}`)
	if saved.Type != "item-saved" {
		t.Fatalf("edit: %+v", saved)
	}
	restored := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(33), "type": "item-restore-history", "capability": capability,
		"item_id": id, "revision": saved.Revision, "history_index": 0,
	})
	if restored.Type != "item-saved" || restored.Revision == "" || restored.Revision == saved.Revision {
		t.Fatalf("restore: %+v", restored)
	}
	detail, err := s.GetItemDetail(id, restored.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Password != "old-password" {
		t.Fatalf("restored password: %q", detail.Password)
	}
	stale := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(34), "type": "item-restore-history", "capability": capability,
		"item_id": id, "revision": saved.Revision, "history_index": 0,
	})
	if stale.Type != "error" {
		t.Fatalf("stale restore accepted: %+v", stale)
	}
}

func TestItemHistoryRefusesUnknownRevisionAndIndex(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	items, revisions, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v %d", err, len(items))
	}
	id := items[0].ID
	wrong := strings.Repeat("f", 64)
	refused := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(35), "type": "item-history", "capability": capability,
		"item_id": id, "revision": wrong,
	})
	if refused.Type != "error" {
		t.Fatalf("stale history accepted: %+v", refused)
	}
	badIndex := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(36), "type": "item-restore-history", "capability": capability,
		"item_id": id, "revision": revisions[id], "history_index": 5,
	})
	if badIndex.Type != "error" {
		t.Fatalf("missing history row accepted: %+v", badIndex)
	}
	if _, err := ReadRequest(bytes.NewReader(frame(`{"v":1,"id":"` + reqID(38) + `","type":"item-restore-history","capability":"` + capability + `","item_id":"` + id + `","revision":"` + revisions[id] + `","history_index":20}`))); err == nil {
		t.Fatal("wire accepted an out-of-range index")
	}
}

// item-history must not accept a restore selector, and a restore must require
// one explicitly.
func TestItemHistoryWireRejectsMismatchedFields(t *testing.T) {
	read := func(value string) error {
		_, err := ReadRequest(bytes.NewReader(frame(value)))
		return err
	}
	base := `"v":1,"id":"` + reqID(37) + `","capability":"` + strings.Repeat("a", 32) + `","item_id":"` + strings.Repeat("b", 32) + `","revision":"` + strings.Repeat("c", 64) + `"`
	if err := read(`{` + base + `,"type":"item-history","history_index":0}`); err == nil {
		t.Fatal("item-history accepted history_index")
	}
	if err := read(`{` + base + `,"type":"item-restore-history"}`); err == nil {
		t.Fatal("item-restore-history accepted a missing index")
	}
	if err := read(`{` + base + `,"type":"item-restore-history","history_index":0}`); err != nil {
		t.Fatalf("valid restore rejected: %v", err)
	}
}
