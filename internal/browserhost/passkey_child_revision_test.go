package browserhost

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func childRevisions(t *testing.T, s *personal.Session, itemID string) map[string]string {
	t.Helper()
	managed, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, value := range managed[itemID] {
		if value.CredentialID == "" || len(value.Revision) != 64 {
			t.Fatalf("managed metadata: %#v", value)
		}
		values[value.CredentialID] = value.Revision
	}
	return values
}

// credential_revision is a strict optional key: only passkey-get/passkey-remove
// may carry it, only with credential_id and the exact parent pair, and only as
// a canonical 64-hex content revision. Legacy requests without it stay valid.
func TestPasskeyChildRevisionStrictWire(t *testing.T) {
	credential := canonicalCredential(0x11)
	itemID, parent, child := reqID(4), strings.Repeat("a", 64), strings.Repeat("b", 64)
	read := func(value map[string]any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		_, e = ReadRequest(bytes.NewReader(frame(string(raw))))
		return e
	}
	get := map[string]any{"v": 1, "id": reqID(300), "type": "passkey-get", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test", credential)}
	with := func(base map[string]any, extra map[string]any) map[string]any {
		value := map[string]any{}
		for k, v := range base {
			value[k] = v
		}
		for k, v := range extra {
			value[k] = v
		}
		return value
	}
	if e := read(get); e != nil {
		t.Fatalf("legacy get refused: %v", e)
	}
	if e := read(with(get, map[string]any{"item_id": itemID, "revision": parent, "credential_id": credential, "credential_revision": child})); e != nil {
		t.Fatalf("exact child-pinned get refused: %v", e)
	}
	if e := read(with(get, map[string]any{"item_id": itemID, "revision": parent, "credential_id": credential})); e != nil {
		t.Fatalf("parent+credential without child refused: %v", e)
	}
	for name, extra := range map[string]map[string]any{
		"child without credential":            {"item_id": itemID, "revision": parent, "credential_revision": child},
		"child without parent":                {"credential_id": credential, "credential_revision": child},
		"child without revision":              {"item_id": itemID, "credential_id": credential, "credential_revision": child},
		"short child":                         {"item_id": itemID, "revision": parent, "credential_id": credential, "credential_revision": "abc"},
		"non-hex child":                       {"item_id": itemID, "revision": parent, "credential_id": credential, "credential_revision": strings.Repeat("z", 64)},
		"uppercase child":                     {"item_id": itemID, "revision": parent, "credential_id": credential, "credential_revision": strings.Repeat("A", 64)},
		"child with non-canonical credential": {"item_id": itemID, "revision": parent, "credential_id": "not-canonical", "credential_revision": child},
	} {
		if e := read(with(get, extra)); e == nil {
			t.Fatalf("passkey-get accepted %s", name)
		}
	}
	create := map[string]any{"v": 1, "id": reqID(301), "type": "passkey-create", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": string(passkeyCreateWire("dXNlcjE", "alice", "Alice"))}
	if e := read(with(create, map[string]any{"credential_revision": child})); e == nil {
		t.Fatal("passkey-create accepted a child revision")
	}
	list := map[string]any{"v": 1, "id": reqID(302), "type": "passkey-list", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test")}
	if e := read(with(list, map[string]any{"credential_revision": child})); e == nil {
		t.Fatal("passkey-list accepted a child revision")
	}
	signal := map[string]any{"v": 1, "id": reqID(303), "type": "passkey-signal", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test")}
	if e := read(with(signal, map[string]any{"credential_revision": child})); e == nil {
		t.Fatal("passkey-signal accepted a child revision")
	}
	remove := map[string]any{"v": 1, "id": reqID(304), "type": "passkey-remove", "capability": reqID(9), "item_id": itemID, "revision": parent, "credential_id": credential}
	if e := read(remove); e != nil {
		t.Fatalf("legacy remove refused: %v", e)
	}
	if e := read(with(remove, map[string]any{"credential_revision": child})); e != nil {
		t.Fatalf("exact remove refused: %v", e)
	}
	if e := read(with(remove, map[string]any{"credential_revision": "short"})); e == nil {
		t.Fatal("passkey-remove accepted a malformed child revision")
	}
	other := map[string]any{"v": 1, "id": reqID(305), "type": "item-get", "capability": reqID(9), "item_id": itemID}
	if e := read(with(other, map[string]any{"credential_revision": child})); e == nil {
		t.Fatal("item-get accepted a child revision")
	}
}

// A pinned child content revision must match the exact reviewed choice before
// anything can be selected; the reviewed choice's own revision is then bound to
// the target. A stale child target is refused, never repaired to current.
func TestPasskeyPinnedChildRevisionBindsExactChoice(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, secondPub := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revisions := childRevisions(t, s, itemID)
	if revisions[first] == "" || revisions[second] == "" || revisions[first] == revisions[second] {
		t.Fatalf("child revisions are not distinct: %#v", revisions)
	}
	parent := revisionOf(t, s, itemID)
	pinned := Request{
		V: 1, ID: reqID(310), Type: "passkey-get", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		ItemID: itemID, Revision: parent, CredentialID: second, CredentialRevision: revisions[second],
		Options: passkeyGetWire("example.test", first, second),
	}
	if e := c.Handle(pinned); e != nil {
		t.Fatal(e)
	}
	pending := waitPasskey(t, c)
	if len(pending.Choices) != 1 || pending.Choices[0].CredentialID != second || pending.Choices[0].CredentialRevision != revisions[second] {
		t.Fatalf("pinned child review: %#v", pending.Choices)
	}
	if e := c.ApprovePasskeyCredential(pinned.ID, itemID, first, nil, nil); e == nil {
		t.Fatal("pinned child review approved a sibling credential")
	}
	if e := c.ApprovePasskeyCredential(pinned.ID, itemID, second, nil, nil); e != nil {
		t.Fatal(e)
	}
	credential := passkeyResult(t, out, pinned.ID)
	if credential.ID != second {
		t.Fatalf("signed %q, pinned %q", credential.ID, second)
	}
	assertSignatureFor(t, credential, secondPub)
	if c.Snapshot().Passkey != nil {
		t.Fatal("approval surface survived exact child approval")
	}

	// A stale/mismatched child revision is refused during review: no choice is
	// offered, no first-record fallback, and no approval surface is left.
	for name, child := range map[string]string{
		"stale child":   revisions[first],
		"unknown child": strings.Repeat("f", 64),
	} {
		stale := pinned
		stale.ID, stale.CredentialRevision = reqID(311+len(name)), child
		if e := c.Handle(stale); e != nil {
			t.Fatalf("%s: %v", name, e)
		}
		waitPasskeyRefusal(t, out, stale.ID)
		if c.Snapshot().Passkey != nil {
			t.Fatalf("%s left an approval surface", name)
		}
	}

	// Even a live review must not silently repair a child target that no longer
	// equals the reviewed choice at resolution time.
	live := pinned
	live.ID, live.CredentialRevision = reqID(320), revisions[second]
	if e := c.Handle(live); e != nil {
		t.Fatal(e)
	}
	if view := waitPasskey(t, c); len(view.Choices) != 1 {
		t.Fatalf("live review: %#v", view.Choices)
	}
	c.mu.Lock()
	c.passkey.target.CredentialRevision = strings.Repeat("e", 64)
	c.mu.Unlock()
	if e := c.ApprovePasskeyCredential(live.ID, itemID, second, nil, nil); e == nil {
		t.Fatal("resolver repaired a stale child target instead of refusing")
	}
	if e := c.RejectPasskey(live.ID); e != nil {
		t.Fatal(e)
	}
}

// Public metadata carries the exact child revision: detail arrays, the legacy
// single object and conditional candidates, without any private material.
func TestPasskeyMetadataExposesChildRevision(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, _ := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revisions := childRevisions(t, s, itemID)
	parent := revisionOf(t, s, itemID)
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(330), "type": "item-get", "capability": capability, "item_id": itemID, "revision": parent})
	if detail.Item == nil || len(detail.Item.Passkeys) != 2 || detail.Item.Passkey != nil {
		t.Fatalf("detail: %#v", detail.Item)
	}
	for _, metadata := range detail.Item.Passkeys {
		if metadata.CredentialRevision != revisions[metadata.CredentialID] {
			t.Fatalf("detail child revision %#v want %q", metadata, revisions[metadata.CredentialID])
		}
	}
	raw, e := json.Marshal(detail)
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"private_key", "user_id", "userHandle", "raw_record"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("detail leaked %q", forbidden)
		}
	}
	items := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(331), "type": "search", "capability": capability, "passkeys_only": true})
	if len(items.Items) != 1 || items.Items[0].PasskeyCount != 2 || items.Items[0].Passkey != nil {
		t.Fatalf("list projection: %#v", items.Items)
	}
	list := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(332), "type": "passkey-list", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test")})
	if list.Type != "passkey-candidates" || len(list.Passkeys) != 2 {
		t.Fatalf("candidates: %#v", list)
	}
	seen := map[string]bool{}
	for _, candidate := range list.Passkeys {
		if candidate.ItemID != itemID || candidate.Revision != parent {
			t.Fatalf("candidate parent: %#v", candidate)
		}
		if candidate.CredentialRevision != revisions[candidate.CredentialID] {
			t.Fatalf("candidate child revision %#v want %q", candidate, revisions[candidate.CredentialID])
		}
		seen[candidate.CredentialID] = true
	}
	if !seen[first] || !seen[second] {
		t.Fatalf("candidates lost a credential: %#v", list.Passkeys)
	}
}

// Removal with a child revision is exact: a stale child is refused and leaves
// both credentials; an exact child removes only that sibling; the legacy remove
// without a child revision remains compatible.
func TestPasskeyRemoveWithChildRevision(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, _ := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revisions := childRevisions(t, s, itemID)
	parent := revisionOf(t, s, itemID)
	stale := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(340), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": parent, "credential_id": first, "credential_revision": revisions[second]})
	if stale.Type != "error" {
		t.Fatalf("stale child remove: %#v", stale)
	}
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(341), "type": "item-get", "capability": capability, "item_id": itemID})
	if detail.Item == nil || len(detail.Item.Passkeys) != 2 {
		t.Fatalf("stale child remove mutated: %#v", detail.Item)
	}
	removed := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(342), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": parent, "credential_id": first, "credential_revision": revisions[first]})
	if removed.Type != "passkey-removed" || removed.CredentialID != first || removed.Revision == "" {
		t.Fatalf("exact child remove: %#v", removed)
	}
	detail = v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(343), "type": "item-get", "capability": capability, "item_id": itemID, "revision": removed.Revision})
	if detail.Item == nil || len(detail.Item.Passkeys) != 1 || detail.Item.Passkeys[0].CredentialID != second || detail.Item.Passkey == nil || detail.Item.Passkey.CredentialID != second || detail.Item.Passkey.CredentialRevision != revisions[second] {
		t.Fatalf("sibling after child remove: %#v", detail.Item)
	}
	legacy := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(344), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": removed.Revision, "credential_id": second})
	if legacy.Type != "passkey-removed" {
		t.Fatalf("legacy remove: %#v", legacy)
	}
	detail = v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(345), "type": "item-get", "capability": capability, "item_id": itemID, "revision": legacy.Revision})
	if detail.Item == nil || detail.Item.HasPasskey || len(detail.Item.Passkeys) != 0 || detail.Item.Passkey != nil {
		t.Fatalf("detail after last removal: %#v", detail.Item)
	}
}
