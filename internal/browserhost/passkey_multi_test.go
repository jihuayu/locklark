package browserhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

func canonicalCredential(seed byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte{seed, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, seed})
}

// attachPasskey adds one more credential carrying the same RP/user handle to an
// existing login and returns the public credential ID and public key.
func attachPasskey(t *testing.T, s *personal.Session, itemID, userID, userName, displayName string) (string, string) {
	t.Helper()
	revision := revisionOf(t, s, itemID)
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	created, e := s.PerformPasskey(personal.PasskeyTarget{
		Context:  personal.BrowserContext{RequestID: reqID(199), Origin: "https://example.test", TabID: 1, DocumentID: "doc-199"},
		Create:   true,
		ID:       itemID,
		Revision: revision,
		Options:  passkeyCreateWire(userID, userName, displayName),
	}, false, gate)
	if e != nil {
		t.Fatal(e)
	}
	return created.ID, created.Response.PublicKey
}

func passkeyResult(t *testing.T, out *memoryPipe, id string) passkey.Response {
	t.Helper()
	for _, response := range out.responses(t) {
		if response.ID == id && response.Type == "passkey-result" {
			var credential passkey.Response
			if e := json.Unmarshal([]byte(response.Credential), &credential); e != nil {
				t.Fatal(e)
			}
			return credential
		}
	}
	t.Fatalf("missing passkey-result for %s", id)
	return passkey.Response{}
}

func assertSignatureFor(t *testing.T, credential passkey.Response, publicKey string) {
	t.Helper()
	pubDER, e := base64.RawURLEncoding.DecodeString(publicKey)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.ParsePKIXPublicKey(pubDER)
	if e != nil {
		t.Fatal(e)
	}
	client, e := base64.RawURLEncoding.DecodeString(credential.Response.ClientDataJSON)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := base64.RawURLEncoding.DecodeString(credential.Response.AuthenticatorData)
	if e != nil {
		t.Fatal(e)
	}
	signature, e := base64.RawURLEncoding.DecodeString(credential.Response.Signature)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(client)
	digest := sha256.Sum256(append(auth, h[:]...))
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("signature does not correspond to the selected credential")
	}
}

func waitPasskeyRefusal(t *testing.T, out *memoryPipe, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, response := range out.responses(t) {
			if response.ID == id && response.Type == "error" {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("passkey request %s was not refused", id)
}

// Two credentials of one login must render as two choices and only the exact
// selected credential may answer. The legacy native API refuses the ambiguous
// parent instead of choosing the first record.
func TestPasskeyMultipleCredentialsExactSelection(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, secondPub := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	if first == second {
		t.Fatal("fixture credentials collided")
	}
	get := Request{
		V: 1, ID: reqID(210), Type: "passkey-get", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: passkeyGetWire("example.test", first, second),
	}
	if e := c.Handle(get); e != nil {
		t.Fatal(e)
	}
	pending := waitPasskey(t, c)
	if len(pending.Choices) != 2 {
		t.Fatalf("choices: %#v", pending.Choices)
	}
	seen := map[string]bool{}
	for _, choice := range pending.Choices {
		if choice.ID != itemID {
			t.Fatalf("choice left its parent: %#v", pending.Choices)
		}
		seen[choice.CredentialID] = true
	}
	if !seen[first] || !seen[second] {
		t.Fatalf("choices lost a credential: %#v", pending.Choices)
	}
	// The old parent-only API cannot decide between two credentials.
	if e := c.ApprovePasskey(get.ID, itemID, nil, nil); e == nil {
		t.Fatal("legacy approval silently chose one of two credentials")
	}
	if e := c.ApprovePasskeyCredential(get.ID, itemID, canonicalCredential(0x5a), nil, nil); e == nil {
		t.Fatal("approval accepted a credential that was not reviewed")
	}
	if e := c.ApprovePasskeyCredential(get.ID, "0123456789abcdef0123456789abcdef", second, nil, nil); e == nil {
		t.Fatal("approval accepted a foreign parent item")
	}
	if e := c.ApprovePasskeyCredential(get.ID, itemID, second, nil, nil); e != nil {
		t.Fatal(e)
	}
	credential := passkeyResult(t, out, get.ID)
	if credential.ID != second {
		t.Fatalf("signed credential %q, selected %q", credential.ID, second)
	}
	assertSignatureFor(t, credential, secondPub)
}

// A pinned request may narrow to one exact credential, but a request that names
// another credential of the same parent must be refused. A stale parent
// revision is refused before any choice is offered.
func TestPasskeyPinnedCredentialAndRevisionRefusals(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, secondPub := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revision := revisionOf(t, s, itemID)
	pinned := Request{
		V: 1, ID: reqID(220), Type: "passkey-get", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		ItemID: itemID, Revision: revision, CredentialID: second,
		Options: passkeyGetWire("example.test", first, second),
	}
	if e := c.Handle(pinned); e != nil {
		t.Fatal(e)
	}
	pending := waitPasskey(t, c)
	if len(pending.Choices) != 1 || pending.Choices[0].CredentialID != second || pending.Choices[0].ID != itemID {
		t.Fatalf("pinned choices: %#v", pending.Choices)
	}
	if e := c.ApprovePasskeyCredential(pinned.ID, itemID, first, nil, nil); e == nil {
		t.Fatal("pinned review approved a sibling credential")
	}
	if e := c.ApprovePasskeyCredential(pinned.ID, itemID, second, nil, nil); e != nil {
		t.Fatal(e)
	}
	if credential := passkeyResult(t, out, pinned.ID); credential.ID != second {
		t.Fatalf("pinned signature %q", credential.ID)
	}
	assertSignatureFor(t, passkeyResult(t, out, pinned.ID), secondPub)

	stale := pinned
	stale.ID, stale.Revision, stale.ItemID = reqID(221), strings.Repeat("a", 64), itemID
	if e := c.Handle(stale); e != nil {
		t.Fatal(e)
	}
	waitPasskeyRefusal(t, out, stale.ID)
	missing := pinned
	missing.ID, missing.CredentialID = reqID(222), canonicalCredential(0x33)
	if e := c.Handle(missing); e != nil {
		t.Fatal(e)
	}
	waitPasskeyRefusal(t, out, missing.ID)
	if c.Snapshot().Passkey != nil {
		t.Fatal("refused review left an approval surface")
	}
}

func TestPasskeyGetCredentialSelectorStrictWire(t *testing.T) {
	credential := canonicalCredential(0x11)
	if !passkey.ValidCredentialID(credential) {
		t.Fatal("fixture selector is not canonical")
	}
	base := map[string]any{"v": 1, "id": reqID(230), "type": "passkey-get", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test", credential)}
	read := func(value map[string]any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		_, e = ReadRequest(bytes.NewReader(frame(string(raw))))
		return e
	}
	with := func(extra map[string]any) map[string]any {
		value := map[string]any{}
		for k, v := range base {
			value[k] = v
		}
		for k, v := range extra {
			value[k] = v
		}
		return value
	}
	if e := read(with(nil)); e != nil {
		t.Fatalf("legacy unpinned get refused: %v", e)
	}
	for name, extra := range map[string]map[string]any{
		"selector without parent": {"credential_id": credential},
		"selector with item only": {"credential_id": credential, "item_id": reqID(4)},
		"selector with revision":  {"credential_id": credential, "revision": strings.Repeat("a", 64)},
		"non-canonical selector":  {"credential_id": "not-canonical", "item_id": reqID(4), "revision": strings.Repeat("a", 64)},
		"padded selector":         {"credential_id": credential + "=", "item_id": reqID(4), "revision": strings.Repeat("a", 64)},
	} {
		if e := read(with(extra)); e == nil {
			t.Fatalf("passkey-get accepted %s", name)
		}
	}
	if e := read(with(map[string]any{"credential_id": credential, "item_id": reqID(4), "revision": strings.Repeat("a", 64)})); e != nil {
		t.Fatalf("complete exact pin refused: %v", e)
	}
	create := map[string]any{"v": 1, "id": reqID(231), "type": "passkey-create", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": passkeyGetWire("example.test"), "credential_id": credential}
	if e := read(create); e == nil {
		t.Fatal("passkey-create accepted a credential selector")
	}
	if count := strings.Count(strings.Join(SupportedCapabilities(), ","), "multiple-passkeys-v1"); count != 1 {
		t.Fatalf("multiple-passkeys-v1 advertised %d times", count)
	}
}

func TestPasskeyMetadataMultipleProjection(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, _ := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revision := revisionOf(t, s, itemID)
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(240), "type": "item-get", "capability": capability, "item_id": itemID, "revision": revision})
	if detail.Type != "item-detail" || detail.Item == nil || !detail.Item.HasPasskey {
		t.Fatalf("detail: %#v", detail)
	}
	if len(detail.Item.Passkeys) != 2 || detail.Item.Passkey != nil {
		t.Fatalf("detail passkeys: %#v legacy %#v", detail.Item.Passkeys, detail.Item.Passkey)
	}
	ids := map[string]bool{}
	for _, metadata := range detail.Item.Passkeys {
		ids[metadata.CredentialID] = true
		if metadata.RPID != "example.test" {
			t.Fatalf("metadata: %#v", metadata)
		}
	}
	if !ids[first] || !ids[second] {
		t.Fatalf("detail credential ids: %#v", detail.Item.Passkeys)
	}
	raw, e := json.Marshal(detail)
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"private_key", "user_id", "userHandle", "raw_record"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("metadata leaked %q: %s", forbidden, raw)
		}
	}
	items := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(241), "type": "search", "capability": capability, "passkeys_only": true})
	if items.Type != "items" || len(items.Items) != 1 || items.Items[0].PasskeyCount != 2 || items.Items[0].Passkey != nil {
		t.Fatalf("list projection: %#v", items.Items)
	}
	// Every credential participates in the public metadata query, not just the
	// first record of the login.
	for _, query := range []string{"second-account", "Second Account"} {
		found := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(242), "type": "vault-search", "capability": capability, "passkeys_only": true, "query": query})
		if len(found.Items) != 1 || found.Items[0].ID != itemID {
			t.Fatalf("metadata query %q: %#v", query, found.Items)
		}
	}
	plain := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(243), "type": "search", "capability": capability, "query": "second-account"})
	if len(plain.Items) != 0 {
		t.Fatalf("plain search widened by metadata: %#v", plain.Items)
	}
}

func TestPasskeyRemoveOneSiblingKeepsRemainder(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, _ := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	revision := revisionOf(t, s, itemID)
	removed := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(250), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": revision, "credential_id": first})
	if removed.Type != "passkey-removed" || removed.CredentialID != first || removed.Revision == "" {
		t.Fatalf("remove: %#v", removed)
	}
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(251), "type": "item-get", "capability": capability, "item_id": itemID, "revision": removed.Revision})
	if detail.Item == nil || !detail.Item.HasPasskey || len(detail.Item.Passkeys) != 1 || detail.Item.Passkeys[0].CredentialID != second || detail.Item.Passkey == nil || detail.Item.Passkey.CredentialID != second {
		t.Fatalf("sibling after removal: %#v", detail.Item)
	}
	removed = v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(252), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": removed.Revision, "credential_id": second})
	if removed.Type != "passkey-removed" {
		t.Fatalf("second remove: %#v", removed)
	}
	detail = v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(253), "type": "item-get", "capability": capability, "item_id": itemID, "revision": removed.Revision})
	if detail.Item == nil || detail.Item.HasPasskey || len(detail.Item.Passkeys) != 0 || detail.Item.Passkey != nil {
		t.Fatalf("detail after last removal: %#v", detail.Item)
	}
}

func TestConditionalPasskeyListKeepsOneCandidatePerCredential(t *testing.T) {
	c, out, s, capability, itemID, _, first := fixturePasskey(t)
	defer c.Close()
	second, _ := attachPasskey(t, s, itemID, "dXNlcjE", "second-account", "Second Account")
	r := Request{V: 1, ID: reqID(260), Type: "passkey-list", Capability: capability, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", Options: passkeyGetWire("example.test")}
	if e := c.Handle(r); e != nil {
		t.Fatal(e)
	}
	frame := candidatesFrame(t, out, r.ID)
	list, _ := frame["passkeys"].([]any)
	if len(list) != 2 {
		t.Fatalf("candidates collapsed: %#v", frame)
	}
	seen := map[string]bool{}
	for _, raw := range list {
		candidate := raw.(map[string]any)
		if candidate["item_id"] != itemID {
			t.Fatalf("candidate parent: %#v", candidate)
		}
		seen[candidate["credential_id"].(string)] = true
	}
	if !seen[first] || !seen[second] {
		t.Fatalf("candidate credentials: %#v", frame)
	}
}
