package browserhost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func fixturePasskey(t *testing.T) (*Connection, *memoryPipe, *personal.Session, string, string, string, string) {
	t.Helper()
	c, out, s, capability := v2Fixture(t)
	create := Request{
		V: 1, ID: reqID(30), Type: "passkey-create", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture User"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`,
	}
	if err := c.Handle(create); err != nil {
		t.Fatal(err)
	}
	pending := waitPasskey(t, c)
	if len(pending.Choices) != 1 {
		t.Fatalf("attachment choices: %#v", pending.Choices)
	}
	itemID := pending.Choices[0].ID
	if err := c.ApprovePasskey(create.ID, itemID, nil, nil); err != nil {
		t.Fatal(err)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "passkey-result" {
		t.Fatalf("creation response: %#v", last)
	}
	var credential passkey.Response
	if err := json.Unmarshal([]byte(last.Credential), &credential); err != nil {
		t.Fatal(err)
	}
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	revision := ""
	for _, row := range rows {
		if row.ID == itemID {
			revision = row.Revision
		}
	}
	if revision == "" {
		t.Fatal("created passkey item missing")
	}
	return c, out, s, capability, itemID, revision, credential.ID
}

func passkeyGetRequest(id, capability, credential string) Request {
	return Request{
		V: 1, ID: id, Type: "passkey-get", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2","allowCredentials":[{"type":"public-key","id":"` + credential + `"}]}`,
	}
}

func TestPasskeyManagementMetadataSearchAndStrictWire(t *testing.T) {
	c, out, _, capability, itemID, revision, credential := fixturePasskey(t)
	defer c.Close()
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(40), "type": "item-get", "capability": capability, "item_id": itemID, "revision": revision})
	if detail.Type != "item-detail" || detail.Item == nil || !detail.Item.HasPasskey || detail.Item.Passkey == nil {
		t.Fatalf("detail metadata: %#v", detail.Item)
	}
	metadata := detail.Item.Passkey
	if metadata.CredentialID != credential || metadata.RPID != "example.test" || metadata.UserName != "passkey-fixture-user" || metadata.DisplayName != "Fixture User" {
		t.Fatalf("metadata: %#v", metadata)
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"private_key", "private", "user_id", "userHandle", "raw_record"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("metadata leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"credential_id"`) || !strings.Contains(text, `"rp_id"`) || !strings.Contains(text, `"user_name"`) || !strings.Contains(text, `"display_name"`) {
		t.Fatalf("metadata fields missing: %s", text)
	}

	items := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(41), "type": "search", "capability": capability, "passkeys_only": true})
	if items.Type != "items" || len(items.Items) != 1 || items.Items[0].ID != itemID || items.Items[0].Passkey == nil {
		t.Fatalf("passkeys-only search: %#v", items.Items)
	}
	for _, query := range []string{"example.test", "passkey-fixture-user", "Fixture User"} {
		found := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(42), "type": "vault-search", "capability": capability, "passkeys_only": true, "query": query})
		if len(found.Items) != 1 || found.Items[0].ID != itemID {
			t.Fatalf("metadata query %q: %#v", query, found.Items)
		}
	}
	// The same public metadata query is not widened outside passkeys-only mode.
	plain := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(43), "type": "search", "capability": capability, "query": "passkey-fixture-user"})
	if len(plain.Items) != 0 {
		t.Fatalf("non-passkey search widened by metadata: %#v", plain.Items)
	}

	for name, raw := range map[string]string{
		"private key":       `{"v":1,"id":"` + reqID(44) + `","type":"search","capability":"` + capability + `","passkeys_only":true,"private_key":"x"}`,
		"wrong bool type":   `{"v":1,"id":"` + reqID(45) + `","type":"search","capability":"` + capability + `","passkeys_only":"true"}`,
		"on item-get":       `{"v":1,"id":"` + reqID(46) + `","type":"item-get","capability":"` + capability + `","item_id":"` + itemID + `","passkeys_only":true}`,
		"remove origin":     `{"v":1,"id":"` + reqID(47) + `","type":"passkey-remove","capability":"` + capability + `","item_id":"` + itemID + `","revision":"` + revision + `","credential_id":"` + credential + `","origin":"https://example.test"}`,
		"remove raw record": `{"v":1,"id":"` + reqID(48) + `","type":"passkey-remove","capability":"` + capability + `","item_id":"` + itemID + `","revision":"` + revision + `","credential_id":"` + credential + `","private_key":"x"}`,
		"remove bad id":     `{"v":1,"id":"` + reqID(49) + `","type":"passkey-remove","capability":"` + capability + `","item_id":"` + itemID + `","revision":"` + revision + `","credential_id":"not-canonical"}`,
	} {
		if _, err := ReadRequest(bytes.NewReader(frame(raw))); err == nil {
			t.Fatalf("strict wire accepted %s", name)
		}
	}
	valid := mustReadRequest(t, map[string]any{"v": 1, "id": reqID(50), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": revision, "credential_id": credential})
	if valid.PasskeysOnly != nil || valid.CredentialID != credential {
		t.Fatal("valid passkey-remove fields")
	}
	for _, capabilityName := range supportedCapabilities {
		if capabilityName == "passkey-management-v1" {
			return
		}
	}
	t.Fatal("passkey-management-v1 capability not advertised")
}

func TestPasskeyPendingApprovalBlocksRemovalSameConnection(t *testing.T) {
	c, out, _, capability, itemID, revision, credential := fixturePasskey(t)
	defer c.Close()
	get := passkeyGetRequest(reqID(60), capability, credential)
	if err := c.Handle(get); err != nil {
		t.Fatal(err)
	}
	before := waitPasskey(t, c)
	busy := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(61), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": revision, "credential_id": credential})
	if busy.Type != "error" {
		t.Fatalf("removal preempted a preapproval passkey: %#v", busy)
	}
	if after := c.Snapshot().Passkey; after == nil || after.ID != get.ID || len(after.Choices) != len(before.Choices) {
		t.Fatalf("busy refusal invalidated the old approval: %#v", after)
	}
	cancel := Request{V: 1, ID: reqID(62), Type: "cancel", Capability: capability}
	if err := c.Handle(cancel); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Passkey != nil {
		t.Fatal("cancel left the approval pending")
	}
	removed := destructiveCall(t, c, out, map[string]any{"v": 1, "id": reqID(63), "type": "passkey-remove", "capability": capability, "item_id": itemID, "revision": revision, "credential_id": credential})
	if removed.Type != "passkey-removed" || removed.ItemID != itemID || removed.CredentialID != credential || removed.Revision == "" || removed.Revision == revision {
		t.Fatalf("remove response: %#v", removed)
	}
	detail := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(64), "type": "item-get", "capability": capability, "item_id": itemID, "revision": removed.Revision})
	if detail.Type != "item-detail" || detail.Item == nil || detail.Item.Revision != removed.Revision || detail.Item.HasPasskey || detail.Item.Passkey != nil || !detail.Item.HasPassword || detail.Item.Username != "alice" || detail.Item.Title != "Existing" {
		t.Fatalf("revision/detail after removal: %#v", detail.Item)
	}
	for _, response := range out.responses(t) {
		if response.ID == get.ID && response.Type == "passkey-result" {
			t.Fatal("removed credential response escaped")
		}
	}
}

func TestPasskeyEpochSuppressesQueuedSignatureAcrossConnections(t *testing.T) {
	c1, out1, s, cap1, itemID, revision, credential := fixturePasskey(t)
	defer c1.Close()
	c2, out2, cap2 := pairedToSession(t, s)
	defer c2.Close()
	get := passkeyGetRequest(reqID(70), cap1, credential)
	if err := c1.Handle(get); err != nil {
		t.Fatal(err)
	}
	pending := waitPasskey(t, c1)
	if len(pending.Choices) != 1 {
		t.Fatalf("signature choices: %#v", pending.Choices)
	}
	release, err := c1.writer.acquire(time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c1.ApprovePasskey(get.ID, pending.Choices[0].ID, nil, nil) }()
	waitForQueuedPasskey(t, c1)
	removed := destructiveCall(t, c2, out2, map[string]any{"v": 1, "id": reqID(71), "type": "passkey-remove", "capability": cap2, "item_id": itemID, "revision": revision, "credential_id": credential})
	if removed.Type != "passkey-removed" {
		t.Fatalf("cross-connection removal: %#v", removed)
	}
	release()
	if err = <-done; err == nil {
		t.Fatal("queued signature was delivered after revocation")
	}
	for _, response := range out1.responses(t) {
		if response.ID == get.ID && response.Type == "passkey-result" {
			t.Fatal("queued credential escaped across connections")
		}
	}
}

func TestPasskeyPendingApprovalBlocksRemovalAcrossConnections(t *testing.T) {
	c1, out1, s, cap1, itemID, revision, credential := fixturePasskey(t)
	defer c1.Close()
	c2, out2, cap2 := pairedToSession(t, s)
	defer c2.Close()
	get := passkeyGetRequest(reqID(80), cap1, credential)
	if err := c1.Handle(get); err != nil {
		t.Fatal(err)
	}
	before := waitPasskey(t, c1)
	busy := v2Handle(t, c2, out2, map[string]any{"v": 1, "id": reqID(81), "type": "passkey-remove", "capability": cap2, "item_id": itemID, "revision": revision, "credential_id": credential})
	if busy.Type != "error" {
		t.Fatalf("cross-connection removal preempted approval: %#v", busy)
	}
	if after := c1.Snapshot().Passkey; after == nil || after.ID != get.ID || len(after.Choices) != len(before.Choices) {
		t.Fatalf("busy refusal invalidated the old approval: %#v", after)
	}
	cancel := Request{V: 1, ID: reqID(82), Type: "cancel", Capability: cap1}
	if err := c1.Handle(cancel); err != nil {
		t.Fatal(err)
	}
	removal := map[string]any{"v": 1, "id": reqID(83), "type": "passkey-remove", "capability": cap2, "item_id": itemID, "revision": revision, "credential_id": credential}
	removed := destructiveCall(t, c2, out2, removal)
	if removed.Type != "passkey-removed" {
		t.Fatalf("cross-connection removal: %#v", removed)
	}
	for _, response := range out1.responses(t) {
		if response.ID == get.ID && response.Type == "passkey-result" {
			t.Fatal("cancelled credential escaped")
		}
	}
}

// removalReviewFixture is a passkey removal review opened on one connection
// while a second connection shares the same Session.
type removalReviewFixture struct {
	c, other               *Connection
	out, otherOut          *memoryPipe
	cap, otherCap          string
	s                      *personal.Session
	itemID, revision, cred string
}

func (f *removalReviewFixture) frame(n int) map[string]any {
	return map[string]any{"v": 1, "id": reqID(n), "type": "passkey-remove", "capability": f.cap, "item_id": f.itemID, "revision": f.revision, "credential_id": f.cred}
}

// review sends the removal, asserts no answer was sent before native approval
// and returns its exact native review.
func (f *removalReviewFixture) review(t *testing.T, n int) *V2ApprovalView {
	t.Helper()
	before := len(f.out.responses(t))
	v2Send(t, f.c, f.frame(n))
	if got := len(f.out.responses(t)); got != before {
		t.Fatal("passkey-remove answered before native approval")
	}
	v := f.c.Snapshot().V2
	if v == nil || v.Type != "passkey-remove" || v.ID != reqID(n) {
		t.Fatalf("no exact native review: %#v", v)
	}
	return v
}

// pending shows the removal's native review without answering it and proves a
// second connection cannot reach the Session while that review holds the slot.
func (f *removalReviewFixture) pending(t *testing.T, n int) {
	t.Helper()
	f.review(t, n)
	busy := v2Handle(t, f.other, f.otherOut, map[string]any{"v": 1, "id": reqID(n + 1), "type": "passkey-remove", "capability": f.otherCap, "item_id": f.itemID, "revision": f.revision, "credential_id": f.cred})
	if busy.Type != "error" || f.other.Snapshot().V2 != nil {
		t.Fatalf("pending removal review did not hold the mutation slot: %#v", busy)
	}
}

func newRemovalReviewFixture(t *testing.T) *removalReviewFixture {
	t.Helper()
	c, out, s, capability, itemID, revision, credential := fixturePasskey(t)
	t.Cleanup(c.Close)
	other, otherOut, otherCap := pairedToSession(t, s)
	t.Cleanup(other.Close)
	return &removalReviewFixture{c: c, out: out, s: s, cap: capability, itemID: itemID, revision: revision, cred: credential, other: other, otherOut: otherOut, otherCap: otherCap}
}

// TestPasskeyRemovalReviewTimerUsesCapabilityDeadline proves the review, its
// passive timer and its exact gate share one deadline that never outlives a
// short-lived capability: once the capability lapses the timer alone clears the
// review, and the still-unlocked shared Session accepts a new registration.
func TestPasskeyRemovalReviewTimerUsesCapabilityDeadline(t *testing.T) {
	f := newRemovalReviewFixture(t)
	// A shared desktop connection keeps the test Session unlocked when its own
	// capability lapses; only the timer may release the reservation.
	f.c.desktopShared = true
	f.c.mu.Lock()
	f.c.until = time.Now().Add(100 * time.Millisecond)
	f.c.mu.Unlock()
	review := f.review(t, 120)
	if limit := time.Now().Add(100 * time.Millisecond); review.Deadline.After(limit) {
		t.Fatalf("review deadline %v outlived the capability %v", review.Deadline, limit)
	}
	// No Snapshot/Handle on the owning connection: only the passive timer may
	// clear it.
	until := time.Now().Add(2 * time.Second)
	for {
		probe := personal.NewMutationGate(time.Now().Add(time.Minute))
		if err := f.s.RegisterMutation(probe); err == nil {
			f.s.ReleaseMutation(probe)
			break
		}
		if time.Now().After(until) {
			t.Fatal("capability expiry left the removal reservation in the Session")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !f.s.Unlocked() {
		t.Fatal("the shared Session locked instead of just releasing the review")
	}
	f.c.mu.Lock()
	pending := f.c.v2pending
	f.c.mu.Unlock()
	if pending != nil {
		t.Fatal("timer did not clear the expired review")
	}
}

// expectSlotReleased proves the shared Session can take a fresh registration,
// so the ended review left no mutation slot behind.
func expectSlotReleased(t *testing.T, s *personal.Session, label string) {
	t.Helper()
	probe := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(probe); err != nil {
		t.Fatalf("%s: review left the mutation slot occupied: %v", label, err)
	}
	s.ReleaseMutation(probe)
}

func TestPasskeyRemovalReviewRejectReleasesMutationSlot(t *testing.T) {
	f := newRemovalReviewFixture(t)
	f.pending(t, 100)
	if err := f.c.RejectV2(reqID(100)); err != nil {
		t.Fatal(err)
	}
	if v := f.c.Snapshot(); v.V2 != nil || !v.Paired {
		t.Fatalf("reject left a review or revoked pairing: %#v", v)
	}
	expectSlotReleased(t, f.s, "reject")
}

// TestPasskeyRemovalReviewInvalidateReleasesSharedSessionSlot covers a
// brokered connection: Invalidate detaches its own Session pointer before it
// clears the review, so only the Session captured at reservation can give the
// shared mutation slot back.
func TestPasskeyRemovalReviewInvalidateReleasesSharedSessionSlot(t *testing.T) {
	f := newRemovalReviewFixture(t)
	f.c.desktopShared = true
	f.pending(t, 110)
	f.c.Invalidate()
	if v := f.c.Snapshot(); v.V2 != nil || v.Paired || f.c.session.Load() != nil {
		t.Fatalf("invalidate left a review or session: %#v", v)
	}
	expectSlotReleased(t, f.s, "invalidate")
}

func pairedToSession(t *testing.T, s *personal.Session) (*Connection, *memoryPipe, string) {
	t.Helper()
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if err := c.Handle(Request{V: 1, ID: reqID(90), Type: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := c.ApproveQuickPair(s); err != nil {
		t.Fatal(err)
	}
	return c, out, out.responses(t)[0].Capability
}

func waitForQueuedPasskey(t *testing.T, c *Connection) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "(*Connection).ApprovePasskey") && strings.Contains(goroutine, "(*Writer).acquire") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("passkey never queued for output")
}

func TestPasskeyFilterRunsBeforeFiveHundredCap(t *testing.T) {
	c, out, s, capability, itemID, _, _ := fixturePasskey(t)
	defer c.Close()
	// The vault schema caps a real vault at 256 items, so shorten the shared
	// truncation bound and prove filtering happens before truncation.
	previous := searchResultLimit
	searchResultLimit = 50
	defer func() { searchResultLimit = previous }()
	// The passkey item sorts after 51 filler items and must survive the cap.
	for i := 0; i < 51; i++ {
		gate := personal.NewMutationGate(time.Now().Add(time.Minute))
		if err := s.RegisterMutation(gate); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.AddItem(vault.Item{Kind: "secure_note", Category: vault.CategorySecureNote, Title: fmt.Sprintf("0000-%03d", i), Notes: "filler"}, gate); err != nil {
			t.Fatalf("filler %d: %v", i, err)
		}
	}
	filtered := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(84), "type": "search", "capability": capability, "passkeys_only": true})
	if filtered.Type != "items" || len(filtered.Items) != 1 || filtered.Items[0].ID != itemID {
		t.Fatalf("passkeys-only filter after cap: %d %#v", len(filtered.Items), filtered.Items)
	}
	unfiltered := v2Handle(t, c, out, map[string]any{"v": 1, "id": reqID(85), "type": "search", "capability": capability})
	if len(unfiltered.Items) != searchResultLimit {
		t.Fatalf("search cap: %d", len(unfiltered.Items))
	}
	for _, item := range unfiltered.Items {
		if item.ID == itemID {
			t.Fatal("fixture did not exercise truncation")
		}
	}
}
