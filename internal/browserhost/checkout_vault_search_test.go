package browserhost

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// TestSessionCheckoutCardReachesCanonicalVaultSearchRow exercises the exact
// journey a real acceptance fixture uses: the ordinary authenticated
// Session.AddItem mutation creates a credit card, then the real wire request
// validator and vault-search handler must return that card with its exact ID,
// revision and canonical category. It also pins the native category contract:
// the extension-facing alias "card" is not a server-side search category.
func TestSessionCheckoutCardReachesCanonicalVaultSearchRow(t *testing.T) {
	c, out, s, capability := v2Fixture(t)
	defer c.Close()

	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(gate); err != nil {
		t.Fatalf("register mutation: %v", err)
	}
	card := vault.Item{
		Kind:     "credit_card",
		Category: vault.CategoryCreditCard,
		Title:    "Browser acceptance card",
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Synthetic Checkout Holder",
			Type:           "visa",
			Number:         "4000000000000002",
			Verification:   "123",
			ExpiryDate:     "2030-01",
			PIN:            "4321",
		},
	}
	id, revision, err := s.AddItem(card, gate)
	if err != nil {
		t.Fatalf("Session.AddItem: %v", err)
	}
	if len(id) != 32 || len(revision) != 64 {
		t.Fatalf("unexpected item identity: id=%d revision=%d", len(id), len(revision))
	}

	for index, kind := range []string{"vault-search", "vault-list"} {
		response := v2Handle(t, c, out, map[string]any{
			"v": 1, "id": reqID(70 + index), "type": kind, "capability": capability,
			"query": "", "category": "credit_card",
		})
		if response.Type != "items" || len(response.Items) != 1 {
			t.Fatalf("%s credit_card rows: %#v", kind, response)
		}
		row := response.Items[0]
		if row.ID != id || row.Revision != revision || row.Category != "credit_card" ||
			row.Title != card.Title || row.Subtitle != "Visa 0002" {
			t.Fatalf("%s card row mismatch: %#v", kind, row)
		}
		raw, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"4000000000000002", `"123"`, `"4321"`} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("%s list response disclosed card material", kind)
			}
		}
	}

	// The UI alias never widens the native category filter; the client must
	// canonicalize before it sends the request.
	alias := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(80), "type": "vault-search", "capability": capability,
		"query": "", "category": "card",
	})
	if alias.Type != "items" || len(alias.Items) != 0 {
		t.Fatalf("alias category unexpectedly matched rows: %#v", alias.Items)
	}

	detail := v2Handle(t, c, out, map[string]any{
		"v": 1, "id": reqID(81), "type": "item-get", "capability": capability,
		"item_id": id, "revision": revision,
	})
	if detail.Type != "item-detail" || detail.Item == nil || detail.Item.ID != id ||
		detail.Item.Revision != revision || detail.Item.Category != "credit_card" ||
		detail.Item.CreditCard == nil {
		t.Fatalf("card detail pipeline: %#v", detail.Item)
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"4000000000000002", `"123"`, `"4321"`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("card detail response disclosed card material")
		}
	}
}
