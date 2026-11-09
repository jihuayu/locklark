package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

func profileFixture(t *testing.T, item vault.Item) (*Session, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if e := Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, rev, e := s.AddItem(item, v2Gate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	return s, id, rev
}

func profileTarget(id, rev, category string) BrowserProfileTarget {
	return BrowserProfileTarget{ID: id, Revision: rev, Category: category, Context: BrowserContext{
		RequestID: "22222222222222222222222222222222", Origin: "https://shop.example.test", TabID: 7, DocumentID: "document-7",
	}}
}

func profileCard() vault.Item {
	return vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Shop Card", CreditCard: &vault.CreditCardDetails{
		CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", PIN: "9999",
	}}
}

func profileIntents(t *testing.T, s *Session) []Event {
	t.Helper()
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	out := []Event{}
	for _, ev := range events {
		if ev.Action == browserProfileFillAction && ev.Result == "intent" {
			out = append(out, ev)
		}
	}
	return out
}

func profileValues(c *BrowserProfileContent) map[string]string {
	out := map[string]string{}
	for _, group := range [][]BrowserProfileValue{c.Fields, c.Card, c.Identity} {
		for _, v := range group {
			out[v.Name] = string(v.Value)
		}
	}
	return out
}

// A profile grant is refused unless the category, revision and authorization
// intent are all consistent, is one-use, and never contains the card PIN.
func TestBrowserProfileFillCardGrantIsAuditedAndOneUse(t *testing.T) {
	s, id, rev := profileFixture(t, profileCard())
	c := profileTarget(id, rev, "credit_card").Context
	if _, e := s.PrepareBrowserProfileFill(BrowserProfileTarget{ID: id, Revision: rev, Category: "document", Context: c}); e == nil {
		t.Fatal("unsupported category accepted")
	}
	if _, e := s.PrepareBrowserProfileFill(BrowserProfileTarget{ID: id, Revision: rev, Category: "identity", Context: c}); e == nil {
		t.Fatal("unknown category accepted")
	}
	before := profileIntents(t, s)
	grant, e := s.PrepareBrowserProfileFill(profileTarget(id, rev, "credit_card"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := json.Marshal(grant); e == nil {
		t.Fatal("grant serialized")
	}
	// The durable intent must exist before any private byte is delivered.
	after := profileIntents(t, s)
	if len(after) != len(before)+1 {
		t.Fatalf("intent events %d -> %d", len(before), len(after))
	}
	intent := after[len(after)-1]
	if intent.Action != browserProfileFillAction || intent.Result != "intent" || !digestOK(intent.Link) || intent.Item != id || intent.BaseRevision != rev {
		t.Fatalf("intent %#v", intent)
	}
	delivered := 0
	e = s.ConsumeBrowserProfileFill(grant, func(content *BrowserProfileContent) error {
		delivered++
		fields := profileValues(content)
		for _, key := range []string{"cc-name", "cc-number", "cc-csc", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-exp-year-short", "cc-type"} {
			if fields[key] == "" {
				t.Fatalf("missing %q in %#v", key, fields)
			}
		}
		if fields["cc-number"] != "4111111111111111" || fields["cc-csc"] != "123" || fields["cc-exp-month"] != "01" || fields["cc-exp-year-short"] != "30" {
			t.Fatalf("card fields %#v", fields)
		}
		for name, value := range fields {
			if value == "9999" || name == "pin" || name == "cc-pin" {
				t.Fatal("card PIN disclosed")
			}
		}
		return nil
	})
	if e != nil || delivered != 1 {
		t.Fatalf("consume %v %d", e, delivered)
	}
	if s.ConsumeBrowserProfileFill(grant, func(*BrowserProfileContent) error { delivered++; return nil }) == nil || delivered != 1 {
		t.Fatal("grant replayed")
	}
	raw, _ := json.Marshal(after)
	if bytes.Contains(raw, []byte("4111111111111111")) || bytes.Contains(raw, []byte("Card Holder")) || bytes.Contains(raw, []byte("9999")) {
		t.Fatal("audit leaked a private value")
	}
	if _, e := s.PrepareBrowserProfileFill(profileTarget(id, strings.Repeat("0", 64), "credit_card")); !errors.Is(e, ErrConflict) {
		t.Fatalf("stale revision accepted: %v", e)
	}
	if next, e := s.SetFavorite(id, rev, true, v2Gate(t, s)); e != nil || next == rev {
		t.Fatalf("favorite mutation %q %v", next, e)
	}
	if _, e := s.PrepareBrowserProfileFill(profileTarget(id, rev, "credit_card")); !errors.Is(e, ErrConflict) {
		t.Fatalf("superseded revision accepted: %v", e)
	}
}

// Lock, cancel-by-discard and expiration all prevent delivery of approved bytes.
func TestBrowserProfileFillGrantNeverSurvivesLockOrDiscard(t *testing.T) {
	s, id, rev := profileFixture(t, profileCard())
	grant, e := s.PrepareBrowserProfileFill(profileTarget(id, rev, "credit_card"))
	if e != nil {
		t.Fatal(e)
	}
	delivered := 0
	s.DiscardBrowserProfileFill(grant)
	if s.ConsumeBrowserProfileFill(grant, func(*BrowserProfileContent) error { delivered++; return nil }) == nil || delivered != 0 {
		t.Fatal("discarded grant consumed")
	}
	grant, e = s.PrepareBrowserProfileFill(profileTarget(id, rev, "credit_card"))
	if e != nil {
		t.Fatal(e)
	}
	s.Lock()
	if s.ConsumeBrowserProfileFill(grant, func(*BrowserProfileContent) error { delivered++; return nil }) == nil || delivered != 0 {
		t.Fatal("locked grant consumed")
	}
}

// A grant minted by another session is foreign: this session's discard is a
// no-op and must never clear the owner's pending target. An expired own grant
// is removed on consume so it cannot occupy a bounded pending slot.
func TestBrowserProfileFillForeignDiscardAndExpiredConsume(t *testing.T) {
	s1, id1, rev1 := profileFixture(t, profileCard())
	s2, _, _ := profileFixture(t, profileCard())
	grant, e := s1.PrepareBrowserProfileFill(profileTarget(id1, rev1, "credit_card"))
	if e != nil {
		t.Fatal(e)
	}
	s2.DiscardBrowserProfileFill(grant)
	delivered := 0
	if e := s1.ConsumeBrowserProfileFill(grant, func(*BrowserProfileContent) error { delivered++; return nil }); e != nil || delivered != 1 {
		t.Fatalf("foreign discard wiped the owner grant: %v %d", e, delivered)
	}
	// Expired own grants release their slot both on consume and on prepare.
	for i := 0; i < maxBrowserProfilePending; i++ {
		g, e := s1.PrepareBrowserProfileFill(profileTarget(id1, rev1, "credit_card"))
		if e != nil {
			t.Fatal(e)
		}
		g.until = time.Now().Add(-time.Second)
		if e := s1.ConsumeBrowserProfileFill(g, func(*BrowserProfileContent) error { return nil }); e == nil {
			t.Fatal("expired grant consumed")
		}
		if s1.profilePending[g] {
			t.Fatal("expired grant kept its pending slot")
		}
	}
	if _, e := s1.PrepareBrowserProfileFill(profileTarget(id1, rev1, "credit_card")); e != nil {
		t.Fatalf("expired grants exhausted the cap: %v", e)
	}
}
