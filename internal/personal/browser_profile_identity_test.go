package personal

import (
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

// Identity fills disclose only the approved profile fields. SSN, passport and
// licence numbers are never copied into any page or DTO projection.
func TestBrowserProfileFillIdentityWhitelist(t *testing.T) {
	s, id, rev := profileFixture(t, vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Owner Identity", Identity: &vault.IdentityDetails{
		FirstName: "First", LastName: "Last", Email: "owner@example.test", Phone: "+1 555 0101",
		AddressLine1: "1 Street", City: "City", State: "ST", PostalCode: "12345", Country: "US",
		Department: "Engineering", Website: "https://owner.example.test",
		SSN: "123-45-6789", PassportNumber: "P-999888", LicenseNumber: "D-777666",
	}})
	grant, e := s.PrepareBrowserProfileFill(profileTarget(id, rev, "identity"))
	if e != nil {
		t.Fatal(e)
	}
	delivered := 0
	e = s.ConsumeBrowserProfileFill(grant, func(content *BrowserProfileContent) error {
		delivered++
		if content.Category != "identity" || len(content.Card) != 0 {
			t.Fatal("wrong projection")
		}
		fields := profileValues(content)
		for _, approved := range []string{"given-name", "family-name", "email", "tel", "street-address", "address-level2", "postal-code", "country", "first_name", "last_name", "department", "website"} {
			if fields[approved] == "" {
				t.Fatalf("approved field %q missing", approved)
			}
		}
		for name, value := range fields {
			switch strings.ToLower(name) {
			case "ssn", "passport", "passport_number", "license", "license_number", "passport-number", "license-number":
				t.Fatalf("private identity field %q projected", name)
			}
			for _, secret := range []string{"123-45-6789", "P-999888", "D-777666"} {
				if value == secret || strings.Contains(value, secret) {
					t.Fatalf("private identity value leaked into %q", name)
				}
			}
		}
		return nil
	})
	if e != nil || delivered != 1 {
		t.Fatalf("consume %v %d", e, delivered)
	}
}

// Every field stays under 16 KiB and the whole projection stays under the
// overall native budget; oversized items are refused, never truncated.
func TestBrowserProfileFillBudgetBounds(t *testing.T) {
	huge := vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Huge", Identity: &vault.IdentityDetails{AddressLine1: strings.Repeat("a", maxBrowserField+1)}}
	if _, e := profileFillContent(huge, "identity"); e == nil {
		t.Fatal("oversized field accepted")
	}
	wide := vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Wide", Identity: &vault.IdentityDetails{
		FirstName: strings.Repeat("b", 15<<10), LastName: strings.Repeat("c", 15<<10), Email: strings.Repeat("d", 15<<10), City: strings.Repeat("e", 15<<10),
	}}
	if _, e := profileFillContent(wide, "identity"); e == nil {
		t.Fatal("overall budget exceeded")
	}
	card := vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Wide Card", CreditCard: &vault.CreditCardDetails{Number: strings.Repeat("1", maxBrowserField+1)}}
	if _, e := profileFillContent(card, "credit_card"); e == nil {
		t.Fatal("oversized card number accepted")
	}
	if _, e := profileFillContent(vault.Item{Kind: "login", Title: "Login"}, "identity"); e == nil {
		t.Fatal("non-profile item accepted")
	}
}
