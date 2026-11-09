package personal

import (
	"strconv"
	"strings"

	"github.com/jihuayu/locklark/internal/vault"
)

// Every disclosed value is bounded individually and as one overall native
// payload. Oversized items are a business refusal, never a truncated fill.
const maxBrowserProfileBudget = 48 << 10

// BrowserProfileValue is one owned private name/value pair in a projection.
type BrowserProfileValue struct {
	Name  string
	Value []byte
}

// BrowserProfileContent owns the approved projection. It is never a snapshot,
// log, JSON or response DTO field; callers may only read it inside the writer
// callback granted to ConsumeBrowserProfileFill.
type BrowserProfileContent struct {
	Category string
	Fields   []BrowserProfileValue
	Identity []BrowserProfileValue
	Card     []BrowserProfileValue
	budget   int
}

func (c *BrowserProfileContent) clear() {
	if c == nil {
		return
	}
	for _, group := range [][]BrowserProfileValue{c.Fields, c.Identity, c.Card} {
		for _, v := range group {
			clear(v.Value)
		}
	}
	c.Fields, c.Identity, c.Card = nil, nil, nil
	c.Category, c.budget = "", 0
}

func (c *BrowserProfileContent) add(dst *[]BrowserProfileValue, name, value string) error {
	if value == "" {
		return nil
	}
	if name == "" || len(name) > 128 || len(value) > maxBrowserField || len(value) > c.budget {
		return ErrBrowserProfileFill
	}
	c.budget -= len(value)
	*dst = append(*dst, BrowserProfileValue{Name: name, Value: []byte(value)})
	return nil
}

// profileFillContent projects only the approved profile fields. Card PINs,
// SSNs, passport and licence numbers are never copied.
func profileFillContent(it vault.Item, category string) (*BrowserProfileContent, error) {
	c := &BrowserProfileContent{Category: category, budget: maxBrowserProfileBudget}
	switch category {
	case "credit_card":
		card := it.NormalizedCreditCard()
		if card == nil {
			return nil, ErrBrowserProfileFill
		}
		month, year, short := profileExpiryParts(card.ExpiryDate)
		for _, pair := range [][2]string{{"cc-name", card.CardholderName}, {"cc-number", card.Number}, {"cc-exp", card.ExpiryDate}, {"cc-exp-month", month}, {"cc-exp-year", year}, {"cc-exp-year-short", short}, {"cc-csc", card.Verification}, {"cc-type", card.Type}} {
			if e := c.add(&c.Fields, pair[0], pair[1]); e != nil {
				return nil, e
			}
		}
		for _, pair := range [][2]string{{"cardholder_name", card.CardholderName}, {"type", card.Type}, {"number", card.Number}, {"verification", card.Verification}, {"expiry_date", card.ExpiryDate}, {"exp_month", month}, {"exp_year", year}, {"exp_year_short", short}} {
			if e := c.add(&c.Card, pair[0], pair[1]); e != nil {
				return nil, e
			}
		}
	case "identity":
		ident := it.NormalizedIdentity()
		if ident == nil {
			return nil, ErrBrowserProfileFill
		}
		name := strings.TrimSpace(ident.FirstName + " " + ident.MiddleName + " " + ident.LastName)
		if name == "" {
			name = ident.Title
		}
		street := strings.TrimSpace(strings.TrimPrefix(ident.AddressLine1+", "+ident.AddressLine2, ", "))
		for _, pair := range [][2]string{{"honorific-prefix", ident.Title}, {"given-name", ident.FirstName}, {"additional-name", ident.MiddleName}, {"family-name", ident.LastName}, {"name", name}, {"organization", ident.Company}, {"organization-title", ident.JobTitle}, {"email", ident.Email}, {"tel", ident.Phone}, {"street-address", street}, {"address-line1", ident.AddressLine1}, {"address-line2", ident.AddressLine2}, {"address-level2", ident.City}, {"address-level1", ident.State}, {"postal-code", ident.PostalCode}, {"country", ident.Country}, {"country-name", ident.Country}, {"bday", ident.BirthDate}} {
			if e := c.add(&c.Fields, pair[0], pair[1]); e != nil {
				return nil, e
			}
		}
		for _, pair := range [][2]string{{"title", ident.Title}, {"first_name", ident.FirstName}, {"middle_name", ident.MiddleName}, {"last_name", ident.LastName}, {"birth_date", ident.BirthDate}, {"company", ident.Company}, {"department", ident.Department}, {"job_title", ident.JobTitle}, {"email", ident.Email}, {"phone", ident.Phone}, {"address_line1", ident.AddressLine1}, {"address_line2", ident.AddressLine2}, {"city", ident.City}, {"state", ident.State}, {"postal_code", ident.PostalCode}, {"country", ident.Country}, {"website", ident.Website}} {
			if e := c.add(&c.Identity, pair[0], pair[1]); e != nil {
				return nil, e
			}
		}
	default:
		return nil, ErrBrowserProfileFill
	}
	return c, nil
}

func profileExpiryParts(expiry string) (month, year, short string) {
	parts := strings.Split(expiry, "-")
	if len(parts) != 2 || len(parts[0]) != 4 || len(parts[1]) != 2 {
		return "", "", ""
	}
	if _, e := strconv.Atoi(parts[0]); e != nil {
		return "", "", ""
	}
	if _, e := strconv.Atoi(parts[1]); e != nil {
		return "", "", ""
	}
	return parts[1], parts[0], parts[0][2:]
}
