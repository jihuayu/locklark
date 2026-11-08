package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func mustRefuse(t *testing.T, raw string) {
	t.Helper()
	_, err := decodeTypedPersonalInput([]byte(raw))
	if !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("expected fixed refusal, got %v", err)
	}
	// The fixed error must not echo the document or any decoded value.
	if text := err.Error(); strings.Contains(text, "secret") || strings.Contains(text, "hunter2") || strings.Contains(text, "title") {
		t.Fatalf("refusal echoed input: %q", text)
	}
}

func TestDecodeTypedPersonalInputLoginWithSectionsURLsTagsFavorite(t *testing.T) {
	raw := `{
		"category": "login",
		"title": "Example",
		"username": "user@example.test",
		"password": "hunter2",
		"notes": "line one\nline two",
		"url": "https://example.test/login",
		"urls": [
			{"url": "https://example.test/login", "label": "Login", "primary": true, "match_mode": "origin"},
			{"url": "https://app.example.test/", "match_mode": "host"}
		],
		"tags": ["work", " Work ", "ops"],
		"favorite": true,
		"sections": [
			{"id": "api", "title": "API", "fields": [
				{"id": "token", "label": "Token", "type": "concealed", "value": "secret-token"},
				{"id": "owner", "label": "Owner", "value": "team"}
			]}
		]
	}`
	item, err := decodeTypedPersonalInput([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if item.Category != vault.CategoryLogin || item.Kind != "login" || item.Title != "Example" {
		t.Fatalf("unexpected identity: %+v", item)
	}
	if item.Username != "user@example.test" || item.Password != "hunter2" || item.URL != "https://example.test/login" {
		t.Fatalf("unexpected login fields: %+v", item)
	}
	if item.VaultID != vault.DefaultVaultID || !item.Favorite {
		t.Fatalf("unexpected vault/favorite: %+v", item)
	}
	if len(item.URLs) != 2 || !item.URLs[0].Primary || item.URLs[1].MatchMode != vault.URLMatchHost {
		t.Fatalf("unexpected urls: %+v", item.URLs)
	}
	if len(item.Tags) != 2 || item.Tags[0] != "work" || item.Tags[1] != "ops" {
		t.Fatalf("unexpected tags: %+v", item.Tags)
	}
	if len(item.Sections) != 1 || len(item.Sections[0].Fields) != 2 {
		t.Fatalf("unexpected sections: %+v", item.Sections)
	}
	if f := item.Sections[0].Fields[0]; f.Type != vault.FieldTypeConcealed || !f.Protected {
		t.Fatalf("concealed field must be protected: %+v", f)
	}
	if f := item.Sections[0].Fields[1]; f.Type != vault.FieldTypeText || f.Protected {
		t.Fatalf("plain field must stay text: %+v", f)
	}
	if len(item.Attachments) != 0 || item.ID != "" || item.State != "" || item.History != nil || item.ImportSource != nil {
		t.Fatalf("parser must not invent native material: %+v", item)
	}
}

func TestDecodeTypedPersonalInputIdentityAndCreditCard(t *testing.T) {
	identity, err := decodeTypedPersonalInput([]byte(`{
		"category": "identity",
		"title": "Personal identity",
		"identity": {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.test", "country": "GB"}
	}`))
	if err != nil {
		t.Fatalf("identity decode: %v", err)
	}
	if identity.Category != vault.CategoryIdentity || identity.Identity == nil || identity.Identity.FirstName != "Ada" || identity.Identity.Country != "GB" {
		t.Fatalf("unexpected identity item: %+v", identity)
	}
	card, err := decodeTypedPersonalInput([]byte(`{
		"category": "credit_card",
		"title": "Example card",
		"credit_card": {"cardholder_name": "Ada Lovelace", "number": "4111111111111111", "verification": "123", "expiry_date": "2030-01"}
	}`))
	if err != nil {
		t.Fatalf("card decode: %v", err)
	}
	if card.Category != vault.CategoryCreditCard || card.CreditCard == nil || card.CreditCard.Number != "4111111111111111" || card.CreditCard.ExpiryDate != "2030-01" {
		t.Fatalf("unexpected card item: %+v", card)
	}
}

func TestDecodeTypedPersonalInputRefusesUnknownAndRawMembers(t *testing.T) {
	for _, raw := range []string{
		`{"title":"x","surprise":true}`,
		`{"title":"x","attachment":"AAAA"}`,
		`{"title":"x","attachments":[{"file_name":"a.txt"}]}`,
		`{"title":"x","passkey":"AAAA"}`,
		`{"title":"x","ssh_seed":"AAAA"}`,
		`{"title":"x","ssh_public_key":"AAAA"}`,
		`{"title":"x","import_source":"AAAA"}`,
		`{"title":"x","history":[]}`,
		`{"title":"x","id":"0123456789abcdef"}`,
		`{"title":"x","kind":"login"}`,
		`{"title":"x","state":"archived"}`,
		`{"title":"x","vault_id":"personal"}`,
		`{"title":"x","created_at":1}`,
		`{"title":"x","updated_at":1}`,
		`{"title":"x","trashed_at":null}`,
		`{"title":"x","auto_submit":true}`,
	} {
		mustRefuse(t, raw)
	}
}

func TestDecodeTypedPersonalInputRefusesBadShape(t *testing.T) {
	for _, raw := range []string{
		``,
		`[]`,
		`{"title":"x"} {"title":"y"}`,
		`{"title":"x"} trailing`,
		`{"title":"x"} {}`,
		`{"title":""}`,
		`{"title":"   "}`,
		`{"category":"ssh_key","title":"key"}`,
		`{"category":"document","title":"doc"}`,
		`{"category":"unknown","title":"x"}`,
		`{"title":"x","url":"ftp://example.test"}`,
		`{"title":"x","url":"https://user:pass@example.test"}`,
		`{"title":"x","urls":[{"url":"https://example.test","primary":true},{"url":"https://two.example.test","primary":true}]}`,
		`{"title":"x","urls":[{"url":"https://example.test"},{"url":"https://example.test"}]}`,
		`{"title":"x","urls":[{"url":"https://example.test","match_mode":"wildcard"}]}`,
		`{"title":"x","sections":[{"id":"a b","title":"S"}]}`,
		`{"title":"x","sections":[{"id":"s","title":"S"},{"id":"S","title":"dup"}]}`,
		`{"title":"x","sections":[{"id":"s","title":"S","fields":[{"id":"f","label":"F","type":"file","value":"AAAA"}]}]}`,
		`{"title":"x","sections":[{"id":"s","title":"S","fields":[{"id":"f","label":"F"},{"id":"F","label":"dup"}]}]}`,
		`{"title":"x","sections":[{"id":"s","title":"S","fields":[{"id":"f","label":"F","type":"bogus","value":"v"}]}]}`,
		`{"title":"x","credit_card":{"number":"4111111111111111"}}`,
		`{"category":"identity","title":"x","credit_card":{"number":"4111111111111111"}}`,
		`{"title":"x","identity":{"first_name":"Ada"}}`,
		"{\"title\":\"bad\x01control\"}",
	} {
		mustRefuse(t, raw)
	}
	if _, err := decodeTypedPersonalInput([]byte{0xff, 0xfe, 0xfd}); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("invalid utf-8: %v", err)
	}
}

func TestDecodeTypedPersonalInputRefusesDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"title":"x","title":"y"}`,
		`{"Title":"x","title":"y"}`,
		`{"title":"x","urls":[{"url":"https://example.test","URL":"https://two.example.test"}]}`,
		`{"title":"x","sections":[{"id":"s","title":"S","fields":[{"id":"f","label":"F","Label":"G"}]}]}`,
		`{"title":"x","credit_card":{"number":"4111111111111111","Number":"4111111111111112"}}`,
	} {
		mustRefuse(t, raw)
	}
}

func TestDecodeTypedPersonalInputBounds(t *testing.T) {
	if _, err := decodeTypedPersonalInput(make([]byte, maxTypedInputBytes+1)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("oversized document: %v", err)
	}
	tooDeep := strings.Repeat(`{"a":`, maxTypedJSONDepth+1) + `1` + strings.Repeat(`}`, maxTypedJSONDepth+1)
	if _, err := decodeTypedPersonalInput([]byte(tooDeep)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("deep document: %v", err)
	}
	tooManyURLs := `{"title":"x","urls":[` + strings.TrimSuffix(strings.Repeat(`{"url":"https://example.test"},`, maxTypedURLs+1), ",") + `]}`
	if _, err := decodeTypedPersonalInput([]byte(tooManyURLs)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("too many urls: %v", err)
	}
	tooLongTitle := `{"title":"` + strings.Repeat("a", maxTypedTitle+1) + `"}`
	if _, err := decodeTypedPersonalInput([]byte(tooLongTitle)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("title bound: %v", err)
	}
}
