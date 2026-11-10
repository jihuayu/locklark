package onepux

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

func onepuxItem(t testing.TB, uuid, category, state string, overview, details map[string]any) map[string]any {
	t.Helper()
	item := map[string]any{"uuid": uuid, "categoryUuid": category, "state": state, "overview": overview, "details": details}
	return item
}

func onepuxArchive(t testing.TB, items []map[string]any, files map[string][]byte) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"accounts": []any{map[string]any{"attrs": map[string]any{"uuid": "account-1", "name": "Account"}, "vaults": []any{map[string]any{"attrs": map[string]any{"uuid": "vault-1", "name": "Vault"}, "items": items}}}}})
	if err != nil {
		t.Fatal(err)
	}
	entries := []entry{}
	if len(files) > 0 {
		entries = append(entries, entry{"files/", ""})
	}
	for name, content := range files {
		entries = append(entries, entry{name, string(content)})
	}
	return pack(t, attributes, string(data), entries...)
}

func typedSection(name, title string, fields ...map[string]any) map[string]any {
	return map[string]any{"name": name, "title": title, "fields": fields}
}

func typedField(id, title string, value any) map[string]any {
	return map[string]any{"id": id, "title": title, "value": value}
}

func TestMapArchiveV2CategoryFeatureAndAttachmentMapping(t *testing.T) {
	seed := bytes.Repeat([]byte{33}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(block)
	if privatePEM == nil {
		t.Fatal("private key encoding failed")
	}
	items := []map[string]any{
		onepuxItem(t, "login-1", "001", "active",
			map[string]any{"title": "Login Item", "url": "https://example.test/login", "urls": []any{map[string]any{"url": "https://example.test/login", "label": "primary"}, map[string]any{"url": "https://other.example.test/", "label": "other"}}, "tags": []any{"work", "shared"}},
			map[string]any{
				"notesPlain": "login notes",
				"loginFields": []any{
					map[string]any{"id": "u", "name": "username", "designation": "username", "fieldType": "T", "value": "private-user"},
					map[string]any{"id": "p", "name": "password", "designation": "password", "fieldType": "P", "value": "private-password"},
					map[string]any{"id": "extra", "name": "extra label", "fieldType": "T", "value": "extra value"},
				},
				"sections": []any{
					typedSection("section-one", "Section One",
						typedField("secret", "Secret", map[string]any{"concealed": "concealed-value"}),
						typedField("otp", "TOTP", map[string]any{"totp": "otpauth://totp/example?secret=AAAA"}),
						typedField("email", "Email", map[string]any{"email": map[string]any{"email_address": "private@example.test"}}),
						typedField("when", "Date", map[string]any{"date": 1700000000}),
						typedField("month", "Month", map[string]any{"monthYear": 202611}),
						typedField("phone", "Phone", map[string]any{"phone": "+1 555 0100"}),
						typedField("address", "Address", map[string]any{"address": map[string]any{"street": "1 Main St", "city": "City", "state": "ST", "zip": "12345", "country": "US"}}),
						typedField("reference", "Reference", map[string]any{"reference": "op://vault/item/field"}),
						typedField("menu", "Menu", map[string]any{"menu": "option"}),
						typedField("url", "URL", map[string]any{"url": "https://field.example.test/"}),
					),
				},
				"passwordHistory": []any{map[string]any{"value": "old-password", "time": 1600000000}, map[string]any{"value": "older-password", "time": 1500000000}},
			}),
		onepuxItem(t, "card-1", "002", "active", map[string]any{"title": "Card Item", "tags": []any{"finance"}}, map[string]any{
			"sections": []any{typedSection("card", "Card",
				typedField("cardholder", "Cardholder", map[string]any{"string": "Card Holder"}),
				typedField("type", "Type", map[string]any{"creditCardType": "visa"}),
				typedField("ccnum", "Number", map[string]any{"creditCardNumber": "4111111111111111"}),
				typedField("cvv", "CVV", map[string]any{"concealed": "123"}),
				typedField("expiry", "Expiry", map[string]any{"monthYear": 203001}),
				typedField("validFrom", "Valid From", map[string]any{"monthYear": 202001}),
				typedField("pin", "PIN", map[string]any{"concealed": "9999"}),
				typedField("bank", "Bank", map[string]any{"string": "Example Bank"}),
			)},
		}),
		onepuxItem(t, "identity-1", "004", "archived", map[string]any{"title": "Identity Item"}, map[string]any{
			"sections": []any{typedSection("identity", "Identity",
				typedField("firstname", "First", map[string]any{"string": "First"}),
				typedField("initial", "Initial", map[string]any{"string": "M"}),
				typedField("lastname", "Last", map[string]any{"string": "Last"}),
				typedField("birthdate", "Birthday", map[string]any{"date": 631152000}),
				typedField("company", "Company", map[string]any{"string": "Company"}),
				typedField("department", "Department", map[string]any{"string": "Department"}),
				typedField("jobtitle", "Job Title", map[string]any{"string": "Engineer"}),
				typedField("email", "Email", map[string]any{"email": map[string]any{"email_address": "identity@example.test"}}),
				typedField("defphone", "Phone", map[string]any{"phone": "+1 555 0101"}),
				typedField("address", "Address", map[string]any{"address": map[string]any{"street": "2 Main St", "city": "Town", "state": "TS", "zip": "54321", "country": "US"}}),
			)},
		}),
		onepuxItem(t, "note-1", "003", "trashed", map[string]any{"title": "Secure Note"}, map[string]any{
			"sections": []any{typedSection("notes", "Notes", typedField("body", "Body", map[string]any{"string": "note body"}))},
		}),
		onepuxItem(t, "api-1", "112", "active", map[string]any{"title": "API Credential"}, map[string]any{
			"sections": []any{typedSection("api", "API", typedField("token", "Token", map[string]any{"concealed": "api-secret"}))},
		}),
		onepuxItem(t, "medical-1", "113", "active", map[string]any{"title": "Medical Record"}, map[string]any{
			"sections": []any{typedSection("medical", "Medical", typedField("provider", "Provider", map[string]any{"string": "Clinic"}))},
		}),
		onepuxItem(t, "doc-1", "114", "active", map[string]any{"title": "Document Item"}, map[string]any{
			"documentAttributes": map[string]any{"documentId": "doc-id", "fileName": "report.txt", "decryptedSize": 11},
		}),
		onepuxItem(t, "ssh-1", "115", "active", map[string]any{"title": "SSH Key"}, map[string]any{
			"sections": []any{typedSection("ssh", "SSH", typedField("key", "Private Key", map[string]any{"sshKey": string(privatePEM)}))},
		}),
	}
	items[0]["favIndex"] = 1
	items[4]["favIndex"] = 2
	items[0]["createdAt"] = 123
	items[0]["updatedAt"] = 456
	items[6]["file"] = map[string]any{"path": "files/report.txt"}
	raw := onepuxArchive(t, items, map[string][]byte{"files/report.txt": []byte("hello world")})
	before := bytes.Clone(raw)
	mapped, err := MapArchiveV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) || mapped.Report.Profile != FullProfileV2 || mapped.Report.Items != len(items) || mapped.Report.Archived != 1 {
		t.Fatalf("report or source changed: %+v", mapped.Report)
	}
	byTitle := map[string]vault.Item{}
	for _, item := range mapped.Items {
		byTitle[item.Title] = item
	}
	login := byTitle["Login Item"]
	if login.Category != vault.CategoryLogin || login.Kind != "login" || login.Username != "private-user" || login.Password != "private-password" || login.OTP == "" || !login.Favorite || login.CreatedAt != 123 || login.UpdatedAt != 456 || !reflect.DeepEqual(login.Tags, []string{"work", "shared"}) {
		t.Fatalf("login mapping lost: %+v", login)
	}
	if len(login.URLs) != 2 || !login.URLs[0].Primary || login.URLs[0].Label != "primary" || login.URLs[1].Primary {
		t.Fatalf("login URLs lost: %+v", login.URLs)
	}
	if len(login.History) != 2 || login.History[0].Password != "old-password" || login.History[0].Timestamp != 1600000000 || login.History[0].Action != "import-1pux" {
		t.Fatalf("password history lost: %+v", login.History)
	}
	byField := map[string]vault.CustomField{}
	for _, section := range login.Sections {
		for _, field := range section.Fields {
			byField[field.ID] = field
		}
	}
	if byField["secret"].Type != vault.FieldTypeConcealed || !byField["secret"].Protected || byField["otp"].Type != vault.FieldTypeOTP || byField["email"].Type != vault.FieldTypeEmail || byField["when"].Value != "2023-11-14" || byField["month"].Value != "2026-11" || byField["phone"].Value != "+1 555 0100" || byField["address"].Value != "1 Main St, City, ST, 12345, US" || byField["reference"].Type != vault.FieldTypeReference || byField["menu"].Type != vault.FieldTypeMenu || byField["url"].Type != vault.FieldTypeURL {
		t.Fatalf("section field types or values lost: %+v", byField)
	}
	card := byTitle["Card Item"]
	if card.Category != vault.CategoryCreditCard || card.CreditCard == nil || card.CreditCard.CardholderName != "Card Holder" || card.CreditCard.Type != "visa" || card.CreditCard.Number != "4111111111111111" || card.CreditCard.Verification != "123" || card.CreditCard.ExpiryDate != "2030-01" || card.CreditCard.ValidFrom != "2020-01" || card.CreditCard.PIN != "9999" || card.CreditCard.IssuingBank != "Example Bank" {
		t.Fatalf("credit card mapping lost: %+v", card.CreditCard)
	}
	identity := byTitle["Identity Item"]
	if identity.Category != vault.CategoryIdentity || identity.State != "archived" || identity.Identity == nil || identity.Identity.FirstName != "First" || identity.Identity.MiddleName != "M" || identity.Identity.LastName != "Last" || identity.Identity.Company != "Company" || identity.Identity.Email != "identity@example.test" || identity.Identity.Phone != "+1 555 0101" || identity.Identity.AddressLine1 != "2 Main St" || identity.Identity.City != "Town" || identity.Identity.State != "TS" || identity.Identity.PostalCode != "54321" || identity.Identity.Country != "US" || identity.Identity.BirthDate != "1990-01-01" {
		t.Fatalf("identity mapping lost: %+v", identity.Identity)
	}
	if byTitle["Secure Note"].Category != vault.CategorySecureNote || byTitle["Secure Note"].State != "trashed" || byTitle["API Credential"].Category != vault.CategoryAPICredential || !byTitle["API Credential"].Favorite {
		t.Fatal("category or state mapping lost")
	}
	if byTitle["Medical Record"].Category != vault.CategoryMedicalRecord {
		t.Fatal("medical record category lost")
	}
	doc := byTitle["Document Item"]
	if doc.Category != vault.CategoryDocument || doc.Filename != "report.txt" || string(doc.Attachment) != "hello world" || len(doc.Attachments) != 1 || string(doc.Attachments[0].Content) != "hello world" || doc.Attachments[0].Size != 11 || doc.Attachments[0].SHA256 != vault.AttachmentSHA256([]byte("hello world")) {
		t.Fatalf("document attachment lost: %+v", doc)
	}
	sshk := byTitle["SSH Key"]
	if sshk.Category != vault.CategorySSHKey || !bytes.Equal(sshk.SSHSeed, seed) {
		t.Fatalf("ssh key material lost: %+v", sshk)
	}
	pub, err := ssh.ParsePublicKey(sshk.SSHPublicKey)
	if err != nil || pub.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("ssh public key invalid: %v", err)
	}
	for _, item := range mapped.Items {
		if !strings.Contains(string(item.ImportSource), "locklark/1pux-source/v1") || !strings.Contains(string(item.ImportSource), "account-1") {
			t.Fatal("import provenance lost")
		}
	}
	again, err := MapArchiveV2(raw)
	if err != nil || !reflect.DeepEqual(mapped, again) {
		t.Fatal("v2 mapping is not deterministic")
	}
	report, _ := json.Marshal(mapped.Report)
	if strings.Contains(string(report), "private-") || strings.Contains(string(report), "Account") {
		t.Fatal("report leaked source data")
	}
	// The narrow login profile must remain unable to flatten v2 categories.
	if _, err := MapLogins(raw); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("MapLogins accepted a full v2 archive: %v", err)
	}
}

func TestMapArchiveV2RejectsLossyOrUnsupportedInput(t *testing.T) {
	base := func() map[string]any {
		return onepuxItem(t, "login", "001", "active", map[string]any{"title": "Login"}, map[string]any{
			"loginFields": []any{map[string]any{"designation": "password", "fieldType": "P", "value": "value"}},
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown category": func(item map[string]any) { item["categoryUuid"] = "999" },
		"unknown state":    func(item map[string]any) { item["state"] = "future" },
		"http url": func(item map[string]any) {
			item["overview"] = map[string]any{"title": "Login", "url": "http://example.test"}
		},
		"duplicate tag": func(item map[string]any) {
			item["overview"] = map[string]any{"title": "Login", "tags": []any{"a", "A"}}
		},
		"unknown detail": func(item map[string]any) { item["details"].(map[string]any)["future"] = true },
		"unknown value": func(item map[string]any) {
			item["details"].(map[string]any)["sections"] = []any{typedSection("s", "S", typedField("f", "F", map[string]any{"future": "x"}))}
		},
		"missing document": func(item map[string]any) {
			item["categoryUuid"], item["details"] = "114", map[string]any{"documentAttributes": map[string]any{"fileName": "missing.txt", "decryptedSize": 1}}
		},
		"mismatched size": func(item map[string]any) {
			item["categoryUuid"], item["details"] = "114", map[string]any{"documentAttributes": map[string]any{"fileName": "a.txt", "decryptedSize": 2}}
		},
		"non-https section": func(item map[string]any) {
			item["overview"] = map[string]any{"title": "Login", "url": "https://example.test/path", "urls": []any{map[string]any{"url": "http://example.test/path"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			item := base()
			mutate(item)
			files := map[string][]byte{}
			if name == "mismatched size" {
				files["files/a.txt"] = []byte("x")
			}
			mapped, err := MapArchiveV2(onepuxArchive(t, []map[string]any{item}, files))
			if err == nil || !reflect.DeepEqual(mapped, MappedLogins{}) {
				t.Fatal("lossy input accepted", err)
			}
			if strings.Contains(err.Error(), "Login") || strings.Contains(err.Error(), "a.txt") {
				t.Fatal("error leaked source data")
			}
		})
	}
	if _, err := MapArchiveV2(onepuxArchive(t, []map[string]any{base()}, map[string][]byte{"files/extra.txt": []byte("x")})); err != nil {
		t.Fatalf("unlinked extra file broke mapping: %v", err)
	}
}

func TestMapArchiveV2CapacityBound(t *testing.T) {
	items := make([]map[string]any, vault.MaxItems+1)
	for n := range items {
		item := onepuxItem(t, "login-"+string(rune('a'+n%26))+"-"+strings.Repeat("x", n/26+1), "001", "active", map[string]any{"title": "Login"}, map[string]any{
			"loginFields": []any{map[string]any{"designation": "password", "fieldType": "P", "value": "value"}},
		})
		items[n] = item
	}
	if _, err := MapArchiveV2(onepuxArchive(t, items, nil)); !errors.Is(err, ErrLimit) {
		t.Fatal("item cap bypassed", err)
	}
}

func TestMapArchiveV2UnknownEnvelopeNeverReflected(t *testing.T) {
	raw := onepuxArchive(t, []map[string]any{onepuxItem(t, "login", "001", "active", map[string]any{"title": "Login"}, map[string]any{"notesPlain": nil})}, nil)
	if _, err := MapArchiveV2(raw); err == nil || strings.Contains(err.Error(), "Login") {
		t.Fatal("invalid details accepted or echoed")
	}
}

func FuzzMapArchiveV2(f *testing.F) {
	f.Add([]byte("PK"))
	f.Add(onepuxArchive(f, []map[string]any{onepuxItem(f, "login", "001", "active", map[string]any{"title": "Login"}, map[string]any{"loginFields": []any{map[string]any{"designation": "password", "fieldType": "P", "value": "value"}}})}, nil))
	f.Fuzz(func(t *testing.T, raw []byte) {
		mapped, err := MapArchiveV2(raw)
		if err != nil {
			if mapped.Items != nil || mapped.Report != (MappingReport{}) {
				t.Fatal("failed mapping returned partial result")
			}
		}
	})
}
