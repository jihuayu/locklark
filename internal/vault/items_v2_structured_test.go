package vault

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

func TestItemV2StructuredFieldsRejectXMLControlCharacters(t *testing.T) {
	const control = "synthetic\x01value"

	t.Run("credit card", func(t *testing.T) {
		base := CreditCardDetails{CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01", PIN: "9999", IssuingBank: "Bank"}
		typ := reflect.TypeOf(base)
		for n := 0; n < typ.NumField(); n++ {
			if typ.Field(n).Type.Kind() != reflect.String {
				continue
			}
			t.Run(typ.Field(n).Name, func(t *testing.T) {
				cc := base
				reflect.ValueOf(&cc).Elem().Field(n).SetString(control)
				item := Item{ID: "card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card", CreditCard: &cc}
				if err := ValidateItems(nil, []Item{item}); !errors.Is(err, ErrSnapshot) {
					t.Fatalf("control character in %s accepted: %v", typ.Field(n).Name, err)
				}
			})
		}
	})

	t.Run("identity", func(t *testing.T) {
		base := IdentityDetails{Title: "Identity", FirstName: "First", MiddleName: "Middle", LastName: "Last", BirthDate: "1990-01-02", Company: "Company", Department: "Department", JobTitle: "Job", Email: "person@example.test", Phone: "+1 555 0100", AddressLine1: "1 Street", AddressLine2: "Suite 2", City: "City", State: "ST", PostalCode: "12345", Country: "US", SSN: "000-00-0000", PassportNumber: "P0000000", LicenseNumber: "L0000000", Website: "https://person.example.test"}
		typ := reflect.TypeOf(base)
		for n := 0; n < typ.NumField(); n++ {
			if typ.Field(n).Type.Kind() != reflect.String {
				continue
			}
			t.Run(typ.Field(n).Name, func(t *testing.T) {
				id := base
				reflect.ValueOf(&id).Elem().Field(n).SetString(control)
				item := Item{ID: "identity", Kind: "identity", Category: CategoryIdentity, Title: "identity", Identity: &id}
				if err := ValidateItems(nil, []Item{item}); !errors.Is(err, ErrSnapshot) {
					t.Fatalf("control character in %s accepted: %v", typ.Field(n).Name, err)
				}
			})
		}
	})

	t.Run("history", func(t *testing.T) {
		base := ItemHistoryEntry{Timestamp: 1, Action: "edit", Password: "old-password", Title: "Old", Username: "old-user", Notes: "old-notes"}
		typ := reflect.TypeOf(base)
		for n := 0; n < typ.NumField(); n++ {
			if typ.Field(n).Type.Kind() != reflect.String {
				continue
			}
			t.Run(typ.Field(n).Name, func(t *testing.T) {
				h := base
				reflect.ValueOf(&h).Elem().Field(n).SetString(control)
				item := Item{ID: "history", Kind: "secure_note", Category: CategorySecureNote, Title: "history", History: []ItemHistoryEntry{h}}
				if err := ValidateItems(nil, []Item{item}); !errors.Is(err, ErrSnapshot) {
					t.Fatalf("control character in %s accepted: %v", typ.Field(n).Name, err)
				}
			})
		}
	})
}

func TestItemV2StructuredFieldLengthBoundary(t *testing.T) {
	t.Run("credit card", func(t *testing.T) {
		base := CreditCardDetails{}
		typ := reflect.TypeOf(base)
		for n := 0; n < typ.NumField(); n++ {
			if typ.Field(n).Type.Kind() != reflect.String {
				continue
			}
			for _, tc := range []struct {
				name   string
				length int
				valid  bool
			}{{"maximum", 1024, true}, {"over maximum", 1025, false}} {
				t.Run(typ.Field(n).Name+"/"+tc.name, func(t *testing.T) {
					cc := base
					reflect.ValueOf(&cc).Elem().Field(n).SetString(strings.Repeat("a", tc.length))
					item := Item{ID: "card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card", CreditCard: &cc}
					err := ValidateItems(nil, []Item{item})
					if (err == nil) != tc.valid {
						t.Fatalf("%s length %d valid=%v, error=%v", typ.Field(n).Name, tc.length, tc.valid, err)
					}
				})
			}
		}
	})

	t.Run("identity", func(t *testing.T) {
		base := IdentityDetails{}
		typ := reflect.TypeOf(base)
		for n := 0; n < typ.NumField(); n++ {
			if typ.Field(n).Type.Kind() != reflect.String {
				continue
			}
			for _, tc := range []struct {
				name   string
				length int
				valid  bool
			}{{"maximum", 1024, true}, {"over maximum", 1025, false}} {
				t.Run(typ.Field(n).Name+"/"+tc.name, func(t *testing.T) {
					id := base
					reflect.ValueOf(&id).Elem().Field(n).SetString(strings.Repeat("a", tc.length))
					item := Item{ID: "identity", Kind: "identity", Category: CategoryIdentity, Title: "identity", Identity: &id}
					err := ValidateItems(nil, []Item{item})
					if (err == nil) != tc.valid {
						t.Fatalf("%s length %d valid=%v, error=%v", typ.Field(n).Name, tc.length, tc.valid, err)
					}
				})
			}
		}
	})
}

func TestItemV2StructuredDetailsMaxPayloadAccounting(t *testing.T) {
	t.Run("credit card", func(t *testing.T) {
		cc := CreditCardDetails{CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01", PIN: "9999", IssuingBank: "Bank"}
		item := Item{ID: "card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card", CreditCard: &cc}
		assertMaxPayloadBoundary(t, item, len(item.ID)+len(item.Kind)+len(item.Title)+stringFieldsBytes(&cc))
	})

	t.Run("identity", func(t *testing.T) {
		id := IdentityDetails{Title: "Identity", FirstName: "First", LastName: "Last", Email: "person@example.test"}
		item := Item{ID: "identity", Kind: "identity", Category: CategoryIdentity, Title: "identity", Identity: &id}
		assertMaxPayloadBoundary(t, item, len(item.ID)+len(item.Kind)+len(item.Title)+stringFieldsBytes(&id))
	})

	t.Run("history", func(t *testing.T) {
		h := ItemHistoryEntry{Timestamp: 1, Action: "edit", Password: "old-password", Title: "Old", Username: "old-user", Notes: "old-notes", Sections: []ItemSection{{ID: "section-one", Title: "Section", Fields: []CustomField{{ID: "field-one", Label: "Field", Type: FieldTypeText, Value: "value", Purpose: "purpose"}}}}}
		item := Item{ID: "history", Kind: "secure_note", Category: CategorySecureNote, Title: "history", History: []ItemHistoryEntry{h}}
		assertMaxPayloadBoundary(t, item, len(item.ID)+len(item.Kind)+len(item.Title)+historyPayloadBytes(h))
	})

	t.Run("attachments", func(t *testing.T) {
		content := []byte("synthetic attachment body")
		att := AttachmentMeta{ID: "attachment-one", FileName: "fixture.bin", Size: int64(len(content)), MIMEType: "application/octet-stream", SHA256: AttachmentSHA256(content), Content: content}
		item := Item{ID: "note", Kind: "secure_note", Category: CategorySecureNote, Title: "note", Attachments: []AttachmentMeta{att}}
		assertMaxPayloadBoundary(t, item, len(item.ID)+len(item.Kind)+len(item.Title)+len(att.ID)+len(att.FileName)+len(att.MIMEType)+len(att.SHA256)+int(att.Size))
	})
}

func TestItemV2StructuredDetailsExportRoundTrip(t *testing.T) {
	special := "A&B <tag> \"quote\" 'apos'\t\n\r中文"
	items := []Item{
		{ID: "card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card & <title>", CreditCard: &CreditCardDetails{CardholderName: special, Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01", PIN: "9999", IssuingBank: "Bank & <Trust>"}},
		{ID: "identity", Kind: "identity", Category: CategoryIdentity, Title: "identity", Identity: &IdentityDetails{Title: special, FirstName: "First", LastName: "Last", Email: "person@example.test", AddressLine1: "1 Street & <Apt>", Website: "https://person.example.test/?a=1&b=<2>"}},
		{ID: "history", Kind: "secure_note", Category: CategorySecureNote, Title: "history", History: []ItemHistoryEntry{{Timestamp: 1, Action: "edit", Password: special, Title: "Old & <Title>", Username: "old-user", Notes: special, Sections: []ItemSection{{ID: "section-one", Title: "Section & <One>", Fields: []CustomField{{ID: "field-one", Label: "Field & <One>", Type: FieldTypeText, Value: special, Purpose: "purpose"}}}}}}},
	}
	const password = "synthetic-export-password"
	raw, err := ExportKDBX(items, password)
	if err != nil {
		t.Fatal(err)
	}
	db := kdbx.NewDatabase()
	db.Credentials = kdbx.NewPasswordCredentials(password)
	if err := kdbx.NewDecoder(bytes.NewReader(raw)).Decode(db); err != nil {
		t.Fatal(err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	if len(db.Content.Root.Groups) != 1 {
		t.Fatalf("export group count = %d", len(db.Content.Root.Groups))
	}
	entries := map[string]kdbx.Entry{}
	for _, entry := range db.Content.Root.Groups[0].Entries {
		entries[entry.GetContent("Locklark.ID")] = entry
	}
	envelopes := map[string]itemV2Envelope{}
	for n := range items {
		entry, ok := entries[items[n].ID]
		if !ok {
			t.Fatalf("missing export entry %q", items[n].ID)
		}
		env, err := decodeItemV2Envelope(entry.GetContent(itemV2Slot))
		if err != nil {
			t.Fatalf("decode %s envelope: %v", items[n].ID, err)
		}
		envelopes[items[n].ID] = env
	}
	if !reflect.DeepEqual(envelopes["card"].CreditCard, items[0].CreditCard) {
		t.Fatalf("credit card changed across export: %+v", envelopes["card"].CreditCard)
	}
	if !reflect.DeepEqual(envelopes["identity"].Identity, items[1].Identity) {
		t.Fatalf("identity changed across export: %+v", envelopes["identity"].Identity)
	}
	if !reflect.DeepEqual(envelopes["history"].History, items[2].History) {
		t.Fatalf("history changed across export: %+v", envelopes["history"].History)
	}
}

func TestItemV2StructuredDetailsExportRejectsXMLControl(t *testing.T) {
	item := Item{ID: "card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card", CreditCard: &CreditCardDetails{CardholderName: "synthetic\x01value"}}
	if _, err := ExportKDBX([]Item{item}, "synthetic-export-password"); !errors.Is(err, ErrSnapshot) {
		t.Fatalf("export accepted XML control character: %v", err)
	}
}

func stringFieldsBytes(v any) int {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		panic("stringFieldsBytes requires a pointer to a struct")
	}
	value = value.Elem()
	total := 0
	for n := 0; n < value.NumField(); n++ {
		if value.Field(n).Kind() == reflect.String {
			total += len(value.Field(n).String())
		}
	}
	return total
}

func historyPayloadBytes(h ItemHistoryEntry) int {
	total := stringFieldsBytes(&h)
	for _, s := range h.Sections {
		total += len(s.ID) + len(s.Title)
		for _, f := range s.Fields {
			total += len(f.ID) + len(f.Label) + len(f.Value) + len(f.Purpose)
		}
	}
	return total
}

func assertMaxPayloadBoundary(t *testing.T, item Item, payload int) {
	t.Helper()
	if payload <= 0 || payload >= MaxPayload {
		t.Fatalf("test payload %d outside (0, MaxPayload)", payload)
	}
	if !validItems([]Item{item}, MaxPayload-payload) {
		t.Fatal("item rejected at the exact MaxPayload budget")
	}
	if validItems([]Item{item}, MaxPayload-payload+1) {
		t.Fatal("item accepted over the MaxPayload budget")
	}
}
