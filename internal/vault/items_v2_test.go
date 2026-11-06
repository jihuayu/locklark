package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"golang.org/x/crypto/ssh"
)

func TestItemModelV2CategoriesAndFieldTypes(t *testing.T) {
	categories := []ItemCategory{
		CategoryLogin, CategoryPassword, CategorySecureNote, CategoryCreditCard,
		CategoryIdentity, CategorySSHKey, CategoryAPICredential, CategoryDatabase,
		CategoryServer, CategoryDocument, CategoryBankAccount, CategoryWirelessRouter,
		CategorySoftwareLicense, CategoryMembership, CategoryCryptoWallet,
		CategoryMedicalRecord,
	}
	for _, c := range categories {
		if !ValidCategory(c) {
			t.Fatalf("category %q rejected", c)
		}
		if got, ok := CategoryFromKind(string(c), c); !ok || got != c {
			t.Fatalf("category/kind mismatch for %q", c)
		}
	}
	if ValidCategory("unknown") || ValidCategory("") {
		t.Fatal("unknown category accepted")
	}
	if _, ok := CategoryFromKind("credit_card", CategoryLogin); ok {
		t.Fatal("mismatched kind and category accepted")
	}
	for _, tc := range []struct {
		kind string
		cat  ItemCategory
		want ItemCategory
	}{{"login", "", CategoryLogin}, {"document", "", CategoryDocument}, {"ssh-key", "", CategorySSHKey}, {"ssh_key", "", CategorySSHKey}, {"", CategoryCreditCard, CategoryCreditCard}, {"ssh-key", CategorySSHKey, CategorySSHKey}, {"login", CategorySSHKey, ""}} {
		got, ok := CategoryFromKind(tc.kind, tc.cat)
		if (tc.want == "") == ok || ok && got != tc.want {
			t.Fatalf("CategoryFromKind(%q, %q) = %q, %v", tc.kind, tc.cat, got, ok)
		}
	}
	types := []FieldType{
		FieldTypeText, FieldTypeConcealed, FieldTypeURL, FieldTypeEmail, FieldTypeOTP,
		FieldTypeDate, FieldTypeMonthYear, FieldTypePhone, FieldTypeAddress,
		FieldTypeReference, FieldTypeMenu, FieldTypeString, FieldTypeTOTP, FieldTypeFile,
	}
	for _, typ := range types {
		if !ValidFieldType(typ) {
			t.Fatalf("field type %q rejected", typ)
		}
	}
	if ValidFieldType("unknown") || ValidFieldType("") {
		t.Fatal("unknown field type accepted")
	}
	if !reflect.DeepEqual(Field{}, CustomField{}) || !reflect.DeepEqual(Section{}, ItemSection{}) || !reflect.DeepEqual(ItemRevision{}, ItemHistoryEntry{}) {
		t.Fatal("compatibility aliases diverged")
	}
}

func v2FixtureItems(t *testing.T) []Item {
	t.Helper()
	now := time.Unix(1700000000, 0).UTC()
	falseValue := false
	trueValue := true
	sha := AttachmentSHA256([]byte("attachment body"))
	seed := bytes.Repeat([]byte{91}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	request, err := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"name":"Example"},"user":{"id":"dXNlcg","name":"user"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if err != nil {
		t.Fatal(err)
	}
	passkeyRecord, _, err := passkey.Create(request, false)
	if err != nil {
		t.Fatal(err)
	}
	var items []Item
	categories := []ItemCategory{CategoryLogin, CategoryPassword, CategorySecureNote, CategoryCreditCard, CategoryIdentity, CategorySSHKey, CategoryAPICredential, CategoryDatabase, CategoryServer, CategoryDocument, CategoryBankAccount, CategoryWirelessRouter, CategorySoftwareLicense, CategoryMembership, CategoryCryptoWallet, CategoryMedicalRecord}
	for n, cat := range categories {
		it := Item{
			ID:         "item-" + string(cat),
			Category:   cat,
			Title:      "Title " + string(cat),
			Favorite:   n%2 == 0,
			AutoSubmit: &falseValue,
			Tags:       []string{"tag-" + string(cat)},
			URL:        "https://example.test/" + string(cat),
			URLs:       []ItemURL{{Label: "primary", URL: "https://example.test/" + string(cat), Primary: true, MatchMode: URLMatchOrigin}, {Label: "other", URL: "https://other.example.test/path", MatchMode: URLMatchHost}},
			Notes:      "notes " + string(cat),
			CreatedAt:  now.Unix(),
			UpdatedAt:  now.Unix(),
			Sections: []ItemSection{{ID: "section-one", Title: "Section One", Fields: []CustomField{
				{ID: "text-field", Label: "Text", Type: FieldTypeText, Value: "text"},
				{ID: "secret-field", Label: "Secret", Type: FieldTypeConcealed, Value: "secret", Protected: true},
				{ID: "otp-field", Label: "OTP", Type: FieldTypeOTP, Value: "otpauth://totp/example?secret=AAAA", Protected: true},
				{ID: "string-field", Label: "String", Type: FieldTypeString, Value: "string"},
				{ID: "totp-field", Label: "TOTP", Type: FieldTypeTOTP, Value: "seed", Protected: true},
				{ID: "file-field", Label: "File", Type: FieldTypeFile, Value: "file.txt"},
				{ID: "purpose-field", Label: "Card", Type: FieldTypeText, Value: "4111111111111111", Purpose: "cc-number"},
			}}},
			History: []ItemHistoryEntry{{Timestamp: now.Unix(), Action: "edit", Password: "old-password", Title: "Old", Username: "old-user", Notes: "old-notes"}},
		}
		switch cat {
		case CategoryLogin:
			it.Kind = "login"
			it.Username = "user"
			it.Password = "password"
			it.OTP = "otpauth://totp/example?secret=AAAA"
			it.Passkey = passkeyRecord
		case CategoryDocument:
			it.Kind = "document"
			it.Filename = "document.bin"
			it.Attachment = []byte("document bytes")
		case CategorySSHKey:
			it.Kind = "ssh_key"
			it.SSHSeed = append([]byte(nil), seed...)
			it.SSHPublicKey = append([]byte(nil), public.Marshal()...)
		case CategoryCreditCard:
			it.Kind = string(cat)
			it.CreditCard = &CreditCardDetails{CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01", PIN: "9999", IssuingBank: "Bank"}
			it.URLs = nil
		case CategoryIdentity:
			it.Kind = string(cat)
			it.Identity = &IdentityDetails{FirstName: "First", LastName: "Last", Email: "person@example.test", Phone: "+1 555 0100", AddressLine1: "1 Street", City: "City", State: "ST", PostalCode: "12345", Country: "US", BirthDate: "1990-01-02", Website: "https://person.example.test"}
			it.URLs = nil
		default:
			it.Kind = string(cat)
			it.Password = "category-password"
		}
		it.Attachments = []AttachmentMeta{{ID: "attachment-" + string(cat), FileName: "file.txt", Size: int64(len("attachment body")), MIMEType: "text/plain", SHA256: sha, Protected: n%3 == 0, Content: []byte("attachment body")}}
		if n == 1 {
			it.VaultID = "abc123"
			it.TrashedAt = &now
			it.State = "trashed"
			it.PreviousState = "archived"
			it.AutoSubmit = &trueValue
		}
		items = append(items, it)
	}
	// Pure v1 items must remain untouched by the v2 envelope.
	items = append(items,
		Item{ID: "v1-login", Kind: "login", Title: "v1 login", Username: "u", Password: "p", OTP: "otpauth://totp/x?secret=AAAA", Notes: "n", URL: "https://v1.example.test/"},
		Item{ID: "v1-document", Kind: "document", Title: "v1 document", Filename: "v1.bin", Attachment: []byte("v1 bytes"), AttachmentProtected: true},
		Item{ID: "v1-ssh", Kind: "ssh-key", Title: "v1 ssh", SSHSeed: append([]byte(nil), seed...), SSHPublicKey: append([]byte(nil), public.Marshal()...)},
		Item{ID: "v1-passkey", Kind: "login", Title: "v1 passkey", Passkey: passkeyRecord},
	)
	return items
}

func TestItemModelV2KDBXRoundTrip(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	want := v2FixtureItems(t)
	for n := range want {
		if err := ValidateItems(nil, []Item{want[n]}); err != nil {
			t.Fatalf("fixture item %d %s invalid: %+v", n, want[n].ID, want[n])
		}
	}
	snapshot, err := SealItems([]byte("v2 layout"), want, 1, []*age.X25519Recipient{device.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	metadata, got, err := OpenItems(snapshot, device, pub, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(metadata) != "v2 layout" || len(got) != len(want) {
		t.Fatalf("metadata/items mismatch: %q %d", metadata, len(got))
	}
	for n := range want {
		if want[n].EffectiveCategory() != got[n].EffectiveCategory() || want[n].Kind != got[n].Kind || want[n].Title != got[n].Title || want[n].Favorite != got[n].Favorite {
			t.Fatalf("item %d identity lost: %+v vs %+v", n, want[n], got[n])
		}
		if !reflect.DeepEqual(want[n].Tags, got[n].Tags) || !reflect.DeepEqual(want[n].URLs, got[n].URLs) || !reflect.DeepEqual(want[n].Sections, got[n].Sections) || !reflect.DeepEqual(want[n].History, got[n].History) {
			t.Fatalf("item %d v2 metadata lost", n)
		}
		if (want[n].TrashedAt == nil) != (got[n].TrashedAt == nil) || want[n].TrashedAt != nil && !want[n].TrashedAt.Equal(*got[n].TrashedAt) {
			t.Fatalf("item %d trash time lost", n)
		}
		if len(want[n].Attachments) != len(got[n].Attachments) {
			t.Fatalf("item %d attachments lost", n)
		}
		for m := range want[n].Attachments {
			if string(want[n].Attachments[m].Content) != string(got[n].Attachments[m].Content) || want[n].Attachments[m].SHA256 != got[n].Attachments[m].SHA256 || want[n].Attachments[m].Protected != got[n].Attachments[m].Protected {
				t.Fatalf("item %d attachment %d lost", n, m)
			}
		}
		if !reflect.DeepEqual(want[n].CreditCard, got[n].CreditCard) || !reflect.DeepEqual(want[n].Identity, got[n].Identity) {
			t.Fatalf("item %d structured details lost", n)
		}
		if !bytes.Equal(want[n].Passkey, got[n].Passkey) || !bytes.Equal(want[n].SSHSeed, got[n].SSHSeed) || !bytes.Equal(want[n].SSHPublicKey, got[n].SSHPublicKey) || !bytes.Equal(want[n].Attachment, got[n].Attachment) {
			t.Fatalf("item %d key material lost", n)
		}
	}
}

func TestItemModelV2ExportAndSlotCompatibility(t *testing.T) {
	items := v2FixtureItems(t)
	raw, err := ExportKDBX(items, "synthetic-export-password")
	if err != nil {
		t.Fatal(err)
	}
	db := kdbx.NewDatabase()
	db.Credentials = kdbx.NewPasswordCredentials("synthetic-export-password")
	if err := kdbx.NewDecoder(bytes.NewReader(raw)).Decode(db); err != nil {
		t.Fatal(err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	group := db.Content.Root.Groups[0]
	if len(group.Entries) != len(items) {
		t.Fatalf("export lost entries: %d", len(group.Entries))
	}
	binaries := map[string]int{}
	for _, b := range db.Content.InnerHeader.Binaries {
		binaries[string(b.Content)]++
	}
	if binaries["attachment body"] != 2 {
		t.Fatalf("attachments were not deduplicated per protection flag: %v", binaries)
	}
	for _, entry := range group.Entries {
		id := entry.GetContent("Locklark.ID")
		values := map[string]kdbx.V{}
		for _, v := range entry.Values {
			values[v.Key] = v.Value
		}
		v, ok := values[itemV2Slot]
		if strings.HasPrefix(id, "v1-") {
			if ok {
				t.Fatalf("v1 item received v2 envelope: %s", id)
			}
			continue
		}
		if !ok {
			t.Fatalf("missing v2 envelope for %s", id)
		}
		if !v.Protected.Bool {
			t.Fatal("v2 envelope was not protected")
		}
	}
	// The pure v1 login keeps its exact legacy slot set.
	for _, entry := range group.Entries {
		if entry.GetContent("Locklark.ID") != "v1-login" {
			continue
		}
		keys := make([]string, 0, len(entry.Values))
		for _, v := range entry.Values {
			keys = append(keys, v.Key)
		}
		want := []string{"Title", "Locklark.ID", "Locklark.Kind", "Notes", "URL", "Password", "otp", "UserName"}
		if !reflect.DeepEqual(keys, want) {
			t.Fatalf("v1 slot layout changed: %v", keys)
		}
	}
}

func TestItemModelV2RejectsTampering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		alter  func(*kdbx.Database, *kdbx.Entry)
		target string
	}{
		{"unprotected envelope", func(db *kdbx.Database, e *kdbx.Entry) {
			for n := range e.Values {
				if e.Values[n].Key == itemV2Slot {
					e.Values[n].Value.Protected.Bool = false
				}
			}
		}, "item-credit_card"},
		{"unknown envelope field", func(db *kdbx.Database, e *kdbx.Entry) {
			for n := range e.Values {
				if e.Values[n].Key != itemV2Slot {
					continue
				}
				raw, _ := base64.StdEncoding.DecodeString(e.Values[n].Value.Content)
				var object map[string]any
				_ = json.Unmarshal(raw, &object)
				object["future"] = true
				changed, _ := json.Marshal(object)
				e.Values[n].Value.Content = base64.StdEncoding.EncodeToString(changed)
			}
		}, "item-credit_card"},
		{"attachment digest mismatch", func(db *kdbx.Database, e *kdbx.Entry) {
			for n := range db.Content.InnerHeader.Binaries {
				db.Content.InnerHeader.Binaries[n].Content = []byte("tampered body")
			}
		}, "item-secure_note"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
			items := []Item{{ID: "item-credit_card", Kind: "credit_card", Category: CategoryCreditCard, Title: "card", CreatedAt: 1}, {ID: "item-secure_note", Kind: "secure_note", Category: CategorySecureNote, Title: "note", CreatedAt: 1, Attachments: []AttachmentMeta{{ID: "attachment", FileName: "a.txt", Size: 4, SHA256: AttachmentSHA256([]byte("body")), Content: []byte("body")}}}}
			if err := writeItems(db, nil, items); err != nil {
				t.Fatal(err)
			}
			group := db.Content.Root.Groups[0]
			for n := range group.Entries {
				if group.Entries[n].GetContent("Locklark.ID") != tc.target {
					continue
				}
				if err := db.LockProtectedEntries(); err == nil {
					_ = db.UnlockProtectedEntries()
				}
				tc.alter(db, &group.Entries[n])
			}
			if _, _, err := readItems(db, group); err == nil {
				t.Fatal("tampered v2 entry accepted")
			}
		})
	}
}

func TestItemModelV2Accessors(t *testing.T) {
	auto := true
	it := Item{Kind: "login", URL: "https://primary.example.test", URLs: []ItemURL{{URL: "https://primary.example.test", Primary: true, MatchMode: URLMatchHost}, {URL: "https://second.example.test", MatchMode: URLMatchNever}, {URL: ""}}, Favorite: true, VaultID: "", AutoSubmit: &auto}
	if it.EffectiveCategory() != CategoryLogin || it.EffectiveVaultID() != DefaultVaultID {
		t.Fatal("legacy defaults lost")
	}
	urls := it.AllURLs()
	if len(urls) != 2 || urls[0].MatchMode != URLMatchHost || urls[1].URL != "https://second.example.test" {
		t.Fatalf("AllURLs did not preserve primary override: %+v", urls)
	}
	ccItem := Item{Kind: "credit_card", Sections: []ItemSection{{ID: "s", Fields: []CustomField{{ID: "n", Purpose: "cc-number", Value: "4111"}, {ID: "e", Purpose: "cc-exp", Value: "2030-01"}}}}}
	cc := ccItem.NormalizedCreditCard()
	if cc == nil || cc.Number != "4111" || cc.ExpiryDate != "2030-01" {
		t.Fatalf("synthesized credit card lost: %+v", cc)
	}
	if (Item{Kind: "login"}).NormalizedCreditCard() != nil || (Item{Kind: "login"}).NormalizedIdentity() != nil {
		t.Fatal("non-structured item synthesized details")
	}
	idItem := Item{Kind: "identity", Sections: []ItemSection{{ID: "s", Fields: []CustomField{{ID: "g", Purpose: "given-name", Value: "First"}, {ID: "f", Purpose: "family-name", Value: "Last"}, {ID: "e", Purpose: "email", Value: "a@b.test"}}}}}
	id := idItem.NormalizedIdentity()
	if id == nil || id.FirstName != "First" || id.LastName != "Last" || id.Email != "a@b.test" {
		t.Fatalf("synthesized identity lost: %+v", id)
	}
	if !HasV2Extension(it) || HasV2Extension(Item{Kind: "login"}) || HasV2Extension(Item{Kind: "login", Category: CategoryLogin}) {
		t.Fatal("v2 extension detection changed")
	}
}
