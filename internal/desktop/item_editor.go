package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// ItemDraft is the editable, unlocked representation of an item. It is
// created only from a reveal-authorized read and zeroed on cancel or lock.
type ItemDraft struct {
	ID       string
	Revision string
	Category vault.ItemCategory
	VaultID  string

	Title    string
	Username string
	Password string
	OTP      string
	URL      string
	Notes    string
	Favorite bool
	Tags     []string

	URLs     []vault.ItemURL
	Sections []vault.ItemSection

	CreditCard vault.CreditCardDetails
	Identity   vault.IdentityDetails

	NewTag          string
	NewSectionTitle string
	NewFieldLabel   string
	NewFieldType    vault.FieldType
	NewFieldValue   string
	NewFieldSection int
	NewURL          string
	NewURLLabel     string
	NewURLMatch     string
	NewAttachment   string
}

// field is a small template helper.
func field(id, label string, typ vault.FieldType, purpose string) vault.CustomField {
	f := vault.CustomField{ID: id, Label: label, Type: typ, Purpose: purpose}
	if typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP {
		f.Protected = true
	}
	return f
}

func section(id, title string, fields ...vault.CustomField) vault.ItemSection {
	return vault.ItemSection{ID: id, Title: title, Fields: fields}
}

// CategoryTemplate returns the default sections and fields provisioned for a
// new item of category. The returned slices are fresh and safe to mutate.
func CategoryTemplate(category vault.ItemCategory) []vault.ItemSection {
	switch category {
	case vault.CategoryCreditCard:
		return []vault.ItemSection{
			section("card", "Card Details",
				field("cardholder", "cardholder name", vault.FieldTypeString, "cc-name"),
				field("type", "type", vault.FieldTypeMenu, "cc-type"),
				field("number", "number", vault.FieldTypeConcealed, "cc-number"),
				field("verification", "verification number", vault.FieldTypeConcealed, "cc-csc"),
				field("expiry", "expiry date", vault.FieldTypeMonthYear, "cc-exp"),
				field("valid_from", "valid from", vault.FieldTypeMonthYear, ""),
			),
			section("details", "Additional Details",
				field("issuing_bank", "issuing bank", vault.FieldTypeString, ""),
				field("pin", "PIN", vault.FieldTypeConcealed, "cc-pin"),
				field("credit_limit", "credit limit", vault.FieldTypeString, ""),
			),
		}
	case vault.CategoryIdentity:
		return []vault.ItemSection{
			section("identification", "Identification",
				field("first_name", "first name", vault.FieldTypeString, "given-name"),
				field("middle_name", "middle name", vault.FieldTypeString, "additional-name"),
				field("last_name", "last name", vault.FieldTypeString, "family-name"),
				field("birth_date", "birth date", vault.FieldTypeDate, "bday"),
				field("company", "company", vault.FieldTypeString, "organization"),
				field("department", "department", vault.FieldTypeString, "department"),
				field("job_title", "job title", vault.FieldTypeString, "organization-title"),
			),
			section("contact", "Contact",
				field("email", "email", vault.FieldTypeEmail, "email"),
				field("phone", "phone", vault.FieldTypePhone, "tel"),
				field("address", "address", vault.FieldTypeAddress, "street-address"),
				field("city", "city", vault.FieldTypeString, "address-level2"),
				field("state", "state", vault.FieldTypeString, "address-level1"),
				field("postal_code", "postal code", vault.FieldTypeString, "postal-code"),
				field("country", "country", vault.FieldTypeString, "country"),
				field("website", "website", vault.FieldTypeURL, ""),
			),
		}
	case vault.CategoryDocument:
		return []vault.ItemSection{
			section("document", "Document",
				field("file", "file", vault.FieldTypeFile, ""),
			),
		}
	case vault.CategorySSHKey:
		return []vault.ItemSection{
			section("ssh", "SSH Key",
				field("private_key", "private key", vault.FieldTypeConcealed, ""),
				field("public_key", "public key", vault.FieldTypeString, ""),
				field("fingerprint", "fingerprint", vault.FieldTypeString, ""),
				field("key_type", "key type", vault.FieldTypeMenu, ""),
			),
		}
	case vault.CategoryAPICredential:
		return []vault.ItemSection{
			section("api", "API Credential",
				field("username", "username", vault.FieldTypeString, "username"),
				field("credential", "credential", vault.FieldTypeConcealed, "password"),
				field("type", "type", vault.FieldTypeMenu, ""),
				field("hostname", "hostname / URL", vault.FieldTypeURL, ""),
				field("valid_from", "valid from", vault.FieldTypeDate, ""),
				field("expires", "expires", vault.FieldTypeDate, ""),
			),
		}
	case vault.CategoryDatabase:
		return []vault.ItemSection{
			section("database", "Database",
				field("database_type", "type", vault.FieldTypeMenu, ""),
				field("server", "server", vault.FieldTypeString, ""),
				field("port", "port", vault.FieldTypeString, ""),
				field("database", "database", vault.FieldTypeString, ""),
				field("username", "username", vault.FieldTypeString, "username"),
				field("password", "password", vault.FieldTypeConcealed, "password"),
				field("sid", "SID", vault.FieldTypeString, ""),
				field("options", "connection options", vault.FieldTypeText, ""),
			),
		}
	case vault.CategoryServer:
		return []vault.ItemSection{
			section("server", "Server",
				field("url", "URL", vault.FieldTypeURL, ""),
				field("username", "username", vault.FieldTypeString, "username"),
				field("password", "password", vault.FieldTypeConcealed, "password"),
			),
			section("admin_console", "Admin Console",
				field("admin_url", "admin console URL", vault.FieldTypeURL, ""),
				field("admin_username", "admin console username", vault.FieldTypeString, ""),
				field("admin_password", "admin console password", vault.FieldTypeConcealed, ""),
			),
			section("hosting", "Hosting Provider",
				field("name", "name", vault.FieldTypeString, ""),
				field("website", "website", vault.FieldTypeURL, ""),
				field("support_url", "support URL", vault.FieldTypeURL, ""),
				field("support_phone", "support phone", vault.FieldTypePhone, ""),
			),
		}
	case vault.CategoryWirelessRouter:
		return []vault.ItemSection{
			section("router", "Wireless Router",
				field("name", "base station name", vault.FieldTypeString, ""),
				field("password", "base station password", vault.FieldTypeConcealed, ""),
				field("server", "server / IP address", vault.FieldTypeString, ""),
				field("ssid", "network name (SSID)", vault.FieldTypeString, ""),
				field("security", "wireless security", vault.FieldTypeMenu, ""),
				field("wireless_password", "wireless network password", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategorySoftwareLicense:
		return []vault.ItemSection{
			section("license", "License",
				field("version", "version", vault.FieldTypeString, ""),
				field("license_key", "license key", vault.FieldTypeConcealed, ""),
				field("licensed_to", "licensed to", vault.FieldTypeString, ""),
				field("email", "registered email", vault.FieldTypeEmail, ""),
				field("company", "company", vault.FieldTypeString, ""),
				field("download_url", "download page", vault.FieldTypeURL, ""),
			),
			section("publisher", "Publisher",
				field("publisher", "publisher", vault.FieldTypeString, ""),
				field("publisher_website", "website", vault.FieldTypeURL, ""),
				field("retail_price", "retail price", vault.FieldTypeString, ""),
			),
			section("order", "Order",
				field("order_number", "order number", vault.FieldTypeString, ""),
				field("purchase_date", "purchase date", vault.FieldTypeDate, ""),
				field("order_total", "order total", vault.FieldTypeString, ""),
			),
		}
	case vault.CategoryBankAccount:
		return []vault.ItemSection{
			section("bank", "Bank Account",
				field("bank_name", "bank name", vault.FieldTypeString, ""),
				field("owner", "name on account", vault.FieldTypeString, ""),
				field("type", "type", vault.FieldTypeMenu, ""),
				field("routing_number", "routing number", vault.FieldTypeString, ""),
				field("account_number", "account number", vault.FieldTypeConcealed, ""),
				field("swift", "SWIFT", vault.FieldTypeString, ""),
				field("iban", "IBAN", vault.FieldTypeString, ""),
				field("telephone_pin", "PIN", vault.FieldTypeConcealed, ""),
			),
			section("branch", "Branch Information",
				field("branch_phone", "branch phone", vault.FieldTypePhone, ""),
				field("branch_address", "branch address", vault.FieldTypeAddress, ""),
			),
		}
	case vault.CategoryCryptoWallet:
		return []vault.ItemSection{
			section("wallet", "Crypto Wallet",
				field("wallet_type", "wallet type", vault.FieldTypeMenu, ""),
				field("address", "address", vault.FieldTypeString, ""),
				field("network", "network", vault.FieldTypeMenu, ""),
				field("private_key", "private key", vault.FieldTypeConcealed, ""),
				field("seed_phrase", "seed phrase", vault.FieldTypeConcealed, ""),
				field("password", "password", vault.FieldTypeConcealed, ""),
			),
		}
	case vault.CategoryMedicalRecord:
		return []vault.ItemSection{
			section("medical", "Medical Record",
				field("patient_name", "patient name", vault.FieldTypeString, ""),
				field("blood_type", "blood type", vault.FieldTypeMenu, ""),
				field("allergies", "allergies", vault.FieldTypeText, ""),
				field("medications", "medications", vault.FieldTypeText, ""),
				field("conditions", "conditions", vault.FieldTypeText, ""),
				field("doctor", "doctor", vault.FieldTypeString, ""),
				field("phone", "phone", vault.FieldTypePhone, ""),
				field("insurance_provider", "insurance provider", vault.FieldTypeString, ""),
				field("policy_number", "policy number", vault.FieldTypeString, ""),
			),
		}
	case vault.CategoryMembership:
		return []vault.ItemSection{
			section("membership", "Membership",
				field("organization", "organization", vault.FieldTypeString, ""),
				field("website", "website", vault.FieldTypeURL, ""),
				field("phone", "phone", vault.FieldTypePhone, ""),
				field("member_name", "member name", vault.FieldTypeString, ""),
				field("member_since", "member since", vault.FieldTypeMonthYear, ""),
				field("expiry_date", "expiry date", vault.FieldTypeMonthYear, ""),
				field("membership_number", "membership number", vault.FieldTypeConcealed, ""),
				field("pin", "PIN", vault.FieldTypeConcealed, ""),
			),
		}
	}
	// login, password and secure_note use the top-level username/password/
	// OTP/notes slots; their templates intentionally start with no custom
	// section so the primary fields are not duplicated.
	return nil
}

func newItemDraft(category vault.ItemCategory) *ItemDraft {
	if !vault.ValidCategory(category) {
		category = vault.CategoryLogin
	}
	vaultID := vault.DefaultVaultID
	return &ItemDraft{
		Category:     category,
		VaultID:      vaultID,
		NewFieldType: vault.FieldTypeString,
		Sections:     CategoryTemplate(category),
	}
}

func draftFromDetail(detail personal.ItemDetail) *ItemDraft {
	draft := &ItemDraft{
		ID:           detail.ID,
		Revision:     detail.Revision,
		Category:     detail.Category,
		VaultID:      detail.VaultID,
		Title:        detail.Title,
		Username:     detail.Username,
		Password:     detail.Password,
		OTP:          detail.OTP,
		URL:          detail.URL,
		Notes:        detail.Notes,
		Favorite:     detail.Favorite,
		Tags:         append([]string(nil), detail.Tags...),
		URLs:         append([]vault.ItemURL(nil), detail.URLs...),
		Sections:     vault.CloneSections(detail.Sections),
		NewFieldType: vault.FieldTypeString,
	}
	if detail.CreditCard != nil {
		draft.CreditCard = *detail.CreditCard
	}
	if detail.Identity != nil {
		draft.Identity = *detail.Identity
	}
	if draft.Category == "" {
		draft.Category = vault.CategoryLogin
	}
	if draft.VaultID == "" {
		draft.VaultID = vault.DefaultVaultID
	}
	return draft
}

func (d *ItemDraft) item() vault.Item {
	kind := string(d.Category)
	switch d.Category {
	case vault.CategorySSHKey:
		kind = "ssh-key"
	case vault.CategoryLogin:
		kind = "login"
	case vault.CategoryDocument:
		kind = "document"
	}
	item := vault.Item{
		ID:       d.ID,
		Kind:     kind,
		Category: d.Category,
		VaultID:  d.VaultID,
		Title:    strings.TrimSpace(d.Title),
		Username: d.Username,
		Password: d.Password,
		OTP:      d.OTP,
		URL:      strings.TrimSpace(d.URL),
		Notes:    d.Notes,
		Favorite: d.Favorite,
		Tags:     append([]string(nil), d.Tags...),
		URLs:     append([]vault.ItemURL(nil), d.URLs...),
		Sections: vault.CloneSections(d.Sections),
	}
	if d.Category == vault.CategoryCreditCard {
		cc := d.CreditCard
		item.CreditCard = &cc
	}
	if d.Category == vault.CategoryIdentity {
		id := d.Identity
		item.Identity = &id
	}
	return item
}

// normalizeFieldType maps the display names used by the editor to the
// canonical vault.FieldType set. "password", "credit-card-number" and
// "ssh-key" are aliases for a concealed field.
func normalizeFieldType(raw string) (vault.FieldType, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "string", "text":
		if strings.ToLower(strings.TrimSpace(raw)) == "text" {
			return vault.FieldTypeText, true
		}
		return vault.FieldTypeString, true
	case "concealed", "password", "credit-card-number", "credit_card_number", "ssh-key", "ssh_key":
		return vault.FieldTypeConcealed, true
	case "totp", "otp", "one-time password", "one_time_password":
		return vault.FieldTypeOTP, true
	case "url":
		return vault.FieldTypeURL, true
	case "email":
		return vault.FieldTypeEmail, true
	case "phone":
		return vault.FieldTypePhone, true
	case "date":
		return vault.FieldTypeDate, true
	case "month_year", "month-year", "monthyear":
		return vault.FieldTypeMonthYear, true
	case "address":
		return vault.FieldTypeAddress, true
	case "menu":
		return vault.FieldTypeMenu, true
	case "file":
		return vault.FieldTypeFile, true
	case "reference":
		return vault.FieldTypeReference, true
	}
	return "", false
}

func (a *App) newItem(category vault.ItemCategory) {
	if a.session == nil {
		return
	}
	a.EnableV2()
	if category == "" {
		category = a.v2.category
	}
	if category == "" {
		category = vault.CategoryLogin
	}
	if !vault.ValidCategory(category) {
		a.status = "未知条目类别：" + string(category)
		return
	}
	draft := newItemDraft(category)
	draft.VaultID = vault.DefaultVaultID
	if a.v2.vaultID != "" && a.v2.vaultID != "all" {
		draft.VaultID = a.v2.vaultID
	}
	a.v2.detail = nil
	a.v2.detailPlain = nil
	a.v2.selectedID, a.v2.selectedRevision = "", ""
	a.selected = nil
	a.v2.historyOpen = false
	a.v2.confirmPurge = false
	a.v2.draft = draft
	a.v2.editing = true
	a.v2.editorError = ""
	a.touchActivity()
	a.status = "新建条目：" + CategoryDisplayName(category)
}

func (a *App) NewItem(category vault.ItemCategory) {
	a.newItem(category)
}

// beginEdit reads the full unmasked item once, then stores only a draft.
// The read is audited by personal.GetItemDetail(revealConcealed=true).
func (a *App) beginEdit() error {
	if a.session == nil || a.v2.detail == nil {
		return personal.ErrMutationRefused
	}
	detail := *a.v2.detail
	if detail.State == "trashed" {
		a.status = "回收站中的条目需先恢复后才能编辑"
		return personal.ErrTrashed
	}
	s := a.session
	generation := a.generation
	var opErr error
	a.run(func() outcome {
		plain, err := s.GetItemDetail(detail.ID, detail.Revision, true)
		if err != nil {
			opErr = err
			return outcome{err: err}
		}
		return outcome{apply: func() {
			if a.generation != generation || a.session != s || a.v2.detail == nil || a.v2.detail.ID != detail.ID {
				return
			}
			a.v2.detailPlain = &plain
			a.v2.draft = draftFromDetail(plain)
			a.v2.editing = true
			a.v2.historyOpen = false
			a.v2.editorError = ""
			a.v2.revealed = map[string]bool{}
			a.touchActivity()
			a.status = "编辑条目：" + plain.Title
		}}
	})
	return opErr
}

func (a *App) EditSelected() error { return a.beginEdit() }
func (a *App) OpenEditor() error   { return a.beginEdit() }

func (a *App) cancelEdit() {
	if a.v2.draft != nil {
		a.v2.draft.Password = ""
		a.v2.draft.OTP = ""
		for i := range a.v2.draft.Sections {
			for j := range a.v2.draft.Sections[i].Fields {
				if a.v2.draft.Sections[i].Fields[j].Protected {
					a.v2.draft.Sections[i].Fields[j].Value = ""
				}
			}
		}
	}
	a.v2.draft = nil
	a.v2.editing = false
	a.v2.editorError = ""
	a.status = "已取消编辑；未保存"
}

func (a *App) CancelEdit() { a.cancelEdit() }

// saveDraft validates and persists the current editor draft. It preserves
// the sidebar filter/search and refreshes the same view after the mutation.
func (a *App) saveDraft() error {
	draft := a.v2.draft
	if draft == nil || a.session == nil {
		return personal.ErrMutationRefused
	}
	if strings.TrimSpace(draft.Title) == "" {
		a.v2.editorError = "标题不能为空"
		return personal.ErrMutationRefused
	}
	if !vault.ValidCategory(draft.Category) {
		a.v2.editorError = "未知条目类别"
		return personal.ErrMutationRefused
	}
	item := draft.item()
	s := a.session
	filter := a.currentFilter()
	isNew := draft.ID == ""
	var opErr error
	var saved personal.ItemDetail
	var hasSaved bool
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		if isNew {
			id, revision, err := s.AddItem(item, g)
			if err != nil {
				opErr = err
				return nativeResult{err: err}
			}
			item.ID = id
			saved, err = s.GetItemDetail(id, revision, false)
			if err != nil {
				opErr = err
				return nativeResult{err: err}
			}
			hasSaved = true
		} else {
			revision, err := s.EditItem(draft.ID, draft.Revision, item, g)
			if err != nil {
				opErr = err
				return nativeResult{err: err}
			}
			saved, err = s.GetItemDetail(draft.ID, revision, false)
			if err != nil {
				opErr = err
				return nativeResult{err: err}
			}
			hasSaved = true
		}
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.v2.draft = nil
		a.v2.editing = false
		a.v2.editorError = ""
		a.applyV2Snapshot(snap, false)
		if hasSaved {
			a.v2.detail = &saved
			a.v2.selectedID, a.v2.selectedRevision = saved.ID, saved.Revision
			row := legacyRow(personal.ItemSummary{ID: saved.ID, Revision: saved.Revision, Kind: saved.Kind, Category: saved.Category, Title: saved.Title, State: saved.State, RestoreState: saved.RestoreState})
			a.selected = &row
		}
		a.status = "条目已保存"
	})
	if !ok {
		if opErr == nil {
			opErr = personal.ErrMutationRefused
		}
		return opErr
	}
	return opErr
}

func (a *App) SaveDraft() error { return a.saveDraft() }

// ---------- Custom sections and typed fields ----------

func nextSectionID(sections []vault.ItemSection) string {
	used := map[string]bool{}
	for _, s := range sections {
		used[strings.ToLower(s.ID)] = true
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("section-%d", n)
		if !used[id] {
			return id
		}
	}
}

func nextFieldID(section vault.ItemSection) string {
	used := map[string]bool{}
	for _, f := range section.Fields {
		used[strings.ToLower(f.ID)] = true
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("field-%d", n)
		if !used[id] {
			return id
		}
	}
}

func (a *App) addSection(title string) {
	if a.v2.draft == nil {
		return
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "New Section"
	}
	a.v2.draft.Sections = append(a.v2.draft.Sections, vault.ItemSection{ID: nextSectionID(a.v2.draft.Sections), Title: title})
	a.v2.draft.NewSectionTitle = ""
	a.v2.editorError = ""
}

func (a *App) AddSection(title string) { a.addSection(title) }

func (a *App) removeSection(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections = append(a.v2.draft.Sections[:index], a.v2.draft.Sections[index+1:]...)
}

func (a *App) renameSection(index int, title string) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections[index].Title = strings.TrimSpace(title)
}

func (a *App) moveSection(index, delta int) {
	if a.v2.draft == nil {
		return
	}
	target := index + delta
	if index < 0 || index >= len(a.v2.draft.Sections) || target < 0 || target >= len(a.v2.draft.Sections) {
		return
	}
	a.v2.draft.Sections[index], a.v2.draft.Sections[target] = a.v2.draft.Sections[target], a.v2.draft.Sections[index]
}

func (a *App) addField(sectionIndex int, label, typ, value string) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fieldType, ok := normalizeFieldType(typ)
	if !ok {
		a.v2.editorError = "未知字段类型：" + typ
		return
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "New Field"
	}
	f := vault.CustomField{ID: nextFieldID(a.v2.draft.Sections[sectionIndex]), Label: label, Type: fieldType, Value: value}
	if fieldType == vault.FieldTypeConcealed || fieldType == vault.FieldTypeOTP || fieldType == vault.FieldTypeTOTP {
		f.Protected = true
	}
	a.v2.draft.Sections[sectionIndex].Fields = append(a.v2.draft.Sections[sectionIndex].Fields, f)
	a.v2.draft.NewFieldLabel = ""
	a.v2.draft.NewFieldValue = ""
	a.v2.editorError = ""
}

func (a *App) AddField(sectionIndex int, label, typ, value string) {
	a.addField(sectionIndex, label, typ, value)
}

func (a *App) removeField(sectionIndex, fieldIndex int) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	if fieldIndex < 0 || fieldIndex >= len(fields) {
		return
	}
	a.v2.draft.Sections[sectionIndex].Fields = append(fields[:fieldIndex], fields[fieldIndex+1:]...)
}

func (a *App) renameField(sectionIndex, fieldIndex int, label string) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	if fieldIndex < 0 || fieldIndex >= len(fields) {
		return
	}
	fields[fieldIndex].Label = strings.TrimSpace(label)
}

func (a *App) moveField(sectionIndex, fieldIndex, delta int) {
	if a.v2.draft == nil || sectionIndex < 0 || sectionIndex >= len(a.v2.draft.Sections) {
		return
	}
	fields := a.v2.draft.Sections[sectionIndex].Fields
	target := fieldIndex + delta
	if fieldIndex < 0 || fieldIndex >= len(fields) || target < 0 || target >= len(fields) {
		return
	}
	fields[fieldIndex], fields[target] = fields[target], fields[fieldIndex]
}

// ---------- URLs, tags and favorites ----------

func (a *App) addURL(rawURL, label, matchMode string) {
	if a.v2.draft == nil {
		return
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		a.v2.editorError = "URL 不能为空"
		return
	}
	switch matchMode {
	case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
	default:
		a.v2.editorError = "未知的自动填充匹配模式"
		return
	}
	primary := len(a.v2.draft.URLs) == 0
	a.v2.draft.URLs = append(a.v2.draft.URLs, vault.ItemURL{Label: strings.TrimSpace(label), URL: rawURL, Primary: primary, MatchMode: matchMode})
	if a.v2.draft.URL == "" {
		a.v2.draft.URL = rawURL
	}
	a.v2.draft.NewURL = ""
	a.v2.draft.NewURLLabel = ""
	a.v2.editorError = ""
}

func (a *App) AddURL(rawURL, label, matchMode string) { a.addURL(rawURL, label, matchMode) }

func (a *App) removeURL(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	removedPrimary := a.v2.draft.URLs[index].Primary
	a.v2.draft.URLs = append(a.v2.draft.URLs[:index], a.v2.draft.URLs[index+1:]...)
	if removedPrimary && len(a.v2.draft.URLs) > 0 {
		a.v2.draft.URLs[0].Primary = true
	}
}

func (a *App) setPrimaryURL(index int) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	for i := range a.v2.draft.URLs {
		a.v2.draft.URLs[i].Primary = i == index
	}
	a.v2.draft.URL = a.v2.draft.URLs[index].URL
}

func (a *App) setURLMatchMode(index int, mode string) {
	if a.v2.draft == nil || index < 0 || index >= len(a.v2.draft.URLs) {
		return
	}
	switch mode {
	case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
		a.v2.draft.URLs[index].MatchMode = mode
	default:
		a.v2.editorError = "未知的自动填充匹配模式"
	}
}

func (a *App) addTag(tag string) {
	if a.v2.draft == nil {
		return
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return
	}
	for _, existing := range a.v2.draft.Tags {
		if strings.EqualFold(existing, tag) {
			return
		}
	}
	a.v2.draft.Tags = append(a.v2.draft.Tags, tag)
	a.v2.draft.NewTag = ""
}

func (a *App) AddTag(tag string) { a.addTag(tag) }

func (a *App) removeTag(tag string) {
	if a.v2.draft == nil {
		return
	}
	kept := a.v2.draft.Tags[:0]
	for _, existing := range a.v2.draft.Tags {
		if !strings.EqualFold(existing, tag) {
			kept = append(kept, existing)
		}
	}
	a.v2.draft.Tags = kept
}

func (a *App) toggleDraftFavorite() {
	if a.v2.draft != nil {
		a.v2.draft.Favorite = !a.v2.draft.Favorite
		return
	}
	a.toggleSelectedFavorite()
}

// toggleSelectedFavorite persists the star immediately, as the reference
// desktop does from both the list and detail view.
func (a *App) toggleSelectedFavorite() {
	if a.v2.detail == nil || a.session == nil {
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	favorite := !a.v2.detail.Favorite
	filter := a.currentFilter()
	var snap v2Snapshot
	var newRevision string
	a.runNative(func(g *personal.MutationGate) nativeResult {
		rev, err := s.SetFavorite(id, revision, favorite, g)
		if err != nil {
			return nativeResult{err: err}
		}
		newRevision = rev
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		if a.v2.detail != nil {
			a.v2.detail.Favorite = favorite
			a.v2.detail.Revision = newRevision
		}
		a.status = "已更新收藏"
	})
}

func (a *App) ToggleFavorite() { a.toggleSelectedFavorite() }

// saveSelectedTags persists tags immediately for the detail view.
func (a *App) saveSelectedTags(tags []string) {
	if a.v2.detail == nil || a.session == nil {
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	filter := a.currentFilter()
	var snap v2Snapshot
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if _, err := s.SetTags(id, revision, tags, g); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.v2.detail.Tags = append([]string(nil), tags...)
		a.status = "标签已更新"
	})
}

// fillGeneratorPassword writes the generated candidate into the draft
// password or the selected concealed field. The caller must save the draft;
// the old password is then recorded in item history by the store.
func (a *App) fillGeneratorPassword(value string) {
	if value == "" {
		return
	}
	if a.v2.draft == nil {
		return
	}
	target := a.v2.generator.target
	switch target {
	case "", "password":
		a.v2.draft.Password = value
	case "otp":
		a.v2.draft.OTP = value
	}
	if target != "" && target != "password" && target != "otp" {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) == 2 {
			for si := range a.v2.draft.Sections {
				if a.v2.draft.Sections[si].ID != parts[0] {
					continue
				}
				for fi := range a.v2.draft.Sections[si].Fields {
					if a.v2.draft.Sections[si].Fields[fi].ID == parts[1] {
						a.v2.draft.Sections[si].Fields[fi].Value = value
					}
				}
			}
		}
	}
	a.v2.generator.open = false
	a.status = "已填入生成的密码；保存条目后生效"
}

// CategoryDisplayName is the English label used by the sidebar and editor.
func CategoryDisplayName(category vault.ItemCategory) string {
	switch category {
	case vault.CategoryLogin:
		return "Login"
	case vault.CategoryPassword:
		return "Password"
	case vault.CategorySecureNote:
		return "Secure Note"
	case vault.CategoryCreditCard:
		return "Credit Card"
	case vault.CategoryIdentity:
		return "Identity"
	case vault.CategorySSHKey:
		return "SSH Key"
	case vault.CategoryAPICredential:
		return "API Credential"
	case vault.CategoryDatabase:
		return "Database"
	case vault.CategoryServer:
		return "Server"
	case vault.CategoryWirelessRouter:
		return "Wireless Router"
	case vault.CategorySoftwareLicense:
		return "Software License"
	case vault.CategoryBankAccount:
		return "Bank Account"
	case vault.CategoryCryptoWallet:
		return "Crypto Wallet"
	case vault.CategoryMedicalRecord:
		return "Medical Record"
	case vault.CategoryDocument:
		return "Document"
	case vault.CategoryMembership:
		return "Membership"
	}
	return string(category)
}

// AllCategories is the stable sidebar category order (16 categories: the 14
// benchmark categories plus password and membership).
func AllCategories() []vault.ItemCategory {
	return []vault.ItemCategory{
		vault.CategoryLogin,
		vault.CategoryPassword,
		vault.CategorySecureNote,
		vault.CategoryCreditCard,
		vault.CategoryIdentity,
		vault.CategorySSHKey,
		vault.CategoryAPICredential,
		vault.CategoryDatabase,
		vault.CategoryServer,
		vault.CategoryWirelessRouter,
		vault.CategorySoftwareLicense,
		vault.CategoryBankAccount,
		vault.CategoryCryptoWallet,
		vault.CategoryMedicalRecord,
		vault.CategoryDocument,
		vault.CategoryMembership,
	}
}

var _ = time.Now
