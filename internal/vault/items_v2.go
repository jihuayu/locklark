package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
)

// FieldType defines the semantic type of a custom or structured field.
type FieldType string

const (
	FieldTypeText      FieldType = "text"
	FieldTypeConcealed FieldType = "concealed"
	FieldTypeURL       FieldType = "url"
	FieldTypeEmail     FieldType = "email"
	FieldTypeOTP       FieldType = "otp"
	FieldTypeDate      FieldType = "date"       // YYYY-MM-DD
	FieldTypeMonthYear FieldType = "month_year" // YYYY-MM or MM/YYYY
	FieldTypePhone     FieldType = "phone"
	FieldTypeAddress   FieldType = "address"
	FieldTypeReference FieldType = "reference" // item/field reference
	FieldTypeMenu      FieldType = "menu"
	FieldTypeString    FieldType = "string"
	FieldTypeTOTP      FieldType = "totp"
	FieldTypeFile      FieldType = "file"
)

// ValidFieldType reports whether t is one of the canonical field types.
func ValidFieldType(t FieldType) bool {
	switch t {
	case FieldTypeText, FieldTypeConcealed, FieldTypeURL, FieldTypeEmail,
		FieldTypeOTP, FieldTypeDate, FieldTypeMonthYear, FieldTypePhone,
		FieldTypeAddress, FieldTypeReference, FieldTypeMenu, FieldTypeString,
		FieldTypeTOTP, FieldTypeFile:
		return true
	default:
		return false
	}
}

// CustomField is a typed field inside an item section.
type CustomField struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Type      FieldType `json:"type"`
	Value     string    `json:"value"`
	Protected bool      `json:"protected,omitempty"`
	Purpose   string    `json:"purpose,omitempty"`
}

// Field is a compatibility alias for CustomField.
type Field = CustomField

// ItemSection groups custom fields.
type ItemSection struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Fields []CustomField `json:"fields,omitempty"`
}

// Section is a compatibility alias for ItemSection.
type Section = ItemSection

// URLMatchMode controls how the browser extension matches an ItemURL against a tab origin.
const (
	URLMatchOrigin = "origin" // default: scheme + host + port via origin.Website
	URLMatchHost   = "host"   // exact hostname match
	URLMatchDomain = "domain" // registrable domain (eTLD+1) match
	URLMatchExact  = "exact"  // exact URL match
	URLMatchNever  = "never"  // do not offer autofill on this URL
)

// ItemURL is a website associated with an item.
type ItemURL struct {
	Label     string `json:"label,omitempty"`
	URL       string `json:"url"`
	Primary   bool   `json:"primary,omitempty"`
	MatchMode string `json:"match_mode,omitempty"` // "", "origin", "host", "domain", "exact", "never"
}

// CreditCardDetails provides deterministic structured fields for credit_card items.
type CreditCardDetails struct {
	CardholderName string `json:"cardholder_name,omitempty"`
	Type           string `json:"type,omitempty"`         // e.g. "visa", "mastercard", "amex", "discover", "other"
	Number         string `json:"number,omitempty"`       // digits only or formatted PAN
	Verification   string `json:"verification,omitempty"` // CVV / CVC
	ExpiryDate     string `json:"expiry_date,omitempty"`  // YYYY-MM
	ValidFrom      string `json:"valid_from,omitempty"`   // YYYY-MM
	PIN            string `json:"pin,omitempty"`
	IssuingBank    string `json:"issuing_bank,omitempty"`
}

// IdentityDetails provides deterministic structured fields for identity items.
type IdentityDetails struct {
	Title          string `json:"title,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	MiddleName     string `json:"middle_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
	BirthDate      string `json:"birth_date,omitempty"` // YYYY-MM-DD
	Company        string `json:"company,omitempty"`
	Department     string `json:"department,omitempty"`
	JobTitle       string `json:"job_title,omitempty"`
	Email          string `json:"email,omitempty"`
	Phone          string `json:"phone,omitempty"`
	AddressLine1   string `json:"address_line1,omitempty"`
	AddressLine2   string `json:"address_line2,omitempty"`
	City           string `json:"city,omitempty"`
	State          string `json:"state,omitempty"`
	PostalCode     string `json:"postal_code,omitempty"`
	Country        string `json:"country,omitempty"` // ISO 3166-1 alpha-2 or country name
	SSN            string `json:"ssn,omitempty"`
	PassportNumber string `json:"passport_number,omitempty"`
	LicenseNumber  string `json:"license_number,omitempty"`
	Website        string `json:"website,omitempty"`
}

// ItemHistoryEntry captures a historical password or item field snapshot.
type ItemHistoryEntry struct {
	Timestamp int64         `json:"timestamp"`          // Unix seconds UTC
	Action    string        `json:"action,omitempty"`   // e.g. "password-change", "edit", "import-1pux"
	Password  string        `json:"password,omitempty"` // previous password value
	Title     string        `json:"title,omitempty"`    // previous title if changed
	Username  string        `json:"username,omitempty"` // previous username if changed
	Notes     string        `json:"notes,omitempty"`    // previous notes if changed
	Sections  []ItemSection `json:"sections"`           // previous sections snapshot; nil means legacy partial entry
}

// ItemRevision is a compatibility alias for ItemHistoryEntry.
type ItemRevision = ItemHistoryEntry

// MaxAttachmentSize bounds a single v2 attachment.
const MaxAttachmentSize = 2 << 20

// AttachmentMeta describes an encrypted attachment whose raw bytes are stored in KDBX Binaries.
type AttachmentMeta struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	Size      int64  `json:"size"`
	MIMEType  string `json:"mime_type,omitempty"`
	SHA256    string `json:"sha256"`              // lowercase hex SHA-256 of Content
	Protected bool   `json:"protected,omitempty"` // KDBX MemoryProtection == 1
	Content   []byte `json:"-"`                   // populated in memory when opened from KDBX Binaries
}

// VaultMeta describes a logical sub-vault within the personal database.
type VaultMeta struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

// itemV2Envelope is the protected Locklark.V2 KDBX slot payload.
type itemV2Envelope struct {
	Version     int                `json:"v"` // always 2
	Category    ItemCategory       `json:"category,omitempty"`
	VaultID     string             `json:"vault_id,omitempty"`
	Favorite    bool               `json:"favorite,omitempty"`
	AutoSubmit  *bool              `json:"auto_submit,omitempty"`
	Tags        []string           `json:"tags,omitempty"`
	URLs        []ItemURL          `json:"urls,omitempty"`
	Sections    []ItemSection      `json:"sections,omitempty"`
	CreditCard  *CreditCardDetails `json:"credit_card,omitempty"`
	Identity    *IdentityDetails   `json:"identity,omitempty"`
	History     []ItemHistoryEntry `json:"history,omitempty"`
	Attachments []AttachmentMeta   `json:"attachments,omitempty"`
	TrashedAt   *time.Time         `json:"trashed_at,omitempty"`
	CreatedAt   int64              `json:"created_at,omitempty"`
	UpdatedAt   int64              `json:"updated_at,omitempty"`
}

const itemV2Slot = "Locklark.V2"
const attachmentRefPrefix = "att/"

// EffectiveCategory returns the canonical ItemCategory for both v1 and v2 items.
func (it Item) EffectiveCategory() ItemCategory {
	if cat, ok := CategoryFromKind(it.Kind, it.Category); ok {
		return cat
	}
	return CategoryLogin
}

// EffectiveVaultID returns it.VaultID if non-empty, or DefaultVaultID.
func (it Item) EffectiveVaultID() string {
	if it.VaultID == "" {
		return DefaultVaultID
	}
	return it.VaultID
}

// AllURLs returns the deduplicated list of ItemURLs, always including the
// primary it.URL first if set.
func (it Item) AllURLs() []ItemURL {
	var out []ItemURL
	if it.URL != "" {
		out = append(out, ItemURL{URL: it.URL, Primary: true, MatchMode: URLMatchOrigin})
	}
	for _, u := range it.URLs {
		if u.URL == "" {
			continue
		}
		if len(out) > 0 && out[0].URL == u.URL && u.Primary {
			out[0] = u
			continue
		}
		out = append(out, u)
	}
	return out
}

// NormalizedCreditCard returns CreditCardDetails from it.CreditCard or
// synthesizes it from Section fields by Purpose.
func (it Item) NormalizedCreditCard() *CreditCardDetails {
	if it.CreditCard != nil {
		cp := *it.CreditCard
		return &cp
	}
	if it.EffectiveCategory() != CategoryCreditCard {
		return nil
	}
	cc := &CreditCardDetails{}
	for _, sec := range it.Sections {
		for _, f := range sec.Fields {
			switch f.Purpose {
			case "cc-name":
				cc.CardholderName = f.Value
			case "cc-type":
				cc.Type = f.Value
			case "cc-number":
				cc.Number = f.Value
			case "cc-csc":
				cc.Verification = f.Value
			case "cc-exp":
				cc.ExpiryDate = f.Value
			case "cc-pin":
				cc.PIN = f.Value
			}
		}
	}
	return cc
}

// NormalizedIdentity returns IdentityDetails from it.Identity or synthesizes
// it from Section fields by Purpose.
func (it Item) NormalizedIdentity() *IdentityDetails {
	if it.Identity != nil {
		id := *it.Identity
		return &id
	}
	if it.EffectiveCategory() != CategoryIdentity {
		return nil
	}
	id := &IdentityDetails{}
	for _, sec := range it.Sections {
		for _, f := range sec.Fields {
			switch f.Purpose {
			case "honorific-prefix":
				id.Title = f.Value
			case "given-name":
				id.FirstName = f.Value
			case "additional-name":
				id.MiddleName = f.Value
			case "family-name":
				id.LastName = f.Value
			case "organization":
				id.Company = f.Value
			case "organization-title":
				id.JobTitle = f.Value
			case "email":
				id.Email = f.Value
			case "tel":
				id.Phone = f.Value
			case "address-line1", "street-address":
				id.AddressLine1 = f.Value
			case "address-line2":
				id.AddressLine2 = f.Value
			case "address-level2":
				id.City = f.Value
			case "address-level1":
				id.State = f.Value
			case "postal-code":
				id.PostalCode = f.Value
			case "country", "country-name":
				id.Country = f.Value
			case "bday":
				id.BirthDate = f.Value
			}
		}
	}
	return id
}

// HasV2Extension reports whether an item must be encoded with the
// "Locklark.V2" KDBX envelope. Pure v1 items remain byte-compatible.
func HasV2Extension(it Item) bool { return hasV2Extension(it) }

func hasV2Extension(it Item) bool {
	if it.Category != "" && !(it.Category == CategoryLogin && it.Kind == "login" ||
		it.Category == CategoryDocument && it.Kind == "document" ||
		it.Category == CategorySSHKey && it.Kind == "ssh-key") {
		return true
	}
	if it.VaultID != "" && it.VaultID != DefaultVaultID {
		return true
	}
	return it.Favorite || it.AutoSubmit != nil || len(it.Tags) > 0 || len(it.URLs) > 0 ||
		len(it.Sections) > 0 || it.CreditCard != nil || it.Identity != nil ||
		len(it.History) > 0 || len(it.Attachments) > 0 || it.TrashedAt != nil ||
		it.CreatedAt != 0 || it.UpdatedAt != 0
}

// AttachmentSHA256 returns the lowercase hex SHA-256 of content.
func AttachmentSHA256(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// CloneItem returns a deep copy suitable for transactional mutation.
func CloneItem(it Item) Item {
	out := it
	out.ImportSource = cloneBytes(it.ImportSource)
	out.SSHSeed = cloneBytes(it.SSHSeed)
	out.SSHPublicKey = cloneBytes(it.SSHPublicKey)
	out.Passkey = cloneBytes(it.Passkey)
	out.Passkeys = clonePasskeyRecords(it.Passkeys)
	out.Attachment = cloneBytes(it.Attachment)
	out.Tags = append([]string(nil), it.Tags...)
	out.URLs = append([]ItemURL(nil), it.URLs...)
	out.Sections = CloneSections(it.Sections)
	out.History = CloneHistory(it.History)
	out.Attachments = append([]AttachmentMeta(nil), it.Attachments...)
	for i := range out.Attachments {
		out.Attachments[i].Content = cloneBytes(out.Attachments[i].Content)
	}
	if it.CreditCard != nil {
		cp := *it.CreditCard
		out.CreditCard = &cp
	}
	if it.Identity != nil {
		cp := *it.Identity
		out.Identity = &cp
	}
	if it.AutoSubmit != nil {
		v := *it.AutoSubmit
		out.AutoSubmit = &v
	}
	if it.TrashedAt != nil {
		v := *it.TrashedAt
		out.TrashedAt = &v
	}
	return out
}

// CloneSections deep-copies sections and their fields.
func CloneSections(in []ItemSection) []ItemSection {
	if in == nil {
		return nil
	}
	out := make([]ItemSection, len(in))
	for i, s := range in {
		out[i] = s
		out[i].Fields = append([]CustomField(nil), s.Fields...)
	}
	return out
}

// CloneHistory deep-copies item history entries.
func CloneHistory(in []ItemHistoryEntry) []ItemHistoryEntry {
	if in == nil {
		return nil
	}
	out := make([]ItemHistoryEntry, len(in))
	for i, h := range in {
		out[i] = h
		out[i].Sections = CloneSections(h.Sections)
	}
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

// ValidItemID reports whether id is the canonical lowercase hex item ID shape
// used by the personal journal, or a bounded v1 fixture identifier.
func ValidItemID(id string) bool {
	if id == "" || len(id) > 256 || !xmlText(id) {
		return false
	}
	return true
}

func selectorID(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func validFieldTypeValue(t FieldType) bool {
	return t == "" || ValidFieldType(t)
}

func validMatchMode(m string) bool {
	switch m {
	case "", URLMatchOrigin, URLMatchHost, URLMatchDomain, URLMatchExact, URLMatchNever:
		return true
	}
	return false
}

func validAttachmentName(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || !xmlText(name) {
		return false
	}
	return true
}

func validHexDigest(s string) bool {
	if len(s) != sha256.Size*2 || s != strings.ToLower(s) {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}

func validTag(t string) bool {
	return t != "" && len(t) <= 256 && xmlText(t)
}

func validURL(u string) bool {
	if u == "" || len(u) > 2048 {
		return false
	}
	_, err := origin.Website(u)
	return err == nil
}

func validSections(sections []ItemSection) bool {
	if len(sections) > 64 {
		return false
	}
	sectionIDs := map[string]bool{}
	fieldIDs := map[string]bool{}
	for _, s := range sections {
		if !selectorID(s.ID) || sectionIDs[strings.ToLower(s.ID)] || len(s.Title) > 1024 || !xmlText(s.Title) {
			return false
		}
		sectionIDs[strings.ToLower(s.ID)] = true
		if len(s.Fields) > 256 {
			return false
		}
		for _, f := range s.Fields {
			if !selectorID(f.ID) || fieldIDs[strings.ToLower(f.ID)] || len(f.Label) > 1024 || !xmlText(f.Label) || !validFieldTypeValue(f.Type) || len(f.Purpose) > 64 || !xmlText(f.Purpose) || !utf8.ValidString(f.Value) {
				return false
			}
			fieldIDs[strings.ToLower(f.ID)] = true
			if (f.Type == FieldTypeConcealed || f.Type == FieldTypeOTP || f.Type == FieldTypeTOTP) && !f.Protected {
				return false
			}
		}
	}
	return true
}

func validCreditCard(cc *CreditCardDetails) bool {
	if cc == nil {
		return true
	}
	for _, s := range []string{cc.CardholderName, cc.Type, cc.Number, cc.Verification, cc.ExpiryDate, cc.ValidFrom, cc.PIN, cc.IssuingBank} {
		if len(s) > 1024 || !utf8.ValidString(s) {
			return false
		}
	}
	return true
}

func validIdentity(id *IdentityDetails) bool {
	if id == nil {
		return true
	}
	for _, s := range []string{id.Title, id.FirstName, id.MiddleName, id.LastName, id.BirthDate, id.Company, id.Department, id.JobTitle, id.Email, id.Phone, id.AddressLine1, id.AddressLine2, id.City, id.State, id.PostalCode, id.Country, id.SSN, id.PassportNumber, id.LicenseNumber, id.Website} {
		if len(s) > 1024 || !utf8.ValidString(s) {
			return false
		}
	}
	return true
}
