package browserhost

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
)

func isV2Operation(kind string) bool {
	switch kind {
	case "search", "list", "vault-search", "vault-list", "item-get",
		"item-copy-field", "item-reveal-field", "item-create", "item-edit", "item-save",
		"item-state", "match-profiles", "fill-profile", "passkey-remove":
		return true
	}
	return false
}

func (c *Connection) handleV2(r Request) error {
	switch r.Type {
	case "search", "list", "vault-search", "vault-list":
		return c.handleSearch(r)
	case "item-get":
		return c.handleItemGet(r)
	case "item-copy-field", "item-reveal-field":
		return c.handleFieldValue(r)
	case "item-create", "item-edit", "item-save":
		return c.handleItemSave(r)
	case "item-state":
		return c.handleItemState(r)
	case "match-profiles":
		return c.handleMatchProfiles(r)
	case "fill-profile":
		return c.handleFillProfile(r)
	case "passkey-remove":
		return c.passkeyRemove(r)
	}
	return c.refuse(r.ID)
}

// categoryOf / vaultOf read the durable item model directly; the browser view
// never consults a separate metadata store.
func categoryOf(it vault.Item) string { return string(it.EffectiveCategory()) }

func vaultOf(it vault.Item) string { return it.EffectiveVaultID() }

func primaryURLOf(it vault.Item) string {
	if it.URL != "" {
		return it.URL
	}
	for _, u := range it.URLs {
		if u.Primary {
			return u.URL
		}
	}
	if len(it.URLs) > 0 {
		return it.URLs[0].URL
	}
	return ""
}

func stateName(s string) string {
	if s == "" {
		return "active"
	}
	return s
}

func summaryFor(it vault.Item, rev string, watch *personal.WatchtowerItemFinding) BrowserItemSummary {
	category := categoryOf(it)
	summary := BrowserItemSummary{ID: it.ID, Revision: rev, Category: category, VaultID: vaultOf(it), Title: it.Title, State: stateName(it.State), Favorite: it.Favorite, HasOTP: it.OTP != "", HasPasskey: len(it.PasskeyRecords()) != 0, PrimaryURL: primaryURLOf(it), UpdatedAt: it.UpdatedAt}
	summary.Tags = append([]string(nil), it.Tags...)
	switch category {
	case "credit_card":
		if card := it.NormalizedCreditCard(); card != nil {
			summary.Subtitle = strings.TrimSpace(strings.Title(card.Type) + " " + last4(card.Number))
		}
	case "identity":
		if ident := it.NormalizedIdentity(); ident != nil {
			name := strings.TrimSpace(ident.FirstName + " " + ident.LastName)
			summary.Subtitle = strings.TrimSpace(strings.TrimPrefix(name+" · "+ident.Email, " · "))
		}
	default:
		summary.Subtitle = it.Username
	}
	if watch != nil {
		summary.WatchtowerFlags = watch.Flags
		summary.StrengthScore = watch.StrengthScore
		summary.StrengthCategory = watch.StrengthCategory
	}
	return summary
}

func siteOrEmpty(raw string) string {
	if raw == "" {
		return ""
	}
	site, e := origin.Website(raw)
	if e != nil {
		return ""
	}
	return site
}

func last4(number string) string {
	digits := make([]byte, 0, len(number))
	for _, r := range number {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r))
		}
	}
	if len(digits) >= 4 {
		return string(digits[len(digits)-4:])
	}
	return string(digits)
}

func maskedCard(number string) string {
	last := last4(number)
	if last == "" {
		return "•••• •••• •••• ••••"
	}
	return "•••• •••• •••• " + last
}

// searchResultLimit is the production truncation bound. Tests may shorten it
// to prove filtering is applied before truncation; the vault schema itself is
// capped at 256 items, so a real vault cannot otherwise exercise 500+ rows.
var searchResultLimit = 500

func (c *Connection) handleSearch(r Request) error {
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	passkeys, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil {
		return c.refuse(r.ID)
	}
	watch, _ := s.WatchtowerSummaryLocal("")
	watchByID := map[string]*personal.WatchtowerItemFinding{}
	for i := range watch.Findings {
		f := watch.Findings[i]
		watchByID[f.ID] = &f
	}
	category := r.Category
	if category == "all" {
		category = ""
	}
	vaultFilter := r.VaultID
	if vaultFilter == "all" {
		vaultFilter = ""
	}
	state := r.StateFilter
	if state == "" {
		state = "active"
	}
	query := strings.ToLower(strings.TrimSpace(r.Query))
	out := []BrowserItemSummary{}
	vaultSet := map[string]bool{}
	for _, it := range items {
		rev := revisions[it.ID]
		if rev == "" {
			continue
		}
		if state != "all" && stateName(it.State) != state {
			continue
		}
		if category != "" && categoryOf(it) != category {
			continue
		}
		if vaultFilter != "" && vaultOf(it) != vaultFilter {
			continue
		}
		if r.FavoritesOnly != nil && *r.FavoritesOnly && !it.Favorite {
			continue
		}
		if r.Tag != "" {
			found := false
			for _, tag := range it.Tags {
				if tag == r.Tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if r.Origin != "" {
			site := siteOrEmpty(it.URL)
			if site != r.Origin {
				matched := false
				for _, u := range it.URLs {
					if siteOrEmpty(u.URL) == r.Origin {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
		}
		passkeyMetadata, hasPasskey := passkeys[it.ID]
		if r.PasskeysOnly != nil && *r.PasskeysOnly && !hasPasskey {
			continue
		}
		if query != "" {
			title := strings.ToLower(it.Title)
			subtitle := strings.ToLower(it.Username)
			matched := strings.Contains(title, query) || strings.Contains(subtitle, query)
			if !matched && r.PasskeysOnly != nil && *r.PasskeysOnly {
				// Every credential's public RP/account metadata is considered;
				// a multi-credential login is never judged by its first record.
				matched = passkeysMetadataMatch(passkeyMetadata, query)
			}
			if !matched {
				continue
			}
		}
		vaultSet[vaultOf(it)] = true
		summary := summaryFor(it, rev, watchByID[it.ID])
		// A list frame carries only the count plus the unambiguous legacy
		// single-credential projection; full arrays belong to one detail frame.
		summary.PasskeyCount = len(passkeyMetadata)
		if len(passkeyMetadata) == 1 {
			summary.Passkey = browserPasskey(passkeyMetadata[0])
		}
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	vaultSet["personal"] = true
	vaults := []BrowserVaultSummary{}
	for id := range vaultSet {
		name := "Personal"
		if id != "personal" {
			name = strings.Title(id)
		}
		vaults = append(vaults, BrowserVaultSummary{ID: id, Name: name})
	}
	sort.Slice(vaults, func(i, j int) bool { return vaults[i].ID < vaults[j].ID })
	if len(out) > searchResultLimit {
		out = out[:searchResultLimit]
	}
	return c.response(Response{ID: r.ID, Type: "items", Items: out, Vaults: vaults})
}

func (c *Connection) findItem(items []vault.Item, id string) (vault.Item, bool) {
	for _, it := range items {
		if it.ID == id {
			return it, true
		}
	}
	return vault.Item{}, false
}

func (c *Connection) handleItemGet(r Request) error {
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	passkeys, e := s.ReadManagedPasskeysMetadata(false)
	if e != nil {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, r.ItemID)
	if !ok {
		return c.refuse(r.ID)
	}
	rev := revisions[it.ID]
	if r.Revision != "" && r.Revision != rev {
		return c.refuse(r.ID)
	}
	category := categoryOf(it)
	detail := &BrowserItemDetail{ID: it.ID, Revision: rev, Category: category, VaultID: vaultOf(it), Title: it.Title, Username: it.Username, HasPassword: it.Password != "" && (category == "login" || category == "password"), HasOTP: it.OTP != "", HasNotes: it.Notes != "", HasPasskey: len(it.PasskeyRecords()) != 0, URL: it.URL, State: stateName(it.State), Favorite: it.Favorite, AutoSubmit: it.AutoSubmit, CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt}
	if metadata := passkeys[it.ID]; len(metadata) > 0 {
		// A detail frame is the only place per-credential arrays appear, and it
		// stays bounded. The legacy field remains single-credential only.
		for _, value := range metadata {
			if len(detail.Passkeys) == MaxBrowserPasskeys {
				break
			}
			detail.Passkeys = append(detail.Passkeys, *browserPasskey(value))
		}
		if len(metadata) == 1 {
			detail.Passkey = browserPasskey(metadata[0])
		}
	}
	detail.Tags = append([]string(nil), it.Tags...)
	for _, u := range it.URLs {
		detail.URLs = append(detail.URLs, BrowserItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	// Attachment metadata only: the durable body never enters a detail frame.
	for _, att := range it.Attachments {
		if !attachmentSelector(att.ID) || !validAttachmentFileName(att.FileName) {
			continue
		}
		detail.Attachments = append(detail.Attachments, *attachmentSummary(att))
	}
	if len(detail.URLs) == 0 && it.URL != "" {
		detail.URLs = []BrowserItemURL{{URL: it.URL, Primary: true, MatchMode: "origin"}}
	}
	for _, sec := range it.Sections {
		section := BrowserItemSection{ID: sec.ID, Title: sec.Title}
		for _, f := range sec.Fields {
			concealed := f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP
			value := f.Value
			if concealed {
				value = ""
			}
			section.Fields = append(section.Fields, BrowserCustomField{ID: f.ID, Label: f.Label, Type: string(f.Type), Value: value, Concealed: concealed, Purpose: f.Purpose, HasValue: f.Value != ""})
		}
		detail.Sections = append(detail.Sections, section)
	}
	if card := it.NormalizedCreditCard(); card != nil {
		detail.CreditCard = &BrowserCreditCardSummary{CardholderName: card.CardholderName, Type: card.Type, Last4: last4(card.Number), MaskedNumber: maskedCard(card.Number), ExpiryDate: card.ExpiryDate, ValidFrom: card.ValidFrom, IssuingBank: card.IssuingBank, HasCVV: card.Verification != "", HasPIN: card.PIN != ""}
	}
	if ident := it.NormalizedIdentity(); ident != nil {
		detail.Identity = identitySummary(ident)
	}
	if w, e := s.WatchtowerSummaryLocal(""); e == nil {
		for _, f := range w.Findings {
			if f.ID == it.ID {
				detail.WatchtowerFlags = f.Flags
				detail.StrengthScore = f.StrengthScore
				detail.StrengthCategory = f.StrengthCategory
				break
			}
		}
	}
	return c.response(Response{ID: r.ID, Type: "item-detail", Item: detail})
}

func identitySummary(in *vault.IdentityDetails) *BrowserIdentitySummary {
	if in == nil {
		return nil
	}
	return &BrowserIdentitySummary{Title: in.Title, FirstName: in.FirstName, MiddleName: in.MiddleName, LastName: in.LastName, BirthDate: in.BirthDate, Company: in.Company, Department: in.Department, JobTitle: in.JobTitle, Email: in.Email, Phone: in.Phone, AddressLine1: in.AddressLine1, AddressLine2: in.AddressLine2, City: in.City, State: in.State, PostalCode: in.PostalCode, Country: in.Country, Website: in.Website}
}

func (c *Connection) withFieldValue(r Request, deliver func(id, revision, value string, expires int, otpExpiry time.Time) error) error {
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, r.ItemID)
	if !ok || revisions[it.ID] != r.Revision || it.State == "trashed" {
		return c.refuse(r.ID)
	}
	value := ""
	expires := 0
	var otpExpiry time.Time
	category := categoryOf(it)
	switch {
	case r.Field == "username":
		value = it.Username
	case r.Field == "password":
		if category != "login" && category != "password" {
			return c.refuse(r.ID)
		}
		value = it.Password
	case r.Field == "notes":
		value = it.Notes
	case r.Field == "url":
		value = it.URL
	case r.Field == "otp":
		if it.OTP == "" {
			return c.refuse(r.ID)
		}
		config, err := totp.Parse(it.OTP)
		if err != nil {
			return c.refuse(r.ID)
		}
		code, err := config.At(time.Now().Unix())
		config.Clear()
		if err != nil {
			return c.refuse(r.ID)
		}
		value = code.Value()
		expires = int(code.Window().Until - time.Now().Unix())
		otpExpiry = time.Unix(code.Window().Until, 0)
		if expires < 0 {
			expires = 0
		}
	case r.Field == "cc-number", r.Field == "cc-csc", r.Field == "cc-pin":
		card := it.NormalizedCreditCard()
		if card == nil {
			return c.refuse(r.ID)
		}
		switch r.Field {
		case "cc-number":
			value = card.Number
		case "cc-csc":
			value = card.Verification
		case "cc-pin":
			value = card.PIN
		}
	case strings.HasPrefix(r.Field, "section:"):
		parts := strings.Split(r.Field, ":")
		if len(parts) != 3 {
			return c.refuse(r.ID)
		}
		found := false
		for _, sec := range it.Sections {
			if sec.ID != parts[1] {
				continue
			}
			for _, f := range sec.Fields {
				if f.ID == parts[2] {
					value = f.Value
					found = true
					break
				}
			}
		}
		if !found {
			return c.refuse(r.ID)
		}
	default:
		return c.refuse(r.ID)
	}
	if e := s.AuditV2Disclosure(it.ID, revisions[it.ID], r.Field); e != nil {
		return c.refuse(r.ID)
	}
	return deliver(it.ID, revisions[it.ID], value, expires, otpExpiry)
}

// handleFieldValue keeps the original inline field-value wire exactly. Only the
// resolver and audit are shared with the native prepare path.
func (c *Connection) handleFieldValue(r Request) error {
	return c.withFieldValue(r, func(id, revision, value string, expires int, _ time.Time) error {
		action := r.FieldAction
		if action == "" {
			if r.Type == "item-reveal-field" {
				action = "reveal"
			} else {
				action = "copy"
			}
		}
		if action == "copy" && expires == 0 {
			expires = 30
		}
		return c.response(Response{ID: r.ID, Type: "field-value", ItemID: id, Revision: revision, Field: r.Field, FieldValue: value, Copied: action == "copy", ExpiresInSeconds: expires})
	})
}

var allowedCategories = map[string]bool{
	"login": true, "password": true, "secure_note": true, "credit_card": true,
	"identity": true, "ssh_key": true, "api_credential": true, "database": true,
	"server": true, "document": true, "bank_account": true, "wireless_router": true,
	"software_license": true, "membership": true,
}

func decodeMutation(raw string) (BrowserItemMutation, error) {
	var m BrowserItemMutation
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&m); e != nil {
		return BrowserItemMutation{}, e
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		return BrowserItemMutation{}, ErrProtocol
	}
	if m.Category == "" {
		m.Category = "login"
	}
	// The extension form uses short aliases; store the canonical category.
	switch m.Category {
	case "card":
		m.Category = "credit_card"
	case "note":
		m.Category = "secure_note"
	case "ssh":
		m.Category = "ssh_key"
	}
	if !allowedCategories[m.Category] {
		return BrowserItemMutation{}, ErrProtocol
	}
	// Explicit clears are bounded, unique stable keys. Whether the target
	// exists, is concealed and does not contradict a new value is checked
	// against the authenticated merged item below.
	if len(m.ClearFields) > 100 {
		return BrowserItemMutation{}, ErrProtocol
	}
	seenClear := map[string]bool{}
	for _, key := range m.ClearFields {
		if seenClear[key] || !validClearKey(key) {
			return BrowserItemMutation{}, ErrProtocol
		}
		seenClear[key] = true
	}
	if strings.TrimSpace(m.Title) == "" || len(m.Title) > 1024 || !utf8.ValidString(m.Title) {
		return BrowserItemMutation{}, ErrProtocol
	}
	return m, nil
}

func mergeMeta(meta *personal.V2ItemMeta, m BrowserItemMutation) {
	if m.Category != "" {
		meta.Category = m.Category
	}
	if m.VaultID != "" {
		meta.VaultID = m.VaultID
	}
	if m.Favorite != nil {
		meta.Favorite = *m.Favorite
	}
	if m.AutoSubmit != nil {
		v := *m.AutoSubmit
		meta.AutoSubmit = &v
	}
	if m.Tags != nil {
		meta.Tags = append([]string(nil), m.Tags...)
	}
	if m.URLs != nil {
		meta.URLs = nil
		for _, u := range m.URLs {
			meta.URLs = append(meta.URLs, personal.V2ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
		}
	} else if m.URL != nil && *m.URL != "" {
		meta.URLs = []personal.V2ItemURL{{URL: *m.URL, Primary: true, MatchMode: "origin"}}
	}
	// Sections are applied through the mutation-specific inputs so an omitted
	// value preserves the durable value under the same stable field id.
	if m.CreditCard != nil {
		if meta.CreditCard == nil {
			meta.CreditCard = &personal.V2CreditCard{}
		}
		card := meta.CreditCard
		if m.CreditCard.CardholderName != "" {
			card.CardholderName = m.CreditCard.CardholderName
		}
		if m.CreditCard.Type != "" {
			card.Type = m.CreditCard.Type
		}
		if m.CreditCard.Number != nil {
			card.Number = *m.CreditCard.Number
		}
		if m.CreditCard.Verification != nil {
			card.Verification = *m.CreditCard.Verification
		}
		if m.CreditCard.ExpiryDate != "" {
			card.ExpiryDate = m.CreditCard.ExpiryDate
		}
		if m.CreditCard.ValidFrom != "" {
			card.ValidFrom = m.CreditCard.ValidFrom
		}
		if m.CreditCard.PIN != nil {
			card.PIN = *m.CreditCard.PIN
		}
		if m.CreditCard.IssuingBank != "" {
			card.IssuingBank = m.CreditCard.IssuingBank
		}
	}
	if m.Identity != nil {
		ident := personal.V2Identity{}
		if meta.Identity != nil {
			// Preserve the protected identifiers this DTO cannot edit.
			ident = *meta.Identity
		}
		ident.Title, ident.FirstName, ident.MiddleName, ident.LastName = m.Identity.Title, m.Identity.FirstName, m.Identity.MiddleName, m.Identity.LastName
		ident.BirthDate, ident.Company, ident.Department, ident.JobTitle = m.Identity.BirthDate, m.Identity.Company, m.Identity.Department, m.Identity.JobTitle
		ident.Email, ident.Phone = m.Identity.Email, m.Identity.Phone
		ident.AddressLine1, ident.AddressLine2 = m.Identity.AddressLine1, m.Identity.AddressLine2
		ident.City, ident.State, ident.PostalCode, ident.Country = m.Identity.City, m.Identity.State, m.Identity.PostalCode, m.Identity.Country
		ident.Website = m.Identity.Website
		meta.Identity = &ident
	}
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func (c *Connection) handleItemSave(r Request) error {
	m, e := decodeMutation(r.ItemJSON)
	if e != nil {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	if m.Category == "credit_card" && m.CreditCard != nil && m.CreditCard.Number != nil && *m.CreditCard.Number != "" {
		if last4(*m.CreditCard.Number) == "" {
			return c.refuse(r.ID)
		}
	}
	edit := r.Type == "item-edit" || r.Type == "item-save" && r.ItemID != ""
	var id, rev string
	if !edit {
		id, rev, e = c.createV2Item(s, m)
	} else {
		id, rev, e = c.editV2Item(s, r.ItemID, r.Revision, m)
	}
	if e != nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(false)
	if e != nil {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, id)
	if !ok {
		return c.refuse(r.ID)
	}
	if rev == "" {
		rev = revisions[id]
	}
	summary := summaryFor(it, rev, nil)
	return c.response(Response{ID: r.ID, Type: "item-saved", ItemID: id, Revision: rev, ItemSummary: &summary})
}

// v2ItemFromMutation builds the complete durable item for one browser
// mutation: the rich v2 model comes from the projected metadata DTO and only
// the supplied scalar pointers are applied. Every field the browser did not
// touch is carried over from base.
func v2ItemFromMutation(base vault.Item, m BrowserItemMutation, create bool) (vault.Item, error) {
	// decodeMutation already refused an empty or oversized title.
	base.Title = m.Title
	meta := personal.V2ItemMeta{}
	if !create {
		meta = *personal.V2MetaFromItem(base)
	}
	mergeMeta(&meta, m)
	item, err := personal.V2ItemApplyMutation(base, &meta, mutationSections(m.Sections))
	if err != nil {
		return vault.Item{}, err
	}
	item.Title = m.Title
	if m.Username != nil {
		item.Username = *m.Username
	}
	if m.URL != nil {
		item.URL = *m.URL
	}
	if m.Notes != nil {
		item.Notes = *m.Notes
	}
	if m.OTP != nil {
		// An explicit empty OTP clears the stored TOTP seed.
		if *m.OTP == "" {
			item.OTP = ""
		} else {
			config, err := totp.Parse(*m.OTP)
			if err != nil {
				return vault.Item{}, ErrProtocol
			}
			config.Clear()
			item.OTP = *m.OTP
		}
	}
	if m.Password != nil {
		// An empty password keeps the previous semantics and never clears a
		// stored secret through this channel.
		if *m.Password != "" || create {
			item.Password = *m.Password
		}
	}
	if create && (item.EffectiveCategory() == vault.CategoryLogin || item.EffectiveCategory() == vault.CategoryPassword) && item.Password == "" {
		return vault.Item{}, ErrProtocol
	}
	if item.EffectiveCategory() == vault.CategoryCreditCard {
		if card := item.CreditCard; card != nil && card.Number != "" && last4(card.Number) == "" {
			return vault.Item{}, ErrProtocol
		}
	}
	if item.EffectiveCategory() == vault.CategoryDocument && (create || base.EffectiveCategory() != vault.CategoryDocument) {
		// No atomic document+file creation exists on this channel, so an empty
		// document is never created. Editing an existing document is allowed
		// because the whole-item mutation retains its file and attachments.
		return vault.Item{}, ErrProtocol
	}
	if err := applyClearFields(&item, m); err != nil {
		return vault.Item{}, err
	}
	if !vault.ValidNotes(item.Notes) {
		return vault.Item{}, ErrProtocol
	}
	return item, nil
}

func (c *Connection) createV2Item(s *personal.Session, m BrowserItemMutation) (string, string, error) {
	item, e := v2ItemFromMutation(vault.Item{}, m, true)
	if e != nil {
		return "", "", e
	}
	gate := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
	if s.RegisterMutation(gate) != nil {
		return "", "", personal.ErrMutationCancelled
	}
	id, rev, e := s.AddItem(item, gate)
	if e != nil {
		return "", "", e
	}
	return id, rev, nil
}

func (c *Connection) editV2Item(s *personal.Session, id, revIn string, m BrowserItemMutation) (string, string, error) {
	if !token.MatchString(id) || !revision.MatchString(revIn) {
		return "", "", ErrProtocol
	}
	// Authenticated read of the current whole item; a stale revision is
	// refused here before any mutation is attempted.
	detail, e := s.GetItemDetail(id, revIn, true)
	if e != nil {
		return "", "", e
	}
	item, e := v2ItemFromMutation(itemFromDetail(detail), m, false)
	if e != nil {
		return "", "", e
	}
	gate := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
	if s.RegisterMutation(gate) != nil {
		return "", "", personal.ErrMutationCancelled
	}
	rev, e := s.EditItem(id, revIn, item, gate)
	if e != nil {
		return "", "", e
	}
	return id, rev, nil
}

// itemFromDetail reconstructs the durable item shape from an authenticated
// item detail. Opaque material the detail deliberately omits (attachments,
// SSH seeds, passkey records, import provenance, state history) is re-attached
// by the whole-item edit mutation itself.
func itemFromDetail(d personal.ItemDetail) vault.Item {
	item := vault.Item{
		ID:         d.ID,
		Kind:       d.Kind,
		Category:   d.Category,
		VaultID:    d.VaultID,
		Title:      d.Title,
		Username:   d.Username,
		Password:   d.Password,
		OTP:        d.OTP,
		URL:        d.URL,
		URLs:       append([]vault.ItemURL(nil), d.URLs...),
		Notes:      d.Notes,
		Favorite:   d.Favorite,
		AutoSubmit: d.AutoSubmit,
		Tags:       append([]string(nil), d.Tags...),
		Sections:   vault.CloneSections(d.Sections),
		History:    vault.CloneHistory(d.History),
		TrashedAt:  d.TrashedAt,
		CreatedAt:  d.CreatedAt,
		UpdatedAt:  d.UpdatedAt,
	}
	if d.CreditCard != nil {
		card := *d.CreditCard
		item.CreditCard = &card
	}
	if d.Identity != nil {
		ident := *d.Identity
		item.Identity = &ident
	}
	if d.State == "archived" {
		item.State = "archived"
	}
	return item
}

func (c *Connection) handleItemState(r Request) error {
	action := r.StateAction
	switch action {
	case "favorite", "unfavorite", "archive", "unarchive", "trash", "untrash":
	default:
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	rev, state, e := s.SetV2State(r.ItemID, r.Revision, action)
	if e != nil {
		return c.refuse(r.ID)
	}
	favorite := false
	if meta := s.Meta(r.ItemID); meta != nil {
		favorite = meta.Favorite
	}
	return c.response(Response{ID: r.ID, Type: "item-saved", ItemID: r.ItemID, Revision: rev, State: state, Favorite: favorite})
}

func (c *Connection) handleMatchProfiles(r Request) error {
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	if _, e := origin.Parse(r.Origin); e != nil {
		return c.refuse(r.ID)
	}
	// checkout-frames-v1: the extension only proposes the observed context and
	// the native same-site policy is authoritative. A refused proposal returns
	// before any profile metadata (and so before any secret) is read.
	c.profileCheckout = nil
	var checkout *BrowserCheckout
	if r.Checkout != nil {
		if r.ProfileKind != "credit_card" || !r.Checkout.personal().Valid(r.Context()) {
			c.profileContext = personal.BrowserContext{}
			c.matchedProfiles = map[string]string{}
			return c.refuse(r.ID)
		}
		checkout = r.Checkout.clone()
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	kind := r.ProfileKind
	if kind == "" {
		kind = "all"
	}
	profiles := []BrowserProfileSummary{}
	c.matchedProfiles = map[string]string{}
	for _, it := range items {
		if it.State != "" {
			continue
		}
		category := categoryOf(it)
		if category != "identity" && category != "credit_card" {
			continue
		}
		if kind != "all" && kind != category {
			continue
		}
		p := BrowserProfileSummary{ID: it.ID, Revision: revisions[it.ID], Category: category, Title: it.Title}
		if category == "credit_card" {
			if card := it.NormalizedCreditCard(); card != nil {
				p.CardBrand = card.Type
				p.CardLast4 = last4(card.Number)
				p.CardExp = card.ExpiryDate
				p.Subtitle = strings.TrimSpace(strings.Title(card.Type) + " •••• " + p.CardLast4)
			}
		}
		if category == "identity" {
			if ident := it.NormalizedIdentity(); ident != nil {
				name := strings.TrimSpace(ident.FirstName + " " + ident.LastName)
				if name == "" {
					name = ident.Title
				}
				p.Subtitle = strings.TrimSpace(strings.TrimPrefix(name+" · "+ident.Email, " · "))
			}
		}
		if p.Revision == "" {
			continue
		}
		c.matchedProfiles[it.ID+":"+p.Revision] = it.ID
		profiles = append(profiles, p)
	}
	c.profileContext = r.Context()
	// Records the exact checkout selectors this card list was produced under;
	// a later fill must repeat them byte for byte.
	c.profileCheckout = checkout
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Title < profiles[j].Title })
	return c.response(Response{ID: r.ID, Type: "profiles", Profiles: profiles})
}

func (c *Connection) handleFillProfile(r Request) error {
	if c.profile != nil || c.pending != nil || c.save != nil || c.otp != nil || c.passkey != nil || c.signal != nil || c.stagedBusy {
		return c.refuse(r.ID)
	}
	if c.profileContext.Origin != r.Origin || c.profileContext.TabID != r.TabID || c.profileContext.DocumentID != r.DocumentID {
		return c.refuse(r.ID)
	}
	// The fill must repeat the exact checkout selectors (top origin, top
	// document and frame id) the card list was produced under, or none at all.
	if !sameCheckout(c.profileCheckout, r.Checkout) {
		return c.refuse(r.ID)
	}
	if _, ok := c.matchedProfiles[r.ItemID+":"+r.Revision]; !ok {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, r.ItemID)
	if !ok || revisions[it.ID] != r.Revision || it.State != "" {
		return c.refuse(r.ID)
	}
	category := categoryOf(it)
	switch category {
	case "credit_card":
		if it.NormalizedCreditCard() == nil {
			return c.refuse(r.ID)
		}
	case "identity":
		if it.NormalizedIdentity() == nil {
			return c.refuse(r.ID)
		}
	default:
		return c.refuse(r.ID)
	}
	if c.profileCheckout != nil && category != "credit_card" {
		return c.refuse(r.ID)
	}
	// Reserve only public selectors. The private projection is prepared later,
	// after the native owner presses the approval button for this exact review;
	// no browser request can cause private fields to be read into a response.
	// Own a private copy of the proposal so the caller cannot mutate the
	// captured review after Handle returned.
	reserved := c.profileCheckout.clone()
	r.Checkout = reserved.clone()
	c.profile = &pendingProfile{
		request:     r,
		checkout:    reserved,
		title:       it.Title,
		category:    category,
		deadline:    c.now().Add(30 * time.Second),
		epoch:       c.epoch,
		cancelEpoch: c.cancelEpoch.Load(),
	}
	return nil
}

func addField(fields map[string]string, key, value string) {
	if value != "" {
		fields[key] = value
	}
}

func expiryParts(expiry string) (month, year, short string) {
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

// validClearKey accepts only the two stable explicit-clear key shapes:
// "notes" and "section:<section id>:<field id>".
func validClearKey(key string) bool {
	if key == "notes" {
		return true
	}
	if !strings.HasPrefix(key, "section:") || len(key) > 600 {
		return false
	}
	parts := strings.Split(key, ":")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" || len(parts[1]) > 256 || len(parts[2]) > 256 {
		return false
	}
	for _, c := range []byte(parts[1] + parts[2]) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// mutationSections converts the mutation-only inputs into the personal layer
// projection. Nil input stays nil so omitted sections preserve everything.
func mutationSections(in []BrowserItemMutationSection) []personal.V2SectionInput {
	if in == nil {
		return nil
	}
	out := make([]personal.V2SectionInput, 0, len(in))
	for _, sec := range in {
		section := personal.V2SectionInput{ID: sec.ID, Title: sec.Title}
		for _, f := range sec.Fields {
			var value *string
			if f.Value != nil {
				v := *f.Value
				value = &v
			}
			section.Fields = append(section.Fields, personal.V2CustomFieldInput{ID: f.ID, Label: f.Label, Type: f.Type, Value: value, Concealed: f.Concealed, Purpose: f.Purpose})
		}
		out = append(out, section)
	}
	return out
}

func mutationFieldValue(in []BrowserItemMutationSection, sectionID, fieldID string) *string {
	for _, sec := range in {
		if !strings.EqualFold(sec.ID, sectionID) {
			continue
		}
		for _, f := range sec.Fields {
			if strings.EqualFold(f.ID, fieldID) {
				return f.Value
			}
		}
	}
	return nil
}

func concealedVaultField(f vault.CustomField) bool {
	return f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP
}

// clearSectionField empties one concealed custom field on the merged item.
// Unknown and non-concealed targets are refused.
func clearSectionField(item *vault.Item, sectionID, fieldID string) bool {
	for s := range item.Sections {
		if !strings.EqualFold(item.Sections[s].ID, sectionID) {
			continue
		}
		for f := range item.Sections[s].Fields {
			field := &item.Sections[s].Fields[f]
			if !strings.EqualFold(field.ID, fieldID) {
				continue
			}
			if !concealedVaultField(*field) {
				return false
			}
			field.Value = ""
			return true
		}
	}
	return false
}

// applyClearFields performs the explicit clears after merge, so the clear lands
// in the same whole-item transaction as the rest of the mutation.
func applyClearFields(item *vault.Item, m BrowserItemMutation) error {
	for _, key := range m.ClearFields {
		if key == "notes" {
			if m.Notes != nil && *m.Notes != "" {
				return ErrProtocol
			}
			item.Notes = ""
			continue
		}
		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			return ErrProtocol
		}
		if v := mutationFieldValue(m.Sections, parts[1], parts[2]); v != nil && *v != "" {
			return ErrProtocol
		}
		if !clearSectionField(item, parts[1], parts[2]) {
			return ErrProtocol
		}
	}
	return nil
}
