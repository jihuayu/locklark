package browserhost

import (
	"crypto/rand"
	"encoding/hex"
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
		"item-state", "match-profiles", "fill-profile":
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
	}
	return c.refuse(r.ID)
}

func categoryOf(meta *personal.V2ItemMeta) string {
	if meta != nil && meta.Category != "" {
		return meta.Category
	}
	return "login"
}

func vaultOf(meta *personal.V2ItemMeta) string {
	if meta != nil && meta.VaultID != "" {
		return meta.VaultID
	}
	return "personal"
}

func stateName(s string) string {
	if s == "" {
		return "active"
	}
	return s
}

func summaryFor(it vault.Item, rev string, meta *personal.V2ItemMeta, watch *personal.WatchtowerItemFinding) BrowserItemSummary {
	category := categoryOf(meta)
	summary := BrowserItemSummary{ID: it.ID, Revision: rev, Category: category, VaultID: vaultOf(meta), Title: it.Title, State: stateName(it.State), HasOTP: it.OTP != "", HasPasskey: len(it.Passkey) != 0, PrimaryURL: it.URL}
	if meta != nil {
		summary.Favorite = meta.Favorite
		summary.Tags = append([]string(nil), meta.Tags...)
		summary.UpdatedAt = meta.UpdatedAt
		if len(meta.URLs) > 0 {
			for _, u := range meta.URLs {
				if u.Primary {
					summary.PrimaryURL = u.URL
					break
				}
			}
			if summary.PrimaryURL == "" {
				summary.PrimaryURL = meta.URLs[0].URL
			}
		}
		switch category {
		case "credit_card":
			if meta.CreditCard != nil {
				last4 := last4(meta.CreditCard.Number)
				summary.Subtitle = strings.TrimSpace(strings.Title(meta.CreditCard.Type) + " " + last4)
			}
		case "identity":
			if meta.Identity != nil {
				name := strings.TrimSpace(meta.Identity.FirstName + " " + meta.Identity.LastName)
				summary.Subtitle = strings.TrimSpace(strings.TrimPrefix(name+" · "+meta.Identity.Email, " · "))
			}
		default:
			summary.Subtitle = it.Username
		}
	} else {
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

func (c *Connection) handleSearch(r Request) error {
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
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
		meta := s.Meta(it.ID)
		if state != "all" && stateName(it.State) != state {
			continue
		}
		if category != "" && categoryOf(meta) != category {
			continue
		}
		if vaultFilter != "" && vaultOf(meta) != vaultFilter {
			continue
		}
		if r.FavoritesOnly != nil && *r.FavoritesOnly && (meta == nil || !meta.Favorite) {
			continue
		}
		if r.Tag != "" {
			found := false
			if meta != nil {
				for _, tag := range meta.Tags {
					if tag == r.Tag {
						found = true
						break
					}
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
				if meta != nil {
					for _, u := range meta.URLs {
						if siteOrEmpty(u.URL) == r.Origin {
							matched = true
							break
						}
					}
				}
				if !matched {
					continue
				}
			}
		}
		if query != "" {
			title := strings.ToLower(it.Title)
			subtitle := strings.ToLower(it.Username)
			if !strings.Contains(title, query) && !strings.Contains(subtitle, query) {
				continue
			}
		}
		vaultSet[vaultOf(meta)] = true
		out = append(out, summaryFor(it, rev, meta, watchByID[it.ID]))
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
	if len(out) > 500 {
		out = out[:500]
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
	it, ok := c.findItem(items, r.ItemID)
	if !ok {
		return c.refuse(r.ID)
	}
	rev := revisions[it.ID]
	if r.Revision != "" && r.Revision != rev {
		return c.refuse(r.ID)
	}
	meta := s.Meta(it.ID)
	category := categoryOf(meta)
	detail := &BrowserItemDetail{ID: it.ID, Revision: rev, Category: category, VaultID: vaultOf(meta), Title: it.Title, Username: it.Username, HasPassword: it.Password != "" && (category == "login" || category == "password"), HasOTP: it.OTP != "", HasNotes: it.Notes != "", HasPasskey: len(it.Passkey) != 0, URL: it.URL, State: stateName(it.State)}
	if meta == nil && it.URL != "" {
		detail.URLs = []BrowserItemURL{{URL: it.URL, Primary: true, MatchMode: "origin"}}
	}
	if meta != nil {
		detail.Favorite = meta.Favorite
		detail.AutoSubmit = meta.AutoSubmit
		detail.Tags = append([]string(nil), meta.Tags...)
		detail.CreatedAt = meta.CreatedAt
		detail.UpdatedAt = meta.UpdatedAt
		for _, u := range meta.URLs {
			detail.URLs = append(detail.URLs, BrowserItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
		}
		if len(detail.URLs) == 0 && it.URL != "" {
			detail.URLs = []BrowserItemURL{{URL: it.URL, Primary: true, MatchMode: "origin"}}
		}
		for _, sec := range meta.Sections {
			section := BrowserItemSection{ID: sec.ID, Title: sec.Title}
			for _, f := range sec.Fields {
				concealed := f.Concealed || f.Type == "concealed" || f.Type == "password"
				value := f.Value
				if concealed {
					value = ""
				}
				section.Fields = append(section.Fields, BrowserCustomField{ID: f.ID, Label: f.Label, Type: f.Type, Value: value, Concealed: concealed, Purpose: f.Purpose})
			}
			detail.Sections = append(detail.Sections, section)
		}
		if meta.CreditCard != nil {
			card := meta.CreditCard
			detail.CreditCard = &BrowserCreditCardSummary{CardholderName: card.CardholderName, Type: card.Type, Last4: last4(card.Number), MaskedNumber: maskedCard(card.Number), ExpiryDate: card.ExpiryDate, ValidFrom: card.ValidFrom, IssuingBank: card.IssuingBank, HasCVV: card.Verification != "", HasPIN: card.PIN != ""}
		}
		if meta.Identity != nil {
			detail.Identity = identitySummary(meta.Identity)
		}
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

func identitySummary(in *personal.V2Identity) *BrowserIdentitySummary {
	if in == nil {
		return nil
	}
	return &BrowserIdentitySummary{Title: in.Title, FirstName: in.FirstName, MiddleName: in.MiddleName, LastName: in.LastName, BirthDate: in.BirthDate, Company: in.Company, Department: in.Department, JobTitle: in.JobTitle, Email: in.Email, Phone: in.Phone, AddressLine1: in.AddressLine1, AddressLine2: in.AddressLine2, City: in.City, State: in.State, PostalCode: in.PostalCode, Country: in.Country, Website: in.Website}
}

func (c *Connection) handleFieldValue(r Request) error {
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
	meta := s.Meta(it.ID)
	value := ""
	expires := 0
	category := categoryOf(meta)
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
		if expires < 0 {
			expires = 0
		}
	case r.Field == "cc-number":
		if meta == nil || meta.CreditCard == nil {
			return c.refuse(r.ID)
		}
		value = meta.CreditCard.Number
	case r.Field == "cc-csc":
		if meta == nil || meta.CreditCard == nil {
			return c.refuse(r.ID)
		}
		value = meta.CreditCard.Verification
	case r.Field == "cc-pin":
		if meta == nil || meta.CreditCard == nil {
			return c.refuse(r.ID)
		}
		value = meta.CreditCard.PIN
	case strings.HasPrefix(r.Field, "section:"):
		parts := strings.Split(r.Field, ":")
		if len(parts) != 3 || meta == nil {
			return c.refuse(r.ID)
		}
		found := false
		for _, sec := range meta.Sections {
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
	action := r.FieldAction
	if action == "" {
		if r.Type == "item-reveal-field" {
			action = "reveal"
		} else {
			action = "copy"
		}
	}
	if e := s.AuditV2Disclosure(it.ID, revisions[it.ID], r.Field); e != nil {
		return c.refuse(r.ID)
	}
	if action == "copy" && expires == 0 {
		expires = 30
	}
	return c.response(Response{ID: r.ID, Type: "field-value", ItemID: it.ID, Revision: revisions[it.ID], Field: r.Field, FieldValue: value, Copied: action == "copy", ExpiresInSeconds: expires})
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
	if !allowedCategories[m.Category] {
		return BrowserItemMutation{}, ErrProtocol
	}
	if strings.TrimSpace(m.Title) == "" || len(m.Title) > 1024 || !utf8.ValidString(m.Title) {
		return BrowserItemMutation{}, ErrProtocol
	}
	return m, nil
}

func randomPlaceholder() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "locklark-item-placeholder"
	}
	return hex.EncodeToString(b[:])
}

func metaFromMutation(m BrowserItemMutation) personal.V2ItemMeta {
	meta := personal.V2ItemMeta{Category: m.Category, VaultID: m.VaultID, Favorite: m.Favorite != nil && *m.Favorite, AutoSubmit: m.AutoSubmit, Tags: append([]string(nil), m.Tags...)}
	if meta.VaultID == "" {
		meta.VaultID = "personal"
	}
	for _, u := range m.URLs {
		meta.URLs = append(meta.URLs, personal.V2ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	if len(meta.URLs) == 0 && m.URL != nil && *m.URL != "" {
		meta.URLs = []personal.V2ItemURL{{URL: *m.URL, Primary: true, MatchMode: "origin"}}
	}
	for _, sec := range m.Sections {
		s := personal.V2Section{ID: sec.ID, Title: sec.Title}
		for _, f := range sec.Fields {
			s.Fields = append(s.Fields, personal.V2CustomField{ID: f.ID, Label: f.Label, Type: f.Type, Value: f.Value, Concealed: f.Concealed, Purpose: f.Purpose})
		}
		meta.Sections = append(meta.Sections, s)
	}
	if m.CreditCard != nil {
		card := &personal.V2CreditCard{CardholderName: m.CreditCard.CardholderName, Type: m.CreditCard.Type, ExpiryDate: m.CreditCard.ExpiryDate, ValidFrom: m.CreditCard.ValidFrom, IssuingBank: m.CreditCard.IssuingBank}
		if m.CreditCard.Number != nil {
			card.Number = *m.CreditCard.Number
		}
		if m.CreditCard.Verification != nil {
			card.Verification = *m.CreditCard.Verification
		}
		if m.CreditCard.PIN != nil {
			card.PIN = *m.CreditCard.PIN
		}
		meta.CreditCard = card
	}
	if m.Identity != nil {
		meta.Identity = &personal.V2Identity{Title: m.Identity.Title, FirstName: m.Identity.FirstName, MiddleName: m.Identity.MiddleName, LastName: m.Identity.LastName, BirthDate: m.Identity.BirthDate, Company: m.Identity.Company, Department: m.Identity.Department, JobTitle: m.Identity.JobTitle, Email: m.Identity.Email, Phone: m.Identity.Phone, AddressLine1: m.Identity.AddressLine1, AddressLine2: m.Identity.AddressLine2, City: m.Identity.City, State: m.Identity.State, PostalCode: m.Identity.PostalCode, Country: m.Identity.Country, Website: m.Identity.Website}
	}
	return meta
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
	if m.Sections != nil {
		meta.Sections = nil
		for _, sec := range m.Sections {
			out := personal.V2Section{ID: sec.ID, Title: sec.Title}
			for _, f := range sec.Fields {
				out.Fields = append(out.Fields, personal.V2CustomField{ID: f.ID, Label: f.Label, Type: f.Type, Value: f.Value, Concealed: f.Concealed, Purpose: f.Purpose})
			}
			meta.Sections = append(meta.Sections, out)
		}
	}
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
		meta.Identity = &personal.V2Identity{Title: m.Identity.Title, FirstName: m.Identity.FirstName, MiddleName: m.Identity.MiddleName, LastName: m.Identity.LastName, BirthDate: m.Identity.BirthDate, Company: m.Identity.Company, Department: m.Identity.Department, JobTitle: m.Identity.JobTitle, Email: m.Identity.Email, Phone: m.Identity.Phone, AddressLine1: m.Identity.AddressLine1, AddressLine2: m.Identity.AddressLine2, City: m.Identity.City, State: m.Identity.State, PostalCode: m.Identity.PostalCode, Country: m.Identity.Country, Website: m.Identity.Website}
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
	meta := s.Meta(id)
	summary := summaryFor(it, rev, meta, nil)
	return c.response(Response{ID: r.ID, Type: "item-saved", ItemID: id, Revision: rev, ItemSummary: &summary})
}

func (c *Connection) createV2Item(s *personal.Session, m BrowserItemMutation) (string, string, error) {
	title := m.Title
	username := derefString(m.Username)
	website := derefString(m.URL)
	notes := derefString(m.Notes)
	otp := derefString(m.OTP)
	password := derefString(m.Password)
	if m.Identity != nil {
		if username == "" {
			username = m.Identity.Email
		}
		if m.Identity.Website != "" && website == "" {
			website = m.Identity.Website
		}
	}
	if m.CreditCard != nil && username == "" {
		username = m.CreditCard.CardholderName
	}
	if password == "" {
		if m.Category == "login" || m.Category == "password" {
			return "", "", ErrProtocol
		}
		password = randomPlaceholder()
	}
	if website != "" {
		if _, e := origin.Website(website); e != nil {
			return "", "", ErrProtocol
		}
	}
	if otp != "" {
		config, e := totp.Parse(otp)
		if e != nil {
			return "", "", ErrProtocol
		}
		config.Clear()
	}
	if !vault.ValidNotes(notes) {
		return "", "", ErrProtocol
	}
	until := minTime(c.until, c.now().Add(30*time.Second))
	gate := personal.NewMutationGate(until)
	if s.RegisterMutation(gate) != nil {
		return "", "", personal.ErrMutationCancelled
	}
	receipt, e := s.SaveNativeLogin(personal.NativeLoginMetadata{Title: title, URL: website}, []byte(username), []byte(password), gate)
	if e != nil {
		return "", "", e
	}
	rev := receipt.Revision
	for _, field := range []struct{ name, value string }{{"otp", otp}, {"notes", notes}} {
		if field.value == "" {
			continue
		}
		g := personal.NewMutationGate(until)
		if s.RegisterMutation(g) != nil {
			return "", "", personal.ErrMutationCancelled
		}
		next, e := s.EditNativeField(receipt.ID, rev, field.name, []byte(field.value), g)
		if e != nil {
			return "", "", e
		}
		rev = next
	}
	s.PatchMeta(receipt.ID, func(meta *personal.V2ItemMeta) {
		*meta = metaFromMutation(m)
	})
	return receipt.ID, rev, nil
}

func (c *Connection) editV2Item(s *personal.Session, id, revIn string, m BrowserItemMutation) (string, string, error) {
	if !token.MatchString(id) || !revision.MatchString(revIn) {
		return "", "", ErrProtocol
	}
	rev := revIn
	fields := []struct {
		name  string
		value string
		set   bool
	}{
		{"title", m.Title, true},
		{"username", derefString(m.Username), m.Username != nil},
		{"url", derefString(m.URL), m.URL != nil},
	}
	for _, field := range fields {
		if !field.set {
			continue
		}
		g := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
		if s.RegisterMutation(g) != nil {
			return "", "", personal.ErrMutationCancelled
		}
		next, e := s.EditNativeField(id, rev, field.name, []byte(field.value), g)
		if e != nil {
			return "", "", e
		}
		rev = next
	}
	if m.Password != nil && *m.Password != "" {
		g := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
		if s.RegisterMutation(g) != nil {
			return "", "", personal.ErrMutationCancelled
		}
		next, e := s.EditNativeField(id, rev, "password", []byte(*m.Password), g)
		if e != nil {
			return "", "", e
		}
		rev = next
	}
	if m.OTP != nil && *m.OTP != "" {
		g := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
		if s.RegisterMutation(g) != nil {
			return "", "", personal.ErrMutationCancelled
		}
		next, e := s.EditNativeField(id, rev, "otp", []byte(*m.OTP), g)
		if e != nil {
			return "", "", e
		}
		rev = next
	}
	if m.Notes != nil {
		g := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
		if s.RegisterMutation(g) != nil {
			return "", "", personal.ErrMutationCancelled
		}
		next, e := s.SaveNativeNotes(id, rev, []byte(*m.Notes), g)
		if e != nil {
			return "", "", e
		}
		rev = next
	}
	s.PatchMeta(id, func(meta *personal.V2ItemMeta) { mergeMeta(meta, m) })
	return id, rev, nil
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
		meta := s.Meta(it.ID)
		category := categoryOf(meta)
		if category != "identity" && category != "credit_card" {
			continue
		}
		if kind != "all" && kind != category {
			continue
		}
		p := BrowserProfileSummary{ID: it.ID, Revision: revisions[it.ID], Category: category, Title: it.Title}
		if category == "credit_card" && meta != nil && meta.CreditCard != nil {
			card := meta.CreditCard
			p.CardBrand = card.Type
			p.CardLast4 = last4(card.Number)
			p.CardExp = card.ExpiryDate
			brand := strings.Title(card.Type)
			p.Subtitle = strings.TrimSpace(brand + " •••• " + p.CardLast4)
		}
		if category == "identity" && meta != nil && meta.Identity != nil {
			ident := meta.Identity
			name := strings.TrimSpace(ident.FirstName + " " + ident.LastName)
			if name == "" {
				name = ident.Title
			}
			p.Subtitle = strings.TrimSpace(strings.TrimPrefix(name+" · "+ident.Email, " · "))
		}
		if p.Revision == "" {
			continue
		}
		c.matchedProfiles[it.ID+":"+p.Revision] = it.ID
		profiles = append(profiles, p)
	}
	c.profileContext = r.Context()
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Title < profiles[j].Title })
	return c.response(Response{ID: r.ID, Type: "profiles", Profiles: profiles})
}

func (c *Connection) handleFillProfile(r Request) error {
	if c.profileContext.Origin != r.Origin || c.profileContext.TabID != r.TabID || c.profileContext.DocumentID != r.DocumentID {
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
	meta := s.Meta(it.ID)
	if meta == nil {
		return c.refuse(r.ID)
	}
	fill := &BrowserProfileFill{ItemID: it.ID, Revision: r.Revision, Category: categoryOf(meta), Fields: map[string]string{}}
	switch categoryOf(meta) {
	case "credit_card":
		if meta.CreditCard == nil {
			return c.refuse(r.ID)
		}
		card := meta.CreditCard
		month, year, short := expiryParts(card.ExpiryDate)
		cc := &BrowserCreditCardFill{CardholderName: card.CardholderName, Type: card.Type, Number: card.Number, Verification: card.Verification, ExpiryDate: card.ExpiryDate, ExpMonth: month, ExpYear: year, ExpYearShort: short, PIN: card.PIN}
		fill.CreditCard = cc
		addField(fill.Fields, "cc-name", card.CardholderName)
		addField(fill.Fields, "cc-number", card.Number)
		addField(fill.Fields, "cc-exp", card.ExpiryDate)
		addField(fill.Fields, "cc-exp-month", month)
		addField(fill.Fields, "cc-exp-year", year)
		addField(fill.Fields, "cc-exp-year-short", short)
		addField(fill.Fields, "cc-csc", card.Verification)
		addField(fill.Fields, "cc-type", card.Type)
	case "identity":
		if meta.Identity == nil {
			return c.refuse(r.ID)
		}
		ident := meta.Identity
		fill.Identity = identitySummary(ident)
		addField(fill.Fields, "honorific-prefix", ident.Title)
		addField(fill.Fields, "given-name", ident.FirstName)
		addField(fill.Fields, "additional-name", ident.MiddleName)
		addField(fill.Fields, "family-name", ident.LastName)
		name := strings.TrimSpace(ident.FirstName + " " + ident.MiddleName + " " + ident.LastName)
		if name == "" {
			name = ident.Title
		}
		addField(fill.Fields, "name", name)
		addField(fill.Fields, "organization", ident.Company)
		addField(fill.Fields, "organization-title", ident.JobTitle)
		addField(fill.Fields, "email", ident.Email)
		addField(fill.Fields, "tel", ident.Phone)
		street := strings.TrimSpace(strings.TrimPrefix(ident.AddressLine1+", "+ident.AddressLine2, ", "))
		addField(fill.Fields, "street-address", street)
		addField(fill.Fields, "address-line1", ident.AddressLine1)
		addField(fill.Fields, "address-line2", ident.AddressLine2)
		addField(fill.Fields, "address-level2", ident.City)
		addField(fill.Fields, "address-level1", ident.State)
		addField(fill.Fields, "postal-code", ident.PostalCode)
		addField(fill.Fields, "country", ident.Country)
		addField(fill.Fields, "country-name", ident.Country)
		addField(fill.Fields, "bday", ident.BirthDate)
	default:
		return c.refuse(r.ID)
	}
	return c.response(Response{ID: r.ID, Type: "profile-fill", ProfileFill: fill})
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
