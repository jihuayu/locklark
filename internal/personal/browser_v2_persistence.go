package personal

import (
	"errors"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// ---------------------------------------------------------------------------
// v2 metadata projection
//
// There is no process-wide v2 metadata overlay. V2ItemMeta is a pure DTO
// projection of authenticated vault.Item fields, and every write goes through
// the same whole-item, exact-revision, signed-audit mutation path as the
// desktop vault (AddItem / EditItem / SetFavorite).
// ---------------------------------------------------------------------------

// v2ValidationPlaceholderID is a selector-safe stand-in for schema validation
// of an item that has not been assigned its random ID yet. It is never stored.
const v2ValidationPlaceholderID = "v2-meta-validation"

// V2MetaFromItem projects the durable v2 attributes of an already
// authenticated item into the browser DTO. Callers must not treat the result
// as an independent source of truth: it is derived, never merged back from
// process memory.
func V2MetaFromItem(it vault.Item) *V2ItemMeta {
	meta := &V2ItemMeta{
		Category:  string(it.EffectiveCategory()),
		VaultID:   it.EffectiveVaultID(),
		Favorite:  it.Favorite,
		Tags:      append([]string(nil), it.Tags...),
		CreatedAt: it.CreatedAt,
		UpdatedAt: it.UpdatedAt,
	}
	if it.AutoSubmit != nil {
		v := *it.AutoSubmit
		meta.AutoSubmit = &v
	}
	for _, u := range it.URLs {
		meta.URLs = append(meta.URLs, V2ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	for _, sec := range it.Sections {
		section := V2Section{ID: sec.ID, Title: sec.Title}
		for _, f := range sec.Fields {
			section.Fields = append(section.Fields, V2CustomField{
				ID:        f.ID,
				Label:     f.Label,
				Type:      string(f.Type),
				Value:     f.Value,
				Concealed: concealedCustomField(f),
				Purpose:   f.Purpose,
			})
		}
		meta.Sections = append(meta.Sections, section)
	}
	if cc := it.NormalizedCreditCard(); cc != nil {
		meta.CreditCard = &V2CreditCard{
			CardholderName: cc.CardholderName,
			Type:           cc.Type,
			Number:         cc.Number,
			Verification:   cc.Verification,
			ExpiryDate:     cc.ExpiryDate,
			ValidFrom:      cc.ValidFrom,
			PIN:            cc.PIN,
			IssuingBank:    cc.IssuingBank,
		}
	}
	if id := it.NormalizedIdentity(); id != nil {
		meta.Identity = &V2Identity{
			Title:          id.Title,
			FirstName:      id.FirstName,
			MiddleName:     id.MiddleName,
			LastName:       id.LastName,
			BirthDate:      id.BirthDate,
			Company:        id.Company,
			Department:     id.Department,
			JobTitle:       id.JobTitle,
			Email:          id.Email,
			Phone:          id.Phone,
			AddressLine1:   id.AddressLine1,
			AddressLine2:   id.AddressLine2,
			City:           id.City,
			State:          id.State,
			PostalCode:     id.PostalCode,
			Country:        id.Country,
			SSN:            id.SSN,
			PassportNumber: id.PassportNumber,
			LicenseNumber:  id.LicenseNumber,
			Website:        id.Website,
		}
	}
	return meta
}

// V2ItemApplyMeta returns base with the DTO projection applied explicitly,
// field by field. Durable data that the DTO cannot express (history,
// attachments, SSH material, passkeys, import provenance, state) and any
// protected custom field value the caller could not read are preserved.
// The result is validated against the same schema used by the durable
// mutation path before it is returned.
func V2ItemApplyMeta(base vault.Item, meta *V2ItemMeta) (vault.Item, error) {
	if meta == nil {
		return vault.Item{}, ErrMutationRefused
	}
	return v2ItemApplyMeta(base, meta, func(previous []vault.ItemSection) ([]vault.ItemSection, error) {
		return v2SectionsFromMeta(previous, meta.Sections)
	})
}

// v2ItemApplyMeta is the shared explicit application path. sectionsFrom owns
// the section projection so the DTO round-trip and the mutation-specific
// section inputs cannot drift apart.
func v2ItemApplyMeta(base vault.Item, meta *V2ItemMeta, sectionsFrom func([]vault.ItemSection) ([]vault.ItemSection, error)) (vault.Item, error) {
	if meta == nil {
		return vault.Item{}, ErrMutationRefused
	}
	out := vault.CloneItem(base)
	category := vault.ItemCategory(meta.Category)
	if category == "" {
		category = out.EffectiveCategory()
	}
	if !vault.ValidCategory(category) {
		return vault.Item{}, ErrMutationRefused
	}
	out.Category = category
	if category == vault.CategorySSHKey && out.Kind == "ssh-key" {
		// Keep the v1 SSH key shape so its Ed25519 material keeps validating.
	} else {
		out.Kind = string(category)
	}
	out.VaultID = meta.VaultID
	if out.VaultID == "" {
		out.VaultID = vault.DefaultVaultID
	}
	out.Favorite = meta.Favorite
	if meta.AutoSubmit != nil {
		v := *meta.AutoSubmit
		out.AutoSubmit = &v
	} else {
		out.AutoSubmit = nil
	}
	out.Tags = append([]string(nil), meta.Tags...)
	out.URLs = nil
	for _, u := range meta.URLs {
		out.URLs = append(out.URLs, vault.ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	sections, err := sectionsFrom(base.Sections)
	if err != nil {
		return vault.Item{}, err
	}
	out.Sections = sections
	if meta.CreditCard != nil {
		out.CreditCard = &vault.CreditCardDetails{
			CardholderName: meta.CreditCard.CardholderName,
			Type:           meta.CreditCard.Type,
			Number:         meta.CreditCard.Number,
			Verification:   meta.CreditCard.Verification,
			ExpiryDate:     meta.CreditCard.ExpiryDate,
			ValidFrom:      meta.CreditCard.ValidFrom,
			PIN:            meta.CreditCard.PIN,
			IssuingBank:    meta.CreditCard.IssuingBank,
		}
	} else {
		out.CreditCard = nil
	}
	if meta.Identity != nil {
		out.Identity = &vault.IdentityDetails{
			Title:          meta.Identity.Title,
			FirstName:      meta.Identity.FirstName,
			MiddleName:     meta.Identity.MiddleName,
			LastName:       meta.Identity.LastName,
			BirthDate:      meta.Identity.BirthDate,
			Company:        meta.Identity.Company,
			Department:     meta.Identity.Department,
			JobTitle:       meta.Identity.JobTitle,
			Email:          meta.Identity.Email,
			Phone:          meta.Identity.Phone,
			AddressLine1:   meta.Identity.AddressLine1,
			AddressLine2:   meta.Identity.AddressLine2,
			City:           meta.Identity.City,
			State:          meta.Identity.State,
			PostalCode:     meta.Identity.PostalCode,
			Country:        meta.Identity.Country,
			SSN:            meta.Identity.SSN,
			PassportNumber: meta.Identity.PassportNumber,
			LicenseNumber:  meta.Identity.LicenseNumber,
			Website:        meta.Identity.Website,
		}
	} else {
		out.Identity = nil
	}
	if err := validateV2Candidate(out); err != nil {
		return vault.Item{}, err
	}
	return out, nil
}

// validateV2Candidate checks title/category/URL/section/card/identity schema
// bounds without requiring the opaque durable material (attachments, SSH
// seeds, passkeys, history) that only the whole-item mutation path can
// authenticate.
func validateV2Candidate(it vault.Item) error {
	probe := vault.CloneItem(it)
	probe.ID = v2ValidationPlaceholderID
	probe.SSHSeed, probe.SSHPublicKey = nil, nil
	probe.Attachment, probe.AttachmentProtected, probe.Filename = nil, false, ""
	probe.Attachments = nil
	probe.Passkey = nil
	probe.History = nil
	if probe.Kind == "ssh-key" {
		probe.Kind = string(vault.CategorySSHKey)
	}
	normalized, err := normalizeV2Item(probe)
	if err != nil {
		return err
	}
	if vault.ValidateItems(nil, []vault.Item{normalized}) != nil {
		return ErrMutationRefused
	}
	return nil
}

func concealedCustomField(f vault.CustomField) bool {
	return f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP
}

// v2FieldType maps browser field type spellings onto the canonical encrypted
// field types. Unknown spellings are refused instead of being stored as free
// form text.
func v2FieldType(raw string, concealed bool) (vault.FieldType, error) {
	t := vault.FieldType(strings.ToLower(strings.TrimSpace(raw)))
	switch t {
	case "":
		if concealed {
			return vault.FieldTypeConcealed, nil
		}
		return vault.FieldTypeText, nil
	case vault.FieldTypeText, vault.FieldTypeConcealed, vault.FieldTypeURL, vault.FieldTypeEmail,
		vault.FieldTypeOTP, vault.FieldTypeDate, vault.FieldTypeMonthYear,
		vault.FieldTypePhone, vault.FieldTypeAddress, vault.FieldTypeReference,
		vault.FieldTypeMenu, vault.FieldTypeString, vault.FieldTypeTOTP, vault.FieldTypeFile:
		return t, nil
	case "password", "cvv", "cvc", "card_number", "card-number", "secret":
		return vault.FieldTypeConcealed, nil
	case "multiline", "note", "notes":
		return vault.FieldTypeText, nil
	}
	return "", ErrMutationRefused
}

// v2SectionsFromMeta converts the DTO sections into encrypted sections. A
// protected field whose value the caller could not read (empty) keeps the
// durable value from previous, and protected fields missing from the DTO are
// re-attached to their existing section so a masked round-trip cannot destroy
// concealed data.
func v2SectionsFromMeta(previous []vault.ItemSection, in []V2Section) ([]vault.ItemSection, error) {
	if in == nil {
		return vault.CloneSections(previous), nil
	}
	out := make([]vault.ItemSection, 0, len(in))
	for _, sec := range in {
		section := vault.ItemSection{ID: sec.ID, Title: sec.Title}
		for _, f := range sec.Fields {
			typ, err := v2FieldType(f.Type, f.Concealed)
			if err != nil {
				return nil, err
			}
			protected := f.Concealed || typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP
			value := f.Value
			if protected && value == "" {
				if old, ok := findPreviousField(previous, sec.ID, f.ID); ok {
					value = old.Value
				}
			}
			section.Fields = append(section.Fields, vault.CustomField{ID: f.ID, Label: f.Label, Type: typ, Value: value, Protected: protected, Purpose: f.Purpose})
		}
		for _, old := range previous {
			if !strings.EqualFold(old.ID, sec.ID) || !concealedSection(old) {
				continue
			}
			for _, oldField := range old.Fields {
				if !concealedCustomField(oldField) || hasSectionField(section.Fields, oldField.ID) {
					continue
				}
				section.Fields = append(section.Fields, oldField)
			}
		}
		out = append(out, section)
	}
	return out, nil
}

func concealedSection(sec vault.ItemSection) bool {
	for _, f := range sec.Fields {
		if concealedCustomField(f) {
			return true
		}
	}
	return false
}

func hasSectionField(fields []vault.CustomField, id string) bool {
	for _, f := range fields {
		if strings.EqualFold(f.ID, id) {
			return true
		}
	}
	return false
}

func findPreviousField(sections []vault.ItemSection, sectionID, fieldID string) (vault.CustomField, bool) {
	for _, sec := range sections {
		if !strings.EqualFold(sec.ID, sectionID) {
			continue
		}
		for _, f := range sec.Fields {
			if strings.EqualFold(f.ID, fieldID) {
				return f, true
			}
		}
	}
	return vault.CustomField{}, false
}

// authenticatedItemLocked reads one item through the full slot, snapshot,
// schema and history authentication path. Caller holds Session.mu.
func (s *Session) authenticatedItemLocked(id string) (vault.Item, string, error) {
	var item vault.Item
	revision := ""
	if e := s.active(true); e != nil {
		return vault.Item{}, "", e
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return vault.Item{}, "", e
	}
	e = db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "item.list", s)
		if e != nil {
			return e
		}
		defer a.clear()
		revision = a.revisions[id]
		if revision == "" {
			return ErrNotFound
		}
		for _, it := range a.items {
			if it.ID == id {
				// Clone before a.clear() wipes SSH/passkey material.
				item = vault.CloneItem(it)
				return nil
			}
		}
		return ErrNotFound
	})
	if closeErr := db.Close(); closeErr != nil && e == nil {
		e = ErrCommandClose
	}
	if errors.Is(e, invalid) {
		s.lock()
	}
	if e != nil {
		return vault.Item{}, "", e
	}
	if s.active(false) != nil {
		return vault.Item{}, "", ErrSessionLocked
	}
	return item, revision, nil
}

// persistMeta performs one whole-item audited mutation that writes the patched
// projection back to the durable v2 records. There is no memory-only fallback:
// a refused or conflicting mutation returns an error and leaves the vault
// untouched.
func (s *Session) persistMeta(id string, patch func(*V2ItemMeta)) error {
	if s == nil || !idOK(id) || patch == nil {
		return ErrMutationRefused
	}
	s.mu.Lock()
	item, revision, err := s.authenticatedItemLocked(id)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	meta := V2MetaFromItem(item)
	patch(meta)
	updated, err := V2ItemApplyMeta(item, meta)
	if err != nil {
		return err
	}
	gate := NewMutationGate(time.Now().Add(30 * time.Second))
	if err := s.RegisterMutation(gate); err != nil {
		return ErrMutationCancelled
	}
	if _, err := s.EditItem(id, revision, updated, gate); err != nil {
		return err
	}
	return nil
}
