package personal

import (
	"errors"
	"strings"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrReferenceProfile = errors.New("unsupported personal reference metadata profile")
var ErrReferenceMetadata = errors.New("invalid personal reference metadata")

// ProjectReferenceMetadata describes the built-in personal item profile.
// The caller owns the immutable inputs and must authenticate the snapshot and
// derive revisions from the same journal transaction. Neither the profile tag
// nor a well-formed revision authenticates an input or grants field access.
// Only item identity, kind, title and field identities are read. Field values
// never enter the output or affect which field identities are present.
func ProjectReferenceMetadata(metadata []byte, vaultID, name string, items []vault.Item, revisions map[string]string) ([]reference.Vault, error) {
	return ProjectReferenceMetadataV2(metadata, vaultID, name, nil, items, revisions)
}

// ProjectReferenceMetadataV2 adds logical sub-vaults to the catalog so
// op://<vault id or name>/<item>/[section/]field resolves against the v2
// VaultID while the default account catalog remains addressable by its ID and
// the "Personal" name.
func ProjectReferenceMetadataV2(metadata []byte, vaultID, name string, vaults []vault.VaultMeta, items []vault.Item, revisions map[string]string) ([]reference.Vault, error) {
	if string(metadata) != schema {
		return nil, ErrReferenceProfile
	}
	if len(items) > 256 {
		return nil, reference.ErrLimit
	}
	if items == nil || len(revisions) != len(items) {
		return nil, ErrReferenceMetadata
	}
	all, err := projectItems(vaultID, name, items, revisions)
	if err != nil {
		return nil, err
	}
	catalog := []reference.Vault{all}
	if len(vaults) > 64 {
		return nil, reference.ErrLimit
	}
	seen := map[string]bool{strings.ToLower(vaultID): true}
	for _, meta := range vaults {
		if meta.ID == "" || strings.EqualFold(meta.ID, vaultID) {
			continue
		}
		if !selectorID(meta.ID) || len(meta.Name) > 1024 || seen[strings.ToLower(meta.ID)] {
			return nil, ErrReferenceMetadata
		}
		seen[strings.ToLower(meta.ID)] = true
		var sub []vault.Item
		subRevs := map[string]string{}
		for _, it := range items {
			if it.EffectiveVaultID() != meta.ID {
				continue
			}
			sub = append(sub, it)
			subRevs[it.ID] = revisions[it.ID]
		}
		projected, err := projectItems(meta.ID, meta.Name, sub, subRevs)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, projected)
	}
	if err := reference.Validate(catalog); err != nil {
		return nil, err
	}
	return catalog, nil
}

func projectItems(vaultID, name string, items []vault.Item, revisions map[string]string) (reference.Vault, error) {
	v := reference.Vault{ID: vaultID, Name: name, Items: make([]reference.Item, 0, len(items))}
	seen := make(map[string]bool, len(items))
	for _, it := range items {
		revision, found := revisions[it.ID]
		if !idOK(it.ID) || seen[it.ID] || !found || !digestOK(revision) {
			return reference.Vault{}, ErrReferenceMetadata
		}
		seen[it.ID] = true
		cat, ok := vault.CategoryFromKind(it.Kind, it.Category)
		if !ok {
			return reference.Vault{}, ErrReferenceMetadata
		}
		out := reference.Item{ID: it.ID, Name: it.Title, Revision: revision}
		fields, err := projectReferenceFields(it, cat)
		if err != nil {
			return reference.Vault{}, err
		}
		out.Fields = fields.ItemFields
		out.Sections = fields.Sections
		v.Items = append(v.Items, out)
	}
	return v, nil
}

type projectedFields struct {
	ItemFields []reference.Field
	Sections   []reference.Section
}

func projectReferenceFields(it vault.Item, cat vault.ItemCategory) (projectedFields, error) {
	var out projectedFields
	add := func(id, name string, typ reference.ValueType) error {
		for _, f := range out.ItemFields {
			if strings.EqualFold(f.ID, id) {
				return ErrReferenceMetadata
			}
		}
		if !selectorID(id) || len(name) > 1024 {
			return ErrReferenceMetadata
		}
		out.ItemFields = append(out.ItemFields, reference.Field{ID: id, Name: name, Type: typ})
		return nil
	}
	switch cat {
	case vault.CategoryLogin:
		// Keep exactly the legacy three fields for pure v1 logins; v2 items
		// additionally expose notes.
		if err := add("username", "username", reference.TypeText); err != nil {
			return projectedFields{}, err
		}
		if err := add("password", "password", reference.TypePassword); err != nil {
			return projectedFields{}, err
		}
		if err := add("otp", "otp", reference.TypeOTP); err != nil {
			return projectedFields{}, err
		}
	case vault.CategoryPassword, vault.CategoryDatabase, vault.CategoryServer, vault.CategoryAPICredential, vault.CategoryWirelessRouter:
		if err := add("password", "password", reference.TypePassword); err != nil {
			return projectedFields{}, err
		}
	case vault.CategoryCreditCard:
		for _, f := range []reference.Field{
			{ID: "cc-name", Name: "Cardholder Name", Type: reference.TypeText},
			{ID: "cc-type", Name: "Card Type", Type: reference.TypeText},
			{ID: "cc-number", Name: "Card Number", Type: reference.TypePassword},
			{ID: "cc-csc", Name: "CVV", Type: reference.TypePassword},
			{ID: "cc-exp", Name: "Expiry Date", Type: reference.TypeText},
			{ID: "cc-exp-month", Name: "Expiry Month", Type: reference.TypeText},
			{ID: "cc-exp-year", Name: "Expiry Year", Type: reference.TypeText},
			{ID: "cc-pin", Name: "PIN", Type: reference.TypePassword},
			{ID: "cc-bank", Name: "Issuing Bank", Type: reference.TypeText},
		} {
			if err := add(f.ID, f.Name, f.Type); err != nil {
				return projectedFields{}, err
			}
		}
	case vault.CategoryIdentity:
		for _, f := range []reference.Field{
			{ID: "honorific-prefix", Name: "Title", Type: reference.TypeText},
			{ID: "given-name", Name: "First Name", Type: reference.TypeText},
			{ID: "additional-name", Name: "Middle Name", Type: reference.TypeText},
			{ID: "family-name", Name: "Last Name", Type: reference.TypeText},
			{ID: "bday", Name: "Birth Date", Type: reference.TypeText},
			{ID: "organization", Name: "Company", Type: reference.TypeText},
			{ID: "department", Name: "Department", Type: reference.TypeText},
			{ID: "organization-title", Name: "Job Title", Type: reference.TypeText},
			{ID: "email", Name: "Email", Type: reference.TypeText},
			{ID: "tel", Name: "Phone", Type: reference.TypeText},
			{ID: "address-line1", Name: "Address Line 1", Type: reference.TypeText},
			{ID: "address-line2", Name: "Address Line 2", Type: reference.TypeText},
			{ID: "address-level2", Name: "City", Type: reference.TypeText},
			{ID: "address-level1", Name: "State", Type: reference.TypeText},
			{ID: "postal-code", Name: "Postal Code", Type: reference.TypeText},
			{ID: "country", Name: "Country", Type: reference.TypeText},
			{ID: "ssn", Name: "SSN", Type: reference.TypePassword},
			{ID: "passport-number", Name: "Passport Number", Type: reference.TypeText},
			{ID: "license-number", Name: "License Number", Type: reference.TypeText},
			{ID: "url", Name: "Website", Type: reference.TypeText},
		} {
			if err := add(f.ID, f.Name, f.Type); err != nil {
				return projectedFields{}, err
			}
		}
	}
	if vault.HasV2Extension(it) {
		if err := add("notes", "notes", reference.TypeText); err != nil {
			return projectedFields{}, err
		}
	}
	for _, sec := range it.Sections {
		if !selectorID(sec.ID) || len(sec.Title) > 1024 {
			return projectedFields{}, ErrReferenceMetadata
		}
		rs := reference.Section{ID: sec.ID, Name: sec.Title}
		for _, f := range sec.Fields {
			if !selectorID(f.ID) || len(f.Label) > 1024 {
				return projectedFields{}, ErrReferenceMetadata
			}
			typ := reference.TypeText
			switch f.Type {
			case vault.FieldTypeConcealed:
				typ = reference.TypePassword
			case vault.FieldTypeOTP, vault.FieldTypeTOTP:
				typ = reference.TypeOTP
			}
			if f.Protected && typ == reference.TypeText {
				typ = reference.TypePassword
			}
			rs.Fields = append(rs.Fields, reference.Field{ID: f.ID, Name: f.Label, Type: typ})
		}
		out.Sections = append(out.Sections, rs)
	}
	return out, nil
}
