package main

// Strict parser for `personal add-item --input` typed JSON.
//
// This phase only decodes and validates an explicit local input document into
// the native encrypted item model. The CLI wiring, owner-only file read and the
// session SAVE mutation land separately; keeping the decoder isolated means the
// bounded schema rules are unit-testable without a terminal or a vault.
//
// Rules:
//   - one JSON object, strict UTF-8, at most 1 MiB;
//   - duplicate keys are refused case-insensitively at any depth, as are
//     unknown keys (json.DisallowUnknownFields) and trailing values;
//   - raw credential / identity / provenance / history / attachment members are
//     not part of the accepted schema, so they are refused as unknown keys;
//   - every refusal returns the same fixed error that never echoes input.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
)

// errTypedInputRefused is the single fixed failure for any refused document.
// It must never wrap or embed decoded values, keys or parser diagnostics.
var errTypedInputRefused = errors.New("typed item input refused")

const (
	maxTypedInputBytes   = 1 << 20
	maxTypedJSONDepth    = 16
	maxTypedJSONNodes    = 4096
	maxTypedJSONKeys     = 128
	maxTypedJSONArray    = 128
	maxTypedTitle        = 1024
	maxTypedText         = 64 << 10
	maxTypedLabel        = 1024
	maxTypedTag          = 256
	maxTypedURL          = 2048
	maxTypedPurpose      = 64
	maxTypedURLs         = 8
	maxTypedTags         = 64
	maxTypedSections     = 64
	maxTypedSectionField = 256
)

// categoryKinds is the add-item category whitelist. SSH keys and documents need
// raw key/attachment material that this phase refuses, so they are excluded.
var categoryKinds = map[string]vault.ItemCategory{
	string(vault.CategoryLogin):           vault.CategoryLogin,
	string(vault.CategoryPassword):        vault.CategoryPassword,
	string(vault.CategorySecureNote):      vault.CategorySecureNote,
	string(vault.CategoryCreditCard):      vault.CategoryCreditCard,
	string(vault.CategoryIdentity):        vault.CategoryIdentity,
	string(vault.CategoryAPICredential):   vault.CategoryAPICredential,
	string(vault.CategoryDatabase):        vault.CategoryDatabase,
	string(vault.CategoryServer):          vault.CategoryServer,
	string(vault.CategoryBankAccount):     vault.CategoryBankAccount,
	string(vault.CategoryWirelessRouter):  vault.CategoryWirelessRouter,
	string(vault.CategorySoftwareLicense): vault.CategorySoftwareLicense,
	string(vault.CategoryMembership):      vault.CategoryMembership,
	string(vault.CategoryCryptoWallet):    vault.CategoryCryptoWallet,
	string(vault.CategoryMedicalRecord):   vault.CategoryMedicalRecord,
}

// fieldTypes is the native custom-field type whitelist. "file" is an attachment
// payload and is therefore refused in this phase.
var fieldTypes = map[vault.FieldType]bool{
	vault.FieldTypeText:      true,
	vault.FieldTypeConcealed: true,
	vault.FieldTypeURL:       true,
	vault.FieldTypeEmail:     true,
	vault.FieldTypeOTP:       true,
	vault.FieldTypeDate:      true,
	vault.FieldTypeMonthYear: true,
	vault.FieldTypePhone:     true,
	vault.FieldTypeAddress:   true,
	vault.FieldTypeReference: true,
	vault.FieldTypeMenu:      true,
	vault.FieldTypeString:    true,
	vault.FieldTypeTOTP:      true,
}

// typedPersonalURL and typedPersonalSection use the native type spellings so
// the accepted document stays a projection of vault.Item, not a second model.
type typedPersonalInput struct {
	Category   string                   `json:"category"`
	Title      string                   `json:"title"`
	Username   string                   `json:"username"`
	Password   string                   `json:"password"`
	URL        string                   `json:"url"`
	Notes      string                   `json:"notes"`
	OTP        string                   `json:"otp"`
	URLs       []vault.ItemURL          `json:"urls"`
	Tags       []string                 `json:"tags"`
	Favorite   bool                     `json:"favorite"`
	Sections   []typedPersonalSection   `json:"sections"`
	CreditCard *vault.CreditCardDetails `json:"credit_card"`
	Identity   *vault.IdentityDetails   `json:"identity"`
}

type typedPersonalSection struct {
	ID     string               `json:"id"`
	Title  string               `json:"title"`
	Fields []typedPersonalField `json:"fields"`
}

type typedPersonalField struct {
	ID        string          `json:"id"`
	Label     string          `json:"label"`
	Type      vault.FieldType `json:"type"`
	Value     string          `json:"value"`
	Protected bool            `json:"protected"`
	Purpose   string          `json:"purpose"`
}

// decodeTypedPersonalInput parses one bounded typed item document into the
// native vault item. It never assigns the item ID, state, timestamps or any raw
// material; the authenticated session owns those.
func decodeTypedPersonalInput(raw []byte) (vault.Item, error) {
	if len(raw) == 0 || len(raw) > maxTypedInputBytes || !utf8.Valid(raw) {
		return vault.Item{}, errTypedInputRefused
	}
	if !strictTypedJSON(raw) {
		return vault.Item{}, errTypedInputRefused
	}
	var input typedPersonalInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return vault.Item{}, errTypedInputRefused
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return vault.Item{}, errTypedInputRefused
	}
	return input.toVaultItem()
}

// strictTypedJSON enforces shape limits, case-insensitive duplicate-key refusal
// and a single trailing-free value without materialising the document first.
func strictTypedJSON(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	nodes := 0
	var walk func(depth int) bool
	walk = func(depth int) bool {
		nodes++
		if depth > maxTypedJSONDepth || nodes > maxTypedJSONNodes {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return false
				}
				name = strings.ToLower(name)
				if seen[name] || len(seen) >= maxTypedJSONKeys {
					return false
				}
				seen[name] = true
				if !walk(depth + 1) {
					return false
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim('}') {
				return false
			}
		case json.Delim('['):
			n := 0
			for decoder.More() {
				n++
				if n > maxTypedJSONArray || !walk(depth+1) {
					return false
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim(']') {
				return false
			}
		}
		return true
	}
	if !walk(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func (input typedPersonalInput) toVaultItem() (vault.Item, error) {
	categoryName := strings.TrimSpace(input.Category)
	if categoryName == "" {
		categoryName = string(vault.CategoryLogin)
	}
	category, ok := categoryKinds[categoryName]
	if !ok {
		return vault.Item{}, errTypedInputRefused
	}
	title := input.Title
	if !validTypedText(title, maxTypedTitle) || strings.TrimSpace(title) == "" {
		return vault.Item{}, errTypedInputRefused
	}
	for _, value := range []string{input.Username, input.Password, input.OTP, input.Notes} {
		if !validTypedText(value, maxTypedText) {
			return vault.Item{}, errTypedInputRefused
		}
	}
	item := vault.Item{
		Kind:     string(category),
		Category: category,
		VaultID:  vault.DefaultVaultID,
		Title:    title,
		Username: input.Username,
		Password: input.Password,
		OTP:      input.OTP,
		Notes:    input.Notes,
		Favorite: input.Favorite,
	}
	if input.URL != "" {
		if !validTypedURL(input.URL) {
			return vault.Item{}, errTypedInputRefused
		}
		item.URL = input.URL
	}
	if len(input.URLs) > maxTypedURLs {
		return vault.Item{}, errTypedInputRefused
	}
	primarySeen := false
	seenURL := map[string]bool{}
	for _, u := range input.URLs {
		if !validTypedURL(u.URL) || !validTypedText(u.Label, maxTypedLabel) {
			return vault.Item{}, errTypedInputRefused
		}
		switch u.MatchMode {
		case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
		default:
			return vault.Item{}, errTypedInputRefused
		}
		key := strings.ToLower(u.URL)
		if seenURL[key] {
			return vault.Item{}, errTypedInputRefused
		}
		seenURL[key] = true
		if u.Primary {
			// The legacy top-level url is already the implicit primary, so a
			// duplicate entry may only mark that same URL primary.
			if primarySeen || item.URL != "" && u.URL != item.URL {
				return vault.Item{}, errTypedInputRefused
			}
			primarySeen = true
		}
		item.URLs = append(item.URLs, vault.ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	if len(input.Tags) > maxTypedTags {
		return vault.Item{}, errTypedInputRefused
	}
	seenTag := map[string]bool{}
	for _, tag := range input.Tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !validTypedText(tag, maxTypedTag) {
			return vault.Item{}, errTypedInputRefused
		}
		key := strings.ToLower(tag)
		if seenTag[key] {
			continue
		}
		seenTag[key] = true
		item.Tags = append(item.Tags, tag)
	}
	if len(input.Sections) > maxTypedSections {
		return vault.Item{}, errTypedInputRefused
	}
	seenSection := map[string]bool{}
	seenField := map[string]bool{}
	for _, section := range input.Sections {
		if !validTypedSelector(section.ID) || !validTypedText(section.Title, maxTypedLabel) {
			return vault.Item{}, errTypedInputRefused
		}
		key := strings.ToLower(section.ID)
		if seenSection[key] {
			return vault.Item{}, errTypedInputRefused
		}
		seenSection[key] = true
		if len(section.Fields) > maxTypedSectionField {
			return vault.Item{}, errTypedInputRefused
		}
		converted := vault.ItemSection{ID: section.ID, Title: section.Title}
		for _, field := range section.Fields {
			if !validTypedSelector(field.ID) || !validTypedText(field.Label, maxTypedLabel) || !validTypedText(field.Purpose, maxTypedPurpose) || !validTypedText(field.Value, maxTypedText) {
				return vault.Item{}, errTypedInputRefused
			}
			fieldKey := strings.ToLower(field.ID)
			if seenField[fieldKey] {
				return vault.Item{}, errTypedInputRefused
			}
			seenField[fieldKey] = true
			typ := field.Type
			if typ == "" {
				typ = vault.FieldTypeText
			}
			if !fieldTypes[typ] {
				return vault.Item{}, errTypedInputRefused
			}
			protected := field.Protected || typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP
			converted.Fields = append(converted.Fields, vault.CustomField{ID: field.ID, Label: field.Label, Type: typ, Value: field.Value, Protected: protected, Purpose: field.Purpose})
		}
		item.Sections = append(item.Sections, converted)
	}
	if input.CreditCard != nil {
		if category != vault.CategoryCreditCard || !validTypedCreditCard(input.CreditCard) {
			return vault.Item{}, errTypedInputRefused
		}
		card := *input.CreditCard
		item.CreditCard = &card
	}
	if input.Identity != nil {
		if category != vault.CategoryIdentity || !validTypedIdentity(input.Identity) {
			return vault.Item{}, errTypedInputRefused
		}
		identity := *input.Identity
		item.Identity = &identity
	}
	return item, nil
}

func validTypedCreditCard(card *vault.CreditCardDetails) bool {
	for _, value := range []string{card.CardholderName, card.Type, card.Number, card.Verification, card.ExpiryDate, card.ValidFrom, card.PIN, card.IssuingBank} {
		if !validTypedText(value, maxTypedTitle) {
			return false
		}
	}
	return true
}

func validTypedIdentity(identity *vault.IdentityDetails) bool {
	for _, value := range []string{identity.Title, identity.FirstName, identity.MiddleName, identity.LastName, identity.BirthDate, identity.Company, identity.Department, identity.JobTitle, identity.Email, identity.Phone, identity.AddressLine1, identity.AddressLine2, identity.City, identity.State, identity.PostalCode, identity.Country, identity.SSN, identity.PassportNumber, identity.LicenseNumber, identity.Website} {
		if !validTypedText(value, maxTypedTitle) {
			return false
		}
	}
	return true
}

func validTypedURL(value string) bool {
	if len(value) == 0 || len(value) > maxTypedURL {
		return false
	}
	_, err := origin.Website(value)
	return err == nil
}

// validTypedText mirrors the native XML-safe plain-text bound without trimming
// or normalising the value.
func validTypedText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// validTypedSelector mirrors the native selector-safe identifier shape used by
// sections and custom fields.
func validTypedSelector(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, c := range []byte(value) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}
