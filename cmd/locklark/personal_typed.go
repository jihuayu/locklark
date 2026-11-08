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
//   - duplicate keys are refused ASCII-case-insensitively at any depth, as are
//     unknown keys (json.DisallowUnknownFields) and trailing values; object keys
//     must be ASCII because Go binds struct fields with Unicode simple folding,
//     while Unicode in values stays allowed untrimmed and unnormalised;
//   - \uD800..\uDFFF escapes must form a valid high/low pair, so a decoded value
//     is never silently rewritten to U+FFFD (literal non-BMP runes stay fine);
//   - raw credential / identity / provenance / history / attachment members are
//     not part of the accepted schema, so they are refused as unknown keys;
//   - every refusal returns the same fixed error that never echoes input.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
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

	// Attachments are named by an explicit path, a safe basename and a bounded
	// MIME type. The count matches the native 16-attachment item limit; the
	// per-file byte bound is enforced by the private binary reader.
	maxTypedAttachments    = 16
	maxTypedAttachmentPath = 4096
	maxTypedAttachmentName = 255
	maxTypedAttachmentMIME = 256
)

// categoryKinds is the add-item category whitelist. SSH keys need raw private
// key material that this command refuses. Documents are accepted only when at
// least one explicit private attachment file is requested, because the native
// document payload is the attachment itself.
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
	string(vault.CategoryDocument):        vault.CategoryDocument,
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
	// Attachments name explicit private files. A raw/base64 body, an
	// attachment ID, a size/digest or provenance material is not part of the
	// accepted schema and is refused as an unknown key.
	Attachments []typedPersonalAttachment `json:"attachments"`
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

// typedPersonalAttachment is one explicit private-file request.
type typedPersonalAttachment struct {
	File     string `json:"file"`
	FileName string `json:"file_name"`
	MIMEType string `json:"mime_type"`
}

// typedAttachmentRequest is the unresolved half of an attachment: the decoder
// reports it separately so the item-only decode wrapper cannot return an item
// whose attachment request was silently forgotten before file resolution.
type typedAttachmentRequest struct {
	file     string
	fileName string
	mimeType string
}

// decodeTypedPersonalInput parses one bounded typed item document into the
// native vault item. It never assigns the item ID, state, timestamps or any raw
// material; the authenticated session owns those.
//
// This item-only wrapper has no file resolver, so it refuses a document that
// still requests explicit attachment files instead of returning an item whose
// attachments were silently dropped. Callers that resolve files must use
// decodeTypedPersonalDocument.
func decodeTypedPersonalInput(raw []byte) (vault.Item, error) {
	item, requests, err := decodeTypedPersonalDocument(raw)
	if err != nil {
		return vault.Item{}, err
	}
	if len(requests) != 0 {
		return vault.Item{}, errTypedInputRefused
	}
	return item, nil
}

// decodeTypedPersonalDocument parses one bounded typed item document and
// returns the native item plus every unresolved explicit attachment file
// request in document order. item.Attachments carries only the requested
// metadata (never content); the creator must resolve each request from a
// private regular file before SAVE.
func decodeTypedPersonalDocument(raw []byte) (vault.Item, []typedAttachmentRequest, error) {
	if len(raw) == 0 || len(raw) > maxTypedInputBytes || !utf8.Valid(raw) {
		return vault.Item{}, nil, errTypedInputRefused
	}
	// encoding/json silently rewrites an unpaired surrogate escape to U+FFFD, so
	// the raw escapes are rejected before anything is decoded.
	if !strictTypedUnicode(raw) || !strictTypedJSON(raw) {
		return vault.Item{}, nil, errTypedInputRefused
	}
	var input typedPersonalInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return vault.Item{}, nil, errTypedInputRefused
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return vault.Item{}, nil, errTypedInputRefused
	}
	return input.toVaultItem()
}

// strictTypedJSON enforces shape limits, ASCII-only keys, ASCII-case-insensitive
// duplicate-key refusal and a single trailing-free value without materialising
// the document first.
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
				if err != nil || !ok || !typedASCIIJSONKey(name) {
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

// typedASCIIJSONKey reports whether an object key is pure ASCII. Go's decoder
// binds struct fields with Unicode simple folding, so a key like "tag\u017f"
// reaches Tags exactly as "tags" does, while the duplicate walk here only
// lowercases. A non-ASCII key could therefore bind one field twice and let the
// later value win unseen. Every member of the accepted schema is ASCII, so
// non-ASCII keys are refused instead; only keys are affected, not values.
func typedASCIIJSONKey(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// strictTypedUnicode rejects JSON strings whose \u escapes encode an unpaired
// surrogate, which encoding/json replaces with U+FFFD instead of failing. The
// scan works on the raw bytes and skips escaped backslashes and quotes, so only
// real escapes are inspected: a high surrogate must be followed immediately by
// a low surrogate. Valid pairs, literal non-BMP runes and literal U+FFFD values
// pass through untouched and stay lossless.
func strictTypedUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for n := 0; n < len(raw); n++ {
		if raw[n] != '"' {
			continue
		}
		n++
		for ; n < len(raw) && raw[n] != '"'; n++ {
			if raw[n] != '\\' {
				continue
			}
			n++
			if n >= len(raw) {
				return false
			}
			if raw[n] != 'u' {
				continue
			}
			if n+4 >= len(raw) {
				return false
			}
			v, err := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
			if err != nil {
				return false
			}
			n += 4
			if v >= 0xdc00 && v <= 0xdfff {
				return false
			}
			if v >= 0xd800 && v <= 0xdbff {
				if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
					return false
				}
				w, err := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
				if err != nil || w < 0xdc00 || w > 0xdfff {
					return false
				}
				n += 6
			}
		}
	}
	return true
}

func (input typedPersonalInput) toVaultItem() (vault.Item, []typedAttachmentRequest, error) {
	categoryName := strings.TrimSpace(input.Category)
	if categoryName == "" {
		categoryName = string(vault.CategoryLogin)
	}
	category, ok := categoryKinds[categoryName]
	if !ok {
		return vault.Item{}, nil, errTypedInputRefused
	}
	if category == vault.CategoryDocument {
		// A v2 document carries its payload in attachments and has no legacy
		// Filename/Attachment bytes. The native document encoding has no slot
		// for these scalar fields, so accepting them would silently drop
		// them; attachments and the v2 envelope keep the rest.
		if input.Username != "" || input.Password != "" || input.OTP != "" || input.Notes != "" || input.URL != "" {
			return vault.Item{}, nil, errTypedInputRefused
		}
	}
	title := input.Title
	if !validTypedText(title, maxTypedTitle) || strings.TrimSpace(title) == "" {
		return vault.Item{}, nil, errTypedInputRefused
	}
	for _, value := range []string{input.Username, input.Password, input.OTP, input.Notes} {
		if !validTypedText(value, maxTypedText) {
			return vault.Item{}, nil, errTypedInputRefused
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
			return vault.Item{}, nil, errTypedInputRefused
		}
		item.URL = input.URL
	}
	if len(input.URLs) > maxTypedURLs {
		return vault.Item{}, nil, errTypedInputRefused
	}
	primarySeen := false
	seenURL := map[string]bool{}
	for _, u := range input.URLs {
		if !validTypedURL(u.URL) || !validTypedText(u.Label, maxTypedLabel) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		switch u.MatchMode {
		case "", vault.URLMatchOrigin, vault.URLMatchHost, vault.URLMatchDomain, vault.URLMatchExact, vault.URLMatchNever:
		default:
			return vault.Item{}, nil, errTypedInputRefused
		}
		key := strings.ToLower(u.URL)
		if seenURL[key] {
			return vault.Item{}, nil, errTypedInputRefused
		}
		seenURL[key] = true
		if u.Primary {
			// The legacy top-level url is already the implicit primary, so a
			// duplicate entry may only mark that same URL primary.
			if primarySeen || item.URL != "" && u.URL != item.URL {
				return vault.Item{}, nil, errTypedInputRefused
			}
			primarySeen = true
		}
		item.URLs = append(item.URLs, vault.ItemURL{Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode})
	}
	if len(input.Tags) > maxTypedTags {
		return vault.Item{}, nil, errTypedInputRefused
	}
	seenTag := map[string]bool{}
	for _, tag := range input.Tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !validTypedText(tag, maxTypedTag) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		key := strings.ToLower(tag)
		if seenTag[key] {
			continue
		}
		seenTag[key] = true
		item.Tags = append(item.Tags, tag)
	}
	if len(input.Sections) > maxTypedSections {
		return vault.Item{}, nil, errTypedInputRefused
	}
	seenSection := map[string]bool{}
	seenField := map[string]bool{}
	for _, section := range input.Sections {
		if !validTypedSelector(section.ID) || !validTypedText(section.Title, maxTypedLabel) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		key := strings.ToLower(section.ID)
		if seenSection[key] {
			return vault.Item{}, nil, errTypedInputRefused
		}
		seenSection[key] = true
		if len(section.Fields) > maxTypedSectionField {
			return vault.Item{}, nil, errTypedInputRefused
		}
		converted := vault.ItemSection{ID: section.ID, Title: section.Title}
		for _, field := range section.Fields {
			if !validTypedSelector(field.ID) || !validTypedText(field.Label, maxTypedLabel) || !validTypedText(field.Purpose, maxTypedPurpose) || !validTypedText(field.Value, maxTypedText) {
				return vault.Item{}, nil, errTypedInputRefused
			}
			fieldKey := strings.ToLower(field.ID)
			if seenField[fieldKey] {
				return vault.Item{}, nil, errTypedInputRefused
			}
			seenField[fieldKey] = true
			typ := field.Type
			if typ == "" {
				typ = vault.FieldTypeText
			}
			if !fieldTypes[typ] {
				return vault.Item{}, nil, errTypedInputRefused
			}
			protected := field.Protected || typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP
			converted.Fields = append(converted.Fields, vault.CustomField{ID: field.ID, Label: field.Label, Type: typ, Value: field.Value, Protected: protected, Purpose: field.Purpose})
		}
		item.Sections = append(item.Sections, converted)
	}
	if input.CreditCard != nil {
		if category != vault.CategoryCreditCard || !validTypedCreditCard(input.CreditCard) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		card := *input.CreditCard
		item.CreditCard = &card
	}
	if input.Identity != nil {
		if category != vault.CategoryIdentity || !validTypedIdentity(input.Identity) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		identity := *input.Identity
		item.Identity = &identity
	}
	if len(input.Attachments) > maxTypedAttachments {
		return vault.Item{}, nil, errTypedInputRefused
	}
	requests := make([]typedAttachmentRequest, 0, len(input.Attachments))
	for _, attachment := range input.Attachments {
		if !validTypedAttachmentPath(attachment.File) || !validTypedAttachmentName(attachment.FileName) || !validTypedAttachmentMIME(attachment.MIMEType) {
			return vault.Item{}, nil, errTypedInputRefused
		}
		requests = append(requests, typedAttachmentRequest{file: attachment.File, fileName: attachment.FileName, mimeType: attachment.MIMEType})
		// Content stays an owned empty slice until the creator resolves the
		// request; Size/SHA/ID remain for native normalization to derive.
		item.Attachments = append(item.Attachments, vault.AttachmentMeta{FileName: attachment.FileName, MIMEType: attachment.MIMEType, Content: []byte{}})
	}
	if category == vault.CategoryDocument && len(requests) == 0 {
		return vault.Item{}, nil, errTypedInputRefused
	}
	return item, requests, nil
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

// validTypedAttachmentPath accepts only an explicit absolute path. Relative
// paths are refused so no implicit working-directory file is ever read, and
// control characters (including NUL) are refused so the descriptor is opened
// on exactly the path that was validated. The bound covers the largest common
// POSIX path; longer Windows paths stay refused rather than guessed at.
func validTypedAttachmentPath(path string) bool {
	if path == "" || len(path) > maxTypedAttachmentPath || !utf8.ValidString(path) || !filepath.IsAbs(path) {
		return false
	}
	for _, r := range path {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// validTypedAttachmentName keeps the stored name a safe basename: no path
// separator, no dot entries, no control characters and the native 255-byte
// bound.
func validTypedAttachmentName(name string) bool {
	if name == "" || len(name) > maxTypedAttachmentName || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// validTypedAttachmentMIME bounds the native MIME slot and refuses control
// characters; final native item validation remains authoritative for storage.
func validTypedAttachmentMIME(value string) bool {
	if len(value) > maxTypedAttachmentMIME || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
