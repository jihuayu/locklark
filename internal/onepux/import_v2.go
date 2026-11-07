package onepux

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

// FullProfileV2 is the profile tag for the full 1PUX v3 category mapping.
const FullProfileV2 = "1pux-full-v2"

const importItemDomain = "locklark/import/1pux/item/v2\x00"
const importAttachmentDomain = "locklark/import/1pux/attachment/v2\x00"

var categoryV2 = map[string]vault.ItemCategory{
	"001": vault.CategoryLogin,
	"002": vault.CategoryCreditCard,
	"003": vault.CategorySecureNote,
	"004": vault.CategoryIdentity,
	"005": vault.CategoryPassword,
	"100": vault.CategorySoftwareLicense,
	"101": vault.CategoryBankAccount,
	"102": vault.CategoryDatabase,
	"103": vault.CategoryIdentity,
	"104": vault.CategoryIdentity,
	"105": vault.CategoryMembership,
	"106": vault.CategoryIdentity,
	"107": vault.CategoryMembership,
	"108": vault.CategoryIdentity,
	"109": vault.CategoryWirelessRouter,
	"110": vault.CategoryServer,
	"111": vault.CategoryLogin,
	"112": vault.CategoryAPICredential,
	"113": vault.CategoryMedicalRecord,
	"114": vault.CategoryDocument,
	"115": vault.CategorySSHKey,
}

// MapArchiveV2 maps every supported 1PUX v3 category into the Item Model v2.
// MapLogins remains the narrow, byte-stable login profile.
func MapArchiveV2(raw []byte) (MappedLogins, error) {
	inventory, err := Inspect(raw)
	if err != nil {
		return MappedLogins{}, err
	}
	if inventory.Items == 0 {
		return MappedLogins{}, ErrUnsupported
	}
	if inventory.Items > 256 {
		return MappedLogins{}, ErrLimit
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return MappedLogins{}, ErrInvalid
	}
	files := map[string][]byte{}
	var root, attrs map[string]any
	for _, f := range z.File {
		if f.Mode().IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name, "files/") {
			data, _, e := readEntry(f, MaxEntry, true)
			if e != nil {
				return MappedLogins{}, e
			}
			files[f.Name] = data
			continue
		}
		if f.Name != "export.data" && f.Name != "export.attributes" {
			continue
		}
		data, _, e := readEntry(f, MaxJSON, true)
		if e != nil {
			return MappedLogins{}, e
		}
		object, e := decodeObject(data)
		clear(data)
		if e != nil {
			return MappedLogins{}, e
		}
		if f.Name == "export.data" {
			root = object
		} else {
			attrs = object
		}
	}
	if root == nil || attrs == nil || extra(root, "accounts") || extra(attrs, "version", "description", "createdAt") {
		return MappedLogins{}, ErrUnsupported
	}
	out := MappedLogins{Report: MappingReport{Profile: FullProfileV2, Items: inventory.Items}, Items: make([]vault.Item, 0, inventory.Items)}
	for _, a := range root["accounts"].([]any) {
		account := a.(map[string]any)
		accountAttrs := account["attrs"].(map[string]any)
		if extra(account, "attrs", "vaults") || extra(accountAttrs, "uuid", "accountName", "name", "avatar", "email", "domain") {
			return MappedLogins{}, ErrUnsupported
		}
		for _, v := range account["vaults"].([]any) {
			sourceVault := v.(map[string]any)
			vaultAttrs := sourceVault["attrs"].(map[string]any)
			if extra(sourceVault, "attrs", "items") || extra(vaultAttrs, "uuid", "desc", "avatar", "name", "type") {
				return MappedLogins{}, ErrUnsupported
			}
			for _, i := range sourceVault["items"].([]any) {
				source := i.(map[string]any)
				item, e := mapArchiveItem(source, files)
				if e != nil {
					return MappedLogins{}, e
				}
				identity, _ := json.Marshal([]any{accountAttrs["uuid"], vaultAttrs["uuid"], source["uuid"]})
				h := sha256.Sum256(append([]byte(importItemDomain), identity...))
				item.ID = hex.EncodeToString(h[:16])
				for n := range item.Attachments {
					item.Attachments[n].ID = attachmentID(item.ID, item.Attachments[n].FileName, item.Attachments[n].Content)
				}
				item.ImportSource, e = json.Marshal(map[string]any{"format": "locklark/1pux-source/v1", "attributes": attrs, "account": accountAttrs, "vault": vaultAttrs, "item": source})
				if e != nil {
					return MappedLogins{}, ErrInvalid
				}
				if vault.ValidateItems(nil, []vault.Item{item}) != nil {
					return MappedLogins{}, ErrLimit
				}
				if item.State == "archived" {
					out.Report.Archived++
				}
				out.Items = append(out.Items, item)
			}
		}
	}
	if vault.ValidateItems(nil, out.Items) != nil {
		return MappedLogins{}, ErrLimit
	}
	return out, nil
}

func mapArchiveItem(source map[string]any, files map[string][]byte) (vault.Item, error) {
	var err error
	reject := func() (vault.Item, error) { return vault.Item{}, ErrUnsupported }
	code, ok := source["categoryUuid"].(string)
	if !ok {
		return reject()
	}
	cat, ok := categoryV2[code]
	if !ok || extra(source, "uuid", "categoryUuid", "state", "favIndex", "createdAt", "updatedAt", "overview", "details", "file") {
		return reject()
	}
	state, _ := source["state"].(string)
	item := vault.Item{Kind: string(cat), Category: cat}
	switch state {
	case "active":
	case "archived":
		item.State = "archived"
	case "trashed":
		item.State = "trashed"
	default:
		return reject()
	}
	if raw, found := source["favIndex"]; found {
		n, ok := raw.(json.Number)
		if !ok {
			return reject()
		}
		v, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return reject()
		}
		item.Favorite = v > 0
	}
	for key, dst := range map[string]*int64{"createdAt": &item.CreatedAt, "updatedAt": &item.UpdatedAt} {
		if raw, found := source[key]; found {
			n, ok := raw.(json.Number)
			if !ok {
				return reject()
			}
			v, err := strconv.ParseInt(string(n), 10, 64)
			if err != nil || v < 0 {
				return reject()
			}
			*dst = v
		}
	}
	overview, ok := source["overview"].(map[string]any)
	if !ok || extra(overview, "title", "subtitle", "url", "urls", "tags") {
		return reject()
	}
	title, ok := overview["title"].(string)
	if !ok || strings.TrimSpace(title) == "" || len(title) > 1024 || !validSourceText(title) {
		return reject()
	}
	item.Title = title
	if raw, found := overview["url"]; found {
		u, ok := raw.(string)
		if !ok || u != "" && !validItemURL(u) {
			return reject()
		}
		item.URL = u
	}
	if raw, found := overview["urls"]; found {
		list, ok := raw.([]any)
		if !ok || len(list) > 64 {
			return reject()
		}
		seenURLs := map[string]bool{}
		for _, value := range list {
			u, ok := value.(map[string]any)
			if !ok || extra(u, "url", "label") {
				return reject()
			}
			url, ok := u["url"].(string)
			if !ok || !validItemURL(url) || seenURLs[url] {
				return reject()
			}
			seenURLs[url] = true
			label := ""
			if rawLabel, found := u["label"]; found {
				label, ok = rawLabel.(string)
				if !ok || len(label) > 256 || !validSourceText(label) {
					return reject()
				}
			}
			item.URLs = append(item.URLs, vault.ItemURL{Label: label, URL: url, Primary: item.URL != "" && url == item.URL})
		}
	}
	if item.URL == "" && len(item.URLs) > 0 {
		item.URL = item.URLs[0].URL
		item.URLs[0].Primary = true
	}
	if raw, found := overview["tags"]; found {
		list, ok := raw.([]any)
		if !ok || len(list) > 64 {
			return reject()
		}
		seen := map[string]bool{}
		for _, value := range list {
			tag, ok := value.(string)
			if !ok || strings.TrimSpace(tag) == "" || len(tag) > 256 || !validSourceText(tag) || seen[strings.ToLower(tag)] {
				return reject()
			}
			seen[strings.ToLower(tag)] = true
			item.Tags = append(item.Tags, tag)
		}
	}
	details, ok := source["details"].(map[string]any)
	if !ok || extra(details, "loginFields", "notesPlain", "sections", "passwordHistory", "documentAttributes") {
		return reject()
	}
	if raw, found := details["notesPlain"]; found {
		notes, ok := raw.(string)
		if !ok || !vault.ValidNotes(notes) {
			return reject()
		}
		item.Notes = notes
	}
	usedSections := map[string]bool{}
	usedFields := map[string]bool{}
	if raw, found := details["loginFields"]; found {
		fields, ok := raw.([]any)
		if !ok {
			return reject()
		}
		if err := mapLoginFields(&item, fields, usedSections, usedFields); err != nil {
			return vault.Item{}, err
		}
	}
	var identityFields map[string]string
	if raw, found := details["sections"]; found {
		sections, ok := raw.([]any)
		if !ok || len(sections) > 64 {
			return reject()
		}
		for n, value := range sections {
			section, ok := value.(map[string]any)
			if !ok || extra(section, "name", "title", "fields") {
				return reject()
			}
			name, _ := section["name"].(string)
			title, _ := section["title"].(string)
			if !validSourceText(name) || !validSourceText(title) || len(title) > 1024 {
				return reject()
			}
			id := ""
			if selector(name) {
				id = name
			}
			if id == "" {
				id = "section-" + strconv.Itoa(n+1)
			}
			id = uniqueID(id, "section", usedSections)
			out := vault.ItemSection{ID: id, Title: title}
			if out.Title == "" {
				out.Title = name
			}
			if out.Title == "" {
				out.Title = "Section " + strconv.Itoa(n+1)
			}
			rawFields, ok := section["fields"].([]any)
			if !ok {
				return reject()
			}
			for m, rawField := range rawFields {
				field, ok := rawField.(map[string]any)
				if !ok || extra(field, "id", "title", "value") {
					return reject()
				}
				fieldID, _ := field["id"].(string)
				label, _ := field["title"].(string)
				if !validSourceText(fieldID) || !validSourceText(label) || len(label) > 1024 {
					return reject()
				}
				parsed, err := parseTypedField(field["value"])
				if err != nil {
					return vault.Item{}, err
				}
				if parsed.sshSeed != nil {
					if len(item.SSHSeed) > 0 && !bytes.Equal(item.SSHSeed, parsed.sshSeed) {
						return reject()
					}
					item.SSHSeed = parsed.sshSeed
					item.SSHPublicKey = parsed.sshPublic
					continue
				}
				if parsed.totp != "" && item.OTP == "" {
					item.OTP = parsed.totp
				}
				if parsed.purpose == "" {
					parsed.purpose = purposeForCategoryField(item.Category, fieldID)
				}
				if fieldID == "" {
					fieldID = "field-" + strconv.Itoa(m+1)
				}
				fieldID = uniqueID(fieldID, "field", usedFields)
				cf := vault.CustomField{ID: fieldID, Label: label, Type: parsed.typ, Value: parsed.value, Protected: parsed.protected, Purpose: parsed.purpose}
				if cf.Label == "" {
					cf.Label = fieldID
				}
				out.Fields = append(out.Fields, cf)
				if identityFields == nil {
					identityFields = map[string]string{}
				}
				if parsed.purpose != "" {
					if _, exists := identityFields[parsed.purpose]; !exists {
						identityFields[parsed.purpose] = parsed.value
					}
				}
				for key, value := range parsed.identity {
					if _, exists := identityFields[key]; !exists {
						identityFields[key] = value
					}
				}
			}
			item.Sections = append(item.Sections, out)
		}
	}
	if raw, found := details["passwordHistory"]; found {
		entries, ok := raw.([]any)
		if !ok {
			return reject()
		}
		if len(entries) > 100 {
			return vault.Item{}, ErrLimit
		}
		for _, value := range entries {
			entry, ok := value.(map[string]any)
			if !ok || extra(entry, "value", "time") {
				return reject()
			}
			old, ok := entry["value"].(string)
			if !ok || !utf8.ValidString(old) {
				return reject()
			}
			var stamp int64
			if rawTime, found := entry["time"]; found {
				n, ok := rawTime.(json.Number)
				if !ok {
					return reject()
				}
				stamp, err = strconv.ParseInt(string(n), 10, 64)
				if err != nil || stamp < 0 {
					return reject()
				}
			}
			item.History = append(item.History, vault.ItemHistoryEntry{Timestamp: stamp, Action: "import-1pux", Password: old})
		}
	}
	if item.Category == vault.CategoryCreditCard {
		item.CreditCard = creditCardFromFields(item.Sections)
	}
	if item.Category == vault.CategoryIdentity {
		item.Identity = identityFromFields(identityFields)
	}
	// Attachments: the 1PUX documentAttributes record links the item to a
	// CRC/length-checked entry under files/.
	fileName, attachmentPath, expectedSize := "", "", int64(-1)
	if raw, found := details["documentAttributes"]; found {
		doc, ok := raw.(map[string]any)
		if !ok || extra(doc, "documentId", "fileName", "decryptedSize") {
			return reject()
		}
		fileName, _ = doc["fileName"].(string)
		if rawSize, found := doc["decryptedSize"]; found {
			n, ok := rawSize.(json.Number)
			if !ok {
				return reject()
			}
			expectedSize, err = strconv.ParseInt(string(n), 10, 64)
			if err != nil || expectedSize < 0 {
				return reject()
			}
		}
	}
	if raw, found := source["file"]; found {
		file, ok := raw.(map[string]any)
		if !ok || extra(file, "path", "attrs") {
			return reject()
		}
		if rawAttrs, found := file["attrs"]; found {
			attrs, ok := rawAttrs.(map[string]any)
			if !ok || len(attrs) > 0 {
				if !ok {
					return reject()
				}
			}
		}
		if rawPath, found := file["path"]; found {
			attachmentPath, _ = rawPath.(string)
		}
	}
	if fileName != "" || attachmentPath != "" || item.Category == vault.CategoryDocument || expectedSize >= 0 {
		if attachmentPath == "" && fileName != "" {
			attachmentPath = "files/" + fileName
		}
		if !strings.HasPrefix(attachmentPath, "files/") {
			return reject()
		}
		content, found := files[attachmentPath]
		if !found {
			return reject()
		}
		if expectedSize >= 0 && int64(len(content)) != expectedSize {
			return reject()
		}
		if len(content) > vault.MaxAttachmentSize {
			return vault.Item{}, ErrLimit
		}
		name := fileName
		if name == "" {
			name = strings.TrimPrefix(path.Base(attachmentPath), "files/")
		}
		if !validAttachmentName(name) {
			return reject()
		}
		att := vault.AttachmentMeta{ID: attachmentID(item.ID, name, content), FileName: name, Size: int64(len(content)), MIMEType: mimeFor(name), SHA256: vault.AttachmentSHA256(content), Content: content}
		item.Attachments = append(item.Attachments, att)
		if item.Category == vault.CategoryDocument {
			item.Filename = name
			item.Attachment = content
		}
	}
	if !vault.ValidNotes(item.Notes) {
		return reject()
	}
	return item, nil
}

func mapLoginFields(item *vault.Item, fields []any, usedSections, usedFields map[string]bool) error {
	seenDesignation := map[string]bool{}
	var custom []vault.CustomField
	for _, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok || extra(field, "id", "name", "designation", "type", "fieldType", "value") {
			return ErrUnsupported
		}
		name, _ := field["name"].(string)
		if !validSourceText(name) || len(name) > 1024 {
			return ErrUnsupported
		}
		designation, _ := field["designation"].(string)
		value := ""
		typ := vault.FieldTypeText
		protected := false
		if rawValue, found := field["value"]; found {
			if s, ok := rawValue.(string); ok {
				value = s
				if !utf8.ValidString(value) {
					return ErrUnsupported
				}
			} else {
				parsed, err := parseTypedField(rawValue)
				if err != nil {
					return err
				}
				value, typ, protected = parsed.value, parsed.typ, parsed.protected
			}
		}
		if designation == "username" || designation == "password" {
			if seenDesignation[designation] {
				return ErrUnsupported
			}
			seenDesignation[designation] = true
			if designation == "username" {
				item.Username = value
			} else {
				item.Password = value
			}
			continue
		}
		switch strings.ToLower(designation) {
		case "otp", "totp", "one-time password", "one-time-password":
			if item.OTP == "" && value != "" {
				item.OTP = value
				continue
			}
		}
		id, _ := field["id"].(string)
		if id == "" {
			id = "login-field-" + strconv.Itoa(len(custom)+1)
		}
		id = uniqueID(id, "field", usedFields)
		label := name
		if label == "" {
			label = designation
		}
		if label == "" {
			label = id
		}
		custom = append(custom, vault.CustomField{ID: id, Label: label, Type: typ, Value: value, Protected: protected})
	}
	if len(custom) > 0 {
		item.Sections = append(item.Sections, vault.ItemSection{ID: uniqueID("login_fields", "section", usedSections), Title: "Login Fields", Fields: custom})
	}
	return nil
}

type parsedTypedField struct {
	typ       vault.FieldType
	value     string
	protected bool
	purpose   string
	sshSeed   []byte
	sshPublic []byte
	totp      string
	identity  map[string]string
}

func parseTypedField(raw any) (parsedTypedField, error) {
	out := parsedTypedField{typ: vault.FieldTypeText}
	if raw == nil {
		return out, nil
	}
	if s, ok := raw.(string); ok {
		if !utf8.ValidString(s) {
			return out, ErrUnsupported
		}
		out.value = s
		return out, nil
	}
	object, ok := raw.(map[string]any)
	if !ok || len(object) != 1 {
		return out, ErrUnsupported
	}
	for key, value := range object {
		switch key {
		case "string":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ = s, vault.FieldTypeText
		case "concealed":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ, out.protected = s, vault.FieldTypeConcealed, true
		case "totp":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ, out.protected, out.totp = s, vault.FieldTypeOTP, true, s
		case "url":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ = s, vault.FieldTypeURL
		case "email":
			s, err := typedString(value)
			if err != nil {
				return out, err
			}
			out.value, out.typ, out.purpose = s, vault.FieldTypeEmail, "email"
		case "date":
			s, err := typedDate(value)
			if err != nil {
				return out, err
			}
			out.value, out.typ = s, vault.FieldTypeDate
		case "monthYear":
			s, err := typedMonthYear(value)
			if err != nil {
				return out, err
			}
			out.value, out.typ = s, vault.FieldTypeMonthYear
		case "phone":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ, out.purpose = s, vault.FieldTypePhone, "tel"
		case "address":
			parts, ok := value.(map[string]any)
			if !ok || extra(parts, "street", "city", "state", "zip", "country", "zipCode") {
				return out, ErrUnsupported
			}
			var pieces []string
			identity := map[string]string{}
			for _, k := range []string{"street", "city", "state", "zip", "zipCode", "country"} {
				rawPart, found := parts[k]
				if !found {
					continue
				}
				part, ok := rawPart.(string)
				if !ok || !validSourceText(part) {
					return out, ErrUnsupported
				}
				if strings.TrimSpace(part) != "" {
					pieces = append(pieces, part)
				}
				switch k {
				case "street":
					identity["address-line1"] = part
				case "city":
					identity["address-level2"] = part
				case "state":
					identity["address-level1"] = part
				case "zip", "zipCode":
					identity["postal-code"] = part
				case "country":
					identity["country"] = part
				}
			}
			out.value, out.typ, out.identity = strings.Join(pieces, ", "), vault.FieldTypeAddress, identity
		case "reference":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ = s, vault.FieldTypeReference
		case "menu":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ = s, vault.FieldTypeMenu
		case "creditCardNumber":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ, out.purpose = s, vault.FieldTypeText, "cc-number"
		case "creditCardType":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			out.value, out.typ, out.purpose = s, vault.FieldTypeMenu, "cc-type"
		case "sshKey":
			s, ok := value.(string)
			if !ok {
				return out, ErrUnsupported
			}
			seed, public, parsedOK := parseEd25519PrivateKey(s)
			if parsedOK {
				out.sshSeed, out.sshPublic = seed, public
				break
			}
			out.value, out.typ, out.protected = s, vault.FieldTypeConcealed, true
		default:
			return out, ErrUnsupported
		}
	}
	if !utf8.ValidString(out.value) {
		return out, ErrUnsupported
	}
	return out, nil
}

func typedString(value any) (string, error) {
	if s, ok := value.(string); ok {
		return s, nil
	}
	object, ok := value.(map[string]any)
	if !ok || extra(object, "email_address") {
		return "", ErrUnsupported
	}
	s, ok := object["email_address"].(string)
	if !ok {
		return "", ErrUnsupported
	}
	return s, nil
}

func typedDate(value any) (string, error) {
	switch v := value.(type) {
	case string:
		if !validSourceText(v) {
			return "", ErrUnsupported
		}
		return v, nil
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < 0 {
			return "", ErrUnsupported
		}
		return time.Unix(n, 0).UTC().Format("2006-01-02"), nil
	default:
		return "", ErrUnsupported
	}
}

func typedMonthYear(value any) (string, error) {
	switch v := value.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < 100001 || n > 999912 {
			return "", ErrUnsupported
		}
		month := strconv.FormatInt(n%100, 10)
		if len(month) == 1 {
			month = "0" + month
		}
		return strconv.FormatInt(n/100, 10) + "-" + month, nil
	case string:
		if !validSourceText(v) {
			return "", ErrUnsupported
		}
		if len(v) == 7 && v[4] == '-' {
			return v, nil
		}
		if len(v) == 7 && v[2] == '/' {
			return v[3:] + "-" + v[:2], nil
		}
		return "", ErrUnsupported
	default:
		return "", ErrUnsupported
	}
}

func parseEd25519PrivateKey(value string) ([]byte, []byte, bool) {
	parsed, err := ssh.ParseRawPrivateKey([]byte(value))
	if err != nil {
		return nil, nil, false
	}
	var private ed25519.PrivateKey
	switch key := parsed.(type) {
	case *ed25519.PrivateKey:
		private = *key
	case ed25519.PrivateKey:
		private = key
	default:
		return nil, nil, false
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, nil, false
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, nil, false
	}
	seed := append([]byte(nil), private.Seed()...)
	return seed, append([]byte(nil), public.Marshal()...), true
}

func purposeForCategoryField(cat vault.ItemCategory, id string) string {
	id = strings.ToLower(id)
	switch cat {
	case vault.CategoryCreditCard:
		switch id {
		case "cardholder", "cardholder name", "ccname":
			return "cc-name"
		case "type", "creditcardtype", "cctype":
			return "cc-type"
		case "ccnum", "creditcardnumber", "ccnumber", "number":
			return "cc-number"
		case "cvv", "cvc", "cc-csc", "verification":
			return "cc-csc"
		case "expiry", "expirydate", "ccexp":
			return "cc-exp"
		case "validfrom", "ccvalidfrom":
			return "cc-valid-from"
		case "pin", "ccpin":
			return "cc-pin"
		case "bank", "issuingbank", "ccbank":
			return "cc-bank"
		}
	case vault.CategoryIdentity:
		switch id {
		case "firstname", "first-name":
			return "given-name"
		case "initial", "middlename":
			return "additional-name"
		case "lastname", "last-name":
			return "family-name"
		case "birthdate", "bday":
			return "bday"
		case "company", "organization":
			return "organization"
		case "department":
			return "department"
		case "jobtitle", "job-title":
			return "organization-title"
		case "email":
			return "email"
		case "defphone", "phone", "tel":
			return "tel"
		case "url", "website":
			return "url"
		case "ssn":
			return "ssn"
		case "passportnumber":
			return "passport-number"
		case "licensenumber":
			return "license-number"
		}
	}
	return ""
}

func creditCardFromFields(sections []vault.ItemSection) *vault.CreditCardDetails {
	cc := &vault.CreditCardDetails{}
	set := func(field vault.CustomField) {
		id := strings.ToLower(field.ID)
		purpose := strings.ToLower(field.Purpose)
		switch {
		case purpose == "cc-name" || id == "cardholder" || id == "cardholder name" || id == "cc-name":
			cc.CardholderName = field.Value
		case purpose == "cc-type" || id == "type" || id == "cc-type":
			cc.Type = field.Value
		case purpose == "cc-number" || id == "ccnum" || id == "cc-number" || id == "creditcardnumber":
			cc.Number = field.Value
		case purpose == "cc-csc" || id == "cvv" || id == "cvc" || id == "cc-csc":
			cc.Verification = field.Value
		case purpose == "cc-exp" || id == "expiry" || id == "cc-exp" || id == "expirydate":
			cc.ExpiryDate = monthYearValue(field.Value)
		case id == "validfrom" || id == "cc-valid-from":
			cc.ValidFrom = monthYearValue(field.Value)
		case purpose == "cc-pin" || id == "pin" || id == "cc-pin":
			cc.PIN = field.Value
		case id == "bank" || id == "issuingbank" || id == "cc-bank":
			cc.IssuingBank = field.Value
		}
	}
	for _, section := range sections {
		for _, field := range section.Fields {
			set(field)
		}
	}
	if *cc == (vault.CreditCardDetails{}) {
		return nil
	}
	return cc
}

func identityFromFields(values map[string]string) *vault.IdentityDetails {
	if len(values) == 0 {
		return nil
	}
	id := &vault.IdentityDetails{}
	mapID := map[string]*string{
		"honorific-prefix":   &id.Title,
		"given-name":         &id.FirstName,
		"additional-name":    &id.MiddleName,
		"family-name":        &id.LastName,
		"bday":               &id.BirthDate,
		"organization":       &id.Company,
		"department":         &id.Department,
		"organization-title": &id.JobTitle,
		"email":              &id.Email,
		"tel":                &id.Phone,
		"address-line1":      &id.AddressLine1,
		"address-line2":      &id.AddressLine2,
		"address-level2":     &id.City,
		"address-level1":     &id.State,
		"postal-code":        &id.PostalCode,
		"country":            &id.Country,
		"ssn":                &id.SSN,
		"passport-number":    &id.PassportNumber,
		"license-number":     &id.LicenseNumber,
		"url":                &id.Website,
	}
	for key, value := range values {
		if dst, ok := mapID[key]; ok && *dst == "" {
			*dst = value
		}
	}
	if *id == (vault.IdentityDetails{}) {
		return nil
	}
	return id
}

func monthYearValue(value string) string {
	if len(value) == 7 && value[4] == '-' {
		return value
	}
	if len(value) == 7 && value[2] == '/' {
		return value[3:] + "-" + value[:2]
	}
	return value
}

func validItemURL(raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	_, err := origin.Website(raw)
	return err == nil
}

func validSourceText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

func validAttachmentName(s string) bool {
	if s == "" || len(s) > 255 || s == "." || s == ".." || strings.ContainsAny(s, "/\\") || !validSourceText(s) {
		return false
	}
	return true
}

func selector(s string) bool {
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

func uniqueID(base, prefix string, used map[string]bool) string {
	if !selector(base) {
		base = prefix
	}
	id := base
	for n := 2; used[strings.ToLower(id)]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	used[strings.ToLower(id)] = true
	return id
}

func attachmentID(itemID, name string, content []byte) string {
	h := sha256.New()
	h.Write([]byte(importAttachmentDomain))
	h.Write([]byte(itemID))
	h.Write([]byte{0})
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func mimeFor(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".kdbx":
		return "application/x-keepass2"
	}
	return "application/octet-stream"
}
