package onepux

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jihuayu/locklark/internal/vault"
)

// MappingReport deliberately contains no source names, identifiers or values.
// Profile is narrow: unrepresented values are refused, never silently skipped.
type MappingReport struct {
	Profile      string `json:"profile"`
	SourceDigest string `json:"source_digest"`
	Items        int    `json:"items"`
	Archived     int    `json:"archived"`
}
type MappedLogins struct {
	Report MappingReport
	Items  []vault.Item
}

// MapLogins maps a supported login profile and retains original attributes and
// item JSON as protected provenance. Provenance is immutable source evidence;
// subsequent edits affect the native fields, not the historical source record.
func MapLogins(raw []byte) (MappedLogins, error) {
	inventory, err := Inspect(raw)
	if err != nil {
		return MappedLogins{}, err
	}
	if inventory.Files != 0 || inventory.Items == 0 {
		return MappedLogins{}, ErrUnsupported
	}
	if inventory.Accounts != 1 || inventory.Vaults != 1 {
		return MappedLogins{}, ErrUnsupported
	}
	if inventory.Items > 256 {
		return MappedLogins{}, ErrLimit
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return MappedLogins{}, ErrInvalid
	}
	var root, attrs map[string]any
	for _, f := range z.File {
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
	if extra(root, "accounts") || extra(attrs, "version", "description", "createdAt") {
		return MappedLogins{}, ErrUnsupported
	}
	sum := sha256.Sum256(raw)
	out := MappedLogins{Report: MappingReport{Profile: "login-v1", SourceDigest: hex.EncodeToString(sum[:]), Items: inventory.Items, Archived: inventory.Archived}, Items: make([]vault.Item, 0, inventory.Items)}
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
				item, e := mapLogin(source)
				if e != nil {
					return MappedLogins{}, e
				}
				identity, _ := json.Marshal([]any{accountAttrs["uuid"], vaultAttrs["uuid"], source["uuid"]})
				h := sha256.Sum256(append([]byte("locklark/import/1pux/login/v1\x00"), identity...))
				item.ID = hex.EncodeToString(h[:16])
				item.ImportSource, e = json.Marshal(map[string]any{"format": "locklark/1pux-source/v1", "attributes": attrs, "account": accountAttrs, "vault": vaultAttrs, "item": source})
				if e != nil {
					return MappedLogins{}, ErrInvalid
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

func mapLogin(source map[string]any) (vault.Item, error) {
	reject := func() (vault.Item, error) { return vault.Item{}, ErrUnsupported }
	if source["categoryUuid"] != "001" || extra(source, "uuid", "categoryUuid", "state", "favIndex", "createdAt", "updatedAt", "overview", "details") {
		return reject()
	}
	if value, found := source["favIndex"]; found && value != json.Number("0") {
		return reject()
	}
	state, _ := source["state"].(string)
	if state != "active" && state != "archived" {
		return reject()
	}
	overview, ok := source["overview"].(map[string]any)
	if !ok || extra(overview, "title", "subtitle", "url", "urls", "tags") {
		return reject()
	}
	title, ok := overview["title"].(string)
	if !ok || strings.TrimSpace(title) == "" {
		return reject()
	}
	if value, found := overview["tags"]; found {
		list, ok := value.([]any)
		if !ok || len(list) != 0 {
			return reject()
		}
	}
	url := ""
	if value, found := overview["url"]; found {
		url, ok = value.(string)
		if !ok {
			return reject()
		}
	}
	// Duplicate copies of the primary URL retain their original labels in the
	// provenance record. Distinct websites require the future multi-URL schema.
	if value, found := overview["urls"]; found {
		urls, ok := value.([]any)
		if !ok {
			return reject()
		}
		for _, value := range urls {
			u, ok := value.(map[string]any)
			if !ok || extra(u, "url", "label") || u["url"] != url || url == "" {
				return reject()
			}
		}
	}
	details, ok := source["details"].(map[string]any)
	if !ok || extra(details, "loginFields", "notesPlain", "sections", "passwordHistory") {
		return reject()
	}
	if value, found := details["notesPlain"]; found && value != "" {
		return reject()
	}
	for _, key := range []string{"sections", "passwordHistory"} {
		if value, found := details[key]; found {
			list, ok := value.([]any)
			if !ok || len(list) > 0 {
				return reject()
			}
		}
	}
	fields, ok := details["loginFields"].([]any)
	if !ok {
		return reject()
	}
	item := vault.Item{Kind: "login", Title: title, URL: url}
	if state == "archived" {
		item.State = state
	}
	seen := map[string]bool{}
	for _, f := range fields {
		field := f.(map[string]any) // Inspect already checked element types.
		if extra(field, "id", "name", "designation", "type", "fieldType", "value") {
			return reject()
		}
		designation, ok := field["designation"].(string)
		if !ok || designation != "username" && designation != "password" || seen[designation] {
			return reject()
		}
		seen[designation] = true
		expected := "T"
		if designation == "password" {
			expected = "P"
		}
		first, firstOK := field["type"]
		second, secondOK := field["fieldType"]
		if !firstOK && !secondOK || firstOK && first != expected || secondOK && second != expected {
			return reject()
		}
		value, ok := field["value"].(string)
		if !ok {
			return reject()
		}
		if designation == "username" {
			item.Username = value
		} else {
			item.Password = value
		}
	}
	if !seen["password"] {
		return reject()
	}
	// Validate values independently of source IDs before committing any result.
	item.ID = "probe"
	if vault.ValidateItems(nil, []vault.Item{item}) != nil {
		return reject()
	}
	item.ID = ""
	return item, nil
}
