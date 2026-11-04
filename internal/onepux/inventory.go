package onepux

import (
	"sort"
	"strings"
)

func extra(object map[string]any, allowed ...string) bool {
	for key := range object {
		found := false
		for _, known := range allowed {
			if key == known {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func identity(object map[string]any, seen map[string]bool) bool {
	id, ok := object["uuid"].(string)
	if !ok || len(id) == 0 || len(id) > 256 || seen[id] {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	seen[id] = true
	return true
}

func inventory(root map[string]any, r *Report, reasons map[string]bool) error {
	mark := func(object map[string]any, allowed ...string) {
		if extra(object, allowed...) {
			reasons["additional-metadata"] = true
		}
	}
	mark(root, "accounts")
	accounts, ok := root["accounts"].([]any)
	if !ok {
		return ErrInvalid
	}
	accountIDs := map[string]bool{}
	counts := map[string]int{}
	for _, raw := range accounts {
		account, ok := raw.(map[string]any)
		attrs, attrsOK := account["attrs"].(map[string]any)
		vaults, vaultsOK := account["vaults"].([]any)
		if !ok || !attrsOK || !vaultsOK || !identity(attrs, accountIDs) {
			return ErrInvalid
		}
		r.Accounts++
		if r.Accounts+r.Vaults+r.Items > MaxObjects {
			return ErrLimit
		}
		mark(account, "attrs", "vaults")
		mark(attrs, "uuid", "accountName", "name", "avatar", "email", "domain")
		vaultIDs := map[string]bool{}
		for _, raw := range vaults {
			vault, ok := raw.(map[string]any)
			attrs, attrsOK := vault["attrs"].(map[string]any)
			items, itemsOK := vault["items"].([]any)
			if !ok || !attrsOK || !itemsOK || !identity(attrs, vaultIDs) {
				return ErrInvalid
			}
			r.Vaults++
			if r.Accounts+r.Vaults+r.Items > MaxObjects {
				return ErrLimit
			}
			mark(vault, "attrs", "items")
			mark(attrs, "uuid", "desc", "avatar", "name", "type")
			itemIDs := map[string]bool{}
			for _, raw := range items {
				item, ok := raw.(map[string]any)
				if !ok || !identity(item, itemIDs) {
					return ErrInvalid
				}
				code, ok := item["categoryUuid"].(string)
				if !ok || len(code) != 3 || strings.IndexFunc(code, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
					return ErrInvalid
				}
				state, ok := item["state"].(string)
				if !ok || strings.TrimSpace(state) == "" || len(state) > 256 {
					return ErrInvalid
				}
				r.Items++
				if r.Accounts+r.Vaults+r.Items > MaxObjects {
					return ErrLimit
				}
				counts[code]++
				if code != "001" && code != "114" {
					reasons["unknown-category"] = true
				}
				switch state {
				case "active":
					r.Active++
				case "archived":
					r.Archived++
				default:
					r.OtherStates++
					reasons["unknown-state"] = true
				}
				mark(item, "uuid", "categoryUuid", "state", "favIndex", "createdAt", "updatedAt", "overview", "details", "file")
				if overview, exists := item["overview"]; exists {
					object, ok := overview.(map[string]any)
					if !ok {
						return ErrInvalid
					}
					mark(object, "title", "subtitle", "url", "urls", "tags")
				}
				if details, exists := item["details"]; exists {
					object, ok := details.(map[string]any)
					if !ok {
						return ErrInvalid
					}
					mark(object, "loginFields", "notesPlain", "sections", "passwordHistory", "documentAttributes")
					for key, reason := range map[string]string{"sections": "sections-unmapped", "passwordHistory": "password-history-unmapped", "loginFields": "login-fields-unmapped"} {
						if raw, exists := object[key]; exists {
							list, ok := raw.([]any)
							if !ok {
								return ErrInvalid
							}
							for _, value := range list {
								if _, ok := value.(map[string]any); !ok {
									return ErrInvalid
								}
							}
							if len(list) > 0 {
								reasons[reason] = true
							}
						}
					}
					if _, exists := object["documentAttributes"]; exists {
						reasons["file-linkage-unverified"] = true
					}
				}
				if _, exists := item["file"]; exists {
					reasons["file-linkage-unverified"] = true
				}
			}
		}
	}
	for code, count := range counts {
		r.Categories = append(r.Categories, Category{code, count})
	}
	sort.Slice(r.Categories, func(i, j int) bool { return r.Categories[i].Code < r.Categories[j].Code })
	return nil
}
