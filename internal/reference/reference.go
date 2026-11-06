// Package reference resolves a limited op-style reference against metadata.
// A resolved target identifies an object; it never grants permission to use it.
package reference

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxReference = 4096
const MaxObjects = 4096

var ErrInvalid = errors.New("invalid field reference")
var ErrUnsupported = errors.New("field reference attributes are not supported")
var ErrNotFound = errors.New("field reference target not found")
var ErrAmbiguous = errors.New("field reference target is ambiguous")
var ErrCatalog = errors.New("invalid field reference metadata")
var ErrLimit = errors.New("field reference capacity exceeded")

type Reference struct{ Vault, Item, Section, Field string }

// Field describes a selectable field identity. Type is a hint for binding and
// never carries a value; an empty Type defaults to text.
type Field struct {
	ID, Name string
	Type     ValueType
}
type Section struct {
	ID, Name string
	Fields   []Field
}
type Item struct {
	ID, Name, Revision string
	Fields             []Field
	Sections           []Section
}
type Vault struct {
	ID, Name string
	Items    []Item
}

// Target contains the unique IDs selected from the caller's metadata snapshot
// and its opaque item revision. This package does not authenticate that snapshot.
// Callers must revalidate its provenance, revision and authorization, then
// commit their audit before use.
type Target struct {
	VaultID   string `json:"vault_id"`
	ItemID    string `json:"item_id"`
	SectionID string `json:"section_id,omitempty"`
	FieldID   string `json:"field_id"`
	Revision  string `json:"revision"`
}

// Parse supports literal ASCII names/IDs with spaces, hyphens, underscores
// and dots. Percent encoding and query attributes are not interpreted.
func Parse(raw string) (Reference, error) {
	if len(raw) > MaxReference {
		return Reference{}, ErrLimit
	}
	if len(raw) < 5 || !strings.EqualFold(raw[:5], "op://") {
		return Reference{}, ErrInvalid
	}
	if strings.Contains(raw, "?") {
		return Reference{}, ErrUnsupported
	}
	parts := strings.Split(raw[5:], "/")
	if len(parts) != 3 && len(parts) != 4 {
		return Reference{}, ErrInvalid
	}
	for _, p := range parts {
		if len(p) > 256 {
			return Reference{}, ErrLimit
		}
		if !selector(p, true) {
			return Reference{}, ErrInvalid
		}
	}
	r := Reference{Vault: parts[0], Item: parts[1], Field: parts[len(parts)-1]}
	if len(parts) == 4 {
		r.Section = parts[2]
	}
	return r, nil
}

func selector(s string, spaces bool) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || spaces && c == ' ' {
			continue
		}
		return false
	}
	return true
}

// Resolve reads an immutable metadata snapshot owned by the caller. Every
// failure returns a zero target so unknown selectors cannot become audit IDs.
func Resolve(raw string, vaults []Vault) (Target, error) {
	r, err := Parse(raw)
	if err != nil {
		return Target{}, err
	}
	if err = Validate(vaults); err != nil {
		return Target{}, err
	}
	v, err := choose(vaults, r.Vault, func(v Vault) (string, string) { return v.ID, v.Name })
	if err != nil {
		return Target{}, err
	}
	it, err := choose(v.Items, r.Item, func(i Item) (string, string) { return i.ID, i.Name })
	if err != nil {
		return Target{}, err
	}
	var out Target
	count := 0
	consider := func(sectionID string, fields []Field) {
		for _, f := range fields {
			if matches(r.Field, f.ID, f.Name) {
				count++
				out = Target{v.ID, it.ID, sectionID, f.ID, it.Revision}
			}
		}
	}
	if r.Section != "" {
		s, err := choose(it.Sections, r.Section, func(s Section) (string, string) { return s.ID, s.Name })
		if err != nil {
			return Target{}, err
		}
		consider(s.ID, s.Fields)
	} else {
		consider("", it.Fields)
		for _, s := range it.Sections {
			consider(s.ID, s.Fields)
		}
	}
	if count == 0 {
		return Target{}, ErrNotFound
	}
	if count != 1 {
		return Target{}, ErrAmbiguous
	}
	return out, nil
}

func matches(s, id, name string) bool {
	return strings.EqualFold(s, id) || selector(name, true) && strings.EqualFold(s, name)
}

func choose[T any](all []T, s string, names func(T) (string, string)) (T, error) {
	var zero, out T
	count := 0
	for _, value := range all {
		id, name := names(value)
		if matches(s, id, name) {
			out = value
			count++
		}
	}
	if count == 0 {
		return zero, ErrNotFound
	}
	if count != 1 {
		return zero, ErrAmbiguous
	}
	return out, nil
}

// Validate checks only schema, capacity and identity uniqueness. It does not
// authenticate the metadata, establish freshness or grant authority.
func Validate(vaults []Vault) error {
	objects, text := 0, 0
	consume := func(n int) error {
		if n > MaxObjects-objects {
			return ErrLimit
		}
		objects += n
		return nil
	}
	stringOK := func(s string) error {
		if len(s) > 1024 || !utf8.ValidString(s) {
			return ErrCatalog
		}
		for _, r := range s {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return ErrCatalog
			}
		}
		text += len(s)
		if text > 1<<20 {
			return ErrLimit
		}
		return nil
	}
	check := func(id, name string, seen map[string]bool) error {
		if len(id) > 256 || !selector(id, false) {
			return ErrCatalog
		}
		key := strings.ToLower(id)
		if seen[key] {
			return ErrCatalog
		}
		seen[key] = true
		if err := stringOK(id); err != nil {
			return err
		}
		return stringOK(name)
	}
	fields := func(all []Field, seen map[string]bool) error {
		if err := consume(len(all)); err != nil {
			return err
		}
		for _, f := range all {
			if err := check(f.ID, f.Name, seen); err != nil {
				return err
			}
		}
		return nil
	}
	if err := consume(len(vaults)); err != nil {
		return err
	}
	vaultIDs := map[string]bool{}
	for _, v := range vaults {
		if err := check(v.ID, v.Name, vaultIDs); err != nil {
			return err
		}
		if err := consume(len(v.Items)); err != nil {
			return err
		}
		itemIDs := map[string]bool{}
		for _, it := range v.Items {
			if err := check(it.ID, it.Name, itemIDs); err != nil {
				return err
			}
			if strings.TrimSpace(it.Revision) == "" || len(it.Revision) > 256 {
				return ErrCatalog
			}
			if err := stringOK(it.Revision); err != nil {
				return err
			}
			fieldIDs := map[string]bool{}
			if err := fields(it.Fields, fieldIDs); err != nil {
				return err
			}
			if err := consume(len(it.Sections)); err != nil {
				return err
			}
			sectionIDs := map[string]bool{}
			for _, s := range it.Sections {
				if err := check(s.ID, s.Name, sectionIDs); err != nil {
					return err
				}
				if err := fields(s.Fields, fieldIDs); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
