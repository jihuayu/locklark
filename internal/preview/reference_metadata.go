package preview

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrFixtureReferenceProfile = errors.New("unsupported synthetic native reference profile")
var ErrFixtureReferenceMetadata = errors.New("invalid synthetic native reference metadata")

const fixtureReferenceRevision = "snapshot-signature-v1:"

// ProjectFixtureReferenceMetadata supports only the built-in native fixture
// profile. The caller must authenticate the metadata, items and snapshot
// signature together. A signature-shaped string does not establish trust.
// Private native values are never read or reinserted into the source layout.
func ProjectFixtureReferenceMetadata(metadata []byte, items []vault.Item, snapshotSignature string) ([]reference.Vault, error) {
	if len(metadata) > vault.MaxPayload {
		return nil, reference.ErrLimit
	}
	var m nativeMeta
	if err := strictReferenceJSON(metadata, &m); err != nil {
		return nil, err
	}
	if m.Version != 1 || m.Layout == nil {
		return nil, ErrFixtureReferenceProfile
	}
	if len(m.Layout.Slots) != slotCount || len(m.Layout.Parts) != slotCount+1 || len(items) != 2 || !hexSize(snapshotSignature, 64) {
		return nil, ErrFixtureReferenceMetadata
	}
	// Neutral holes let us check source identities without serializing native
	// passwords, OTPs, filenames or attachments into another representation.
	neutral := map[string]string{"login.title": `""`, "login.password": `""`, "login.ops.otp-demo": `""`, "document.title": `""`, "document.filename": `""`, "document.size": "0"}
	var data bytes.Buffer
	for i, part := range m.Layout.Parts {
		if len(part) > (1<<20)-data.Len() {
			return nil, reference.ErrLimit
		}
		data.WriteString(part)
		if i < len(m.Layout.Slots) {
			slot := m.Layout.Slots[i]
			value, ok := neutral[slot]
			if !ok {
				return nil, ErrFixtureReferenceMetadata
			}
			delete(neutral, slot)
			if len(value) > (1<<20)-data.Len() {
				return nil, reference.ErrLimit
			}
			data.WriteString(value)
		}
	}
	if len(neutral) != 0 {
		return nil, ErrFixtureReferenceMetadata
	}
	var source fixtureReferenceSource
	if err := strictReferenceJSON(data.Bytes(), &source); err != nil {
		return nil, err
	}
	l, _, err := splitFixture(data.Bytes())
	if err != nil || !slices.Equal(l.Parts, m.Layout.Parts) || !slices.Equal(l.Slots, m.Layout.Slots) {
		return nil, ErrFixtureReferenceMetadata
	}
	byID := make(map[string]vault.Item, len(items))
	for _, item := range items {
		if _, found := byID[item.ID]; found {
			return nil, ErrFixtureReferenceMetadata
		}
		byID[item.ID] = item
	}
	sv := source.Accounts[0].Vaults[0]
	if sv.Attrs.Type != "P" {
		return nil, ErrFixtureReferenceMetadata
	}
	v := reference.Vault{ID: sv.Attrs.UUID, Name: sv.Attrs.Name, Items: make([]reference.Item, 0, 2)}
	for _, si := range sv.Items {
		item, ok := byID[si.UUID]
		if !ok || si.State != "active" {
			return nil, ErrFixtureReferenceMetadata
		}
		ri := reference.Item{ID: si.UUID, Name: item.Title, Revision: fixtureReferenceRevision + snapshotSignature}
		switch si.CategoryUUID {
		case "001":
			if item.Kind != "login" || si.Details.LoginFields[0].FieldType != "P" || si.Details.DocumentAttributes.DocumentID != "" {
				return nil, ErrFixtureReferenceMetadata
			}
			lf := si.Details.LoginFields[0]
			ri.Fields = []reference.Field{{ID: lf.Name, Name: lf.Name}}
			section := si.Details.Sections[0]
			field := section.Fields[0]
			ri.Sections = []reference.Section{{ID: section.Name, Name: section.Title, Fields: []reference.Field{{ID: field.ID, Name: field.Title}}}}
		case "114":
			if item.Kind != "document" || len(si.Details.LoginFields) != 0 || len(si.Details.Sections) != 0 {
				return nil, ErrFixtureReferenceMetadata
			}
		default:
			return nil, ErrFixtureReferenceMetadata
		}
		v.Items = append(v.Items, ri)
	}
	catalog := []reference.Vault{v}
	if err = reference.Validate(catalog); err != nil {
		return nil, err
	}
	return catalog, nil
}

type fixtureReferenceSource struct {
	Accounts []struct {
		Attrs  struct{ UUID, Name string }
		Vaults []struct {
			Attrs struct{ UUID, Name, Type string }
			Items []struct {
				UUID, CategoryUUID, State string
				Overview                  struct {
					Title string
					Tags  []string
				}
				Details struct {
					LoginFields []struct{ Name, Designation, FieldType, Value string }
					Sections    []struct {
						Name, Title string
						Fields      []struct {
							ID, Title string
							Value     struct{ TOTP string }
						}
					}
					DocumentAttributes struct {
						DocumentID, FileName string
						DecryptedSize        int
					}
				}
			}
		}
	}
}

// encoding/json accepts duplicate and case-aliased object keys. Reject them
// before decoding identities; also bound nesting and token work independently
// of byte limits. Both metadata and source profiles use ASCII property names.
func strictReferenceJSON(data []byte, out any) error {
	if !utf8.Valid(data) {
		return ErrFixtureReferenceMetadata
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 32 || nodes > reference.MaxObjects {
			return reference.ErrLimit
		}
		token, err := d.Token()
		if err != nil {
			return ErrFixtureReferenceMetadata
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok {
					return ErrFixtureReferenceMetadata
				}
				for _, c := range key {
					if c > 127 {
						return ErrFixtureReferenceMetadata
					}
				}
				folded := strings.ToLower(key)
				if seen[folded] {
					return ErrFixtureReferenceMetadata
				}
				seen[folded] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return ErrFixtureReferenceMetadata
			}
		case json.Delim('['):
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return ErrFixtureReferenceMetadata
			}
		case json.Delim('}'), json.Delim(']'):
			return ErrFixtureReferenceMetadata
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrFixtureReferenceMetadata
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return ErrFixtureReferenceMetadata
	}
	return nil
}
