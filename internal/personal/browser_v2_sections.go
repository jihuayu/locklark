package personal

import "github.com/jihuayu/locklark/internal/vault"

// V2CustomFieldInput is the mutation-only custom field input. A nil Value means
// "preserve the durable value stored under this stable field id"; an explicit
// pointer (including an empty string) is an explicit replacement.
type V2CustomFieldInput struct {
	ID        string
	Label     string
	Type      string
	Value     *string
	Concealed bool
	Purpose   string
}

// V2SectionInput is the mutation-only section input. Omitted sections preserve
// every previous section; a supplied list replaces the structure and a field
// absent from a supplied section is removed.
type V2SectionInput struct {
	ID     string
	Title  string
	Fields []V2CustomFieldInput
}

// V2ItemApplyMutation mirrors V2ItemApplyMeta but applies mutation-specific
// section inputs. It is the only path that can express "keep this concealed
// value although I cannot read it" and "explicitly replace it with empty".
func V2ItemApplyMutation(base vault.Item, meta *V2ItemMeta, sections []V2SectionInput) (vault.Item, error) {
	if meta == nil {
		return vault.Item{}, ErrMutationRefused
	}
	return v2ItemApplyMeta(base, meta, func(previous []vault.ItemSection) ([]vault.ItemSection, error) {
		return v2SectionsFromInput(previous, sections)
	})
}

// v2SectionsFromInput converts the mutation inputs into encrypted sections.
// Unlike the DTO projection it never re-attaches a field the caller removed,
// and an explicit empty value is written as empty so an intentional clear is
// durable.
func v2SectionsFromInput(previous []vault.ItemSection, in []V2SectionInput) ([]vault.ItemSection, error) {
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
			old, hadOld := findPreviousField(previous, sec.ID, f.ID)
			if hadOld && concealedCustomField(old) && !protected {
				// A caller that never read the secret cannot reclassify it as plaintext:
				// the next unmasked detail read would then disclose the stored value.
				return nil, ErrMutationRefused
			}
			value := ""
			switch {
			case f.Value == nil && !hadOld:
				// Nothing durable exists under this stable id, so an omitted value
				// cannot be preserved; inventing an empty field is refused.
				return nil, ErrMutationRefused
			case f.Value == nil:
				// Keep the durable value and its secret classification exactly.
				typ, protected, value = old.Type, concealedCustomField(old), old.Value
			case *f.Value == "" && protected && hadOld:
				// A masked echo cannot destroy a protected value: only clear_fields
				// carries explicit clear authority.
				value = old.Value
			default:
				value = *f.Value
			}
			section.Fields = append(section.Fields, vault.CustomField{ID: f.ID, Label: f.Label, Type: typ, Value: value, Protected: protected, Purpose: f.Purpose})
		}
		out = append(out, section)
	}
	return out, nil
}
