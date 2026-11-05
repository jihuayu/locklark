package onepux

import "encoding/json"

// SectionReport counts source occurrences, never target identities. Values are
// classified by JSON shape only, not by semantic field type or import support.
type SectionReport struct {
	Sections             int `json:"sections"`
	Fields               int `json:"fields"`
	RepeatedSectionNames int `json:"repeated_section_names"`
	RepeatedFieldIDs     int `json:"repeated_field_ids"`
	UnidentifiedSections int `json:"unidentified_sections"`
	UnidentifiedFields   int `json:"unidentified_fields"`
	MissingValues        int `json:"missing_values"`
	NullValues           int `json:"null_values"`
	ObjectValues         int `json:"object_values"`
	ArrayValues          int `json:"array_values"`
	StringValues         int `json:"string_values"`
	NumberValues         int `json:"number_values"`
	BooleanValues        int `json:"boolean_values"`
}

// Repeated names/IDs remain visible source occurrences. Neither case folding
// nor merging is safe here; field IDs are not necessarily unique in 1PUX.
func sourceIdentifier(object map[string]any, key string, seen map[string]bool, repeated, unidentified *int) error {
	raw, exists := object[key]
	if !exists {
		*unidentified++
		return nil
	}
	id, ok := raw.(string)
	if !ok {
		return ErrInvalid
	}
	if id == "" {
		*unidentified++
		return nil
	}
	if seen[id] {
		*repeated++
	}
	seen[id] = true
	return nil
}
func sectionInventory(details map[string]any, r *SectionReport, otherObjects int, reasons map[string]bool) error {
	sections, _ := details["sections"].([]any) // Outer container validated by inventory.
	names := map[string]bool{}
	for _, raw := range sections {
		section := raw.(map[string]any)
		r.Sections++
		if r.Sections+r.Fields+otherObjects > MaxObjects {
			return ErrLimit
		}
		if err := sourceIdentifier(section, "name", names, &r.RepeatedSectionNames, &r.UnidentifiedSections); err != nil {
			return err
		}
		if extra(section, "name", "title", "fields") {
			reasons["additional-metadata"] = true
		}
		if value, exists := section["title"]; exists {
			if _, ok := value.(string); !ok {
				return ErrInvalid
			}
		}
		rawFields, exists := section["fields"]
		if !exists {
			reasons["section-fields-missing"] = true
			continue
		}
		fields, ok := rawFields.([]any)
		if !ok {
			return ErrInvalid
		}
		ids := map[string]bool{}
		for _, rawField := range fields {
			field, ok := rawField.(map[string]any)
			if !ok {
				return ErrInvalid
			}
			r.Fields++
			if r.Sections+r.Fields+otherObjects > MaxObjects {
				return ErrLimit
			}
			if err := sourceIdentifier(field, "id", ids, &r.RepeatedFieldIDs, &r.UnidentifiedFields); err != nil {
				return err
			}
			if extra(field, "id", "title", "value") {
				reasons["additional-metadata"] = true
			}
			if title, exists := field["title"]; exists {
				if _, ok := title.(string); !ok {
					return ErrInvalid
				}
			}
			value, exists := field["value"]
			if !exists {
				r.MissingValues++
				continue
			}
			switch value.(type) {
			case nil:
				r.NullValues++
			case map[string]any:
				r.ObjectValues++
			case []any:
				r.ArrayValues++
			case string:
				r.StringValues++
			case json.Number:
				r.NumberValues++
			case bool:
				r.BooleanValues++
			default:
				return ErrInvalid
			}
		}
	}
	if r.Fields > 0 {
		reasons["field-value-semantics-unverified"] = true
	}
	if r.RepeatedFieldIDs > 0 {
		reasons["repeated-field-id"] = true
	}
	if r.RepeatedSectionNames > 0 {
		reasons["repeated-section-name"] = true
	}
	if r.UnidentifiedFields+r.UnidentifiedSections > 0 {
		reasons["source-identifiers-missing"] = true
	}
	return nil
}
