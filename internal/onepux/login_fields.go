package onepux

import "encoding/json"

// LoginFieldReport inventories source occurrences, not normalized credentials.
// type and fieldType are distinct source attributes. Unknown strings and values
// are counted but never copied into the report or accepted as mapped semantics.
type LoginFieldReport struct {
	Fields                  int `json:"fields"`
	RepeatedNames           int `json:"repeated_names"`
	RepeatedIDs             int `json:"repeated_ids"`
	UnnamedFields           int `json:"unnamed_fields"`
	UnidentifiedFields      int `json:"unidentified_fields"`
	UsernameDesignations    int `json:"username_designations"`
	PasswordDesignations    int `json:"password_designations"`
	MissingDesignations     int `json:"missing_designations"`
	EmptyDesignations       int `json:"empty_designations"`
	UnknownDesignations     int `json:"unknown_designations"`
	RepeatedDesignations    int `json:"repeated_designations"`
	TypeAttributes          int `json:"type_attributes"`
	FieldTypeAttributes     int `json:"field_type_attributes"`
	BothTypeAttributes      int `json:"both_type_attributes"`
	DifferentTypeAttributes int `json:"different_type_attributes"`
	MissingTypes            int `json:"missing_types"`
	MissingValues           int `json:"missing_values"`
	NullValues              int `json:"null_values"`
	ObjectValues            int `json:"object_values"`
	ArrayValues             int `json:"array_values"`
	StringValues            int `json:"string_values"`
	NumberValues            int `json:"number_values"`
	BooleanValues           int `json:"boolean_values"`
}

func loginFieldInventory(details map[string]any, r *LoginFieldReport, otherObjects int, reasons map[string]bool) error {
	fields, _ := details["loginFields"].([]any) // Container/object types checked by inventory.
	names, ids, designations := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, raw := range fields {
		field := raw.(map[string]any)
		r.Fields++
		if otherObjects+r.Fields > MaxObjects {
			return ErrLimit
		}
		if err := sourceIdentifier(field, "name", names, &r.RepeatedNames, &r.UnnamedFields); err != nil {
			return err
		}
		if err := sourceIdentifier(field, "id", ids, &r.RepeatedIDs, &r.UnidentifiedFields); err != nil {
			return err
		}
		if extra(field, "id", "name", "designation", "type", "fieldType", "value") {
			reasons["additional-metadata"] = true
		}
		if raw, exists := field["designation"]; exists {
			designation, ok := raw.(string)
			if !ok {
				return ErrInvalid
			}
			switch designation {
			case "":
				r.EmptyDesignations++
			case "username":
				r.UsernameDesignations++
			case "password":
				r.PasswordDesignations++
			default:
				r.UnknownDesignations++
			}
			if designation != "" {
				if designations[designation] {
					r.RepeatedDesignations++
				}
				designations[designation] = true
			}
		} else {
			r.MissingDesignations++
		}
		for _, key := range []string{"type", "fieldType"} {
			if raw, exists := field[key]; exists {
				_, ok := raw.(string)
				if !ok {
					return ErrInvalid
				}
				if key == "type" {
					r.TypeAttributes++
				} else {
					r.FieldTypeAttributes++
				}
			}
		}
		first, hasType := field["type"]
		second, hasFieldType := field["fieldType"]
		if hasType && hasFieldType {
			r.BothTypeAttributes++
			if first != second {
				r.DifferentTypeAttributes++
			}
		} else if !hasType && !hasFieldType {
			r.MissingTypes++
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
	for reason, present := range map[string]bool{
		"login-field-semantics-unverified": r.Fields > 0,
		"repeated-login-name":              r.RepeatedNames > 0,
		"repeated-login-id":                r.RepeatedIDs > 0,
		"repeated-login-designation":       r.RepeatedDesignations > 0,
		"unknown-login-designation":        r.UnknownDesignations > 0,
		"login-designations-missing":       r.EmptyDesignations+r.MissingDesignations > 0,
		"login-identifiers-missing":        r.UnnamedFields+r.UnidentifiedFields > 0,
		"login-type-attributes-differ":     r.DifferentTypeAttributes > 0,
		"login-type-missing":               r.MissingTypes > 0,
		"login-value-not-string":           r.Fields-r.StringValues > 0,
	} {
		if present {
			reasons[reason] = true
		}
	}
	return nil
}
