package onepux

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ShapeReport describes JSON syntax, never a verified semantic field type.
type ShapeReport struct {
	Missing  int `json:"missing"`
	Null     int `json:"null"`
	Objects  int `json:"objects"`
	Arrays   int `json:"arrays"`
	Strings  int `json:"strings"`
	Numbers  int `json:"numbers"`
	Booleans int `json:"booleans"`
}

type PasswordHistoryReport struct {
	Entries                        int         `json:"entries"`
	Values                         ShapeReport `json:"values"`
	Times                          ShapeReport `json:"times"`
	IntegerTimes                   int         `json:"integer_times"`
	NegativeIntegerTimes           int         `json:"negative_integer_times"`
	OtherNumberTimes               int         `json:"other_number_times"`
	RepeatedStringValues           int         `json:"repeated_string_values"`
	RepeatedNumberTimes            int         `json:"repeated_number_times"`
	IncreasingAdjacentIntegerTimes int         `json:"increasing_adjacent_integer_times"`
	EqualAdjacentIntegerTimes      int         `json:"equal_adjacent_integer_times"`
	DecreasingAdjacentIntegerTimes int         `json:"decreasing_adjacent_integer_times"`
}

func countShape(object map[string]any, key string, r *ShapeReport) error {
	value, exists := object[key]
	if !exists {
		r.Missing++
		return nil
	}
	switch value.(type) {
	case nil:
		r.Null++
	case map[string]any:
		r.Objects++
	case []any:
		r.Arrays++
	case string:
		r.Strings++
	case json.Number:
		r.Numbers++
	case bool:
		r.Booleans++
	default:
		return ErrInvalid
	}
	return nil
}

// Traverse the original array without sorting, deduplication or mutation. Maps
// only count exact source occurrences within one item; no values leave here.
func passwordHistoryInventory(details map[string]any, r *PasswordHistoryReport, otherObjects int, reasons map[string]bool) error {
	entries, _ := details["passwordHistory"].([]any) // Outer shapes checked by inventory.
	values, numbers := map[string]bool{}, map[string]bool{}
	var previous int64
	previousValid := false
	for _, raw := range entries {
		entry := raw.(map[string]any)
		r.Entries++
		if r.Entries+otherObjects > MaxObjects {
			return ErrLimit
		}
		if extra(entry, "value", "time") {
			reasons["additional-metadata"] = true
		}
		if err := countShape(entry, "value", &r.Values); err != nil {
			return err
		}
		if err := countShape(entry, "time", &r.Times); err != nil {
			return err
		}
		if value, ok := entry["value"].(string); ok {
			if values[value] {
				r.RepeatedStringValues++
			}
			values[value] = true
		}
		number, ok := entry["time"].(json.Number)
		if !ok {
			previousValid = false
			continue
		}
		literal := number.String()
		if numbers[literal] {
			r.RepeatedNumberTimes++
		}
		numbers[literal] = true
		// JSON number syntax is already checked. Do not round through float64
		// or expand arbitrary exponents. Other forms remain unverified numbers.
		current, err := strconv.ParseInt(literal, 10, 64)
		if err != nil || strings.ContainsAny(literal, ".eE") {
			r.OtherNumberTimes++
			previousValid = false
			continue
		}
		r.IntegerTimes++
		if current < 0 {
			r.NegativeIntegerTimes++
		}
		if previousValid {
			switch {
			case current > previous:
				r.IncreasingAdjacentIntegerTimes++
			case current == previous:
				r.EqualAdjacentIntegerTimes++
			default:
				r.DecreasingAdjacentIntegerTimes++
			}
		}
		previous, previousValid = current, true
	}
	for reason, present := range map[string]bool{
		"history-time-semantics-unverified": r.Entries > 0,
		"history-value-missing":             r.Values.Missing > 0,
		"history-value-not-string":          r.Values.Null+r.Values.Objects+r.Values.Arrays+r.Values.Numbers+r.Values.Booleans > 0,
		"history-time-missing":              r.Times.Missing > 0,
		"history-time-not-number":           r.Times.Null+r.Times.Objects+r.Times.Arrays+r.Times.Strings+r.Times.Booleans > 0,
		"history-other-number-time":         r.OtherNumberTimes > 0,
		"history-negative-integer-time":     r.NegativeIntegerTimes > 0,
		"history-repeated-string-value":     r.RepeatedStringValues > 0,
		"history-repeated-number-time":      r.RepeatedNumberTimes > 0,
	} {
		if present {
			reasons[reason] = true
		}
	}
	return nil
}
