package vault

import "math/rand"

// syntheticCapacityItem mirrors the repository-level capacity fixture for
// package-local tests: a schema-valid V2 secure note with one 4 MiB text
// custom field of pseudorandom control bytes (0..31) whose protected encoding
// exceeds MaxStoredSnapshot().
func syntheticCapacityItem() Item {
	const size = 4 << 20
	value := make([]byte, size)
	rng := rand.New(rand.NewSource(97))
	for i := range value {
		value[i] = byte(rng.Intn(32))
	}
	return Item{
		ID:       "item-capacity",
		Category: CategorySecureNote,
		Title:    "Synthetic over-capacity note",
		Sections: []ItemSection{{ID: "section-capacity", Title: "Capacity", Fields: []CustomField{
			{ID: "field-bulk", Label: "Bulk", Type: FieldTypeText, Value: string(value)},
		}}},
	}
}
