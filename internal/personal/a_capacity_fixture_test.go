package personal

import (
	"math/rand"

	"github.com/jihuayu/locklark/internal/vault"
)

// personalCapacityItem mirrors the vault capacity fixture for package-local
// tests: a schema-valid V2 secure note whose protected encoding exceeds
// MaxStoredSnapshot() for both writes and exports.
func personalCapacityItem() vault.Item {
	return capacityNote(4 << 20)
}

func capacityNote(size int) vault.Item {
	value := make([]byte, size)
	rng := rand.New(rand.NewSource(97))
	for i := range value {
		value[i] = byte(rng.Intn(32))
	}
	return vault.Item{
		ID:       "item-capacity",
		Category: vault.CategorySecureNote,
		Title:    "Synthetic over-capacity note",
		Sections: []vault.ItemSection{{ID: "section-capacity", Title: "Capacity", Fields: []vault.CustomField{
			{ID: "field-bulk", Label: "Bulk", Type: vault.FieldTypeText, Value: string(value)},
		}}},
	}
}
