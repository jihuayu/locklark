package reference

import "errors"

var ErrStale = errors.New("field reference revision changed")

type NativeSlot string

const (
	SlotUsername    NativeSlot = "username"
	SlotPassword    NativeSlot = "password"
	SlotOTP         NativeSlot = "otp"
	SlotNotes       NativeSlot = "notes"
	SlotCustomField NativeSlot = "custom_field"
)

type ValueType string

const (
	TypeText     ValueType = "text"
	TypePassword ValueType = "password"
	TypeOTP      ValueType = "otp-configuration"
)

// Binding describes a native slot, never its value or an access grant. The
// profile and target must be revalidated in the authenticated use transaction.
// TypeOTP describes stored OTP configuration, not a generated one-time code.
type Binding struct {
	Profile string     `json:"profile"`
	Target  Target     `json:"target"`
	Slot    NativeSlot `json:"slot"`
	Type    ValueType  `json:"type"`
}

// CheckTarget checks canonical IDs and revision against caller-owned metadata.
// It does not resolve names, authenticate inputs or establish freshness.
func CheckTarget(target Target, catalog []Vault) error {
	if err := Validate(catalog); err != nil {
		return err
	}
	for _, v := range catalog {
		if v.ID != target.VaultID {
			continue
		}
		for _, item := range v.Items {
			if item.ID != target.ItemID {
				continue
			}
			fields := item.Fields
			if target.SectionID != "" {
				fields = nil
				for _, section := range item.Sections {
					if section.ID == target.SectionID {
						fields = section.Fields
						break
					}
				}
			}
			for _, field := range fields {
				if field.ID == target.FieldID {
					if item.Revision != target.Revision {
						return ErrStale
					}
					return nil
				}
			}
			return ErrNotFound
		}
		return ErrNotFound
	}
	return ErrNotFound
}
