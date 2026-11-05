package personal

import (
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

// BindReferenceMetadata maps a resolved target to this profile's native slot.
// It has the same authentication/transaction preconditions as the projection;
// it does not read a field value or authorize its use.
func BindReferenceMetadata(metadata []byte, vaultID, name string, items []vault.Item, revisions map[string]string, target reference.Target) (reference.Binding, error) {
	catalog, err := ProjectReferenceMetadata(metadata, vaultID, name, items, revisions)
	if err != nil {
		return reference.Binding{}, err
	}
	if err = reference.CheckTarget(target, catalog); err != nil {
		return reference.Binding{}, err
	}
	bound := reference.Binding{Profile: schema, Target: target}
	switch target.FieldID {
	case "username":
		bound.Slot, bound.Type = reference.SlotUsername, reference.TypeText
	case "password":
		bound.Slot, bound.Type = reference.SlotPassword, reference.TypePassword
	case "otp":
		bound.Slot, bound.Type = reference.SlotOTP, reference.TypeOTP
	default:
		return reference.Binding{}, reference.ErrNotFound
	}
	return bound, nil
}
