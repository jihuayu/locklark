package personal

import (
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

// BindReferenceMetadata maps a resolved target to this profile's native slot.
// It has the same authentication/transaction preconditions as the projection;
// it does not read a field value or authorize its use.
func BindReferenceMetadata(metadata []byte, vaultID, name string, items []vault.Item, revisions map[string]string, target reference.Target) (reference.Binding, error) {
	return BindReferenceMetadataV2(metadata, vaultID, name, nil, items, revisions, target)
}

// BindReferenceMetadataV2 is BindReferenceMetadata aware of sub-vaults.
func BindReferenceMetadataV2(metadata []byte, vaultID, name string, vaults []vault.VaultMeta, items []vault.Item, revisions map[string]string, target reference.Target) (reference.Binding, error) {
	catalog, err := ProjectReferenceMetadataV2(metadata, vaultID, name, vaults, items, revisions)
	if err != nil {
		return reference.Binding{}, err
	}
	if err = reference.CheckTarget(target, catalog); err != nil {
		return reference.Binding{}, err
	}
	bound := reference.Binding{Profile: schema, Target: target}
	if target.SectionID == "" {
		switch target.FieldID {
		case "username":
			bound.Slot, bound.Type = reference.SlotUsername, reference.TypeText
			return bound, nil
		case "password":
			bound.Slot, bound.Type = reference.SlotPassword, reference.TypePassword
			return bound, nil
		case "otp":
			bound.Slot, bound.Type = reference.SlotOTP, reference.TypeOTP
			return bound, nil
		case "notes":
			bound.Slot, bound.Type = reference.SlotNotes, reference.TypeText
			return bound, nil
		}
	}
	typ := reference.TypeText
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
					if field.Type != "" {
						typ = field.Type
					}
					break
				}
			}
		}
	}
	bound.Slot, bound.Type = reference.SlotCustomField, typ
	return bound, nil
}
