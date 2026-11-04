package preview

import (
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

const fixtureReferenceProfile = "locklark/synthetic/native-fixture/v1"

// BindFixtureReferenceMetadata only maps the built-in source profile to native
// slots. The caller must authenticate all inputs together, as for projection.
// The returned metadata is not an access grant and contains no field values.
func BindFixtureReferenceMetadata(metadata []byte, items []vault.Item, snapshotSignature string, target reference.Target) (reference.Binding, error) {
	catalog, err := ProjectFixtureReferenceMetadata(metadata, items, snapshotSignature)
	if err != nil {
		return reference.Binding{}, err
	}
	if err = reference.CheckTarget(target, catalog); err != nil {
		return reference.Binding{}, err
	}
	bound := reference.Binding{Profile: fixtureReferenceProfile, Target: target}
	switch {
	case target.SectionID == "" && target.FieldID == "password":
		bound.Slot, bound.Type = reference.SlotPassword, reference.TypePassword
	case target.SectionID == "ops" && target.FieldID == "otp-demo":
		bound.Slot, bound.Type = reference.SlotOTP, reference.TypeOTP
	default:
		return reference.Binding{}, reference.ErrNotFound
	}
	return bound, nil
}
