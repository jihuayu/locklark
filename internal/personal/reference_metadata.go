package personal

import (
	"errors"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrReferenceProfile = errors.New("unsupported personal reference metadata profile")
var ErrReferenceMetadata = errors.New("invalid personal reference metadata")

// ProjectReferenceMetadata describes only the built-in personal item profile.
// The caller owns the immutable inputs and must authenticate the snapshot and
// derive revisions from the same journal transaction. Neither the profile tag
// nor a well-formed revision authenticates an input or grants field access.
// Only item identity, kind and title are read. Field values never enter the
// output or affect which field identities are present.
func ProjectReferenceMetadata(metadata []byte, vaultID, name string, items []vault.Item, revisions map[string]string) ([]reference.Vault, error) {
	if string(metadata) != schema {
		return nil, ErrReferenceProfile
	}
	if len(items) > 256 {
		return nil, reference.ErrLimit
	}
	if items == nil || len(revisions) != len(items) {
		return nil, ErrReferenceMetadata
	}
	v := reference.Vault{ID: vaultID, Name: name, Items: make([]reference.Item, 0, len(items))}
	seen := make(map[string]bool, len(items))
	for _, it := range items {
		revision, found := revisions[it.ID]
		if !idOK(it.ID) || seen[it.ID] || !found || !digestOK(revision) {
			return nil, ErrReferenceMetadata
		}
		seen[it.ID] = true
		out := reference.Item{ID: it.ID, Name: it.Title, Revision: revision}
		switch it.Kind {
		case "login":
			out.Fields = []reference.Field{
				{ID: "username", Name: "username"},
				{ID: "password", Name: "password"},
				{ID: "otp", Name: "otp"},
			}
		case "document", "ssh-key":
			// Keep the identity for ambiguity checks. Attachments have no
			// ordinary field reference in this profile.
		default:
			return nil, ErrReferenceMetadata
		}
		v.Items = append(v.Items, out)
	}
	catalog := []reference.Vault{v}
	if err := reference.Validate(catalog); err != nil {
		return nil, err
	}
	return catalog, nil
}
