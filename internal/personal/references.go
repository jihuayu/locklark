package personal

import (
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

const referenceDisclosureAction = "reference.disclose"
const referenceRejectAction = "reference.reject"
const personalVaultName = "Personal"

var ErrReferenceType = errors.New("field reference type does not match the requested operation")

type ReferenceRow struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Revision   string            `json:"revision"`
	References map[string]string `json:"references"`
}

type ReferenceIndex struct {
	VaultID   string         `json:"vault_id"`
	VaultName string         `json:"vault_name"`
	Items     []ReferenceRow `json:"items"`
}

type referenceRequest struct {
	raw, revision string
	otp           bool
}

func referenceOption(raw, revision string, otp bool) (commandOption, error) {
	if _, err := reference.Parse(raw); err != nil {
		return commandOption{}, err
	}
	if !digestOK(revision) {
		return commandOption{}, errors.New("invalid reference revision")
	}
	return commandOption{reference: &referenceRequest{raw, revision, otp}}, nil
}

// ValidateReferenceInput validates syntax only, not a target or permission.
func ValidateReferenceInput(raw, revision string) error {
	_, err := referenceOption(raw, revision, false)
	return err
}

// Account is authenticated by Unwrap before these helpers run. It is a local
// vault identity for the personal profile; restoring creates a new account ID.
func personalReferenceCatalog(account []byte, items []vault.Item, revisions map[string]string) ([]reference.Vault, error) {
	if len(account) != 16 {
		return nil, ErrReferenceMetadata
	}
	return ProjectReferenceMetadata([]byte(schema), hex.EncodeToString(account), personalVaultName, items, revisions)
}

func makeReferenceIndex(account []byte, items []vault.Item, revisions map[string]string) (ReferenceIndex, error) {
	catalog, err := personalReferenceCatalog(account, items, revisions)
	if err != nil {
		return ReferenceIndex{}, err
	}
	v := catalog[0]
	index := ReferenceIndex{VaultID: v.ID, VaultName: v.Name, Items: make([]ReferenceRow, 0, len(v.Items))}
	for _, item := range v.Items {
		row := ReferenceRow{ID: item.ID, Title: item.Name, Revision: item.Revision, References: map[string]string{}}
		for _, field := range item.Fields {
			row.References[field.ID] = "op://" + v.ID + "/" + item.ID + "/" + field.ID
		}
		index.Items = append(index.Items, row)
	}
	return index, nil
}

func (request *referenceRequest) bind(account []byte, items []vault.Item, revisions map[string]string) (string, *Edit, error) {
	catalog, err := personalReferenceCatalog(account, items, revisions)
	if err != nil {
		return "", nil, err
	}
	target, err := reference.Resolve(request.raw, catalog)
	if err != nil {
		return "", nil, err
	}
	bound, err := BindReferenceMetadata([]byte(schema), catalog[0].ID, personalVaultName, items, revisions, target)
	if err != nil {
		return "", nil, err
	}
	var action string
	if request.otp {
		if bound.Type != reference.TypeOTP || bound.Slot != reference.SlotOTP {
			return "", nil, ErrReferenceType
		}
		action = otpDisclosureAction
	} else {
		switch {
		case bound.Type == reference.TypeText && bound.Slot == reference.SlotUsername:
			action = "item.reveal.username"
		case bound.Type == reference.TypePassword && bound.Slot == reference.SlotPassword:
			action = "item.reveal.password"
		default:
			return "", nil, ErrReferenceType
		}
	}
	if target.Revision != request.revision {
		return "", nil, ErrConflict
	}
	return action, &Edit{ID: target.ItemID, Revision: target.Revision, Field: string(bound.Slot)}, nil
}

func referenceRejection(err error) (string, bool) {
	switch {
	case errors.Is(err, reference.ErrNotFound):
		return "not-found", true
	case errors.Is(err, reference.ErrAmbiguous):
		return "ambiguous", true
	case errors.Is(err, ErrReferenceType):
		return "wrong-type", true
	case errors.Is(err, ErrConflict):
		return "stale", true
	default:
		return "", false
	}
}

func References(path, pw string, key []byte) (ReferenceIndex, error) {
	r, err := command(path, pw, key, "reference.list", vault.Item{}, nil)
	if err != nil {
		return ReferenceIndex{}, err
	}
	return r.references, nil
}

// A reference selects a target, never a permission. Values and code generation
// use the same authenticated transaction and disclosure rules as direct IDs.
func RevealReference(path, pw string, key []byte, raw, revision string, terminal io.Writer) (DisclosureReceipt, error) {
	option, err := referenceOption(raw, revision, false)
	if err != nil {
		return DisclosureReceipt{}, err
	}
	return disclosePrepared(terminal, func() (result, error) {
		return command(path, pw, key, referenceDisclosureAction, vault.Item{}, nil, option)
	})
}

func RevealOTPReference(path, pw string, key []byte, raw, revision string, terminal io.Writer) (OTPReceipt, error) {
	option, err := referenceOption(raw, revision, true)
	if err != nil {
		return OTPReceipt{}, err
	}
	return revealOTP(terminal, time.Now, func() (result, error) {
		return command(path, pw, key, referenceDisclosureAction, vault.Item{}, nil, option)
	})
}
