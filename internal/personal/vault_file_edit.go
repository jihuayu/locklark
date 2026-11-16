package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"reflect"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

type VaultFileTitleRename struct {
	ItemID           string `json:"item_id"`
	ExpectedOldTitle string `json:"expected_old_title"`
	NewTitle         string `json:"new_title"`
}

// VaultFileSealedTitleRename contains only sealed bytes and the frozen journal
// precondition. It carries no decrypted item, VUK or personal signing key.
type VaultFileSealedTitleRename struct {
	State  vaultfilejournal.State
	Sealed []byte
}

var ErrVaultFileEditReview = errors.New("vault-file title edit needs local review")
var ErrVaultFileEditVerification = errors.New("vault-file title edit verification rejected")

// SealVaultFileTitleRename makes the direct sealed child of the authenticated
// local base, or returns the exact saved child after proving the same requested
// edit. A second offline edit is refused. The caller must atomically compare
// the returned full State before preparing these bytes; it is never authority
// to adopt a newly loaded state after this Session releases the journal lock.
func (s *Session) SealVaultFileTitleRename(journalPath string, pin *vaultfile.PolicyCheckpoint, request VaultFileTitleRename) (out VaultFileSealedTitleRename, retErr error) {
	if s == nil {
		return out, ErrSessionLocked
	}
	if request.ItemID == "" || len(request.ItemID) > 256 || request.ExpectedOldTitle == "" ||
		request.NewTitle == "" || request.NewTitle == request.ExpectedOldTitle || pin == nil {
		return out, ErrVaultFileEditVerification
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return out, ErrVaultFileBaselineJournal
	}
	defer func() {
		if j != nil && j.Close() != nil && retErr == nil {
			retErr = ErrVaultFileEditReview
		}
		if retErr != nil {
			clear(out.State.BaseBytes)
			clear(out.State.WorkingBytes)
			clear(out.Sealed)
			out = VaultFileSealedTitleRename{}
		}
	}()
	state, err := j.LoadState()
	if err != nil || len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || state.RemoteRevision == "" {
		return out, ErrVaultFileBaselineJournal
	}
	out.State = state
	legacy, err := j.Load()
	clear(legacy.Bytes)
	if err != vaultfilejournal.ErrEmpty {
		return out, ErrVaultFileEditReview
	}
	prepared, prepErr := j.LoadPrepared()
	defer clear(prepared.Proposal.Bytes)
	if prepErr != nil && prepErr != vaultfilejournal.ErrEmpty {
		return out, ErrVaultFileEditReview
	}
	dirty := !bytes.Equal(state.BaseBytes, state.WorkingBytes)
	if !dirty && prepErr == nil || dirty && state.Generation == 0 || state.Generation == math.MaxUint64 && !dirty {
		return out, ErrVaultFileEditReview
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return out, err
	}
	var candidate *auditCache
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, "vault-file.edit-prepared", s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		device, err := age.ParseX25519Identity(auth.identity.Device)
		if err != nil {
			return invalid
		}
		signer := ed25519.NewKeyFromSeed(auth.identity.Signing)
		defer clear(signer)
		base, err := vaultfile.ParseFile(state.BaseBytes)
		if err != nil || vaultfile.VerifyPolicyCheckpoint(base, pin) != nil || base.Header.VaultID != pin.VaultID ||
			len(base.SignedPolicyProofs) == 0 {
			return ErrVaultFileEditVerification
		}
		policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
		if policy.PolicySeq != base.Header.PolicySeq || !bytes.Equal(vaultfile.PolicyDigest(policy), base.Header.PolicyDigest) {
			return ErrVaultFileEditVerification
		}
		deviceID, ok := localVaultFileWriterDevice(policy, device.Recipient().String(), signer.Public().(ed25519.PublicKey))
		if !ok {
			return ErrVaultFileEditVerification
		}
		_, metadata, items, err := vault.OpenAuthenticatedItems(state.BaseBytes, pin, deviceID, device)
		if err != nil {
			return ErrVaultFileEditVerification
		}
		defer clear(metadata)
		defer clearAuthenticatedItems(items)
		changed := make([]vault.Item, len(items))
		for i := range items {
			changed[i] = vault.CloneItem(items[i])
		}
		defer clearAuthenticatedItems(changed)
		matched := 0
		for i := range changed {
			if changed[i].ID == request.ItemID {
				if changed[i].Title != request.ExpectedOldTitle {
					return ErrVaultFileEditReview
				}
				changed[i].Title = request.NewTitle
				matched++
			}
		}
		if matched != 1 {
			return ErrVaultFileEditReview
		}
		if vault.ValidateItems(metadata, changed) != nil {
			return ErrVaultFileEditVerification
		}
		if dirty {
			if vaultfile.VerifyContentTransition(state.BaseBytes, state.WorkingBytes, pin) != nil {
				return ErrVaultFileEditReview
			}
			working, workingMetadata, workingItems, err := vault.OpenAuthenticatedItems(state.WorkingBytes, pin, deviceID, device)
			if err != nil {
				return ErrVaultFileEditReview
			}
			defer clear(workingMetadata)
			defer clearAuthenticatedItems(workingItems)
			if working.Header.AuthorDeviceID != deviceID || !bytes.Equal(metadata, workingMetadata) ||
				!reflect.DeepEqual(changed, workingItems) {
				return ErrVaultFileEditReview
			}
			if prepErr == nil && (prepared.WorkingGeneration != state.Generation ||
				prepared.Proposal.Generation != state.Generation || prepared.Proposal.OperationID != working.Header.OpID ||
				prepared.Proposal.ExpectedRevision != state.RemoteRevision || !bytes.Equal(prepared.Proposal.Bytes, state.WorkingBytes)) {
				return ErrVaultFileEditReview
			}
			out.Sealed = bytes.Clone(state.WorkingBytes)
		} else {
			if base.Header.ContentSeq == math.MaxUint64 {
				return ErrVaultFileEditReview
			}
			var slot *vaultfile.DeviceSlot
			for i := range base.VUKDeviceSlots {
				if base.VUKDeviceSlots[i].DeviceID == deviceID {
					slot = &base.VUKDeviceSlots[i]
					break
				}
			}
			if slot == nil {
				return ErrVaultFileEditVerification
			}
			vuk, err := vaultfile.OpenVUKForDevice(*slot, pin.VaultID, base.Header.KeyEpoch, deviceID,
				device.Recipient().String(), device)
			if err != nil {
				return ErrVaultFileEditVerification
			}
			defer clear(vuk)
			digest, err := vaultfile.FileDigest(base)
			if err != nil {
				return ErrVaultFileEditVerification
			}
			parentDigest, err := hex.DecodeString(digest)
			if err != nil || len(parentDigest) != 32 {
				return ErrVaultFileEditVerification
			}
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return ErrVaultFileEditVerification
			}
			draft := &vaultfile.File{Format: base.Format, Version: base.Version, SignedPolicyProofs: base.SignedPolicyProofs,
				Header: base.Header}
			draft.Header.ContentSeq++
			draft.Header.PrevDigest = parentDigest
			draft.Header.RevisionID = ""
			draft.Header.OpID = hex.EncodeToString(nonce[:])
			draft.Header.AuthorDeviceID = deviceID
			out.Sealed, err = vault.SealAuthenticatedItems(draft, metadata, changed, pin, vuk, signer)
			if err != nil || vaultfile.VerifyContentTransition(state.BaseBytes, out.Sealed, pin) != nil {
				return ErrVaultFileEditVerification
			}
		}
		candidate = auth.nextCache
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return out, err
	}
	if closeErr != nil {
		return out, ErrCommandClose
	}
	current, err := j.LoadState()
	if err != nil || current.Generation != state.Generation || current.RemoteRevision != state.RemoteRevision ||
		!bytes.Equal(current.BaseBytes, state.BaseBytes) || !bytes.Equal(current.WorkingBytes, state.WorkingBytes) {
		clear(current.BaseBytes)
		clear(current.WorkingBytes)
		return out, ErrVaultFileEditReview
	}
	clear(current.BaseBytes)
	clear(current.WorkingBytes)
	if err := j.Close(); err != nil {
		j = nil
		return out, ErrVaultFileEditReview
	}
	j = nil
	if err := s.active(false); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	s.setAuditCache(candidate)
	return out, nil
}

func localVaultFileWriterDevice(policy *vaultfile.Policy, recipient string, signingKey ed25519.PublicKey) (string, bool) {
	if policy == nil || recipient == "" || len(signingKey) != ed25519.PublicKeySize {
		return "", false
	}
	var matched string
	for _, device := range policy.Devices {
		if device.AgeEncryptionKey != recipient || device.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
			!bytes.Equal(device.ContentSigningKey.PublicKey, signingKey) || !vaultFileWriterPrincipal(policy, device.PrincipalID) {
			continue
		}
		if matched != "" {
			return "", false
		}
		matched = device.DeviceID
	}
	return matched, matched != ""
}

func vaultFileWriterPrincipal(policy *vaultfile.Policy, principal string) bool {
	for _, members := range [][]vaultfile.Member{policy.Writers, policy.Admins, policy.Owners} {
		for _, member := range members {
			if member.PrincipalID == principal {
				return true
			}
		}
	}
	return false
}
