package personal

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

// VaultFileBaselineItem is the read-only disclosure from a local baseline.
// ID is present only in the explicit item-reference mode; it is a selector,
// never proof of a grant or authority. Secrets and KDBX handles never leave Session.
type VaultFileBaselineItem struct {
	ID       string             `json:"id,omitempty"`
	Title    string             `json:"title"`
	Category vault.ItemCategory `json:"category"`
}

var ErrVaultFileBaselineJournal = errors.New("vault-file baseline journal rejected")
var ErrVaultFileBaselineVerification = errors.New("vault-file baseline verification rejected")

// OpenVaultFileBaseline opens exactly the existing journal's saved BaseBytes.
// The journal stays locked through verification and decryption; it is never
// written, reconciled or compared with a remote backend. The caller supplies
// the independent checkpoint and checks the journal's physical scope.
func (s *Session) OpenVaultFileBaseline(journalPath string, checkpoint *vaultfile.PolicyCheckpoint) ([]VaultFileBaselineItem, error) {
	return s.openVaultFileBaseline(journalPath, checkpoint, false)
}

// OpenVaultFileBaselineWithItemIDs applies the same full-factor, policy,
// device, journal and freshness checks, then includes existing item data IDs
// in the bounded summary. IDs only locate items for an explicit later edit.
func (s *Session) OpenVaultFileBaselineWithItemIDs(journalPath string, checkpoint *vaultfile.PolicyCheckpoint) ([]VaultFileBaselineItem, error) {
	return s.openVaultFileBaseline(journalPath, checkpoint, true)
}

func (s *Session) openVaultFileBaseline(journalPath string, checkpoint *vaultfile.PolicyCheckpoint, includeItemIDs bool) ([]VaultFileBaselineItem, error) {
	if s == nil {
		return nil, ErrSessionLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return nil, err
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	if checkpoint == nil || checkpoint.VaultID == "" {
		return nil, ErrVaultFileBaselineVerification
	}
	journal, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return nil, ErrVaultFileBaselineJournal
	}
	defer func() {
		if journal != nil {
			_ = journal.Close()
		}
	}()
	state, err := journal.LoadState()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if err != nil || len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || len(state.RemoteRevision) == 0 {
		return nil, ErrVaultFileBaselineJournal
	}
	// One owned byte sequence is used for both the policy proof and the KDBX
	// open. Neither the journal nor a callback can replace it between steps.
	encoded := bytes.Clone(state.BaseBytes)
	defer clear(encoded)

	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	var out []VaultFileBaselineItem
	var candidate *auditCache
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, "vault-file.open-baseline", s, false)
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
		file, err := vaultfile.ParseFile(encoded)
		if err != nil || vaultfile.VerifyPolicyCheckpoint(file, checkpoint) != nil || file.Header.VaultID != checkpoint.VaultID {
			return ErrVaultFileBaselineVerification
		}
		// ValidateFile and VerifyPolicyCheckpoint require the last proof to be
		// the authenticated current policy. No carried roster is used earlier.
		if len(file.SignedPolicyProofs) == 0 {
			return ErrVaultFileBaselineVerification
		}
		policy := &file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1].Policy
		if policy.PolicySeq != file.Header.PolicySeq || !bytes.Equal(vaultfile.PolicyDigest(policy), file.Header.PolicyDigest) {
			return ErrVaultFileBaselineVerification
		}
		deviceID, ok := localVaultFileReaderDevice(policy, device.Recipient().String(), signer.Public().(ed25519.PublicKey))
		if !ok {
			return ErrVaultFileBaselineVerification
		}
		_, metadata, items, err := vault.OpenAuthenticatedItems(encoded, checkpoint, deviceID, device)
		if err != nil {
			return ErrVaultFileBaselineVerification
		}
		defer clear(metadata)
		defer clearAuthenticatedItems(items)
		out = make([]VaultFileBaselineItem, 0, len(items))
		for _, item := range items {
			summary := VaultFileBaselineItem{Title: item.Title, Category: item.EffectiveCategory()}
			if includeItemIDs {
				summary.ID = item.ID
			}
			out = append(out, summary)
		}
		candidate = auth.nextCache
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, ErrCommandClose
	}
	// A cooperating journal writer cannot change this generation under the
	// held lock. Check it again before closing to refuse unexpected drift.
	current, err := journal.LoadState()
	if err != nil || current.Generation != state.Generation || current.RemoteRevision != state.RemoteRevision ||
		!bytes.Equal(current.BaseBytes, state.BaseBytes) || !bytes.Equal(current.WorkingBytes, state.WorkingBytes) {
		clear(current.BaseBytes)
		clear(current.WorkingBytes)
		return nil, ErrVaultFileBaselineJournal
	}
	clear(current.BaseBytes)
	clear(current.WorkingBytes)
	closeErr = journal.Close()
	journal = nil
	if closeErr != nil {
		return nil, ErrVaultFileBaselineJournal
	}
	if err := s.active(false); err != nil {
		return nil, err
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	s.setAuditCache(candidate)
	return out, nil
}

// The read grant is from the already authenticated current policy only. A
// matching recipient without the same content-signing public identity, or a
// device whose principal lacks a reader-or-stronger role, is never selected.
func localVaultFileReaderDevice(policy *vaultfile.Policy, recipient string, signingKey ed25519.PublicKey) (string, bool) {
	if policy == nil || recipient == "" || len(signingKey) != ed25519.PublicKeySize {
		return "", false
	}
	var matched string
	for _, device := range policy.Devices {
		if device.AgeEncryptionKey != recipient || device.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
			!bytes.Equal(device.ContentSigningKey.PublicKey, signingKey) || !vaultFileReadablePrincipal(policy, device.PrincipalID) {
			continue
		}
		if matched != "" {
			return "", false
		}
		matched = device.DeviceID
	}
	return matched, matched != ""
}

func vaultFileReadablePrincipal(policy *vaultfile.Policy, principal string) bool {
	for _, members := range [][]vaultfile.Member{policy.Readers, policy.Writers, policy.Admins, policy.Owners} {
		for _, member := range members {
			if member.PrincipalID == principal {
				return true
			}
		}
	}
	return false
}
