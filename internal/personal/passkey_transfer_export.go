package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const (
	passkeyTransferExportAction     = "vault.passkey.transfer.export"
	passkeyTransferExportLinkDomain = "locklark/personal/passkey-transfer/export/v1\x00"
	maxPasskeyTransferExportTargets = 16
)

// PasskeyTransferTarget is one explicit public source selector. It names an
// exact active login item revision and one exact credential content revision.
// It carries no private key or record bytes.
type PasskeyTransferTarget struct {
	ItemID             string
	Revision           string
	CredentialID       string
	CredentialRevision string
}

// PasskeyTransferExport is the public success receipt. Raw is the signed
// ciphertext packet; it is public transport material, but it is still redacted
// from fmt and JSON so raw bytes never reach diagnostics.
type PasskeyTransferExport struct {
	Raw               []byte
	PacketID          string
	SourceFingerprint string
	TargetFingerprint string
}

func (PasskeyTransferExport) String() string               { return "[passkey transfer export]" }
func (PasskeyTransferExport) GoString() string             { return "[passkey transfer export]" }
func (PasskeyTransferExport) MarshalJSON() ([]byte, error) { return nil, ErrMutationRefused }

type passkeyTransferExportSelector struct {
	ItemID             string `json:"item_id"`
	Revision           string `json:"revision"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision string `json:"credential_revision"`
}

// validatePasskeyTransferTargets refuses a non-canonical selector, a duplicate
// exact selector and a duplicate credential ID before any session or database
// work. It never touches record bytes.
func validatePasskeyTransferTargets(targets []PasskeyTransferTarget) error {
	if len(targets) == 0 || len(targets) > maxPasskeyTransferExportTargets {
		return ErrMutationRefused
	}
	seenCredential := make(map[string]bool, len(targets))
	seenSelector := make(map[string]bool, len(targets))
	for _, target := range targets {
		if !idOK(target.ItemID) || !digestOK(target.Revision) || !passkey.ValidCredentialID(target.CredentialID) || !digestOK(target.CredentialRevision) {
			return ErrMutationRefused
		}
		selector := target.ItemID + "\x00" + target.CredentialID
		if seenCredential[target.CredentialID] || seenSelector[selector] {
			return ErrMutationRefused
		}
		seenCredential[target.CredentialID] = true
		seenSelector[selector] = true
	}
	return nil
}

// passkeyTransferExportLink binds the canonical public selectors, the explicit
// target pin, the invitation digest, the packet digest and the packet ID with
// one keyed HMAC. No selector is persisted in a public audit field.
func passkeyTransferExportLink(key []byte, targets []PasskeyTransferTarget, targetPin, invitationDigest, packetDigest, packetID string) (string, error) {
	if len(key) == 0 || validatePasskeyTransferTargets(targets) != nil || !digestOK(targetPin) || !digestOK(invitationDigest) || !digestOK(packetDigest) || !idOK(packetID) {
		return "", invalid
	}
	selectors := make([]passkeyTransferExportSelector, len(targets))
	for i, target := range targets {
		selectors[i] = passkeyTransferExportSelector{target.ItemID, target.Revision, target.CredentialID, target.CredentialRevision}
	}
	canonical, err := json.Marshal(selectors)
	if err != nil || len(canonical) == 0 {
		return "", invalid
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(passkeyTransferExportLinkDomain))
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(canonical)))
	mac.Write(frame[:])
	mac.Write(canonical)
	mac.Write([]byte(targetPin))
	mac.Write([]byte(invitationDigest))
	mac.Write([]byte(packetDigest))
	mac.Write([]byte(packetID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// verifyPasskeyTransferExportEvent is the exact known-format branch for the
// export intent. It is deliberately not part of passkeyTransferAction: the
// invitation scanner must only ever see invite/revoke/consume state.
func verifyPasskeyTransferExportEvent(e Event, n uint64) error {
	if n <= 1 || !idOK(e.Item) || e.Result != "intent" || e.BaseRevision != "" || !digestOK(e.Link) || e.ReportDigest != "" || e.Generation != nil {
		return invalid
	}
	return nil
}

// ExportPasskeyTransfer seals the explicitly selected durable credentials for
// the pinned remote invitation recipient. It never deletes or mutates a source
// credential and never trusts the packet's self-declared target without the
// caller's explicit targetPin. The receiver must revalidate its current
// invitation audit chain later; the source cannot know receiver revocation.
func (s *Session) ExportPasskeyTransfer(rawInvitation []byte, targetPin string, targets []PasskeyTransferTarget, g *MutationGate) (PasskeyTransferExport, error) {
	return s.exportPasskeyTransfer(rawInvitation, targetPin, targets, g, nil, nil)
}

func (s *Session) exportPasskeyTransfer(rawInvitation []byte, targetPin string, targets []PasskeyTransferTarget, g *MutationGate, afterCommit func(), closeDB func(*bolt.DB) error) (out PasskeyTransferExport, err error) {
	defer s.ReleaseMutation(g)
	if len(rawInvitation) == 0 || len(rawInvitation) > maxPasskeyTransferInvitation || !digestOK(targetPin) {
		return PasskeyTransferExport{}, ErrMutationRefused
	}
	if validatePasskeyTransferTargets(targets) != nil {
		return PasskeyTransferExport{}, ErrMutationRefused
	}
	invitation, err := passkeytransfer.VerifyInvitation(rawInvitation, targetPin, time.Now())
	if err != nil || invitation == nil {
		return PasskeyTransferExport{}, ErrMutationRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return PasskeyTransferExport{}, ErrMutationCancelled
	}
	// No database is opened and no credential record is read for an
	// unproven session.
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		return PasskeyTransferExport{}, freshErr
	}
	db, err := existing(s.path)
	if err != nil {
		return PasskeyTransferExport{}, ErrMutationRefused
	}
	var packet []byte
	var candidate *auditCache
	err = db.Update(func(tx *bolt.Tx) (txErr error) {
		defer func() {
			if txErr != nil {
				clear(packet)
				packet = nil
			}
		}()
		auth, authErr := authenticateState(tx, "", nil, passkeyTransferExportAction, s)
		if authErr != nil {
			return authErr
		}
		defer auth.clear()
		device, deviceErr := age.ParseX25519Identity(auth.identity.Device)
		if deviceErr != nil {
			return invalid
		}
		auditPriv := ed25519.NewKeyFromSeed(auth.identity.Audit)
		sourceFingerprint, fingerprintErr := passkeytransfer.PublicFingerprint(device.Recipient().String(), auditPriv.Public().(ed25519.PublicKey))
		clear(auditPriv)
		if fingerprintErr != nil {
			return invalid
		}
		selections := make([]passkeytransfer.Selection, 0, len(targets))
		owned := make([][]byte, 0, len(targets))
		defer func() {
			for _, raw := range owned {
				clear(raw)
			}
		}()
		for _, target := range targets {
			index := -1
			for n := range auth.items {
				if auth.items[n].ID == target.ItemID {
					if index >= 0 {
						return invalid
					}
					index = n
				}
			}
			if index < 0 || auth.revisions[target.ItemID] != target.Revision {
				return ErrMutationRefused
			}
			item := auth.items[index]
			category, ok := vault.CategoryFromKind(item.Kind, item.Category)
			if !ok || category != vault.CategoryLogin || item.State != "" {
				return ErrMutationRefused
			}
			var recordRaw []byte
			for _, candidateRaw := range item.PasskeyRecords() {
				record, loadErr := passkey.Load(candidateRaw)
				if loadErr != nil {
					clear(recordRaw)
					return ErrMutationRefused
				}
				if record.ID == target.CredentialID {
					if recordRaw != nil {
						// No first-record fallback: two records with the same
						// canonical ID are ambiguous and refused.
						record.Clear()
						clear(recordRaw)
						return invalid
					}
					actual, revisionErr := credentialRevisionFromRecord(auth.identity.AuditEncryption, item.ID, record)
					if revisionErr != nil || actual != target.CredentialRevision {
						record.Clear()
						return ErrMutationRefused
					}
					recordRaw = bytes.Clone(candidateRaw)
				}
				record.Clear()
			}
			if len(recordRaw) == 0 {
				return ErrMutationRefused
			}
			owned = append(owned, recordRaw)
			selections = append(selections, passkeytransfer.Selection{
				SourceItemID:       item.ID,
				SourceRevision:     target.Revision,
				CredentialID:       target.CredentialID,
				CredentialRevision: target.CredentialRevision,
				Title:              item.Title,
				Record:             recordRaw,
			})
		}
		var sealErr error
		packet, sealErr = passkeytransfer.SealSelection(rawInvitation, targetPin, device.Recipient(), auth.identity.Audit, selections, time.Now())
		if sealErr != nil {
			return ErrMutationRefused
		}
		var parsed passkeytransfer.Packet
		if json.Unmarshal(packet, &parsed) != nil || !idOK(parsed.ID) || parsed.InvitationID != invitation.ID || parsed.TargetFingerprint != targetPin || parsed.SourceRecipient != device.Recipient().String() {
			return invalid
		}
		invitationDigest := sha256.Sum256(rawInvitation)
		packetDigest := sha256.Sum256(packet)
		link, linkErr := passkeyTransferExportLink(auth.identity.AuditEncryption, targets, targetPin, hex.EncodeToString(invitationDigest[:]), hex.EncodeToString(packetDigest[:]), parsed.ID)
		if linkErr != nil {
			return invalid
		}
		// The proof must still be fresh at commit time: sealing and the audit
		// intent must not happen on an expired full-factor proof.
		if freshErr := s.requireFreshFullFactor(); freshErr != nil {
			return freshErr
		}
		// Win the registered gate only after every validation and the packet
		// exist. The audit intent is appended in this same transaction and the
		// snapshot (epoch, items, revisions) stays unchanged.
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		if _, appendErr := appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, auth.snapshot, passkeyTransferExportAction, parsed.ID, "intent", "", link); appendErr != nil {
			return appendErr
		}
		candidate = auth.nextCache
		out = PasskeyTransferExport{Raw: packet, PacketID: parsed.ID, SourceFingerprint: sourceFingerprint, TargetFingerprint: targetPin}
		return nil
	})
	if afterCommit != nil {
		afterCommit()
	}
	closeErr := db.Close()
	if closeDB != nil {
		closeErr = closeDB(db)
	}
	if errors.Is(err, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if err != nil || closeErr != nil || !active {
		clear(out.Raw)
		out = PasskeyTransferExport{}
		if g.CommitWon() {
			return out, ErrMutationUnknown
		}
		if !active {
			return out, ErrMutationCancelled
		}
		if err != nil {
			return out, err
		}
		return out, ErrMutationRefused
	}
	if out.PacketID == "" || len(out.Raw) == 0 {
		clear(out.Raw)
		out = PasskeyTransferExport{}
		return out, ErrMutationUnknown
	}
	s.setAuditCache(candidate)
	return out, nil
}
