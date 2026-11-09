package personal

import (
	"errors"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
	bolt "go.etcd.io/bbolt"
)

// NewPasskeyTransferInvitation signs a short-lived invitation with the current
// unlocked vault's existing age recipient and Ed25519 audit seed. It requires
// an explicitly registered mutation gate, appends one known audit event under
// the same transaction and only returns a success receipt after the database
// is closed and the session is still active.
func (s *Session) NewPasskeyTransferInvitation(ttl time.Duration, g *MutationGate) (PasskeyTransferInvitation, error) {
	return s.newPasskeyTransferInvitation(ttl, g, nil, nil)
}

func (s *Session) newPasskeyTransferInvitation(ttl time.Duration, g *MutationGate, afterCommit func(), closeDB func(*bolt.DB) error) (out PasskeyTransferInvitation, err error) {
	defer s.ReleaseMutation(g)
	if ttl < time.Second || ttl > 15*time.Minute {
		return PasskeyTransferInvitation{}, ErrMutationRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return PasskeyTransferInvitation{}, ErrMutationCancelled
	}
	// Freshness is checked before the database is opened, so a quick-unlock or
	// otherwise unproven session refuses without touching vault bytes.
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		return PasskeyTransferInvitation{}, freshErr
	}
	db, err := existing(s.path)
	if err != nil {
		return PasskeyTransferInvitation{}, ErrMutationRefused
	}
	var raw []byte
	var candidate *auditCache
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyTransferInviteAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		public, err := transferPublicIdentity(auth.identity)
		if err != nil {
			return invalid
		}
		device, err := age.ParseX25519Identity(auth.identity.Device)
		if err != nil {
			return invalid
		}
		now := time.Now()
		inviteRaw, invite, err := passkeytransfer.CreateInvite(device.Recipient(), auth.identity.Audit, now, ttl)
		if err != nil {
			return ErrMutationRefused
		}
		defer clear(inviteRaw)
		verified, err := passkeytransfer.VerifyInvitation(inviteRaw, public.Fingerprint, now)
		if err != nil || verified.ID != invite.ID || invite.Fingerprint() != public.Fingerprint || invite.Recipient != public.Recipient || invite.AuditPublic != public.AuditPublic {
			return invalid
		}
		for _, row := range auth.rows {
			if passkeyTransferAction(row.Action) && row.Item == invite.ID {
				return invalid
			}
		}
		link, err := passkeyTransferInviteLink(auth.identity.AuditEncryption, invite)
		if err != nil {
			return invalid
		}
		// The proof must still be fresh at commit time, not only when the
		// transaction started.
		if freshErr := s.requireFreshFullFactor(); freshErr != nil {
			return freshErr
		}
		// Winning the registered gate is required before the audit append. It
		// is not by itself a persistence or delivery receipt.
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		if _, err = appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, auth.snapshot, passkeyTransferInviteAction, invite.ID, "succeeded", "", link); err != nil {
			return err
		}
		candidate = auth.nextCache
		raw = append([]byte(nil), inviteRaw...)
		out = PasskeyTransferInvitation{Raw: raw, Public: public, ExpiresAt: time.Unix(invite.ExpiresAt, 0), ID: invite.ID}
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
		clear(raw)
		out = PasskeyTransferInvitation{}
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
	if out.ID == "" || len(out.Raw) == 0 {
		clear(raw)
		return PasskeyTransferInvitation{}, ErrMutationUnknown
	}
	s.setAuditCache(candidate)
	return out, nil
}

// RevokePasskeyTransferInvitation verifies that rawInvite is a canonical,
// signed invitation for this unlocked identity and derives one-use/revoke
// authority only from the complete authenticated current audit chain.
func (s *Session) RevokePasskeyTransferInvitation(rawInvite []byte, g *MutationGate) error {
	return s.revokePasskeyTransferInvitation(rawInvite, g, nil, nil)
}

func (s *Session) revokePasskeyTransferInvitation(rawInvite []byte, g *MutationGate, afterCommit func(), closeDB func(*bolt.DB) error) (err error) {
	defer s.ReleaseMutation(g)
	if len(rawInvite) == 0 || len(rawInvite) > maxPasskeyTransferInvitation {
		return ErrMutationRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return ErrMutationCancelled
	}
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		return freshErr
	}
	db, err := existing(s.path)
	if err != nil {
		return ErrMutationRefused
	}
	var revoked bool
	var candidate *auditCache
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyTransferRevokeAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		public, err := transferPublicIdentity(auth.identity)
		if err != nil {
			return invalid
		}
		invite, err := passkeytransfer.VerifyInvitation(rawInvite, public.Fingerprint, time.Now())
		if err != nil || invite.Recipient != public.Recipient || invite.AuditPublic != public.AuditPublic {
			return ErrMutationRefused
		}
		link, err := passkeyTransferInviteLink(auth.identity.AuditEncryption, invite)
		if err != nil {
			return invalid
		}
		creation, err := scanPasskeyTransferRows(auth.rows, invite.ID, link)
		if err != nil {
			return ErrMutationRefused
		}
		if freshErr := s.requireFreshFullFactor(); freshErr != nil {
			return freshErr
		}
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		if _, err = appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, auth.snapshot, passkeyTransferRevokeAction, invite.ID, "succeeded", creation, link); err != nil {
			return err
		}
		candidate = auth.nextCache
		revoked = true
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
		if g.CommitWon() {
			return ErrMutationUnknown
		}
		if !active {
			return ErrMutationCancelled
		}
		if err != nil {
			return err
		}
		return ErrMutationRefused
	}
	if !revoked {
		return ErrMutationUnknown
	}
	s.setAuditCache(candidate)
	return nil
}
