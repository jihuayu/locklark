package personal

import (
	"crypto/hmac"
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const passkeyRemoveAction = "item.passkey.remove"

// ReadPasskeysMetadata returns public passkey metadata keyed by item ID, one
// entry per durable credential of that login. The projection happens while the
// authenticated items are still owned by the transaction; callers never receive
// the raw record or its private key.
func (s *Session) ReadPasskeysMetadata(touch bool) (map[string][]passkey.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(touch); err != nil {
		return nil, err
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	metadata := map[string][]passkey.Metadata{}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyGetAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		for _, item := range auth.items {
			var values []passkey.Metadata
			for _, raw := range item.PasskeyRecords() {
				value, err := passkey.MetadataFromRecord(raw)
				if err != nil {
					continue
				}
				values = append(values, value)
			}
			if len(values) > 0 {
				metadata[item.ID] = values
			}
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil && err == nil {
		err = ErrCommandClose
	}
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return nil, err
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	return metadata, nil
}

// ReadPasskeyMetadata is the single-credential compatibility projection. It
// returns only the logins whose metadata is unambiguous, i.e. exactly one
// durable credential. A login with several credentials is reported as absent
// rather than as its first record, so callers that only understand one
// credential per login can never silently act on an arbitrary sibling.
func (s *Session) ReadPasskeyMetadata(touch bool) (map[string]passkey.Metadata, error) {
	all, err := s.ReadPasskeysMetadata(touch)
	if err != nil {
		return nil, err
	}
	metadata := map[string]passkey.Metadata{}
	for id, values := range all {
		if len(values) == 1 {
			metadata[id] = values[0]
		}
	}
	return metadata, nil
}

// PasskeyRevocationEpoch returns the session-wide passkey revocation sequence.
// Browser connections capture it when a pending passkey request starts and
// compare it again before delivering a queued credential response. The epoch is
// monotonic and never grows an unbounded revocation table.
func (s *Session) PasskeyRevocationEpoch() uint64 {
	if s == nil {
		return 0
	}
	return s.passkeyEpoch.Load()
}

// RemovePasskey removes exactly the credential named by credentialID from one
// login through the authenticated, exact-revision, gated mutation path. Every
// other durable item field, every sibling credential and the item's
// active/archived state are preserved. Trashed items are refused. Removing the
// last credential clears both persisted passkey forms; removing one of several
// keeps the versioned collection. The audit, signed snapshot and encrypted
// record removal share one transaction.
func (s *Session) RemovePasskey(id, revision, credentialID string, g *MutationGate) (string, error) {
	return s.removePasskey(id, revision, credentialID, "", g)
}

func (s *Session) removePasskey(id, revision, credentialID, credentialRevision string, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) || !passkey.ValidCredentialID(credentialID) || credentialRevision != "" && !digestOK(credentialRevision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	defer s.ReleaseMutation(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return "", ErrMutationCancelled
	}
	db, err := existing(s.path)
	if err != nil {
		return "", ErrMutationRefused
	}
	var nextRevision string
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyRemoveAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		if auth.revisions[id] == "" {
			return ErrNotFound
		}
		if auth.revisions[id] != revision {
			return ErrConflict
		}
		index := -1
		for n := range auth.items {
			if auth.items[n].ID != id {
				continue
			}
			if index >= 0 {
				return invalid
			}
			index = n
		}
		if index < 0 {
			return ErrNotFound
		}
		current := auth.items[index]
		if current.State == "trashed" {
			return ErrTrashed
		}
		if current.Kind != "login" || current.EffectiveCategory() != vault.CategoryLogin {
			return ErrMutationRefused
		}
		records := current.PasskeyRecords()
		if len(records) == 0 {
			return ErrMutationRefused
		}
		// Select exactly one credential. Unreadable records are preserved
		// byte-for-byte instead of being dropped by a selector mismatch.
		remaining := make([][]byte, 0, len(records))
		matched := false
		for _, raw := range records {
			record, err := passkey.Load(raw)
			if err != nil {
				remaining = append(remaining, raw)
				continue
			}
			remove := record.ID == credentialID
			if remove && credentialRevision != "" {
				// The child revision is checked against the authenticated record
				// before the commit gate, while the parent CAS is still mandatory.
				actual, revisionErr := credentialRevisionFromRecord(auth.identity.AuditEncryption, id, record)
				if revisionErr != nil || !hmac.Equal([]byte(actual), []byte(credentialRevision)) {
					record.Clear()
					return ErrMutationRefused
				}
			}
			record.Clear()
			if remove {
				matched = true
				continue
			}
			remaining = append(remaining, raw)
		}
		if !matched {
			return ErrMutationRefused
		}
		// All selectors, state and the credential identity are now verified.
		// Win the one-shot commit decision before either revoking queued output
		// or writing the snapshot. Winning is not a persistence receipt.
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		// Conservative revocation: a later snapshot/audit failure never
		// restores credentials queued on another shared connection.
		s.passkeyEpoch.Add(1)
		items := append([]vault.Item(nil), auth.items...)
		next := vault.CloneItem(current)
		if len(remaining) == 0 {
			// The last credential is gone: both persisted forms are cleared so
			// the login cannot keep an empty-but-present passkey slot.
			next.ClearPasskeys()
		} else {
			// Removing one of several keeps the versioned collection, even when
			// a single sibling remains. SetPasskeyRecords clones before the
			// borrowed durable bytes below are zeroed.
			if err := next.SetPasskeyRecords(remaining); err != nil {
				return ErrMutationRefused
			}
		}
		current.ClearPasskeys()
		next.UpdatedAt = time.Now().Unix()
		items[index] = next
		if vault.ValidateItems([]byte(schema), items) != nil {
			return ErrMutationRefused
		}
		snapshot, err := seal(tx.Bucket(bucket), auth.identity, auth.snapshot.Epoch+1, items)
		if err != nil {
			return err
		}
		event, err := appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, snapshot, passkeyRemoveAction, id, "succeeded", revision, "", eventDetails{})
		if err != nil {
			return err
		}
		nextRevision = event.hash()
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if err != nil || closeErr != nil || !active {
		if g.CommitWon() {
			return "", ErrMutationUnknown
		}
		if !active {
			return "", ErrMutationCancelled
		}
		if err != nil {
			return "", err
		}
		return "", ErrMutationRefused
	}
	if nextRevision == "" {
		return "", ErrMutationUnknown
	}
	return nextRevision, nil
}
