package personal

import (
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const passkeyRemoveAction = "item.passkey.remove"

// ReadPasskeyMetadata returns public passkey metadata keyed by item ID. The
// projection happens while the authenticated items are still owned by the
// transaction; callers never receive the raw record or its private key.
func (s *Session) ReadPasskeyMetadata(touch bool) (map[string]passkey.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(touch); err != nil {
		return nil, err
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	metadata := map[string]passkey.Metadata{}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyGetAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		for _, item := range auth.items {
			if len(item.Passkey) == 0 {
				continue
			}
			value, err := passkey.MetadataFromRecord(item.Passkey)
			if err != nil {
				continue
			}
			metadata[item.ID] = value
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

// RemovePasskey clears exactly the persisted passkey of one login through the
// authenticated, exact-revision, gated mutation path. Every other durable item
// field and the item's active/archived state are preserved. Trashed items are
// refused. The audit, signed snapshot and encrypted record removal share one
// transaction.
func (s *Session) RemovePasskey(id, revision, credentialID string, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) || !passkey.ValidCredentialID(credentialID) {
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
		if len(current.Passkey) == 0 {
			return ErrMutationRefused
		}
		record, err := passkey.Load(current.Passkey)
		if err != nil {
			return ErrMutationRefused
		}
		matches := record.ID == credentialID
		record.Clear()
		if !matches {
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
		next.Passkey = nil
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
