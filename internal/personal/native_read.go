package personal

import (
	"context"
	"errors"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// Caller holds Session.mu; this worker-only path never appends audit or touches
// idle time. The complete authentication implementation is shared with writes.
func (s *Session) readNativeTarget(id, revision string, inspect func(vault.Item) error) (err error) {
	return s.readNativeTargetWithPurpose(id, revision, "desktop.native.verify", inspect)
}
func (s *Session) readNativeTargetWithPurpose(id, revision, purpose string, inspect func(vault.Item) error) (err error) {
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return e
	}
	defer func() { err = s.finishNativeRead(err, db.Close()) }()
	return db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, purpose, s)
		if e != nil {
			return e
		}
		defer a.clear()
		rev := a.revisions[id]
		if rev == "" {
			return ErrNotFound
		}
		if rev != revision {
			return ErrConflict
		}
		for _, item := range a.items {
			if item.ID == id {
				if item.Kind != "login" {
					return invalid
				}
				if item.State == "trashed" {
					return ErrTrashed
				}
				return inspect(item)
			}
		}
		return invalid
	})
}

// CheckBrokeredRunRevisions verifies that every target still names the exact
// authenticated current revision. It decrypts no item payloads, writes no
// audit event, and does not touch idle time. Any absent, changed, malformed or
// unavailable target is refused with the corresponding error; no field, value
// or digest is returned.
func (s *Session) CheckBrokeredRunRevisions(ctx context.Context, targets []CLIBrokerTarget) (err error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrRunCancelled
	}
	if s == nil {
		return ErrSessionLocked
	}
	if len(targets) < 1 || len(targets) > 16 {
		return ErrRunCredential
	}
	for _, target := range targets {
		if !idOK(target.ID) || !digestOK(target.Revision) {
			return ErrRunCredential
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ErrRunCancelled
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return e
	}
	defer func() { err = s.finishNativeRead(err, db.Close()) }()
	err = db.View(func(tx *bolt.Tx) error {
		a, e := authenticateStateItems(tx, "", nil, "desktop.native.verify", s, false)
		if e != nil {
			return e
		}
		defer a.clear()
		for _, target := range targets {
			revision := a.revisions[target.ID]
			if revision == "" {
				return ErrNotFound
			}
			if revision != target.Revision {
				return ErrConflict
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrRunCancelled
	}
	if e := s.active(false); e != nil {
		return e
	}
	return nil
}

func (s *Session) finishNativeRead(err, closeErr error) error {
	if errors.Is(err, invalid) {
		s.lock()
	}
	if closeErr != nil {
		return ErrCommandClose
	}
	return err
}
