package personal

import (
	"errors"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// Caller holds Session.mu; this worker-only path never appends audit or touches
// idle time. The complete authentication implementation is shared with writes.
func (s *Session) readNativeTarget(id, revision string, inspect func(vault.Item) error) (err error) {
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return e
	}
	defer func() { err = s.finishNativeRead(err, db.Close()) }()
	return db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "desktop.native.verify", s)
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

func (s *Session) finishNativeRead(err, closeErr error) error {
	if errors.Is(err, invalid) {
		s.lock()
	}
	if closeErr != nil {
		return ErrCommandClose
	}
	return err
}
