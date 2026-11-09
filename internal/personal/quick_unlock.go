package personal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

// Fixed, user-safe failures for the system quick-unlock path. They are
// deliberately distinct from ErrSessionLocked: a missing entitlement, an
// expired capsule or a dismissed OS prompt must not be reported as "unlock the
// vault again".
var (
	ErrSystemUnlockUnavailable = errors.New("system quick unlock is unavailable")
	ErrSystemUnlockExpired     = errors.New("system quick unlock has expired")
)

// SystemUnlockStore is a trusted native OS adapter, never a renderer binding.
// Store must protect data with the OS; Load must enforce its authentication
// policy. There is deliberately no plaintext-file fallback.
type SystemUnlockStore interface {
	Store(string, []byte) error
	Load(string) ([]byte, error)
	Delete(string) error
}

// Serialize OS enrollment/load/delete so a cancelled enrollment cannot remove a
// newer enrollment. This mutex is never taken by Session.Lock.
var systemUnlockOperations sync.Mutex

type systemCapsule struct {
	Version  int       `json:"version"`
	Path     string    `json:"path"`
	Slot     [32]byte  `json:"slot"`
	Identity []byte    `json:"identity"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

func systemStoreID(path string) (string, string, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return "", "", ErrSessionLocked
	}
	hash := sha256.Sum256([]byte("locklark/system-unlock/v1\x00" + absolute))
	return hex.EncodeToString(hash[:]), absolute, nil
}

// EnableSystemUnlock requires this session's full-factor unlock and does not
// extend its fixed 24-hour deadline. The OS adapter may prompt during enrollment.
func (s *Session) EnableSystemUnlock(store SystemUnlockStore) error {
	systemUnlockOperations.Lock()
	defer systemUnlockOperations.Unlock()
	raw, id, e := s.prepareSystemUnlock(store)
	if e != nil {
		return e
	}
	defer clear(raw)
	if s.lockRequested.Load() {
		return ErrSessionLocked
	}
	if e := store.Store(id, raw); e != nil {
		return errors.Join(ErrSystemUnlockUnavailable, e)
	}
	s.mu.Lock()
	active := s.active(false) == nil
	s.mu.Unlock()
	if !active {
		// OS deletion can itself fail; report failure, never report enrollment success.
		_ = store.Delete(id)
		return ErrSessionLocked
	}
	return nil
}
func (s *Session) prepareSystemUnlock(store SystemUnlockStore) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if store == nil || s.active(false) != nil {
		return nil, "", ErrSessionLocked
	}
	if s.fullUnlock.IsZero() || time.Since(s.fullUnlock) < 0 || time.Since(s.fullUnlock) >= 24*time.Hour {
		return nil, "", ErrSystemUnlockExpired
	}
	id, path, e := systemStoreID(s.path)
	if e != nil {
		return nil, "", e
	}
	if _, e = s.execute("desktop.system.enable", vault.Item{}, nil, commandOption{}); e != nil {
		return nil, "", e
	}
	capsule := systemCapsule{1, path, s.slotDigest, s.material, s.fullUnlock, s.fullUnlock.Add(24 * time.Hour)}
	raw, e := json.Marshal(capsule)
	if e != nil {
		return nil, "", ErrSessionLocked
	}
	return raw, id, nil
}

// UnlockWithSystem validates the original encrypted slot and the full audit /
// snapshot transaction before returning an unlocked session. No OS error detail
// or material crosses this API. The password path is always available separately.
func UnlockWithSystem(path string, store SystemUnlockStore, idle time.Duration) (*Session, error) {
	return UnlockWithSystemContext(context.Background(), path, store, idle)
}
func UnlockWithSystemContext(ctx context.Context, path string, store SystemUnlockStore, idle time.Duration) (*Session, error) {
	systemUnlockOperations.Lock()
	defer systemUnlockOperations.Unlock()
	if ctx == nil || ctx.Err() != nil || store == nil || idle < time.Second || idle > 15*time.Minute {
		return nil, ErrSessionLocked
	}
	id, absolute, e := systemStoreID(path)
	if e != nil {
		return nil, e
	}
	raw, e := store.Load(id)
	defer clear(raw)
	if ctx.Err() != nil {
		return nil, ErrSessionLocked
	}
	if e != nil {
		return nil, errors.Join(ErrSystemUnlockUnavailable, e)
	}
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, ErrSystemUnlockExpired
	}
	var capsule systemCapsule
	defer func() { clear(capsule.Identity) }()
	if json.Unmarshal(raw, &capsule) != nil {
		return nil, ErrSystemUnlockExpired
	}
	now := time.Now()
	if capsule.Version != 1 || capsule.Path != absolute || len(capsule.Identity) == 0 || now.Before(capsule.Created) || !now.Before(capsule.Expires) || capsule.Expires.Sub(capsule.Created) != 24*time.Hour {
		return nil, ErrSystemUnlockExpired
	}
	s := &Session{path: path, material: append([]byte(nil), capsule.Identity...), slotDigest: capsule.Slot, last: now, idle: idle, pending: make(map[*NativeField]bool)}
	if ctx.Err() != nil {
		s.Lock()
		return nil, ErrSessionLocked
	}
	if _, e = s.execute("desktop.system.unlock", vault.Item{}, nil, commandOption{}); e != nil {
		s.Lock()
		return nil, ErrSessionLocked
	}
	if ctx.Err() != nil {
		s.Lock()
		return nil, ErrSessionLocked
	}
	return s, nil
}
func DisableSystemUnlock(path string, store SystemUnlockStore) error {
	systemUnlockOperations.Lock()
	defer systemUnlockOperations.Unlock()
	if store == nil {
		return ErrSessionLocked
	}
	id, _, e := systemStoreID(path)
	if e != nil {
		return e
	}
	if e := store.Delete(id); e != nil {
		return errors.Join(ErrSystemUnlockUnavailable, e)
	}
	return nil
}
