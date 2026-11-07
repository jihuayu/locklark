package personal

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	bolt "go.etcd.io/bbolt"
)

// ErrSystemPasskeyVerification reports that a native OS user verification did
// not produce a fresh, valid, session-bound result. OS error detail, material
// and any proof stay behind the adapter.
var ErrSystemPasskeyVerification = errors.New("system passkey verification unavailable or declined")

// SystemPasskeyVerificationStore is a trusted native OS adapter, never a
// renderer binding. It exposes exactly one operation: loading the existing
// quick-unlock capsule for one passkey approval. Only Windows Hello and macOS
// Touch ID adapters implement it; the Linux Secret Service adapter deliberately
// does not, because a keyring read is not user verification. The adapter cannot
// report a boolean "verified" result and cannot perform WebAuthn itself.
type SystemPasskeyVerificationStore interface {
	LoadForPasskeyVerification(string) ([]byte, error)
}

// systemPasskeyCapsuleLimit bounds the capsule accepted from the OS adapter.
const systemPasskeyCapsuleLimit = 8192

// decodeSystemPasskeyCapsule accepts only the exact enrollment format written
// by EnableSystemUnlock: unknown fields, trailing data and malformed JSON are
// refused instead of being interpreted.
func decodeSystemPasskeyCapsule(raw []byte) (systemCapsule, error) {
	var capsule systemCapsule
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&capsule) != nil {
		// A failed decode may already have populated Identity before the
		// offending field. Clear it and never interpret the partial value.
		clear(capsule.Identity)
		return capsule, ErrSystemPasskeyVerification
	}
	if decoder.Decode(new(struct{})) != io.EOF {
		clear(capsule.Identity)
		return capsule, ErrSystemPasskeyVerification
	}
	return capsule, nil
}

// validSystemPasskeyCapsuleTime enforces the unchanged enrollment window: the
// capsule must have been created in the past, must still be unexpired, and must
// span exactly 24 hours. It is evaluated again after authentication so a
// capsule that expires while the OS prompt or the vault authentication is
// blocked can never become fresh user verification.
func validSystemPasskeyCapsuleTime(capsule systemCapsule, now time.Time) bool {
	return !now.Before(capsule.Created) && now.Before(capsule.Expires) && capsule.Expires.Sub(capsule.Created) == 24*time.Hour
}

// VerifyPasskeyUserWithSystem performs a fresh OS user verification for exactly
// one passkey approval. Every call asks the platform adapter again: a previous
// UnlockWithSystem result, a cached boolean and any earlier material are never
// reused. The 24-hour quick-unlock capsule, already enrolled from a full-factor
// unlock, is the only protected material involved, and it never leaves this
// method.
//
// The vault path is read under a short session lock, then every Session and
// Connection lock is released while the OS authenticates the user. Enrollment
// and deletion are serialized with the same mutex the quick-unlock path uses,
// while Session.Lock stays unblocked. After the OS returns, the capsule must
// still describe this exact session, and a read-only bbolt transaction must
// authenticate the slot, signed snapshot, schema and full history. No audit
// event and no idle renewal happens at verification alone. The boolean result
// is never a wire value: only a later committed passkey operation can carry UV.
func (s *Session) VerifyPasskeyUserWithSystem(store SystemPasskeyVerificationStore) error {
	if s == nil || store == nil {
		return ErrSessionLocked
	}
	systemUnlockOperations.Lock()
	defer systemUnlockOperations.Unlock()

	s.mu.Lock()
	locked := s.active(false) != nil
	path := s.path
	s.mu.Unlock()
	if locked {
		return ErrSessionLocked
	}
	id, absolute, e := systemStoreID(path)
	if e != nil {
		return ErrSystemPasskeyVerification
	}
	raw, e := store.LoadForPasskeyVerification(id)
	defer clear(raw)
	if e != nil || len(raw) == 0 || len(raw) > systemPasskeyCapsuleLimit {
		return ErrSystemPasskeyVerification
	}
	capsule, e := decodeSystemPasskeyCapsule(raw)
	defer clear(capsule.Identity)
	if e != nil {
		return ErrSystemPasskeyVerification
	}
	if capsule.Version != 1 || capsule.Path != absolute || len(capsule.Identity) == 0 || !validSystemPasskeyCapsuleTime(capsule, time.Now()) {
		return ErrSystemPasskeyVerification
	}
	return s.finishSystemPasskeyVerification(path, capsule)
}

// finishSystemPasskeyVerification binds the returned capsule to the exact
// current session and re-authenticates the stored vault read-only.
func (s *Session) finishSystemPasskeyVerification(path string, capsule systemCapsule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil || s.path != path || len(s.material) == 0 {
		return ErrSessionLocked
	}
	if capsule.Slot != s.slotDigest || subtle.ConstantTimeCompare(capsule.Identity, s.material) != 1 {
		return ErrSystemPasskeyVerification
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return ErrSystemPasskeyVerification
	}
	e = db.View(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, "", nil, passkeyGetAction, s)
		if e != nil {
			return e
		}
		defer auth.clear()
		if sha256.Sum256(tx.Bucket(bucket).Get(slotKey)) != s.slotDigest || !bytes.Equal(auth.opened, s.material) {
			return passkey.ErrRefused
		}
		return nil
	})
	closeErr := db.Close()
	if e != nil || closeErr != nil {
		return ErrSystemPasskeyVerification
	}
	if s.active(false) != nil {
		return ErrSessionLocked
	}
	// Recheck the unchanged 24-hour window after the authentication work: a
	// capsule that expired, or became future-dated, while the OS prompt or the
	// vault read was blocked must not produce user verification.
	if !validSystemPasskeyCapsuleTime(capsule, time.Now()) {
		return ErrSystemPasskeyVerification
	}
	return nil
}
