package onedriveauth

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/egoist/mygo"
)

// RefreshTokenStore keeps one refresh token per local profile in the OS
// credential store. It is a small adapter over the pinned github.com/egoist/mygo
// Secrets API and has no other persistence: no file, environment variable,
// quick-unlock or other fallback exists, and when the OS has no credential store
// every operation fails with ErrStoreUnsupported, for which
// errors.Is(err, errors.ErrUnsupported) holds.
//
// The profile label is a user-selected name for a local profile. It is not a
// verified account identity and this store makes no claim about which Microsoft
// account a stored token belongs to.
//
// Only the refresh token is stored. Access tokens, authorization codes, state,
// verifier and scopes never reach the store. Each item is named by a key derived
// with domain-separated SHA-256 from the explicit client ID, the explicit tenant
// and the profile label bytes, each length-prefixed so no two different inputs
// encode alike, and the store only ever sees that key. The label is never
// converted to a string and never retained, so the caller keeps its only copy in
// a buffer it can clear.
//
// Operations return only fixed sentinels. No error carries a label, key, token or
// library text, and none of them is logged. A save is not claimed to be atomic:
// mygo's backends update, store or write an item with their own calls, and it
// gives no cross-platform atomicity guarantee.
type RefreshTokenStore struct {
	secrets Secrets
}

// StoreNamespace is the fixed service namespace of every item this store
// writes. It is a constant so the store can never be redirected to another
// service.
const StoreNamespace = "app.locklark.onedrive.oauth.v1"

// Bounds on the caller's profile label and on a stored refresh token. The label
// bound is a format bound; the token bound is mygo's MaxSecretSize, the most
// the Windows Credential Manager keeps.
const (
	// MaxProfileLabelLen is the longest profile label, in bytes, the store
	// accepts: the same bound the CLI's hidden prompt enforces.
	MaxProfileLabelLen = 256
	maxRefreshTokenLen = mygo.MaxSecretSize
)

// storeKeyDomain is the SHA-256 domain separation label of the per-profile key.
// Changing it changes every derived key.
const storeKeyDomain = "locklark/onedrive-oauth/refresh-token/v2\x00"

// Store sentinels. Each is a fixed text with no detail, so none can carry a
// label, client ID, tenant, derived key, token or library error. Callers test
// them with errors.Is.
var (
	// ErrStoreInput reports a profile label, refresh token or stored value
	// that is not well formed. No value was written or returned.
	ErrStoreInput = errors.New("onedrive auth: invalid credential store input")
	// ErrStoreUnsupported reports that the OS has no credential store, or
	// that the store failed for any other reason. Library and OS errors are
	// flattened away. When the store reported that it is unsupported,
	// errors.Is(err, errors.ErrUnsupported) holds as well.
	ErrStoreUnsupported = errors.New("onedrive auth: OS credential store unavailable")
	// ErrStoreNotFound reports that no refresh token is stored for the
	// client ID, tenant and profile. It is distinct from every other store
	// error.
	ErrStoreNotFound = errors.New("onedrive auth: no refresh token stored for this profile")
)

// Secrets is the subset of the mygo Secrets methods this store uses. The
// concrete type is obtained only from newSystemSecrets, which binds the fixed
// StoreNamespace; tests substitute a fake.
type Secrets interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
}

// NewRefreshTokenStore returns a store for the system credential store of the
// fixed service namespace.
func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{secrets: newSystemSecrets()}
}

// newSystemSecrets binds mygo's Secrets to StoreNamespace.
func newSystemSecrets() Secrets {
	return mygo.Secrets.Service(StoreNamespace)
}

// SaveRefreshToken stores a copy of token as the refresh token of the profile
// named by clientID, tenant and label. It returns only fixed sentinels. The
// client ID, tenant, label and token are checked before any store call, so an
// invalid input or an oversized token leaves every stored item, including an
// existing one for this profile, untouched. The caller owns label and token,
// keeps the label in mutable bytes, and clears the token copy once
// SaveRefreshToken returns.
func (s RefreshTokenStore) SaveRefreshToken(clientID, tenant string, label, token []byte) error {
	key, ok := storeKey(clientID, tenant, label)
	if !ok {
		return ErrStoreInput
	}
	if !validRefreshToken(token) {
		return ErrStoreInput
	}
	// The slice handed to the store is an owned copy, so it never aliases
	// the caller's buffer, and it is cleared when the call returns.
	owned := make([]byte, len(token))
	copy(owned, token)
	defer clear(owned)
	return classifySecretError(s.secrets.Set(key, owned))
}

// LoadRefreshToken reports whether the profile named by clientID, tenant and
// label has a stored refresh token and returns a copy of it when present. A
// false report with a nil error means the profile is not enrolled; every other
// failure is a fixed sentinel and a nil token. The returned copy is owned by the
// caller and must be cleared.
func (s RefreshTokenStore) LoadRefreshToken(clientID, tenant string, label []byte) ([]byte, bool, error) {
	key, ok := storeKey(clientID, tenant, label)
	if !ok {
		return nil, false, ErrStoreInput
	}
	token, err := s.secrets.Get(key)
	if err != nil {
		clear(token)
		if errors.Is(classifySecretError(err), ErrStoreNotFound) {
			return nil, false, nil
		}
		return nil, false, classifySecretError(err)
	}
	if !validRefreshToken(token) {
		// A stored value outside the accepted form, written by this store
		// or another one, is never returned. The item stays in the store
		// until logout removes it.
		clear(token)
		return nil, false, ErrStoreInput
	}
	return token, true, nil
}

// DeleteRefreshToken removes the refresh token of the profile named by clientID,
// tenant and label. Deleting a profile that is not enrolled is not an error,
// because the store's delete is idempotent.
func (s RefreshTokenStore) DeleteRefreshToken(clientID, tenant string, label []byte) error {
	key, ok := storeKey(clientID, tenant, label)
	if !ok {
		return ErrStoreInput
	}
	return classifySecretError(s.secrets.Delete(key))
}

// classifySecretError flattens a store error to a fixed sentinel.
// ErrStoreNotFound is preserved, and an unsupported store yields
// ErrStoreUnsupported joined with errors.ErrUnsupported. Every other error is a
// bare ErrStoreUnsupported. No library text, which may echo a key, is kept.
func classifySecretError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mygo.ErrSecretNotFound):
		return ErrStoreNotFound
	case errors.Is(err, errors.ErrUnsupported):
		// Both texts are fixed, so the boundary stays observable.
		return errors.Join(ErrStoreUnsupported, errors.ErrUnsupported)
	default:
		return ErrStoreUnsupported
	}
}

// storeKey derives the per-profile store key:
//
//	hex(SHA-256(domain || len(clientID) || clientID || len(tenant) || tenant ||
//	             len(label) || label))
//
// where len is a big-endian uint64 and the label is hashed as bytes. The
// length prefixes make the encoding injective, so different (client ID, tenant,
// label) triples never share a key. The result is 64 lower-case hex characters,
// a fixed shape well within mygo's key limit. ok is false when the client ID,
// tenant or label fails its validator.
func storeKey(clientID, tenant string, label []byte) (key string, ok bool) {
	clientID, err := validClientID(clientID)
	if err != nil {
		return "", false
	}
	tenant, err = validTenant(tenant)
	if err != nil {
		return "", false
	}
	if !validProfileLabel(label) {
		return "", false
	}
	h := sha256.New()
	h.Write([]byte(storeKeyDomain))
	for _, field := range [][]byte{[]byte(clientID), []byte(tenant), label} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// validProfileLabel reports whether label is nonempty, at most
// MaxProfileLabelLen bytes, and made of printable ASCII (0x20-0x7e) only.
func validProfileLabel(label []byte) bool {
	if len(label) == 0 || len(label) > MaxProfileLabelLen {
		return false
	}
	for _, c := range label {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// ValidProfileLabel reports whether label is a valid profile label. It is the
// same check SaveRefreshToken, LoadRefreshToken and DeleteRefreshToken apply.
func ValidProfileLabel(label []byte) bool { return validProfileLabel(label) }

// validRefreshToken reports whether token is nonempty, at most
// maxRefreshTokenLen bytes, and made of visible ASCII (0x21-0x7e) only.
func validRefreshToken(token []byte) bool {
	return len(token) > 0 && len(token) <= maxRefreshTokenLen && visibleASCII(token)
}
