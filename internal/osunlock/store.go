// Package osunlock protects native quick-unlock material with system services.
// It has no disk fallback and no web / IPC bindings.
package osunlock

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrUnavailable is the fixed fallback for a platform failure that the
	// adapter cannot classify. It never includes native status text or values.
	ErrUnavailable = errors.New("system unlock unavailable or authentication declined")
	// ErrMissingEntitlement reports a signed-code or keychain-access-group
	// requirement that this process does not satisfy. macOS returns it for
	// data-protection-keychain items when the app is ad-hoc signed or lacks
	// keychain-access-groups; callers must explain that instead of treating it
	// as a locked vault.
	ErrMissingEntitlement = errors.New("system keychain entitlement is missing")
	// ErrCancelled reports an OS user-presence prompt the user dismissed.
	ErrCancelled = errors.New("system authentication was cancelled")
	// ErrAuthFailed reports a completed user-presence check that did not
	// authenticate: a failed Touch ID match or a wrong system password. It is
	// retryable and does not mean the vault or keychain is unavailable.
	ErrAuthFailed = errors.New("system authentication failed")
	// ErrNotAvailable reports that the OS keychain service itself is not
	// available, for example before first unlock or after a keychain restart.
	ErrNotAvailable = errors.New("system keychain is not available")
	// ErrInteractionNotAllowed reports a prompt that could not be shown, for
	// example because the session is locked or the item is not available now.
	ErrInteractionNotAllowed = errors.New("system keychain interaction is not allowed")
	// ErrNotFound reports that no quick-unlock item is enrolled for this vault
	// path. It is different from an entitlement failure: the user simply has
	// not enabled quick unlock yet, or it was disabled.
	ErrNotFound = errors.New("system quick unlock is not enrolled")
)

// capabilityCache memoizes a platform capability probe for a bounded window, so
// a capability change (lid opened from clamshell mode, Magic Keyboard with
// Touch ID attached) is observed without a process restart while render paths
// do not probe native frameworks on every frame.
type capabilityCache struct {
	mu      sync.Mutex
	value   string
	checked time.Time
}

func (c *capabilityCache) get(now time.Time, ttl time.Duration, probe func() string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checked.IsZero() || now.Before(c.checked) || now.Sub(c.checked) >= ttl {
		c.value, c.checked = probe(), now
	}
	return c.value
}

// deleteBoth removes a native credential and its wrapped secret. Both removals
// are attempted even when the first fails, so a refused credential delete can
// never leave a usable secret behind.
func deleteBoth(deleteCredential, deleteSecret func() error) error {
	credentialErr := deleteCredential()
	secretErr := deleteSecret()
	if credentialErr != nil || secretErr != nil {
		return ErrUnavailable
	}
	return nil
}

type Store interface {
	Store(string, []byte) error
	Load(string) ([]byte, error)
	Delete(string) error
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
