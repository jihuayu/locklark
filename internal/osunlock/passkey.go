package osunlock

// maxPasskeyCapsule bounds the quick-unlock capsule released for one passkey
// user-verification operation. Enrolled capsules are far smaller; the bound
// keeps a corrupted or foreign secret from driving an unbounded native
// allocation.
const maxPasskeyCapsule = 8192

// PasskeyStore is the optional native adapter for a single passkey user
// verification. It is deliberately separate from Store so callers detect
// support with a type assertion and unsupported platforms fail closed instead
// of silently degrading.
//
// Only adapters that perform fresh OS user verification on every call implement
// this interface:
//
//   - Windows: Windows Hello through the Passport Key Storage Provider. Every
//     call opens a new, scoped nonexportable key handle, re-checks
//     NgcCacheType=1 (authentication mandatory), Export Policy 0 and the
//     decrypt-only Key Usage, and forces PinCacheIsGestureRequired=1 before the
//     CNG decrypt. The CNG decrypt result - never a boolean prompt, DPAPI-only
//     key, software key, cached session or reused key handle - releases the
//     capsule. Any property mismatch fails closed.
//   - macOS: the same scoped quick-unlock keychain item, whose userPresence
//     access control is read with a fresh LAContext per call,
//     touchIDAuthenticationAllowableReuseDuration set to 0, an explicit
//     kSecUseAuthenticationContext, and the context invalidated afterwards. No
//     context is reused between calls. Touch ID or the system password is
//     accepted, and the user-facing label must stay truthful about that.
//
// Linux Secret Service and the unavailable build intentionally do not implement
// PasskeyStore: an unlocked login keyring proves no fresh user presence.
//
// id is the same 64-character lowercase hexadecimal capsule id accepted by
// Store, and the returned bytes are the exact capsule previously stored under
// that id, at most maxPasskeyCapsule bytes. An empty, oversized, missing or
// foreign capsule is refused. The caller owns the returned buffer and must
// clear it. Every failure or decline returns ErrUnavailable, without logging
// capsule values or prompt internals.
//
// This method authenticates the capsule only. It is a native-only trusted
// adapter, not a web or IPC binding: after it returns, the caller must still
// re-validate the passkey request (exact released path, slot, Session, revision
// and expiry) before treating user verification as granted.
type PasskeyStore interface {
	LoadForPasskeyVerification(id string) ([]byte, error)
}
