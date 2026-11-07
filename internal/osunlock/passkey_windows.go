//go:build windows

package osunlock

// LoadForPasskeyVerification releases the stored quick-unlock capsule for one
// passkey user-verification operation.
//
// Every call invokes a brand new hello.Load: a new Passport KSP key handle is
// opened from the scoped capsule slot and the existing decrypt path in
// store_windows.go re-verifies that the key is decrypt-only, that NgcCacheType
// is 1 (authentication mandatory) and that Export Policy is 0, then sets
// PinCacheIsGestureRequired=1 before the CNG decrypt. If any of those
// enforcement properties fails, Load fails closed with ErrUnavailable. There is
// no boolean prompt, DPAPI-only, software-key or cached-session fallback, and no
// key handle, wrapping key or prompt result is kept between calls.
//
// The caller must re-validate the passkey request after this returns; this
// method only authenticates the capsule bytes.
func (hello) LoadForPasskeyVerification(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	value, err := hello{}.Load(id)
	if err != nil || len(value) == 0 || len(value) > maxPasskeyCapsule {
		clear(value)
		return nil, ErrUnavailable
	}
	return value, nil
}
