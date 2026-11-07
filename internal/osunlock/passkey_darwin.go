//go:build darwin && cgo

package osunlock

/*
#cgo LDFLAGS: -framework Security -framework Foundation -framework LocalAuthentication
#include <stdlib.h>
#include "passkey_darwin.h"
*/
import "C"

import "unsafe"

// LoadForPasskeyVerification releases the stored quick-unlock capsule for one
// passkey user-verification operation.
//
// The read targets the same scoped keychain item as Store and Load (service
// app.locklark.unlock.v1) and never creates, replaces or migrates it. The item's
// userPresence access control is evaluated by Security.framework through an
// explicit, freshly created LAContext per call (see passkey_darwin.m):
// touchIDAuthenticationAllowableReuseDuration is 0, the context is invalidated
// after the call, and no context is reused. Touch ID or the system password is
// accepted, matching the adapter label. A decline, missing item, oversized
// payload or any native failure returns ErrUnavailable without logging capsule
// values or prompt internals.
//
// The caller must re-validate the passkey request after this returns; this
// method only authenticates the capsule bytes.
func (keychain) LoadForPasskeyVerification(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	var value *C.uchar
	var n C.long
	if C.ll_passkey_load(name, &value, &n) != 0 || value == nil || n <= 0 || n > maxPasskeyCapsule {
		if value != nil {
			C.ll_passkey_clear_free(value, n)
		}
		return nil, ErrUnavailable
	}
	defer C.ll_passkey_clear_free(value, n)
	return C.GoBytes(unsafe.Pointer(value), C.int(n)), nil
}
