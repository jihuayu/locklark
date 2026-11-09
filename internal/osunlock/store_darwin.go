//go:build darwin && cgo

package osunlock

/*
#cgo LDFLAGS: -framework Security -framework Foundation -framework CoreFoundation -framework LocalAuthentication
#include <stdlib.h>
#include "store_darwin.h"
*/
import "C"

import "unsafe"

// Native status codes returned by Security.framework. They are mapped to
// fixed Go errors below so callers can distinguish a signed-code/keychain
// configuration failure from a locked vault or a dismissed prompt.
const (
	statusUserCanceled          = -128
	statusInteractionNotAllowed = -25308
	statusItemNotFound          = -25300
	statusMissingEntitlement    = -34018
)

type keychain struct{}

func New() Store    { return keychain{} }
func Label() string { return "Touch ID / 系统密码" }
func Description() string {
	return "系统钥匙串要求用户验证（Touch ID 或系统密码），仅存于本设备。24 小时后需完整解锁。"
}

// Requirement explains the platform prerequisite in user-facing terms. The
// security page shows it before the enrollment button, so an unsigned
// development build does not look like a locked vault.
func Requirement() string {
	return "macOS 需要已签名的 .app 与 keychain-access-groups entitlement；未签名的开发构建无法使用系统快捷解锁。"
}

func nativeError(status int) error {
	switch status {
	case statusUserCanceled:
		return ErrCancelled
	case statusItemNotFound:
		return ErrNotFound
	case statusMissingEntitlement:
		return ErrMissingEntitlement
	case statusInteractionNotAllowed:
		return ErrInteractionNotAllowed
	default:
		return ErrUnavailable
	}
}

func (keychain) Store(id string, b []byte) error {
	if !validID(id) || len(b) == 0 || len(b) > 8192 {
		return ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	if status := int(C.ll_unlock_store(name, (*C.uchar)(unsafe.Pointer(&b[0])), C.long(len(b)))); status != 0 {
		return nativeError(status)
	}
	return nil
}
func (keychain) Load(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	var value *C.uchar
	var n C.long
	if status := int(C.ll_unlock_load(name, &value, &n)); status != 0 {
		return nil, nativeError(status)
	}
	if value == nil || n <= 0 || n > 8192 {
		if value != nil {
			C.ll_unlock_clear_free(value, n)
		}
		return nil, ErrUnavailable
	}
	defer C.ll_unlock_clear_free(value, n)
	return C.GoBytes(unsafe.Pointer(value), C.int(n)), nil
}
func (keychain) Delete(id string) error {
	if !validID(id) {
		return ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	if status := int(C.ll_unlock_delete(name)); status != 0 {
		return nativeError(status)
	}
	return nil
}
