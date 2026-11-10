//go:build darwin && cgo

package osunlock

/*
#cgo LDFLAGS: -framework Security -framework Foundation -framework CoreFoundation -framework LocalAuthentication
#include <stdlib.h>
#include "store_darwin.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

// Native status codes returned by Security.framework. They are mapped to
// fixed Go errors below so callers can distinguish a signed-code/keychain
// configuration failure from a locked vault, a dismissed prompt or a failed
// Touch ID match.
const (
	statusUserCanceled          = -128
	statusNotAvailable          = -25291
	statusAuthFailed            = -25293
	statusItemNotFound          = -25300
	statusInteractionNotAllowed = -25308
	statusInteractionRequired   = -25315
	statusMissingEntitlement    = -34018
	statusServiceNotAvailable   = -67585
)

type keychain struct{}

func New() Store { return keychain{} }

var biometry capabilityCache

// biometryTTL bounds how long a capability answer is reused. Label and
// Description are rendered together, so this avoids probing native frameworks
// on every frame while still noticing a lid open or an attached Magic Keyboard
// without restarting the app.
const biometryTTL = time.Second

// Biometry reports what the user-presence prompt can use on this Mac. It never
// prompts: canEvaluatePolicy only inspects local capability.
func Biometry() string {
	return biometry.get(time.Now(), biometryTTL, func() string {
		switch int(C.ll_biometry_available()) {
		case 2:
			return "Touch ID"
		case 1:
			return "系统密码"
		default:
			return "不可用"
		}
	})
}

func Label() string {
	switch Biometry() {
	case "Touch ID":
		return "Touch ID / 系统密码"
	case "系统密码":
		return "系统密码"
	default:
		return "系统验证"
	}
}
func Description() string {
	switch Biometry() {
	case "Touch ID":
		return "系统钥匙串要求 Touch ID 或系统密码验证，仅存于本设备。24 小时后需完整解锁。"
	case "系统密码":
		return "此 Mac 当前未检测到可用的 Touch ID；系统钥匙串使用系统密码验证，仅存于本设备。24 小时后需完整解锁。"
	default:
		return "此 Mac 当前没有可用的系统用户验证；系统快捷解锁不可用，请使用完整解锁。"
	}
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
	case statusNotAvailable, statusServiceNotAvailable:
		return ErrNotAvailable
	case statusAuthFailed:
		return ErrAuthFailed
	case statusItemNotFound:
		return ErrNotFound
	case statusMissingEntitlement:
		return ErrMissingEntitlement
	case statusInteractionNotAllowed, statusInteractionRequired:
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
