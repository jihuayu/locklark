//go:build linux

package osunlock

import (
	"reflect"
	"testing"
)

// The Secret Service adapter keeps its existing quick-unlock Store behavior but
// must never implement PasskeyStore: an already-unlocked login keyring proves
// no fresh user presence.
func TestSystemUnlockLinuxKeyringIsNotPasskeyStore(t *testing.T) {
	var _ Store = New()
	if adapter, ok := any(New()).(PasskeyStore); ok {
		t.Fatalf("Linux Secret Service adapter %T must not implement PasskeyStore", adapter)
	}
	if _, ok := reflect.TypeOf(New()).MethodByName("LoadForPasskeyVerification"); ok {
		t.Fatal("Linux Secret Service adapter must not declare LoadForPasskeyVerification")
	}
}
