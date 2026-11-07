//go:build darwin && cgo

package osunlock

import (
	"errors"
	"testing"
)

func TestSystemUnlockDarwinKeychainIsPasskeyStore(t *testing.T) {
	var _ Store = New()
	adapter, ok := any(New()).(PasskeyStore)
	if !ok {
		t.Fatal("macOS keychain adapter must implement PasskeyStore")
	}
	// Invalid ids are refused before Security.framework is asked for the item,
	// so this test never shows a Touch ID or password prompt.
	for _, id := range []string{"", "not-a-capsule", passkeyCapsuleID[:63]} {
		if _, err := adapter.LoadForPasskeyVerification(id); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("capsule id %q returned %v, want ErrUnavailable", id, err)
		}
	}
}
