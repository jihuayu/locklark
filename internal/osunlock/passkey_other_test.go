//go:build (!linux && !windows && !darwin) || (darwin && !cgo)

package osunlock

import "testing"

func TestSystemUnlockUnavailableIsNotPasskeyStore(t *testing.T) {
	var _ Store = New()
	if adapter, ok := any(New()).(PasskeyStore); ok {
		t.Fatalf("unavailable adapter %T must not implement PasskeyStore", adapter)
	}
}
