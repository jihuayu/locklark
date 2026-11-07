//go:build windows

package osunlock

import (
	"errors"
	"testing"
)

func TestSystemUnlockWindowsHelloIsPasskeyStore(t *testing.T) {
	var _ Store = New()
	adapter, ok := any(New()).(PasskeyStore)
	if !ok {
		t.Fatal("Windows Hello adapter must implement PasskeyStore")
	}
	// Invalid ids are refused before any Passport KSP open, so this test never
	// prompts the user or needs Hello hardware.
	for _, id := range []string{"", "not-a-capsule", passkeyCapsuleID[:63]} {
		if _, err := adapter.LoadForPasskeyVerification(id); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("capsule id %q returned %v, want ErrUnavailable", id, err)
		}
	}
}

// TestSystemUnlockWindowsHelloPolicyAcceptance exercises the pure Passport KSP
// policy tuple that verify() enforces before every decrypt. It runs without a
// KSP handle or Hello hardware.
func TestSystemUnlockWindowsHelloPolicyAcceptance(t *testing.T) {
	cases := []struct {
		name   string
		policy helloPolicy
		want   bool
	}{
		{"decrypt only", helloPolicy{usage: 1, cache: 1, export: 0}, true},
		{"no usage flags", helloPolicy{usage: 0, cache: 1, export: 0}, false},
		{"sign only", helloPolicy{usage: 2, cache: 1, export: 0}, false},
		{"decrypt and sign", helloPolicy{usage: 3, cache: 1, export: 0}, false},
		{"key agreement only", helloPolicy{usage: 4, cache: 1, export: 0}, false},
		{"decrypt and key agreement", helloPolicy{usage: 5, cache: 1, export: 0}, false},
		{"import only", helloPolicy{usage: 8, cache: 1, export: 0}, false},
		{"decrypt and import", helloPolicy{usage: 9, cache: 1, export: 0}, false},
		{"all usage flags", helloPolicy{usage: 0xffffff, cache: 1, export: 0}, false},
		{"cache type unauthenticated", helloPolicy{usage: 1, cache: 0, export: 0}, false},
		{"cache type other", helloPolicy{usage: 1, cache: 2, export: 0}, false},
		{"exportable", helloPolicy{usage: 1, cache: 1, export: 1}, false},
		{"all export flags", helloPolicy{usage: 1, cache: 1, export: 0xffffff}, false},
	}
	for _, c := range cases {
		if got := c.policy.valid(); got != c.want {
			t.Errorf("%s: valid() = %v, want %v", c.name, got, c.want)
		}
	}
	// The exact tuple written by enrollment (createKey) must stay accepted.
	if !(helloPolicy{usage: helloKeyUsageDecrypt, cache: helloNgcCacheTypeAuthenticated, export: helloExportPolicyNone}).valid() {
		t.Fatal("enrollment policy tuple must be accepted")
	}
}
