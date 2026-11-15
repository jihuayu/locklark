//go:build windows

package osunlock

import (
	"errors"
	"fmt"
	"testing"

	"github.com/egoist/mygo"
)

const windowsDeleteTestID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Get failures return before blob parsing, KSP deletion, or Credential Manager
// deletion, so these cases exercise the mapping without opening the real store.
func TestWindowsHelloDeleteMapsOnlyMissingCredential(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"missing", mygo.ErrSecretNotFound, ErrNotFound},
		{"wrapped missing", fmt.Errorf("credential manager: read: %w", mygo.ErrSecretNotFound), ErrNotFound},
		{"joined missing", errors.Join(errors.New("credential manager: read"), mygo.ErrSecretNotFound), ErrNotFound},
		{"unknown", errors.New("credential manager: access denied"), ErrUnavailable},
		{"wrapped unknown", fmt.Errorf("credential manager: read: %w", errors.New("access denied")), ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previous := helloSecretGet
			helloSecretGet = func(string) ([]byte, error) { return nil, tc.err }
			t.Cleanup(func() { helloSecretGet = previous })

			err := (hello{}).Delete(windowsDeleteTestID)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Delete() = %v, want %v", err, tc.want)
			}
			if tc.want == ErrNotFound && errors.Is(err, ErrUnavailable) {
				t.Fatalf("missing credential folded into ErrUnavailable: %v", err)
			}
			if tc.want == ErrUnavailable && errors.Is(err, ErrNotFound) {
				t.Fatalf("unknown Get error folded into ErrNotFound: %v", err)
			}
		})
	}
}
