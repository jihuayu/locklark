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

func TestWindowsHelloLoadMapsOnlyMissingCredential(t *testing.T) {
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

			_, err := (hello{}).Load(windowsDeleteTestID)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Load() = %v, want %v", err, tc.want)
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

func TestWindowsHelloClassifyStatus(t *testing.T) {
	cases := []struct {
		name   string
		status uintptr
		want   error
	}{
		{"ok", 0, nil},
		{"nte_user_cancelled", uintptr(uint32(0x80090036)), ErrCancelled},
		{"hresult_error_cancelled", uintptr(uint32(0x800704C7)), ErrCancelled},
		{"scard_cancelled", uintptr(uint32(0x8010006E)), ErrCancelled},
		{"error_cancelled", uintptr(uint32(0x000004C7)), ErrCancelled},
		{"nte_silent_context", uintptr(uint32(0x80090022)), ErrInteractionNotAllowed},
		{"scard_wrong_chv", uintptr(uint32(0x8010006B)), ErrAuthFailed},
		{"error_logon_failure", uintptr(uint32(0x8007052E)), ErrAuthFailed},
		{"winbio_data_protection_failure", uintptr(uint32(0x80098046)), ErrAuthFailed},
		{"bad_keyset", uintptr(uint32(0x80090016)), ErrUnavailable},
		{"not_supported", uintptr(uint32(0x80090029)), ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyHelloStatus(tc.status)
			if !errors.Is(got, tc.want) {
				t.Fatalf("classifyHelloStatus(%#x) = %v, want %v", uint32(tc.status), got, tc.want)
			}
		})
	}
	if helloPadPKCS1 != 2 {
		t.Fatalf("helloPadPKCS1 = %d, want 2 (NCRYPT_PAD_PKCS1_FLAG)", helloPadPKCS1)
	}
}
