//go:build darwin && cgo

package osunlock

import (
	"errors"
	"testing"
)

func TestDarwinNativeStatusClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{name: "cancel", status: statusUserCanceled, want: ErrCancelled},
		{name: "keychain unavailable", status: statusNotAvailable, want: ErrNotAvailable},
		{name: "service unavailable", status: statusServiceNotAvailable, want: ErrNotAvailable},
		{name: "auth failed", status: statusAuthFailed, want: ErrAuthFailed},
		{name: "not enrolled", status: statusItemNotFound, want: ErrNotFound},
		{name: "missing entitlement", status: statusMissingEntitlement, want: ErrMissingEntitlement},
		{name: "interaction not allowed", status: statusInteractionNotAllowed, want: ErrInteractionNotAllowed},
		{name: "interaction required", status: statusInteractionRequired, want: ErrInteractionNotAllowed},
		{name: "unknown", status: -1, want: ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeError(tc.status); !errors.Is(got, tc.want) {
				t.Fatalf("nativeError(%d) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestDarwinBiometryIsReportedWithoutPrompt(t *testing.T) {
	got := Biometry()
	switch got {
	case "Touch ID", "系统密码", "不可用":
	default:
		t.Fatalf("Biometry() = %q, want a fixed capability label", got)
	}
	if Label() == "" {
		t.Fatal("Label() must not be empty")
	}
	if Description() == "" {
		t.Fatal("Description() must not be empty")
	}
}
