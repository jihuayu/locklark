package desktop

import (
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
)

// A native keychain failure, an expired capsule and a cancelled prompt are
// different user actions from a locked vault. Pinning the messages here keeps
// the misleading "unlock again" text from coming back.
func TestSystemUnlockMessagesAreActionable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "expired", err: personal.ErrSystemUnlockExpired, want: "过期"},
		{name: "not enrolled", err: errors.Join(personal.ErrSystemUnlockUnavailable, osunlock.ErrNotFound), want: "尚未启用"},
		{name: "missing entitlement", err: errors.Join(personal.ErrSystemUnlockUnavailable, osunlock.ErrMissingEntitlement), want: "签名权限"},
		{name: "unavailable", err: personal.ErrSystemUnlockUnavailable, want: "系统快捷解锁不可用"},
		{name: "cancelled", err: osunlock.ErrCancelled, want: "已取消"},
		{name: "interaction not allowed", err: osunlock.ErrInteractionNotAllowed, want: "当前不可用"},
		{name: "actually locked", err: personal.ErrSessionLocked, want: "金库已锁定"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := message(tc.err)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("message(%v) = %q, want substring %q", tc.err, got, tc.want)
			}
		})
	}
}
