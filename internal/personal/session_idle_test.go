package personal

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The desktop exposes AutoLockMinutes=0 as "Never". A zero idle is the internal
// representation of that explicit choice, while tiny positive values and
// intervals above the bound remain refused so a typo cannot disable auto-lock.
func TestSessionIdleSupportsExplicitNever(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idle.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockSession(path, []byte("fixture"), key, 500*time.Millisecond); err == nil {
		t.Fatal("sub-second idle accepted")
	}
	if _, err := UnlockSession(path, []byte("fixture"), key, -time.Minute); err == nil {
		t.Fatal("negative idle accepted")
	}
	if _, err := UnlockSession(path, []byte("fixture"), key, maxSessionIdle+time.Second); err == nil {
		t.Fatal("idle above the bound accepted")
	}
	s, err := UnlockSession(path, []byte("fixture"), key, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	deadline, ok := s.IdleDeadline()
	if !ok || !deadline.IsZero() {
		t.Fatalf("never idle reports deadline=%v ok=%v", deadline, ok)
	}
	s.mu.Lock()
	s.last = time.Now().Add(-30 * 24 * time.Hour)
	s.mu.Unlock()
	if !s.Unlocked() {
		t.Fatal("zero idle expired from inactivity")
	}
}

func TestSessionSetIdleTimeoutAppliesToLiveSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idle-live.ll")
	key := bytes.Repeat([]byte{8}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	// The old activity timestamp is preserved: widening the interval must not
	// silently grant a fresh full window.
	s.mu.Lock()
	s.last = time.Now().Add(-30 * time.Second)
	s.mu.Unlock()
	if err := s.SetIdleTimeout(30 * time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline, ok := s.IdleDeadline()
	if !ok {
		t.Fatal("widened session reports no deadline")
	}
	if d := time.Until(deadline); d > 30*time.Minute || d < 29*time.Minute {
		t.Fatalf("widened deadline=%v, want the preserved activity timestamp plus 30 minutes", d)
	}
	if err := s.SetIdleTimeout(0); err != nil {
		t.Fatal(err)
	}
	if deadline, ok := s.IdleDeadline(); !ok || !deadline.IsZero() {
		t.Fatalf("never deadline=%v ok=%v", deadline, ok)
	}
	if err := s.SetIdleTimeout(-time.Second); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("negative live idle err=%v", err)
	}
	// A locked session refuses a policy change.
	s.Lock()
	if err := s.SetIdleTimeout(time.Minute); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("locked idle change err=%v", err)
	}
}
