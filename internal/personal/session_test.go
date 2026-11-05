package personal

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestDesktopSessionLockAndRevision(t *testing.T) {
	path, key, target := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	rows, e := s.List("all")
	if e != nil || len(rows) != 2 {
		t.Fatal("session list", e)
	}
	field, e := s.PrepareField(target, "show")
	if e != nil {
		t.Fatal(e)
	}
	called := 0
	if e = s.Consume(field, func(value []byte) error {
		called++
		if string(value) != "private-value\t\"quoted\"\n" {
			t.Fatal("wrong field")
		}
		return nil
	}); e != nil || called != 1 {
		t.Fatal("consume", e)
	}
	if e = s.Consume(field, func([]byte) error { called++; return nil }); e == nil || called != 1 {
		t.Fatal("lease reused")
	}
	pending, e := s.PrepareField(target, "copy")
	if e != nil {
		t.Fatal(e)
	}
	s.Lock()
	if e = s.Consume(pending, func([]byte) error { called++; return nil }); !errors.Is(e, ErrSessionLocked) || called != 1 {
		t.Fatal("late clipboard after lock", e)
	}
	if _, e = s.List("active"); !errors.Is(e, ErrSessionLocked) {
		t.Fatal("list after lock", e)
	}
	s, e = UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	_, e = EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "new secret"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.PrepareField(target, "show"); e != ErrConflict {
		t.Fatal("session trusted stale revision", e)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, ev := range events {
		found[ev.Action] = true
	}
	for _, action := range []string{"desktop.unlock", "item.desktop.show.password", "item.desktop.copy.password"} {
		if !found[action] {
			t.Fatal("missing desktop audit", action)
		}
	}
}
func TestDesktopSessionIdleAndNoFactorRetention(t *testing.T) {
	path, key, _ := revealFixture(t)
	pw := []byte("fixture")
	s, e := UnlockSession(path, pw, key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	if bytes.Contains(s.material, pw) || bytes.Contains(s.material, key) {
		t.Fatal("unlock factors retained")
	}
	s.mu.Lock()
	s.last = time.Now().Add(-2 * time.Minute)
	s.mu.Unlock()
	if _, e = s.List("active"); !errors.Is(e, ErrSessionLocked) {
		t.Fatal("idle bypass", e)
	}
	if len(s.material) != 0 {
		t.Fatal("locked material retained")
	}
	if _, e = UnlockSession(path, []byte("wrong"), key, time.Minute); e == nil {
		t.Fatal("wrong factors unlocked")
	}
}
