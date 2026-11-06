package personal

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func nativeEditGate(t *testing.T, s *Session) *MutationGate {
	t.Helper()
	g := NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(g); e != nil {
		t.Fatal("register native edit failed")
	}
	return g
}

func TestNativeFieldEditUsesExactRevisionAndRefusalAudit(t *testing.T) {
	path, key, target := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal("native edit unlock failed")
	}
	defer s.Lock()
	revision := target.Revision
	for _, edit := range []struct{ field, value string }{
		{"title", "Native renamed login"}, {"url", "https://example.test/login"},
		{"username", "native-user-canary"}, {"password", "native-password-canary"},
		{"otp", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}, {"notes", "native-notes-canary"},
	} {
		value := []byte(edit.value)
		next, e := s.EditNativeField(target.ID, revision, edit.field, value, nativeEditGate(t, s))
		if e != nil || next == revision || !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("native edit failed or mutable value retained", edit.field)
		}
		revision = next
	}
	if _, e = s.EditNativeField(target.ID, target.Revision, "password", []byte("stale-value"), nativeEditGate(t, s)); !errors.Is(e, ErrConflict) {
		t.Fatal("native edit accepted stale revision")
	}
	if _, e = s.EditNativeField(target.ID, revision, "password", nil, nativeEditGate(t, s)); !errors.Is(e, ErrMutationRefused) {
		t.Fatal("native invalid value lacked audited refusal")
	}
	if !s.Unlocked() {
		t.Fatal("business refusal locked a valid session")
	}
	gate := nativeEditGate(t, s)
	gate.Cancel()
	if _, e = s.EditNativeField(target.ID, revision, "title", []byte("cancelled"), gate); !errors.Is(e, ErrMutationCancelled) {
		t.Fatal("cancelled native edit was not refused")
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal("native edit list failed")
	}
	found := false
	for _, row := range rows {
		if row.ID == target.ID {
			found = row.Title == "Native renamed login" && row.Revision == revision
		}
	}
	if !found {
		t.Fatal("refused edit changed value or revision")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal("native edit audit failed")
	}
	refusal := false
	for _, event := range events {
		if event.Action == "item.edit.password" && event.Result == "native-refused" {
			refusal = true
		}
	}
	if !refusal {
		t.Fatal("missing durable native refusal audit")
	}
}
