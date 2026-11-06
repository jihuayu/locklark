package personal

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const nativeTestOTP = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=60"

func nativeTestVault(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "native.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func nativeTestUnlock(t *testing.T, path string, key []byte) *Session {
	t.Helper()
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func nativeTestAddLogin(t *testing.T, s *Session) (string, string) {
	t.Helper()
	id, err := s.AddLogin("Original", "original-user", "original-password")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return id, row.Revision
		}
	}
	t.Fatal("added login missing from list")
	return "", ""
}

func nativeTestGate(t *testing.T, s *Session) *MutationGate {
	t.Helper()
	g := NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(g); err != nil {
		t.Fatal(err)
	}
	return g
}

func nativeTestInspect(t *testing.T, s *Session, id, revision string) vault.Item {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var item vault.Item
	if err := s.readNativeTarget(id, revision, func(v vault.Item) error {
		item = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return item
}

func nativeTestRevision(t *testing.T, s *Session, state, id string) string {
	t.Helper()
	rows, err := s.List(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return row.Revision
		}
	}
	t.Fatal("login missing from state", state)
	return ""
}

func nativeTestNonReadEvents(events []Event) []Event {
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		switch {
		case ev.Action == "desktop.unlock", ev.Action == "desktop.system.unlock", ev.Action == "audit.list", strings.HasPrefix(ev.Action, "item.list"):
			continue
		}
		out = append(out, ev)
	}
	return out
}

func nativeTestAuditTail(t *testing.T, s *Session) []Event {
	t.Helper()
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	return nativeTestNonReadEvents(events)
}

func nativeTestSameEvents(a, b []Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].hash() != b[i].hash() {
			return false
		}
	}
	return true
}

func TestNativeFieldEditUsesExactRevisionAndRefusal(t *testing.T) {
	path, key := nativeTestVault(t)
	s := nativeTestUnlock(t, path, key)
	defer s.Lock()
	id, rev := nativeTestAddLogin(t, s)
	originalRevision := rev

	valid := []struct{ field, value string }{
		{"title", "Updated title"},
		{"url", "https://example.test/login"},
		{"username", "updated-user"},
		{"password", "updated-password"},
		{"otp", nativeTestOTP},
		{"notes", "updated notes\nsecond line"},
	}
	for _, tc := range valid {
		t.Run("edit/"+tc.field, func(t *testing.T) {
			buf := []byte(tc.value)
			g := nativeTestGate(t, s)
			next, err := s.EditNativeField(id, rev, tc.field, buf, g)
			if err != nil {
				t.Fatalf("edit %s: %v", tc.field, err)
			}
			if next == "" || next == rev {
				t.Fatalf("edit %s did not advance revision", tc.field)
			}
			if !bytes.Equal(buf, make([]byte, len(buf))) {
				t.Fatalf("edit %s retained the mutable input", tc.field)
			}
			item := nativeTestInspect(t, s, id, next)
			var got string
			switch tc.field {
			case "title":
				got = item.Title
			case "url":
				got = item.URL
			case "username":
				got = item.Username
			case "password":
				got = item.Password
			case "otp":
				got = item.OTP
			case "notes":
				got = item.Notes
			}
			if got != tc.value {
				t.Fatalf("edit %s stored %q, want %q", tc.field, got, tc.value)
			}
			rev = next
		})
	}

	t.Run("stale-revision", func(t *testing.T) {
		buf := []byte("stale title")
		g := nativeTestGate(t, s)
		if _, err := s.EditNativeField(id, originalRevision, "title", buf, g); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale revision returned %v", err)
		}
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatal("stale revision retained the mutable input")
		}
		if got := nativeTestInspect(t, s, id, rev).Title; got != "Updated title" {
			t.Fatalf("stale edit changed the item: %q", got)
		}
	})

	t.Run("unknown-item", func(t *testing.T) {
		buf := []byte("unknown")
		g := nativeTestGate(t, s)
		if _, err := s.EditNativeField(strings.Repeat("a", 32), rev, "title", buf, g); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown item returned %v", err)
		}
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatal("unknown item retained the mutable input")
		}
	})

	t.Run("cancelled-gate", func(t *testing.T) {
		buf := []byte("cancelled")
		g := nativeTestGate(t, s)
		g.Cancel()
		if _, err := s.EditNativeField(id, rev, "title", buf, g); !errors.Is(err, ErrMutationCancelled) {
			t.Fatalf("cancelled gate returned %v", err)
		}
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatal("cancelled gate retained the mutable input")
		}
		if got := nativeTestInspect(t, s, id, rev).Title; got != "Updated title" {
			t.Fatalf("cancelled gate changed the item: %q", got)
		}
	})

	invalid := []struct{ name, field, value string }{
		{"empty-title", "title", ""},
		{"insecure-url", "url", "http://example.com"},
		{"bad-scheme", "url", "ftp://example.com"},
		{"invalid-otp", "otp", "not-an-otp"},
		{"oversize-notes", "notes", strings.Repeat("x", vault.MaxNotes+1)},
		{"control-notes", "notes", "bad\x00notes"},
	}
	for _, tc := range invalid {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			buf := []byte(tc.value)
			g := nativeTestGate(t, s)
			if _, err := s.EditNativeField(id, rev, tc.field, buf, g); !errors.Is(err, ErrMutationRefused) {
				t.Fatalf("invalid %s returned %v", tc.name, err)
			}
			if !bytes.Equal(buf, make([]byte, len(buf))) {
				t.Fatalf("invalid %s retained the mutable input", tc.name)
			}
			item := nativeTestInspect(t, s, id, rev)
			if item.Title != "Updated title" || item.URL != "https://example.test/login" || item.Notes != "updated notes\nsecond line" {
				t.Fatal("refused edit changed the item")
			}
		})
	}

	t.Run("state", func(t *testing.T) {
		stateID, stateRevision := nativeTestAddLogin(t, s)
		archive, err := s.SetNativeState(stateID, stateRevision, "item.archive", nativeTestGate(t, s))
		if err != nil {
			t.Fatal(err)
		}
		if got := nativeTestInspect(t, s, stateID, archive).State; got != "archived" {
			t.Fatalf("archive state %q", got)
		}
		if _, err := s.SetNativeState(stateID, archive, "item.archive", nativeTestGate(t, s)); !errors.Is(err, ErrAlreadyArchived) {
			t.Fatalf("second archive returned %v", err)
		}
		unarchive, err := s.SetNativeState(stateID, archive, "item.unarchive", nativeTestGate(t, s))
		if err != nil {
			t.Fatal(err)
		}
		if got := nativeTestInspect(t, s, stateID, unarchive).State; got != "" {
			t.Fatalf("unarchive state %q", got)
		}
		if _, err := s.SetNativeState(stateID, unarchive, "item.unarchive", nativeTestGate(t, s)); !errors.Is(err, ErrAlreadyActive) {
			t.Fatalf("second unarchive returned %v", err)
		}
		trashed, err := s.SetNativeState(stateID, unarchive, "item.trash", nativeTestGate(t, s))
		if err != nil {
			t.Fatal(err)
		}
		if row := nativeTestRevision(t, s, "trashed", stateID); row != trashed {
			t.Fatal("trash revision not listed")
		}
		if _, err := s.SetNativeState(stateID, trashed, "item.trash", nativeTestGate(t, s)); !errors.Is(err, ErrAlreadyTrashed) {
			t.Fatalf("second trash returned %v", err)
		}
		untrashed, err := s.SetNativeState(stateID, trashed, "item.untrash", nativeTestGate(t, s))
		if err != nil {
			t.Fatal(err)
		}
		if got := nativeTestInspect(t, s, stateID, untrashed).State; got != "" {
			t.Fatalf("untrash state %q", got)
		}
		if _, err := s.SetNativeState(stateID, untrashed, "item.untrash", nativeTestGate(t, s)); !errors.Is(err, ErrNotTrashed) {
			t.Fatalf("second untrash returned %v", err)
		}
		if _, err := s.SetNativeState(stateID, untrashed, "item.archive", nativeTestGate(t, s)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetNativeState(stateID, stateRevision, "item.archive", nativeTestGate(t, s)); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale state revision returned %v", err)
		}
		g := nativeTestGate(t, s)
		if _, err := s.SetNativeState(stateID, untrashed, "item.delete", g); !errors.Is(err, ErrMutationRefused) {
			t.Fatalf("invalid state action returned %v", err)
		}
		if g.Pending() {
			t.Fatal("invalid state action retained its gate")
		}
	})
}

func TestSessionEditAndStateCancelOnLockBeforePersistence(t *testing.T) {
	t.Run("blocked-open", func(t *testing.T) {
		for _, kind := range []string{"edit", "state", "native-edit", "native-state"} {
			kind := kind
			t.Run(kind, func(t *testing.T) {
				path, key := nativeTestVault(t)
				s := nativeTestUnlock(t, path, key)
				id, rev := nativeTestAddLogin(t, s)
				before := nativeTestAuditTail(t, s)

				holder, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				var g *MutationGate
				switch kind {
				case "edit":
					go func() {
						_, err := s.Edit(Edit{ID: id, Revision: rev, Field: "title", Value: "blocked change"})
						done <- err
					}()
				case "state":
					go func() {
						_, err := s.SetState(id, rev, "item.archive")
						done <- err
					}()
				case "native-edit":
					g = nativeTestGate(t, s)
					go func() {
						_, err := s.EditNativeField(id, rev, "title", []byte("blocked change"), g)
						done <- err
					}()
				case "native-state":
					g = nativeTestGate(t, s)
					go func() {
						_, err := s.SetNativeState(id, rev, "item.archive", g)
						done <- err
					}()
				}

				time.Sleep(40 * time.Millisecond)
				s.RequestLock()
				if err := holder.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if kind == "edit" || kind == "state" {
						if !errors.Is(err, ErrSessionLocked) {
							t.Fatalf("%s returned %v", kind, err)
						}
					} else if !errors.Is(err, ErrMutationCancelled) {
						t.Fatalf("%s returned %v", kind, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("%s did not finish after the database lock was released", kind)
				}

				fresh := nativeTestUnlock(t, path, key)
				defer fresh.Lock()
				rows, err := fresh.List("all")
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, row := range rows {
					if row.ID != id {
						continue
					}
					found = true
					if row.Title != "Original" || row.State != "active" || row.Revision != rev {
						t.Fatalf("blocked %s changed the item: %+v", kind, row)
					}
				}
				if !found {
					t.Fatal("item missing after blocked operation")
				}
				after := nativeTestAuditTail(t, fresh)
				if !nativeTestSameEvents(before, after) {
					t.Fatalf("blocked %s changed the audit log", kind)
				}
			})
		}
	})

	t.Run("cancelled-before-commit", func(t *testing.T) {
		path, key := nativeTestVault(t)
		s := nativeTestUnlock(t, path, key)
		id, rev := nativeTestAddLogin(t, s)
		before := nativeTestAuditTail(t, s)
		g := nativeTestGate(t, s)
		edit := &Edit{ID: id, Revision: rev, Field: "title", Value: "cancelled change"}
		_, err := s.nativeMutationWith("item.edit.title", vault.Item{}, edit, commandOption{}, g, func(o commandOption) (result, error) {
			g.Cancel()
			return command(s.path, "", nil, "item.edit.title", vault.Item{}, edit, o)
		})
		if !errors.Is(err, ErrMutationCancelled) {
			t.Fatalf("pre-commit cancellation returned %v", err)
		}
		fresh := nativeTestUnlock(t, path, key)
		defer fresh.Lock()
		rows, err := fresh.List("all")
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ID == id && (row.Title != "Original" || row.Revision != rev || row.State != "active") {
				t.Fatalf("pre-commit cancellation persisted a change: %+v", row)
			}
		}
		if after := nativeTestAuditTail(t, fresh); !nativeTestSameEvents(before, after) {
			t.Fatal("pre-commit cancellation appended a mutation audit")
		}
	})

	t.Run("commit-won-before-lock", func(t *testing.T) {
		path, key := nativeTestVault(t)
		s := nativeTestUnlock(t, path, key)
		id, rev := nativeTestAddLogin(t, s)
		g := nativeTestGate(t, s)
		edit := &Edit{ID: id, Revision: rev, Field: "title", Value: "committed before lock"}
		var committed result
		_, err := s.nativeMutationWith("item.edit.title", vault.Item{}, edit, commandOption{}, g, func(o commandOption) (result, error) {
			r, err := command(s.path, "", nil, "item.edit.title", vault.Item{}, edit, o)
			committed = r
			s.RequestLock()
			return r, err
		})
		if !errors.Is(err, ErrMutationUnknown) {
			t.Fatalf("commit-then-lock returned %v", err)
		}
		if !g.CommitWon() || committed.revision == "" {
			t.Fatal("commit-then-lock did not observe a committed mutation")
		}
		fresh := nativeTestUnlock(t, path, key)
		defer fresh.Lock()
		rows, err := fresh.List("all")
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		for _, row := range rows {
			if row.ID != id {
				continue
			}
			seen = true
			if row.Title != "committed before lock" || row.Revision != committed.revision || row.Revision == rev {
				t.Fatalf("committed change was not preserved: %+v", row)
			}
		}
		if !seen {
			t.Fatal("committed item missing")
		}
	})
}
