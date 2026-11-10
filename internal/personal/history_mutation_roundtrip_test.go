package personal

import (
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

func historyRoundtripState(t *testing.T, s *Session, id string) ItemDetail {
	t.Helper()
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID != id {
			continue
		}
		detail, err := s.GetItemDetail(id, row.Revision, true)
		if err != nil {
			t.Fatal(err)
		}
		return detail
	}
	t.Fatalf("login %q missing from active list", id)
	return ItemDetail{}
}

func historyRoundtripLast(t *testing.T, detail ItemDetail) vault.ItemHistoryEntry {
	t.Helper()
	if len(detail.History) == 0 {
		t.Fatalf("history is empty for %q", detail.Title)
	}
	return detail.History[len(detail.History)-1]
}

// TestPasswordMutationPathsAppendHistoryAcrossReopen drives every credential
// mutation path against a real vault file and reopens it between steps. The
// reopened history must contain the previous credential values, not just the
// in-memory item.
func TestPasswordMutationPathsAppendHistoryAcrossReopen(t *testing.T) {
	s, path, key := v2Session(t)
	t.Cleanup(func() { s.Lock() })
	reopen := func() {
		t.Helper()
		s.Lock()
		next, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		s = next
	}

	login := v2LoginItem()
	id, rev, err := s.AddItem(login, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	context := BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "document-1"}
	target := BrowserSaveTarget{Context: BrowserSaveContext{BrowserContext: context, WindowID: 1}, ID: id, Revision: rev}
	receipt, err := s.SaveBrowser(target, []byte("browser-user"), []byte("browser-password"), saveGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	detail := historyRoundtripState(t, s, id)
	if detail.Revision != receipt.Revision || len(detail.History) != 1 {
		t.Fatalf("browser update history: revision=%q want=%q entries=%d", detail.Revision, receipt.Revision, len(detail.History))
	}
	entry := historyRoundtripLast(t, detail)
	if entry.Action != "edit" || entry.Password != "old-password" || entry.Username != "v2-user" || entry.Title != "V2 Login" || entry.Notes != "v2 notes" || !reflect.DeepEqual(entry.Sections, login.Sections) {
		t.Fatalf("browser update history entry: %+v", entry)
	}

	next, err := s.EditNativeField(id, receipt.Revision, "username", []byte("edited-user"), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	detail = historyRoundtripState(t, s, id)
	if detail.Revision != next || len(detail.History) != 2 {
		t.Fatalf("username edit history: revision=%q want=%q entries=%d", detail.Revision, next, len(detail.History))
	}
	entry = historyRoundtripLast(t, detail)
	if entry.Password != "browser-password" || entry.Username != "browser-user" || entry.Notes != "v2 notes" {
		t.Fatalf("username edit history entry: %+v", entry)
	}

	next, err = s.EditNativeField(id, next, "notes", []byte("edited notes"), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	detail = historyRoundtripState(t, s, id)
	if detail.Revision != next || len(detail.History) != 3 {
		t.Fatalf("notes edit history: revision=%q want=%q entries=%d", detail.Revision, next, len(detail.History))
	}
	entry = historyRoundtripLast(t, detail)
	if entry.Password != "browser-password" || entry.Username != "edited-user" || entry.Notes != "v2 notes" {
		t.Fatalf("notes edit history entry: %+v", entry)
	}

	next, err = s.EditNativeField(id, next, "password", []byte("edited-password"), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	detail = historyRoundtripState(t, s, id)
	if detail.Revision != next || len(detail.History) != 4 {
		t.Fatalf("password edit history: revision=%q want=%q entries=%d", detail.Revision, next, len(detail.History))
	}
	entry = historyRoundtripLast(t, detail)
	if entry.Password != "browser-password" || entry.Username != "edited-user" || entry.Notes != "edited notes" {
		t.Fatalf("password edit history entry: %+v", entry)
	}

	s.Lock()
	generated, err := RegeneratePassword(path, "v2-fixture", key, id, next, 24)
	if err != nil {
		t.Fatal(err)
	}
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	detail = historyRoundtripState(t, s, id)
	if detail.Revision != generated.Revision || len(detail.History) != 5 {
		t.Fatalf("regenerate history: revision=%q want=%q entries=%d", detail.Revision, generated.Revision, len(detail.History))
	}
	entry = historyRoundtripLast(t, detail)
	if entry.Password != "edited-password" || entry.Username != "edited-user" || entry.Notes != "edited notes" {
		t.Fatalf("regenerate history entry: %+v", entry)
	}
}

// TestHistoryRestoreReproducesExactSnapshotAcrossReopen starts with empty
// title-adjacent fields and no sections, then changes all of them. Restoring
// the old revision must clear those fields back to their historical empty
// state, including sections that were empty at the snapshot.
func TestHistoryRestoreReproducesExactSnapshotAcrossReopen(t *testing.T) {
	s, path, key := v2Session(t)
	t.Cleanup(func() { s.Lock() })

	original := vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Snapshot Title",
		URL:      "https://example.test/login",
		Username: "",
		Password: "old-password",
		Notes:    "",
	}
	id, rev, err := s.AddItem(original, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	changed := vault.CloneItem(original)
	changed.Title = "Current Title"
	changed.Username = "filled-user"
	changed.Password = "new-password"
	changed.Notes = "filled notes"
	changed.Sections = []vault.ItemSection{{ID: "section-one", Title: "Section One", Fields: []vault.CustomField{
		{ID: "secret", Label: "Secret", Type: vault.FieldTypeConcealed, Value: "concealed-value", Protected: true},
	}}}
	edited, err := s.EditItem(id, rev, changed, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}

	s.Lock()
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	detail := historyRoundtripState(t, s, id)
	if detail.Revision != edited || len(detail.History) != 1 {
		t.Fatalf("snapshot history: revision=%q want=%q entries=%d", detail.Revision, edited, len(detail.History))
	}
	entry := historyRoundtripLast(t, detail)
	if entry.Password != "old-password" || entry.Title != "Snapshot Title" || entry.Username != "" || entry.Notes != "" || entry.Sections == nil || len(entry.Sections) != 0 {
		t.Fatalf("snapshot entry: %+v", entry)
	}

	restored, err := s.RestoreHistory(id, edited, 0, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got := historyRoundtripState(t, s, id)
	if got.Revision != restored || got.Password != "old-password" || got.Title != "Snapshot Title" || got.Username != "" || got.Notes != "" || len(got.Sections) != 0 {
		t.Fatalf("restored snapshot: %+v", got)
	}
}

// TestHistoryRestoreHonorsLegacyAutoEditEmptySnapshotAcrossReopen reproduces
// the historical autoHistory entry shape written before full section snapshots:
// Action "edit" whose Title/Username/Notes were all empty and whose sections
// key is absent because the old writer only stored sections when a concealed
// field changed. Restoring it clears the empty Title/Username/Notes but a nil
// sections key means "not recorded" and must keep the current protected and
// OTP sections. The 1PUX-only row stays password-only.
func TestHistoryRestoreHonorsLegacyAutoEditEmptySnapshotAcrossReopen(t *testing.T) {
	s, path, key := v2Session(t)
	t.Cleanup(func() { s.Lock() })

	legacy := vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Legacy Auto Login",
		URL:      "https://example.test/login",
		Username: "current-user",
		Password: "current-password",
		Notes:    "current notes",
		Sections: []vault.ItemSection{{ID: "section-one", Title: "Section One", Fields: []vault.CustomField{
			{ID: "secret", Label: "Secret", Type: vault.FieldTypeConcealed, Value: "current-secret", Protected: true},
			{ID: "totp", Label: "TOTP", Type: vault.FieldTypeOTP, Value: v2OTPConfig, Protected: true},
		}}},
		History: []vault.ItemHistoryEntry{
			{Timestamp: 1600000000, Action: "edit", Password: "empty-fields-password", Sections: nil},
			{Timestamp: 1600000001, Action: "import-1pux", Password: "imported-password"},
		},
	}
	id, rev, err := s.AddItem(legacy, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if entry := historyRoundtripState(t, s, id).History[0]; entry.Action != "edit" || entry.Title != "" || entry.Username != "" || entry.Notes != "" || entry.Sections != nil {
		t.Fatalf("legacy auto edit row changed shape: %+v", entry)
	}

	legacyRestored, err := s.RestoreHistory(id, rev, 0, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got := historyRoundtripState(t, s, id)
	if got.Revision != legacyRestored || got.Password != "empty-fields-password" || got.Title != "" || got.Username != "" || got.Notes != "" || !reflect.DeepEqual(got.Sections, legacy.Sections) {
		t.Fatalf("legacy auto edit restore: %+v", got)
	}

	// Removing the restored edit row leaves the 1PUX row at index 0. It must
	// still restore only its password and keep the current empty fields and
	// untouched sections.
	importedRestored, err := s.RestoreHistory(id, legacyRestored, 0, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got = historyRoundtripState(t, s, id)
	if got.Revision != importedRestored || got.Password != "imported-password" || got.Title != "" || got.Username != "" || got.Notes != "" || !reflect.DeepEqual(got.Sections, legacy.Sections) {
		t.Fatalf("legacy 1PUX restore: %+v", got)
	}
}

// TestHistoryRestoreKeepsLegacyPasswordOnlyEntryCompatible verifies that an
// imported 1PUX history row, which only ever carried a password, still restores
// that password without clearing fields the row never recorded.
func TestHistoryRestoreKeepsLegacyPasswordOnlyEntryCompatible(t *testing.T) {
	s, path, key := v2Session(t)
	t.Cleanup(func() { s.Lock() })

	legacy := vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Legacy Import",
		URL:      "https://example.test/login",
		Username: "kept-user",
		Password: "current-password",
		Notes:    "kept notes",
		Sections: []vault.ItemSection{{ID: "section-one", Title: "Section One", Fields: []vault.CustomField{
			{ID: "secret", Label: "Secret", Type: vault.FieldTypeConcealed, Value: "kept-secret", Protected: true},
		}}},
		History: []vault.ItemHistoryEntry{{Timestamp: 1600000000, Action: "import-1pux", Password: "legacy-password"}},
	}
	id, rev, err := s.AddItem(legacy, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := s.RestoreHistory(id, rev, 0, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}

	s.Lock()
	s, err = UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got := historyRoundtripState(t, s, id)
	if got.Revision != restored || got.Password != "legacy-password" || got.Title != "Legacy Import" || got.Username != "kept-user" || got.Notes != "kept notes" || !reflect.DeepEqual(got.Sections, legacy.Sections) {
		t.Fatalf("legacy restore: %+v", got)
	}
}
