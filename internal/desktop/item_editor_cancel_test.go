package desktop

import (
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// openEditorFixture adds one real login through the unlocked session, selects
// it the way the detail pane does, and opens the editor through beginEdit.
func openEditorFixture(t *testing.T) (*App, *personal.Session, string) {
	t.Helper()
	a := v2ParitySaveApp(t)
	s := a.session
	id, err := s.AddLogin("synthetic editor item", "synthetic-user", "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	row := bugfixRow(t, a, id)
	a.v2.selectedID, a.v2.selectedRevision = row.ID, row.Revision
	a.v2.detail = &personal.ItemDetail{ID: row.ID, Revision: row.Revision, Kind: "login", Title: row.Title, Username: "synthetic-user"}
	if err := a.beginEdit(); err != nil {
		t.Fatalf("beginEdit: %v", err)
	}
	if a.v2.detailPlain == nil || a.v2.draft == nil {
		t.Fatal("beginEdit did not load the plaintext detail and draft")
	}
	return a, s, id
}

func TestCancelEditReleasesPlaintextLoadedByBeginEdit(t *testing.T) {
	a, _, _ := openEditorFixture(t)

	a.CancelEdit()

	if a.v2.draft != nil || a.v2.editing {
		t.Fatal("cancel edit retained the draft")
	}
	if a.v2.detailPlain != nil {
		t.Fatal("cancel edit retained an unmasked detail with no reveal timer")
	}
	if !a.v2.revealUntil.IsZero() || len(a.v2.revealed) != 0 || a.v2.largeTypeOpen {
		t.Fatal("cancel edit left stale disclosure state")
	}

	// No timer may later be armed for plaintext that is already gone.
	a.backgroundTick(time.Now().Add(time.Hour))
	if a.v2.detailPlain != nil {
		t.Fatal("background tick revived the cancelled plaintext")
	}
}

func TestCancelEditWaitsForLargeTypeBeforeDroppingPlaintext(t *testing.T) {
	a, _, _ := openEditorFixture(t)
	a.showLargeType("password")
	if !a.v2.largeTypeOpen || a.v2.largeTypeValue != "synthetic-password" {
		t.Fatal("large type did not open from the editor plaintext")
	}

	a.CancelEdit()

	if !a.v2.largeTypeOpen || a.v2.largeTypeValue != "synthetic-password" {
		t.Fatal("cancel edit dropped a large type view it still owns")
	}
	if !a.v2.revealUntil.IsZero() || len(a.v2.revealed) != 0 {
		t.Fatal("cancel edit left editor reveal state behind")
	}
	a.CloseLargeType()
	if a.v2.largeTypeOpen || a.v2.largeTypeValue != "" || a.v2.detailPlain != nil {
		t.Fatal("closing large type retained its value or the editor plaintext")
	}
}

func TestCancelEditDuringBeginEditReadNeverStoresPlaintext(t *testing.T) {
	a := v2ParitySaveApp(t)
	id, err := a.session.AddLogin("synthetic racy item", "synthetic-user", "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	row := bugfixRow(t, a, id)
	a.v2.selectedID, a.v2.selectedRevision = row.ID, row.Revision
	a.v2.detail = &personal.ItemDetail{ID: row.ID, Revision: row.Revision, Kind: "login", Title: row.Title}
	a.v2.editing = true
	var worker, complete func()
	a.launch = func(fn func()) { worker = fn }
	a.dispatch = func(fn func()) { complete = fn }

	if err := a.beginEdit(); err != nil {
		t.Fatalf("beginEdit: %v", err)
	}
	a.CancelEdit()
	worker()
	complete()

	if a.v2.detailPlain != nil || a.v2.draft != nil || a.v2.editing {
		t.Fatal("a cancelled edit read repopulated the editor")
	}
}

func TestSaveDraftReleasesPlaintextReadByBeginEdit(t *testing.T) {
	a, _, id := openEditorFixture(t)
	a.revealField("password")
	if !a.v2.revealUntil.After(time.Now()) {
		t.Fatal("reveal did not arm its exposure timer")
	}
	a.v2.draft.Title = "synthetic edited title"

	if err := a.SaveDraft(); err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}

	if a.v2.detailPlain != nil || len(a.v2.revealed) != 0 || !a.v2.revealUntil.IsZero() {
		t.Fatal("save retained the editor plaintext or its reveal state")
	}
	if a.v2.detail == nil || a.v2.detail.Title != "synthetic edited title" || a.v2.detail.ID != id {
		t.Fatalf("saved detail = %+v", a.v2.detail)
	}
}
