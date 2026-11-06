package desktop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

func notesAppFixture(t *testing.T) (*App, string) {
	t.Helper()
	a := dailyAppFixture(t)
	a.launch = func(f func()) { f() }
	id, e := a.session.AddLogin("Notes target", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := a.session.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == id {
			a.selected = &row
		}
	}
	body := " first\r\n备注\t🙂\nlast  \u202e"
	rev, e := a.session.Edit(personal.Edit{ID: id, Revision: a.selected.Revision, Field: "notes", Value: body})
	if e != nil {
		t.Fatal(e)
	}
	a.selected.Revision = rev
	a.rows = []personal.Row{*a.selected}
	return a, body
}

func TestNotesNativeEditorEnterCancelQuickAndSave(t *testing.T) {
	a, body := notesAppFixture(t)
	a.value = "unrelated-password-draft"
	oldRev := a.selected.Revision
	v := ui.NewTester(a.View, 1100, 820)
	for _, label := range []string{"显示备注", "复制备注", "编辑备注"} {
		if !v.HasText(label) {
			t.Fatal("missing native notes entry")
		}
	}
	if v.HasText(body) {
		t.Fatal("selection disclosed notes")
	}
	if e := v.Click("编辑备注"); e != nil {
		t.Fatal(e)
	}
	if a.notesEditor == nil || a.notesEditor.value != body || a.value != "" || a.notesEditor.title != "Notes target" || !v.HasText("登录：Notes target") {
		t.Fatal("audited editor prefill/target failed")
	}
	draft := a.notesEditor
	if e := v.Click("备注正文（可见多行）"); e != nil {
		t.Fatal(e)
	}
	v.Key(0, ui.KeyEnter)
	if a.notesEditor != draft || len(draft.value) != len(body)+1 || a.busy || a.selected.Revision != oldRev {
		t.Fatal("Enter saved instead of inserting newline")
	}
	edited := draft.value
	a.showQuickSearch()
	v.Frame()
	v.Key(0, ui.KeyEscape)
	if a.notesEditor != draft || draft.value != edited || a.quick.open {
		t.Fatal("temporary quick search lost notes draft")
	}
	if e := v.Click("取消编辑备注"); e != nil {
		t.Fatal(e)
	}
	if a.notesEditor != nil || draft.value != "" || a.selected.Revision != oldRev {
		t.Fatal("cancel changed content or retained draft")
	}
	a.editNotes()
	if a.notesEditor == nil || a.notesEditor.value != body {
		t.Fatal("cancel persisted unsaved edit")
	}
	a.notesEditor.value = "saved\nnew notes🙂"
	a.saveNotes(a.notesEditor)
	if a.notesEditor != nil || a.selected != nil || !strings.Contains(a.status, "备注已保存") {
		t.Fatal("save failed or retained editor")
	}
	for _, row := range a.rows {
		if row.ID == draft.target.ID {
			a.selected = &row
		}
	}
	if a.selected == nil || a.selected.Revision == oldRev {
		t.Fatal("notes save did not advance revision")
	}
	a.editNotes()
	if a.notesEditor == nil || a.notesEditor.value != "saved\nnew notes🙂" {
		t.Fatal("saved notes did not reopen exactly")
	}
}

func TestNotesNativeShowCopyFormattingAndLock(t *testing.T) {
	a, body := notesAppFixture(t)
	clip := attachFakeClipboard(a)
	a.disclose("notes", "show")
	if a.display != visibleNotes(body) || !strings.Contains(a.display, "\n") || strings.Contains(a.display, "\r") || strings.Contains(a.display, "\u202e") || !strings.Contains(a.display, `\u{202E}`) {
		t.Fatal("notes display controls or multiline format incorrect")
	}
	a.disclose("notes", "copy")
	if clip.value != body || time.Until(a.clipboardUntil) > 30*time.Second {
		t.Fatal("notes copy lost original bytes/lease")
	}
	a.editNotes()
	draft := a.notesEditor
	a.Lock()
	if a.notesEditor != nil || draft.value != "" || a.display != "" || clip.value != "" {
		t.Fatal("Lock retained notes exposure")
	}
}

func TestNotesLatePrefillAndNavigationClear(t *testing.T) {
	for _, action := range []string{"page-aba", "selection", "lock", "quick-selection"} {
		t.Run(action, func(t *testing.T) {
			a, _ := notesAppFixture(t)
			var complete func()
			a.dispatch = func(f func()) { complete = f }
			a.editNotes()
			switch action {
			case "page-aba":
				a.clearNotesEditor()
				a.clearDailyExposure()
				a.page = "activity"
				a.page = "vault"
			case "selection":
				a.clearDailyExposure()
				a.selected = &personal.Row{ID: "other", Revision: "other", Title: "Other"}
			case "lock":
				a.Lock()
			case "quick-selection":
				a.clearDailyExposure()
				a.selected = nil
			}
			complete()
			if a.notesEditor != nil {
				t.Fatal("late notes prefill survived changed context")
			}
		})
	}
	a, _ := notesAppFixture(t)
	a.editNotes()
	draft := a.notesEditor
	v := ui.NewTester(a.View, 1100, 820)
	if e := v.Click("活动"); e != nil {
		t.Fatal(e)
	}
	if a.notesEditor != nil || draft.value != "" {
		t.Fatal("actual page navigation retained notes draft")
	}
	if e := v.Click("金库"); e != nil {
		t.Fatal(e)
	}
	a.editNotes()
	draft = a.notesEditor
	a.openQuickSearch()
	a.quick.rows = []personal.Row{{ID: "other", Revision: "other", Title: "Other", State: "active"}}
	a.chooseQuickResult(a.quick.generation, a.quick.sequence, a.quick.rows[0])
	if a.notesEditor != nil || draft.value != "" {
		t.Fatal("explicit quick selection retained notes draft")
	}
}

func TestNotesPrefillTitleIsCapturedWithOriginalTarget(t *testing.T) {
	a, _ := notesAppFixture(t)
	var complete func()
	a.dispatch = func(f func()) { complete = f }
	a.editNotes()
	// The metadata shown at approval must be the one captured by that click,
	// even if the in-memory row representation changes before UI dispatch.
	a.selected.Title = "later metadata title"
	complete()
	if a.notesEditor == nil || a.notesEditor.title != "Notes target" {
		t.Fatal("late notes prefill switched displayed target title")
	}
	v := ui.NewTester(a.View, 1100, 820)
	if !v.HasText("登录：Notes target") || v.HasText("登录：later metadata title") {
		t.Fatal("editor did not display frozen target metadata")
	}
}

func TestNotesSaveConflictUnknownAndCaptureCleanup(t *testing.T) {
	a, _ := notesAppFixture(t)
	a.editNotes()
	old := a.notesEditor.target
	if _, e := a.session.Edit(personal.Edit{ID: old.ID, Revision: old.Revision, Field: "notes", Value: "newer value"}); e != nil {
		t.Fatal(e)
	}
	a.notesEditor.value = "stale overwrite"
	a.saveNotes(a.notesEditor)
	if a.notesEditor != nil || !strings.Contains(a.status, "其他操作中变更") || a.mutationUnknown {
		t.Fatal("stale notes save was not a fixed conflict")
	}
	// Failed ownership handoff must clear the captured mutable buffer too.
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := a.session.RegisterMutation(g); e != nil {
		t.Fatal(e)
	}
	buf := []byte("untransferred notes")
	a.saveNotesCaptured(a.session, old, buf, "active")
	a.session.ReleaseMutation(g)
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatal("rejected notes registration retained captured buffer")
	}
	rows, e := a.session.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == old.ID {
			a.selected = &row
		}
	}
	a.editNotes()
	var queued []func()
	var complete func()
	a.launch = func(f func()) { queued = append(queued, f) }
	a.dispatch = func(f func()) { complete = f }
	a.saveNotes(a.notesEditor)
	queued[0]()
	a.Lock()
	complete()
	if !a.mutationUnknown || a.notesEditor != nil || !strings.Contains(a.status, "结果未确认") {
		t.Fatal("late committed notes receipt lost unknown/lock")
	}
	for _, f := range queued[1:] {
		f()
	}
}

func TestNotesDraftFormattingRefusesValues(t *testing.T) {
	d := nativeNotesDraft{value: "private-notes-canary"}
	for _, value := range []any{d, &d} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[native notes draft]" {
				t.Fatal("notes draft formatting not redacted")
			}
		}
		if raw, e := json.Marshal(value); e == nil || len(raw) != 0 {
			t.Fatal("notes draft serialized")
		}
	}
}

func TestNotesCleanupReentryRevokesPrefillAndSave(t *testing.T) {
	for _, stage := range []string{"prefill", "save"} {
		for _, action := range []string{"page-aba", "selection", "lock"} {
			t.Run(stage+"/"+action, func(t *testing.T) {
				a, _ := notesAppFixture(t)
				if stage == "save" {
					a.editNotes()
				}
				clip := attachFakeClipboard(a)
				lease, _ := clip.write([]byte("owned prior value"))
				a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
				before := a.operationSequence
				clip.beforeClear = func() {
					clip.beforeClear = nil
					switch action {
					case "page-aba":
						a.clearDailyExposure()
						a.page = "activity"
						a.page = "vault"
					case "selection":
						a.clearDailyExposure()
						a.selected = &personal.Row{ID: "new-target", Revision: "new-revision", Title: "New target"}
					case "lock":
						a.Lock()
					}
				}
				if stage == "prefill" {
					a.editNotes()
				} else {
					a.saveNotes(a.notesEditor)
				}
				if a.operationSequence != before || a.notesEditor != nil || a.busy {
					t.Fatal("cleanup reentry allowed stale notes prefill/save")
				}
			})
		}
	}
}
