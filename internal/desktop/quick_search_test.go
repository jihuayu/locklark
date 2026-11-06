package desktop

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

func quickSearchDisclosureAction(action string) bool {
	return strings.HasPrefix(action, "item.desktop.show.") ||
		strings.HasPrefix(action, "item.desktop.copy.") ||
		strings.Contains(action, "reveal") || strings.Contains(action, "otp")
}

func TestQuickSearchEntryOpensIndependentPanel(t *testing.T) {
	a := dailyAppFixture(t)
	a.query, a.title, a.value = "main-query", "draft-title", "draft-value"
	v := ui.NewTester(a.View, 1100, 820)
	if e := v.Click("快捷搜索"); e != nil {
		t.Fatal("missing quick-search entry")
	}
	if !v.HasText("快捷搜索活动登录") || !v.Focused("快捷搜索标题") {
		t.Fatal("quick-search panel did not open with focused input")
	}
	if v.HasText("生成强密码并保存") {
		t.Fatal("underlying editor remained actionable")
	}
	if e := v.Click("关闭快捷搜索"); e != nil {
		t.Fatal(e)
	}
	if a.query != "main-query" || a.title != "draft-title" || a.value != "draft-value" {
		t.Fatal("closing quick search changed drafts")
	}
}

func TestQuickSearchExplicitActiveMetadataAndSelection(t *testing.T) {
	a := dailyAppFixture(t)
	s := a.session
	active, e := s.AddLogin("Café account", "private-user", "private-value")
	if e != nil {
		t.Fatal(e)
	}
	archived, e := s.AddLogin("Café archive", "other-user", "other-value")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == archived {
			if _, e = s.SetState(row.ID, row.Revision, "item.archive"); e != nil {
				t.Fatal(e)
			}
		}
	}
	a.launch = func(f func()) { f() }
	a.page, a.scope, a.query = "transfer", "archived", "main-query"
	a.title, a.website, a.username, a.value = "draft", "https://draft.example", "draft-user", "draft-value"
	a.rows = []personal.Row{{ID: "old"}}
	a.regenerate = &personal.NativeLoginView{ID: "old"}
	a.openQuickSearch()
	if a.quick.inFlight != nil || len(a.quick.rows) != 0 || a.quick.query != "" {
		t.Fatal("opening queried metadata")
	}
	a.quick.query = "CAFE\u0301"
	a.searchQuick()
	if a.quick.loading || len(a.quick.rows) != 1 || a.quick.rows[0].ID != active || a.quick.rows[0].State != "active" {
		t.Fatal("query did not use active title search")
	}
	if a.page != "transfer" || a.query != "main-query" || a.rows[0].ID != "old" || a.status != "" {
		t.Fatal("query changed underlying editor/status")
	}
	if a.display != "" || !a.clipboardUntil.IsZero() || a.otpDisplay != "" {
		t.Fatal("query disclosed data")
	}
	target := a.quick.rows[0]
	a.chooseQuickResult(a.quick.generation, a.quick.sequence, target)
	if a.quick.open || a.selected == nil || a.selected.ID != active || a.selected.Revision != target.Revision || a.page != "vault" || a.scope != "active" || a.query != "CAFE\u0301" {
		t.Fatal("explicit result navigation lost target")
	}
	if a.title != "" || a.website != "" || a.username != "" || a.value != "" || a.regenerate != nil || a.display != "" {
		t.Fatal("navigation retained prior edit/disclosure")
	}
	// Empty input is an explicit List(active), never an automatic open action.
	a.openQuickSearch()
	a.searchQuick()
	if len(a.quick.rows) != 1 || a.quick.rows[0].ID != active {
		t.Fatal("empty explicit query did not list active")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	searches := 0
	for _, ev := range events {
		if ev.Action == "item.search" {
			searches++
		}
		if quickSearchDisclosureAction(ev.Action) {
			t.Fatal("metadata query created disclosure intent")
		}
	}
	if searches != 1 {
		t.Fatal("quick search bypassed or duplicated authenticated search audit")
	}
	// Positive control: the same oracle must recognize actual audited desktop
	// intents for both fields and purposes, not just hypothetical action names.
	want := map[string]bool{}
	for _, purpose := range []string{"show", "copy"} {
		for _, field := range []string{"username", "password"} {
			prepared, e := s.PrepareField(personal.RevealTarget{ID: target.ID, Revision: target.Revision, Field: field}, purpose)
			if e != nil {
				t.Fatal(e)
			}
			s.Discard(prepared)
			want["item.desktop."+purpose+"."+field] = false
		}
	}
	events, e = s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	for _, ev := range events {
		if _, expected := want[ev.Action]; expected {
			if !quickSearchDisclosureAction(ev.Action) {
				t.Fatal("metadata-only oracle missed a real desktop disclosure intent")
			}
			want[ev.Action] = true
		}
	}
	for _, seen := range want {
		if !seen {
			t.Fatal("missing real desktop disclosure positive control")
		}
	}
}

func TestQuickSearchSingleWorkerAndLateResults(t *testing.T) {
	a := dailyAppFixture(t)
	var workers, completions []func()
	a.launch = func(f func()) { workers = append(workers, f) }
	a.dispatch = func(f func()) { completions = append(completions, f) }
	a.openQuickSearch()
	a.quick.query = "first"
	a.searchQuick()
	first := a.quick.inFlight
	a.searchQuick()
	a.closeQuickSearch()
	a.openQuickSearch()
	if !a.quick.loading || a.quick.inFlight != first || len(workers) != 1 {
		t.Fatal("reopen lost single worker ownership")
	}
	a.quick.query = "second"
	a.searchQuick()
	if len(workers) != 1 {
		t.Fatal("reopen queued second worker")
	}
	workers[0]()
	completions[0]()
	if a.quick.inFlight != nil || a.quick.loading || len(a.quick.rows) != 0 || a.quick.query != "second" {
		t.Fatal("late result changed reopened panel")
	}
	a.searchQuick()
	second := a.quick.inFlight
	if second == nil || second == first || len(workers) != 2 {
		t.Fatal("slot was not released for explicit retry")
	}
	a.finishQuickSearch(first, []personal.Row{{ID: "stale"}}, nil)
	if a.quick.inFlight != second || !a.quick.loading {
		t.Fatal("old completion released newer worker")
	}
	workers[1]()
	completions[1]()
	if a.quick.loading || a.quick.inFlight != nil {
		t.Fatal("current worker did not release slot")
	}
}

func TestQuickSearchTypingInvalidatesRowsAndInFlightResult(t *testing.T) {
	a := dailyAppFixture(t)
	var workers []func()
	a.launch = func(f func()) { workers = append(workers, f) }
	a.openQuickSearch()
	a.quick.query = "before"
	row := personal.Row{ID: "old", Revision: "revision", Title: "old-title", State: "active"}
	a.quick.rows = []personal.Row{row}
	panel, sequence := a.quick.generation, a.quick.sequence
	v := ui.NewTester(a.View, 1100, 820)
	if !v.HasText("选择登录：old-title") {
		t.Fatal("missing initial metadata result")
	}
	v.Type("after")
	if len(a.quick.rows) != 0 || v.HasText("选择登录：old-title") {
		t.Fatal("typing left old result actionable")
	}
	a.chooseQuickResult(panel, sequence, row)
	if !a.quick.open || a.selected != nil {
		t.Fatal("old result callback navigated")
	}
	v.Key(0, ui.KeyEnter)
	if len(workers) != 1 {
		t.Fatal("Enter did not start query")
	}
	v.Type("changed")
	workers[0]()
	if len(a.quick.rows) != 0 || a.quick.loading {
		t.Fatal("result survived changed input")
	}
}

func TestQuickSearchLockedBusyRepeatedAndOneShotFocus(t *testing.T) {
	locked := New()
	locked.launch = func(func()) { t.Fatal("locked shortcut launched worker") }
	locked.password, locked.secret, locked.status = "draft-password", "draft-factor", "existing"
	locked.showQuickSearch()
	if locked.quick.open || locked.password != "draft-password" || locked.secret != "draft-factor" || locked.status != "existing" {
		t.Fatal("locked shortcut changed unlock state")
	}
	a := dailyAppFixture(t)
	a.busy = true
	a.status, a.display = "existing operation", "authorized display"
	before := a.exposureGeneration
	a.showQuickSearch()
	if a.quick.open || !a.busy || a.status != "existing operation" || a.display != "authorized display" || a.exposureGeneration != before {
		t.Fatal("busy shortcut disturbed operation")
	}
	a.busy = false
	a.value = "draft-preserved-on-Escape"
	a.openQuickSearch()
	v := ui.NewTester(a.View, 1100, 820)
	if !v.Focused("快捷搜索标题") || a.display != "" {
		t.Fatal("new panel did not focus/clear exposure")
	}
	v.Type("keep")
	v.Key(0, ui.KeyEscape)
	if a.quick.open || a.value != "draft-preserved-on-Escape" {
		t.Fatal("Escape in nonempty search input did not dismiss panel/preserve draft")
	}
	// Reopen then move focus away. Repeated invocation must preserve focus/query.
	a.openQuickSearch()
	v.Frame()
	v.Type("keep")
	v.Key(0, ui.KeyTab)
	if v.Focused("快捷搜索标题") {
		t.Fatal("Tab did not leave search input")
	}
	panel := a.quick.generation
	a.showQuickSearch()
	v.Frame()
	if a.quick.query != "keep" || a.quick.generation != panel || v.Focused("快捷搜索标题") {
		t.Fatal("repeated shortcut reset/focused panel")
	}
	v.Key(0, ui.KeyEscape)
	if a.quick.open {
		t.Fatal("Escape did not dismiss panel")
	}
}

func TestQuickSearchMainOperationAndLockRevokeResult(t *testing.T) {
	for _, kind := range []string{"context", "native", "lock", "session"} {
		t.Run(kind, func(t *testing.T) {
			a := dailyAppFixture(t)
			var workers []func()
			a.launch = func(f func()) { workers = append(workers, f) }
			a.openQuickSearch()
			a.quick.query = "pending"
			a.searchQuick()
			r := a.quick.inFlight
			s := a.session
			switch kind {
			case "context":
				a.runContext(func(context.Context) outcome { return outcome{} })
			case "native":
				a.runNative(func(*personal.MutationGate) nativeResult { return nativeResult{} }, func(nativeResult) {})
				t.Cleanup(func() { s.ReleaseMutation(a.operation.gate) })
			case "lock":
				a.Lock()
			case "session":
				// Session replacement is accepted through the common main-operation
				// entry, just like ordinary/system unlock.
				a.run(func() outcome { return outcome{apply: func() { a.session = nil }} })
				workers[1]()
			}
			if a.quick.open || a.quick.query != "" || a.quick.rows != nil || a.quick.loading || a.quick.focus {
				t.Fatal("main transition retained quick state")
			}
			status := a.status
			a.finishQuickSearch(r, []personal.Row{{ID: "stale"}}, nil)
			if a.quick.open || a.quick.inFlight != nil || a.status != status || a.rows != nil {
				t.Fatal("late metadata changed main state")
			}
		})
	}
}

func TestQuickSearchQueryValidationAndFixedRegistrationErrors(t *testing.T) {
	a := dailyAppFixture(t)
	a.openQuickSearch()
	a.launch = func(func()) { t.Fatal("invalid query launched worker") }
	for _, query := range []string{" ", "\n", "bad\u200e", strings.Repeat("x", 257), string([]byte{0xff})} {
		a.quick.query = query
		a.quick.rows = []personal.Row{{ID: "old"}}
		a.searchQuick()
		if len(a.quick.rows) != 0 || a.quick.inFlight != nil || !strings.Contains(a.quick.status, "256") {
			t.Fatal("invalid query retained results")
		}
	}
	a.registerQuickSearch(func(acc string, fn func()) error {
		if acc != "CmdOrCtrl+Shift+L" || fn == nil {
			t.Fatal("wrong shortcut registration")
		}
		return errors.New("private native failure detail")
	})
	v := ui.NewTester(a.securityView, 1100, 820)
	if !v.HasText(quickShortcutUnavailable) || strings.Contains(strings.Join(v.Texts(), " "), "private native") {
		t.Fatal("registration error was hidden or unfiltered")
	}
	a.registerQuickSearch(func(string, func()) error { return nil })
	if a.quickShortcut != quickShortcutPending {
		t.Fatal("registration success claimed completed OS authorization")
	}
}

func TestQuickSearchOpeningClearsOwnedExposureButPreservesDrafts(t *testing.T) {
	a := dailyAppFixture(t)
	clip := attachFakeClipboard(a)
	if e := a.writeClipboard([]byte("synthetic-copy"), time.Now().Add(time.Minute), func() bool { return true }); e != nil {
		t.Fatal(e)
	}
	a.display, a.otpDisplay = "synthetic-display", "123456"
	a.title, a.website, a.username, a.value = "draft", "https://draft.example", "u", "p"
	a.page = "transfer"
	a.selected = &personal.Row{ID: "selected", Revision: "revision"}
	selected := *a.selected
	a.openQuickSearch()
	a.closeQuickSearch()
	if clip.value != "" || a.display != "" || a.otpDisplay != "" || a.clipboardLease != nil {
		t.Fatal("opening retained owned exposure")
	}
	if a.page != "transfer" || !reflect.DeepEqual(*a.selected, selected) || a.title != "draft" || a.website != "https://draft.example" || a.username != "u" || a.value != "p" {
		t.Fatal("cancel changed editing context")
	}
}

func TestQuickSearchRequestLockBeforeQueryOrSelection(t *testing.T) {
	for _, action := range []string{"query", "select"} {
		t.Run(action, func(t *testing.T) {
			a := dailyAppFixture(t)
			a.openQuickSearch()
			row := personal.Row{ID: "target", Revision: "revision", Title: "title", State: "active"}
			a.quick.rows = []personal.Row{row}
			a.quick.query = "title"
			old := a.session
			old.RequestLock()
			var launches int
			a.launch = func(f func()) { launches++ } // Only the asynchronous Session.Lock is permitted.
			if action == "query" {
				a.searchQuick()
			} else {
				a.chooseQuickResult(a.quick.generation, a.quick.sequence, row)
			}
			if a.session != nil || a.quick.open || a.quick.inFlight != nil || a.quick.query != "" || a.selected != nil || launches != 1 {
				t.Fatal("requested session lock allowed metadata query/navigation")
			}
		})
	}
}

func TestQuickSearchKeyboardSelectionAndNewQueryClearsRows(t *testing.T) {
	a := dailyAppFixture(t)
	if _, e := a.session.AddLogin("keyboard target", "synthetic-user", "synthetic-value"); e != nil {
		t.Fatal(e)
	}
	a.launch = func(f func()) { f() }
	a.openQuickSearch()
	v := ui.NewTester(a.View, 1100, 820)
	v.Type("keyboard")
	v.Key(0, ui.KeyEnter)
	if len(a.quick.rows) != 1 || a.quick.query != "keyboard" {
		t.Fatal("typed Enter query did not produce result")
	}
	row := a.quick.rows[0]
	// Input -> search -> close -> first result, all through native UI keyboard semantics.
	v.Key(0, ui.KeyTab)
	v.Key(0, ui.KeyTab)
	v.Key(0, ui.KeyTab)
	if !v.Focused("选择登录：keyboard target") {
		t.Fatal("result is not keyboard reachable")
	}
	v.Key(0, ui.KeyEnter)
	if a.quick.open || a.selected == nil || a.selected.ID != row.ID || a.selected.Revision != row.Revision {
		t.Fatal("keyboard result did not navigate exact target")
	}
	a.openQuickSearch()
	a.quick.rows = []personal.Row{row}
	var worker func()
	a.launch = func(f func()) { worker = f }
	a.searchQuick()
	if worker == nil || !a.quick.loading || len(a.quick.rows) != 0 {
		t.Fatal("new query retained old actionable rows")
	}
	worker()
	if a.quick.loading {
		t.Fatal("query remained loading after completion")
	}
}

func TestQuickSearchFailuresReleaseSlotWithoutLeakingErrorDetails(t *testing.T) {
	a := dailyAppFixture(t)
	var work func()
	a.launch = func(f func()) { work = f }
	a.openQuickSearch()
	a.searchQuick()
	r := a.quick.inFlight
	if r == nil || work == nil {
		t.Fatal("missing pending request")
	}
	a.finishQuickSearch(r, []personal.Row{{ID: "should-not-publish"}}, errors.New("private-path-and-diagnostics"))
	if a.quick.inFlight != nil || a.quick.loading || len(a.quick.rows) != 0 || strings.Contains(a.quick.status, "private") {
		t.Fatal("query failure retained results, slot or raw diagnostic")
	}
	a.searchQuick()
	if a.quick.inFlight == nil {
		t.Fatal("failed query did not release slot")
	}
	a.closeQuickSearch()
}
