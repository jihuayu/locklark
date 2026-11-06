package desktop

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	bolt "go.etcd.io/bbolt"
)

func bugfixKey() []byte { return bytes.Repeat([]byte{4}, 16) }

func bugfixAddLogin(t *testing.T, a *App, title, user, pass string) personal.Row {
	t.Helper()
	id, err := a.session.AddLogin(title, user, pass)
	if err != nil {
		t.Fatal(err)
	}
	return bugfixRow(t, a, id)
}

func bugfixRow(t *testing.T, a *App, id string) personal.Row {
	t.Helper()
	rows, err := a.session.List("all")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatal("login row missing", id)
	return personal.Row{}
}

func bugfixSelect(t *testing.T, a *App, id string) personal.Row {
	t.Helper()
	row := bugfixRow(t, a, id)
	a.selected = &row
	return row
}

func bugfixDrain(t *testing.T, dispatch <-chan func()) {
	t.Helper()
	select {
	case fn := <-dispatch:
		fn()
	case <-time.After(2 * time.Second):
		t.Fatal("dispatched native work did not arrive")
	}
}

func bugfixRows(t *testing.T, a *App) []string {
	t.Helper()
	titles := make([]string, 0, len(a.rows))
	for _, row := range a.rows {
		titles = append(titles, row.Title)
	}
	return titles
}

func bugfixWantRows(t *testing.T, a *App, want ...string) {
	t.Helper()
	got := bugfixRows(t, a)
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for _, title := range want {
		found := false
		for _, gotTitle := range got {
			if gotTitle == title {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("rows = %v, missing %q", got, title)
		}
	}
}

func bugfixOnlyQuery(t *testing.T, a *App, query string) {
	t.Helper()
	for _, row := range a.rows {
		if !strings.Contains(strings.ToLower(row.Title), strings.ToLower(query)) {
			t.Fatalf("row %q does not match active query %q", row.Title, query)
		}
		if row.State != "active" {
			t.Fatalf("row %q leaked state %q into active scope", row.Title, row.State)
		}
	}
}

func TestDesktopClipboardAndDisplayExpireWithoutRendering(t *testing.T) {
	a := dailyAppFixture(t)
	a.launch = func(fn func()) { fn() }
	dispatch := make(chan func(), 16)
	a.dispatch = func(fn func()) { dispatch <- fn }
	clip := attachFakeClipboard(a)

	row := bugfixAddLogin(t, a, "Alpha", "private-user", "private-password")
	rev, err := a.session.Edit(personal.Edit{ID: row.ID, Revision: row.Revision, Field: "notes", Value: "private-notes"})
	if err != nil {
		t.Fatal(err)
	}
	row.Revision = rev
	a.selected = &row

	for _, tc := range []struct{ field, want string }{
		{"username", "private-user"},
		{"password", "private-password"},
		{"notes", "private-notes"},
	} {
		a.disclose(tc.field, "copy")
		bugfixDrain(t, dispatch)
		if clip.value != tc.want || a.clipboardLease == nil || a.clipboardTimer == nil {
			t.Fatalf("copy %s did not arm clipboard ownership", tc.field)
		}
		a.disclose(tc.field, "show")
		bugfixDrain(t, dispatch)
		if a.display != tc.want || a.displayTimer == nil {
			t.Fatalf("show %s did not arm display expiry", tc.field)
		}
	}
	clipTimer, displayTimer := a.clipboardTimer, a.displayTimer
	if clipTimer == nil || displayTimer == nil {
		t.Fatal("timers were not armed without rendering")
	}
	clipTimer.Reset(0)
	displayTimer.Reset(0)
	bugfixDrain(t, dispatch)
	bugfixDrain(t, dispatch)
	if clip.value != "" || a.clipboardLease != nil || a.clipboardTimer != nil {
		t.Fatal("clipboard did not expire without View")
	}
	if a.display != "" || !a.displayUntil.IsZero() || a.displayTimer != nil {
		t.Fatal("display did not expire without View")
	}
}

func TestDesktopClipboardTimerPreservesExternalOwnerAndNewerCopyAndUnlockRace(t *testing.T) {
	t.Run("external-owner", func(t *testing.T) {
		a := New()
		dispatch := make(chan func(), 4)
		a.dispatch = func(fn func()) { dispatch <- fn }
		clip := attachFakeClipboard(a)
		lease, err := clip.write([]byte("owned-value"))
		if err != nil {
			t.Fatal(err)
		}
		a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
		if a.clipboardTimer == nil {
			t.Fatal("clipboard timer not armed")
		}
		clip.replace("external")
		a.clipboardTimer.Reset(0)
		bugfixDrain(t, dispatch)
		if clip.value != "external" {
			t.Fatal("expiry cleared a newer external clipboard owner")
		}
	})

	t.Run("older-timer-newer-copy", func(t *testing.T) {
		a := New()
		dispatch := make(chan func(), 4)
		a.dispatch = func(fn func()) { dispatch <- fn }
		clip := attachFakeClipboard(a)
		if err := a.writeClipboard([]byte("older"), time.Now().Add(time.Minute), func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		olderTimer := a.clipboardTimer
		if olderTimer == nil {
			t.Fatal("older timer not armed")
		}
		olderTimer.Reset(0)
		var older func()
		select {
		case older = <-dispatch:
		case <-time.After(2 * time.Second):
			t.Fatal("older expiry was not queued")
		}
		if err := a.writeClipboard([]byte("newer"), time.Now().Add(time.Minute), func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		older()
		if clip.value != "newer" || a.clipboardLease == nil || a.clipboardTimer == nil {
			t.Fatal("older queued expiry cleared a consecutive newer copy")
		}
		a.clearClipboard()
	})

	t.Run("locked-session-cannot-clear-new-session", func(t *testing.T) {
		a := dailyAppFixture(t)
		a.launch = func(fn func()) { fn() }
		dispatch := make(chan func(), 8)
		a.dispatch = func(fn func()) { dispatch <- fn }
		clip := attachFakeClipboard(a)

		a.showFieldDisplay("old-display", time.Now().Add(time.Minute))
		oldDisplayTimer := a.displayTimer
		if oldDisplayTimer == nil {
			t.Fatal("old display timer not armed")
		}
		oldDisplayTimer.Reset(0)
		var oldDisplay func()
		select {
		case oldDisplay = <-dispatch:
		case <-time.After(2 * time.Second):
			t.Fatal("old display expiry was not queued")
		}
		if err := a.writeClipboard([]byte("old-clipboard"), time.Now().Add(time.Minute), func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		oldClipTimer := a.clipboardTimer
		if oldClipTimer == nil {
			t.Fatal("old clipboard timer not armed")
		}
		oldClipTimer.Reset(0)
		var oldClip func()
		select {
		case oldClip = <-dispatch:
		case <-time.After(2 * time.Second):
			t.Fatal("old clipboard expiry was not queued")
		}

		a.Lock()
		fresh, err := personal.UnlockSession(a.path, []byte("fixture"), bugfixKey(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Lock()
		a.session = fresh
		a.showFieldDisplay("new-display", time.Now().Add(time.Minute))
		if err := a.writeClipboard([]byte("new-clipboard"), time.Now().Add(time.Minute), func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		oldDisplay()
		oldClip()
		if a.display != "new-display" || !a.displayUntil.After(time.Now()) || a.displayTimer == nil {
			t.Fatal("expired callback from a locked session cleared the new display")
		}
		if clip.value != "new-clipboard" || a.clipboardLease == nil || a.clipboardTimer == nil {
			t.Fatal("expired callback from a locked session cleared the new clipboard")
		}
	})
}

func TestDesktopIdleTimerLocksSessionWithoutRendering(t *testing.T) {
	a := New()
	a.path = t.TempDir() + "/idle.ll"
	if err := personal.Create(a.path, "fixture", bugfixKey()); err != nil {
		t.Fatal(err)
	}
	s, err := personal.UnlockSession(a.path, []byte("fixture"), bugfixKey(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a.session = s
	a.launch = func(fn func()) { fn() }
	dispatch := make(chan func(), 8)
	a.dispatch = func(fn func()) { dispatch <- fn }
	clip := attachFakeClipboard(a)
	lease, err := clip.write([]byte("owned-value"))
	if err != nil {
		t.Fatal(err)
	}
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	a.showFieldDisplay("visible", time.Now().Add(time.Minute))
	a.armIdleTimer()
	if a.idleTimer == nil {
		t.Fatal("idle timer not armed")
	}

	time.Sleep(1100 * time.Millisecond)
	a.idleTimer.Reset(0)
	select {
	case fn := <-dispatch:
		fn()
	case <-time.After(3 * time.Second):
		t.Fatal("idle expiry did not dispatch without View")
	}
	if a.session != nil || a.status != "金库已锁定" {
		t.Fatalf("idle expiry did not lock: session=%v status=%q", a.session != nil, a.status)
	}
	if a.display != "" || a.displayTimer != nil {
		t.Fatal("idle lock retained a displayed field")
	}
	if clip.value != "" || a.clipboardLease != nil || a.clipboardTimer != nil {
		t.Fatal("idle lock retained owned clipboard content")
	}
}

func TestDesktopEditAndStateCancelOnLockAndReportUnknownAfterCommit(t *testing.T) {
	runBlocked := func(t *testing.T, a *App, start func()) {
		t.Helper()
		holder, err := bolt.Open(a.path, 0600, &bolt.Options{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		completed := make(chan func(), 8)
		a.launch = func(fn func()) { go fn() }
		a.dispatch = func(fn func()) { completed <- fn }
		start()
		time.Sleep(50 * time.Millisecond)
		a.Lock()
		if err := holder.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case fn := <-completed:
			fn()
		case <-time.After(5 * time.Second):
			t.Fatal("blocked mutation did not finish")
		}
		if a.mutationUnknown {
			t.Fatal("cancelled pre-commit mutation reported an unknown result")
		}
		fresh, err := personal.UnlockSession(a.path, []byte("fixture"), bugfixKey(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Lock()
		rows, err := fresh.List("all")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Title != "Alpha" || rows[0].State != "active" {
			t.Fatalf("blocked mutation changed disk state: %+v", rows)
		}
	}

	t.Run("blocked-edit", func(t *testing.T) {
		a := dailyAppFixture(t)
		a.launch = func(fn func()) { fn() }
		row := bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.selected = &row
		a.editField = "title"
		a.value = "blocked change"
		runBlocked(t, a, a.edit)
	})

	t.Run("blocked-archive", func(t *testing.T) {
		a := dailyAppFixture(t)
		a.launch = func(fn func()) { fn() }
		row := bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.selected = &row
		runBlocked(t, a, func() { a.state("item.archive") })
	})

	t.Run("blocked-trash", func(t *testing.T) {
		a := dailyAppFixture(t)
		a.launch = func(fn func()) { fn() }
		row := bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.selected = &row
		runBlocked(t, a, func() { a.state("item.trash") })
	})

	t.Run("commit-before-dispatch", func(t *testing.T) {
		a := dailyAppFixture(t)
		a.launch = func(fn func()) { fn() }
		row := bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.selected = &row
		var queued []func()
		var complete func()
		a.launch = func(fn func()) { queued = append(queued, fn) }
		a.dispatch = func(fn func()) { complete = fn }
		a.editField = "title"
		a.value = "committed change"
		a.edit()
		if len(queued) != 1 {
			t.Fatalf("edit queued %d workers", len(queued))
		}
		queued[0]()
		if complete == nil {
			t.Fatal("committed edit did not queue its receipt")
		}
		a.Lock()
		if !a.mutationUnknown || !strings.Contains(a.status, mutationUnknownStatus) {
			t.Fatalf("lock after commit did not retain unknown: %q", a.status)
		}
		complete()
		if !a.mutationUnknown || !strings.Contains(a.status, mutationUnknownStatus) {
			t.Fatal("late receipt cleared the unknown result")
		}
		rows, err := personal.List(a.path, "fixture", bugfixKey())
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Title != "committed change" {
			t.Fatalf("committed change was not preserved: %+v", rows)
		}
	})

	t.Run("lock-clears-drafts", func(t *testing.T) {
		a := New()
		draft := &nativeNotesDraft{value: "private-notes"}
		gate := personal.NewMutationGate(time.Now().Add(time.Minute))
		a.title = "title"
		a.website = "website"
		a.username = "username"
		a.value = "value"
		a.notesEditor = draft
		a.regenerate = &personal.NativeLoginView{ID: "id"}
		a.sshTitle = "ssh-title"
		a.sshImportPath = "ssh-path"
		a.browserSaveID = "browser-id"
		a.browserSaveTitle = "browser-title"
		a.operation = &nativeOperation{gate: gate}
		a.display = "displayed"
		a.displayUntil = time.Now().Add(time.Minute)
		a.Lock()
		if a.title != "" || a.website != "" || a.username != "" || a.value != "" {
			t.Fatal("lock retained login drafts")
		}
		if a.notesEditor != nil || draft.value != "" || a.regenerate != nil {
			t.Fatal("lock retained notes or regeneration drafts")
		}
		if a.sshTitle != "" || a.sshImportPath != "" {
			t.Fatal("lock retained SSH drafts")
		}
		if a.browserSaveID != "" || a.browserSaveTitle != "" || a.operation != nil {
			t.Fatal("lock retained browser save or operation state")
		}
		if a.display != "" || !a.displayUntil.IsZero() {
			t.Fatal("lock retained displayed field state")
		}
		if a.mutationUnknown {
			t.Fatal("uncommitted operation reported unknown after lock")
		}
	})
}

func TestDesktopMutationsPreserveActiveSearchFilter(t *testing.T) {
	a := dailyAppFixture(t)
	a.launch = func(fn func()) { fn() }
	alpha := bugfixAddLogin(t, a, "Alpha", "alpha-user", "alpha-password")
	bugfixAddLogin(t, a, "Beta", "beta-user", "beta-password")

	a.query = "Alpha"
	a.refresh()
	bugfixWantRows(t, a, "Alpha")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.editField = "username"
	a.value = "alpha-user-2"
	a.edit()
	bugfixWantRows(t, a, "Alpha")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.editField = "title"
	a.value = "Gamma"
	a.edit()
	if len(a.rows) != 0 {
		t.Fatalf("out-of-query rename leaked rows: %v", bugfixRows(t, a))
	}

	bugfixSelect(t, a, alpha.ID)
	a.editField = "title"
	a.value = "Alpha-2"
	a.edit()
	bugfixWantRows(t, a, "Alpha-2")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.state("item.archive")
	if len(a.rows) != 0 {
		t.Fatalf("archived item or unrelated row leaked: %v", bugfixRows(t, a))
	}
	bugfixSelect(t, a, alpha.ID)
	a.state("item.unarchive")
	bugfixWantRows(t, a, "Alpha-2")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.state("item.trash")
	if len(a.rows) != 0 {
		t.Fatalf("trashed item or unrelated row leaked: %v", bugfixRows(t, a))
	}
	bugfixSelect(t, a, alpha.ID)
	a.state("item.untrash")
	bugfixWantRows(t, a, "Alpha-2")
	bugfixOnlyQuery(t, a, "Alpha")

	a.title = "Alpha-3"
	a.username = "alpha-3-user"
	a.value = "alpha-3-password"
	a.saveNative(false)
	bugfixWantRows(t, a, "Alpha-2", "Alpha-3")
	bugfixOnlyQuery(t, a, "Alpha")

	a.title = "Delta"
	a.username = "delta-user"
	a.value = ""
	a.generationLength = "24"
	a.saveNative(true)
	bugfixWantRows(t, a, "Alpha-2", "Alpha-3")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.reviewRegeneration()
	if a.regenerate == nil {
		t.Fatal("regeneration review did not open")
	}
	a.confirmRegeneration()
	bugfixWantRows(t, a, "Alpha-2", "Alpha-3")
	bugfixOnlyQuery(t, a, "Alpha")

	bugfixSelect(t, a, alpha.ID)
	a.editNotes()
	if a.notesEditor == nil {
		t.Fatal("notes editor did not open")
	}
	a.notesEditor.value = "alpha notes"
	a.saveNotes(a.notesEditor)
	bugfixWantRows(t, a, "Alpha-2", "Alpha-3")
	bugfixOnlyQuery(t, a, "Alpha")

	for _, row := range a.rows {
		if row.Title == "Beta" || row.Title == "Delta" {
			t.Fatalf("unrelated item exposed under active query: %v", row.Title)
		}
	}
}

func TestDesktopLateRefreshAndMutationDropStaleFilterRows(t *testing.T) {
	t.Run("refresh-query-aba", func(t *testing.T) {
		a := dailyAppFixture(t)
		bugfixAddLogin(t, a, "Alpha", "user", "password")
		bugfixAddLogin(t, a, "Beta", "user", "password")
		a.query = "Alpha"
		var work, complete func()
		a.launch = func(fn func()) { work = fn }
		a.dispatch = func(fn func()) { complete = fn }
		a.refresh()
		if work == nil {
			t.Fatal("refresh did not queue a worker")
		}
		work()
		if complete == nil {
			t.Fatal("refresh did not queue its rows")
		}
		a.query = "Beta"
		a.queryGeneration++
		a.query = "Alpha"
		a.queryGeneration++
		complete()
		if a.rows != nil {
			t.Fatalf("stale refresh populated rows: %v", bugfixRows(t, a))
		}
		if !strings.Contains(a.status, "搜索条件已变更") {
			t.Fatalf("stale refresh status = %q", a.status)
		}
	})

	t.Run("refresh-scope-change", func(t *testing.T) {
		a := dailyAppFixture(t)
		bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.query = "Alpha"
		var work, complete func()
		a.launch = func(fn func()) { work = fn }
		a.dispatch = func(fn func()) { complete = fn }
		a.refresh()
		work()
		a.scope = "archived"
		complete()
		if a.rows != nil {
			t.Fatalf("stale scope refresh populated rows: %v", bugfixRows(t, a))
		}
	})

	t.Run("mutation-query-aba", func(t *testing.T) {
		a := dailyAppFixture(t)
		alpha := bugfixAddLogin(t, a, "Alpha", "user", "password")
		bugfixAddLogin(t, a, "Beta", "user", "password")
		a.query = "Alpha"
		bugfixSelect(t, a, alpha.ID)
		var work, complete func()
		a.launch = func(fn func()) { work = fn }
		a.dispatch = func(fn func()) { complete = fn }
		a.editField = "username"
		a.value = "changed-user"
		a.edit()
		if work == nil {
			t.Fatal("edit did not queue a worker")
		}
		work()
		if complete == nil {
			t.Fatal("edit did not queue its receipt")
		}
		a.query = "Beta"
		a.queryGeneration++
		a.query = "Alpha"
		a.queryGeneration++
		complete()
		if a.rows != nil {
			t.Fatalf("stale mutation receipt populated rows: %v", bugfixRows(t, a))
		}
		if a.status != "字段已更新；列表未刷新，请手动刷新" {
			t.Fatalf("stale mutation status = %q", a.status)
		}
		rows, err := a.session.List("all")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatal("committed mutation disappeared")
		}
		for _, got := range rows {
			if got.ID == alpha.ID && got.Revision == alpha.Revision {
				t.Fatal("committed mutation did not advance the revision")
			}
		}
	})

	t.Run("mutation-scope-change", func(t *testing.T) {
		a := dailyAppFixture(t)
		alpha := bugfixAddLogin(t, a, "Alpha", "user", "password")
		a.query = "Alpha"
		bugfixSelect(t, a, alpha.ID)
		var work, complete func()
		a.launch = func(fn func()) { work = fn }
		a.dispatch = func(fn func()) { complete = fn }
		a.editField = "title"
		a.value = "Alpha-renamed"
		a.edit()
		work()
		a.scope = "trashed"
		complete()
		if a.rows != nil {
			t.Fatalf("stale scope mutation populated rows: %v", bugfixRows(t, a))
		}
		if !strings.Contains(a.status, "字段已更新") || !strings.Contains(a.status, "列表未刷新") {
			t.Fatalf("stale scope mutation status = %q", a.status)
		}
	})
}
