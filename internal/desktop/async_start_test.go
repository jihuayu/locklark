package desktop

import (
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// asyncStartApp wires the real production scheduling: work runs on another
// goroutine while every receipt is dispatched later. The helper methods under
// test must return their start state without reading anything the worker owns.
func asyncStartApp(t *testing.T) (*App, chan func()) {
	t.Helper()
	a := dailyAppFixture(t)
	a.EnableV2()
	done := make(chan func(), 8)
	a.launch = func(fn func()) { go fn() }
	a.dispatch = func(fn func()) { done <- fn }
	return a, done
}

func asyncStartWait(t *testing.T, done chan func()) {
	t.Helper()
	select {
	case fn := <-done:
		fn()
	case <-time.After(5 * time.Second):
		t.Fatal("dispatched async receipt did not arrive")
	}
}

func asyncStartDetail(t *testing.T, a *App, row personal.Row) personal.ItemDetail {
	t.Helper()
	detail, err := a.session.GetItemDetail(row.ID, row.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	a.v2.detail = &detail
	a.v2.selectedID, a.v2.selectedRevision = detail.ID, detail.Revision
	return detail
}

// TestAsyncHelpersReturnStartState pins the #102 accept criterion for the
// desktop helpers: with a genuinely asynchronous launcher, beginning an edit,
// saving a draft, restoring history, creating a vault, moving an item and
// emptying the trash all return their start state immediately and deliver the
// real outcome through the dispatcher. Under -race this also proves the return
// path never reads worker-owned frame variables.
func TestAsyncHelpersReturnStartState(t *testing.T) {
	t.Run("begin-edit", func(t *testing.T) {
		a, done := asyncStartApp(t)
		asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		if err := a.beginEdit(); err != nil {
			t.Fatalf("beginEdit start: %v", err)
		}
		asyncStartWait(t, done)
		if !a.v2.editing || a.v2.draft == nil {
			t.Fatal("edit did not open through the dispatcher")
		}
		a.cancelEdit()
	})

	t.Run("begin-edit-failure", func(t *testing.T) {
		a, done := asyncStartApp(t)
		detail := asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		detail.Revision = strings.Repeat("0", 64)
		a.v2.detail = &detail
		if err := a.beginEdit(); err != nil {
			t.Fatalf("beginEdit start reported the worker failure synchronously: %v", err)
		}
		asyncStartWait(t, done)
		t.Logf("begin-edit-failure status=%q", a.status)
		if a.v2.editing || a.status == "处理中…" {
			t.Fatalf("failed edit was not reported through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("save-draft", func(t *testing.T) {
		a, done := asyncStartApp(t)
		detail := asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		a.v2.draft = draftFromDetail(detail)
		a.v2.draft.Notes = "saved"
		a.v2.editing = true
		if err := a.saveDraft(); err != nil {
			t.Fatalf("saveDraft start: %v", err)
		}
		asyncStartWait(t, done)
		if a.v2.editing || a.v2.draft != nil || a.status != "条目已保存" {
			t.Fatalf("save did not finish through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("save-draft-failure", func(t *testing.T) {
		a, done := asyncStartApp(t)
		detail := asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		a.v2.draft = draftFromDetail(detail)
		a.v2.draft.Revision = strings.Repeat("0", 64)
		a.v2.editing = true
		if err := a.saveDraft(); err != nil {
			t.Fatalf("saveDraft start reported the worker failure synchronously: %v", err)
		}
		asyncStartWait(t, done)
		t.Logf("save-draft-failure status=%q", a.status)
		if a.status == "条目已保存" || a.status == "处理中…" {
			t.Fatalf("failed save was not reported through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("restore-history", func(t *testing.T) {
		a, done := asyncStartApp(t)
		row := bugfixAddLogin(t, a, "Alpha", "user", "password")
		detail := asyncStartDetail(t, a, row)
		g := personal.NewMutationGate(time.Now().Add(time.Minute))
		if err := a.session.RegisterMutation(g); err != nil {
			t.Fatal(err)
		}
		draft := draftFromDetail(detail)
		draft.Password = "rotated-password"
		if _, err := a.session.EditItem(detail.ID, detail.Revision, draft.item(), g); err != nil {
			t.Fatal(err)
		}
		asyncStartDetail(t, a, bugfixRow(t, a, row.ID))
		if len(a.v2.detail.History) == 0 {
			t.Fatal("edit did not record history")
		}
		if err := a.restoreHistory(0); err != nil {
			t.Fatalf("restoreHistory start: %v", err)
		}
		asyncStartWait(t, done)
		if a.status != "条目历史已还原" || a.v2.detail == nil {
			t.Fatalf("restore did not finish through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("create-vault", func(t *testing.T) {
		a, done := asyncStartApp(t)
		meta, err := a.createVault("Work", "team work", "briefcase")
		if err != nil {
			t.Fatalf("createVault start: %v", err)
		}
		if meta != (vault.VaultMeta{}) {
			t.Fatalf("createVault returned worker data synchronously: %+v", meta)
		}
		asyncStartWait(t, done)
		if !strings.HasPrefix(a.status, "已创建金库：") {
			t.Fatalf("create did not finish through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("move-item", func(t *testing.T) {
		a, done := asyncStartApp(t)
		detail := asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		id, revision, err := a.moveSelectedToVault(detail.VaultID, true)
		if err != nil {
			t.Fatalf("moveSelectedToVault start: %v", err)
		}
		if id != "" || revision != "" {
			t.Fatalf("move returned worker ids synchronously: %q %q", id, revision)
		}
		asyncStartWait(t, done)
		if a.status != "条目已复制到金库" || a.v2.selectedID == "" {
			t.Fatalf("move did not finish through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("start-only-error-contract", func(t *testing.T) {
		// A synchronous launcher exposes the same contract deterministically: the
		// helper reports only whether the worker started, never its outcome.
		a := dailyAppFixture(t)
		a.EnableV2()
		a.launch = func(fn func()) { fn() }
		a.dispatch = func(fn func()) { fn() }
		detail := asyncStartDetail(t, a, bugfixAddLogin(t, a, "Alpha", "user", "password"))
		a.v2.draft = draftFromDetail(detail)
		a.v2.draft.Revision = strings.Repeat("0", 64)
		a.v2.editing = true
		if err := a.saveDraft(); err != nil {
			t.Fatalf("saveDraft start returned the worker outcome: %v", err)
		}
		if !a.v2.editing || a.v2.draft == nil || a.status == "条目已保存" {
			t.Fatalf("failed save was not reported through the dispatcher: status=%q", a.status)
		}
	})

	t.Run("empty-trash", func(t *testing.T) {
		a, done := asyncStartApp(t)
		n, err := a.emptyTrash(nil)
		if err != nil {
			t.Fatalf("emptyTrash start: %v", err)
		}
		if n != 0 {
			t.Fatalf("emptyTrash returned a worker count synchronously: %d", n)
		}
		asyncStartWait(t, done)
		if !strings.HasPrefix(a.status, "已永久删除") {
			t.Fatalf("purge did not finish through the dispatcher: status=%q", a.status)
		}
	})
}
