package desktop

import (
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"path/filepath"
	"testing"
)

func TestNativeUnlockFieldsAreMasked(t *testing.T) {
	a := New()
	a.password = "private-master"
	a.secret = "private-secret"
	a.path = "owner.ll"
	tt := ui.NewTester(a.View, 1100, 760)
	for _, s := range tt.Texts() {
		if s == a.password || s == a.secret {
			t.Fatal("unlock factor rendered as label")
		}
	}
	if !tt.HasText("解锁金库") {
		t.Fatal("missing unlock entry")
	}
	a.Lock()
	if a.password != "" || a.secret != "" {
		t.Fatal("lock retained factors")
	}
}

func TestLockDropsLateNativeResults(t *testing.T) {
	a := New()
	var worker, completion func()
	a.launch = func(f func()) { worker = f }
	a.dispatch = func(f func()) { completion = f }
	applied, dropped := false, false
	a.run(func() outcome { return outcome{apply: func() { applied = true }, drop: func() { dropped = true }} })
	worker()
	a.Lock()
	completion()
	if applied || !dropped || a.busy {
		t.Fatal("late result survived lock")
	}
}

func TestNativeVaultWorkflowAndChangedSelection(t *testing.T) {
	a := New()
	a.launch = func(f func()) { f() }
	a.path = filepath.Join(t.TempDir(), "desktop.ll")
	key, e := personal.NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	if e = personal.Create(a.path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	a.password = "fixture"
	a.secret = personal.FormatSecret(key)
	a.unlock()
	if a.session == nil {
		t.Fatal("native unlock failed", a.status)
	}
	defer a.Lock()
	a.title = "Account"
	a.username = "person@example.test"
	a.value = "synthetic-secret"
	a.add()
	if len(a.rows) != 1 {
		t.Fatal("native add failed", a.status)
	}
	a.selected = &a.rows[0]
	a.disclose("password", "show")
	if a.display != "synthetic-secret" {
		t.Fatal("native show failed", a.status)
	}
	clip := attachFakeClipboard(a)
	a.disclose("username", "copy")
	if clip.value != "person@example.test" {
		t.Fatal("native copy failed")
	}
	a.editField = "password"
	a.value = "updated-secret"
	a.edit()
	if a.selected != nil || a.display != "" {
		t.Fatal("edit retained old disclosure")
	}
	a.selected = &a.rows[0]
	var complete func()
	a.dispatch = func(f func()) { complete = f }
	a.disclose("password", "show")
	a.selected = nil
	complete()
	if a.display != "" {
		t.Fatal("field delivered into changed selection")
	}
	a.dispatch = func(f func()) { f() }
	a.selected = &a.rows[0]
	a.state("item.trash")
	if len(a.rows) != 0 {
		t.Fatal("trashed item remained active")
	}
	a.scope = "trashed"
	a.refresh()
	if len(a.rows) != 1 {
		t.Fatal("trash list missing item")
	}
	a.selected = &a.rows[0]
	a.state("item.untrash")
	a.scope = "active"
	a.refresh()
	if len(a.rows) != 1 {
		t.Fatal("restore failed")
	}
	a.Lock()
	if clip.value != "" || len(a.rows) != 0 || a.session != nil {
		t.Fatal("lock retained native data")
	}
}
