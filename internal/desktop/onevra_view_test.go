package desktop

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/oneo-me/onevra/source/theme"
)

func TestOnevraVaultRendersThreePaneWorkspace(t *testing.T) {
	a := newOnevraTestApp()
	tester := newOnevraTestTester(a)

	for _, label := range []string{"全部", "全部条目", "Example Login", "登录信息", "编辑"} {
		if !tester.HasText(label) {
			t.Fatalf("Onevra vault missing %q", label)
		}
	}
	if tester.HasText("must-stay-concealed") {
		t.Fatal("Onevra detail exposed an unrevealed password")
	}

	if err := tester.Click("收藏"); err != nil {
		t.Fatal(err)
	}
	if a.v2.nav != navFavorites {
		t.Fatalf("favorite navigation did not update state: %q", a.v2.nav)
	}

	if err := tester.Click("搜索"); err != nil {
		t.Fatal(err)
	}
	tester.Type("example.test")
	tester.Frame()
	if a.query != "example.test" {
		t.Fatalf("search text was not bound: %q", a.query)
	}
}

func TestOnevraVaultResizesAndRemainsUsableAtMinimumWindow(t *testing.T) {
	a := newOnevraTestApp()
	tester := newOnevraTestTesterSize(a, 980, 680)

	checkCoreControls := func() {
		t.Helper()
		for _, label := range []string{"全部", "Example Login", "登录信息", "编辑", "关闭详情"} {
			if !tester.HasText(label) {
				t.Fatalf("minimum-width Onevra vault missing %q", label)
			}
		}
	}
	checkCoreControls()

	beforeSidebar := a.onevra.sidebarWidth
	resize(t, tester, "调整导航和内容宽度", 12)
	if a.onevra.sidebarWidth <= beforeSidebar {
		t.Fatal("pointer drag did not resize the sidebar split")
	}
	afterDrag := a.onevra.sidebarWidth
	tester.Key(0, ui.KeyRight)
	tester.Frame()
	if a.onevra.sidebarWidth <= afterDrag {
		t.Fatal("keyboard did not resize the sidebar split")
	}

	beforeList := a.onevra.listWidth
	resize(t, tester, "调整条目列表和详情宽度", 12)
	if a.onevra.listWidth <= beforeList {
		t.Fatal("pointer drag did not resize the list split")
	}
	afterDrag = a.onevra.listWidth
	tester.Key(0, ui.KeyRight)
	tester.Frame()
	if a.onevra.listWidth <= afterDrag {
		t.Fatal("keyboard did not resize the list split")
	}

	tester.SetDark(true)
	tester.SetPreferences(ui.Preferences{HighContrast: true, TextScale: 1.5})
	tester.SetScale(2)
	tester.SetSize(980, 680)
	checkCoreControls()
}

func TestOnevraVaultLockClearsSelectionButKeepsLayoutPreferences(t *testing.T) {
	a := newOnevraTestApp()
	oldList := a.onevra.list
	a.onevra.rowCursor = 2
	oldList.Selected = &a.onevra.rowCursor
	a.onevra.sidebarWidth = 240
	a.onevra.listWidth = 360
	a.Lock()

	if a.onevra.rowCursor != -1 || a.onevra.list == oldList || a.onevra.list.Selected != nil {
		t.Fatal("lock retained Onevra row selection")
	}
	if a.onevra.sidebarWidth != 240 || a.onevra.listWidth != 360 {
		t.Fatal("lock discarded non-secret column preferences")
	}
}

func TestOnevraVaultHeadlessSnapshot(t *testing.T) {
	target := os.Getenv("LOCKLARK_UI_SNAPSHOT")
	if target == "" {
		t.Skip("set LOCKLARK_UI_SNAPSHOT to write a headless PNG")
	}
	tester := newOnevraTestTester(newOnevraTestApp())
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = png.Encode(f, tester.Image()); err != nil {
		t.Fatal(err)
	}
}

func newOnevraTestApp() *App {
	a := New()
	row := personal.ItemSummary{
		ID:         "item-1",
		Revision:   "revision-1",
		Kind:       "login",
		Category:   vault.CategoryLogin,
		VaultID:    vault.DefaultVaultID,
		Title:      "Example Login",
		Subtitle:   "alice@example.test",
		PrimaryURL: "https://example.test",
		State:      "active",
	}
	a.v2.rows = []personal.ItemSummary{row}
	a.v2.all = []personal.ItemSummary{
		row,
		{
			ID: "item-2", Revision: "revision-2", Kind: "api_credential", Category: vault.CategoryAPICredential,
			VaultID: vault.DefaultVaultID, Title: "Production API", Subtitle: "api.example.test", State: "active", Favorite: true,
		},
		{
			ID: "item-3", Revision: "revision-3", Kind: "secure_note", Category: vault.CategorySecureNote,
			VaultID: vault.DefaultVaultID, Title: "Recovery Runbook", Subtitle: "内部安全说明", State: "active",
		},
	}
	a.v2.rows = a.v2.all
	a.rebuildSidebarCounts()
	a.status = "已解锁 · 5 分钟后自动锁定"
	a.v2.selectedID = row.ID
	a.v2.selectedRevision = row.Revision
	a.v2.detail = &personal.ItemDetail{
		ID:       row.ID,
		Revision: row.Revision,
		Kind:     row.Kind,
		Category: row.Category,
		VaultID:  row.VaultID,
		Title:    row.Title,
		Username: row.Subtitle,
		Password: "must-stay-concealed",
		URL:      row.PrimaryURL,
		State:    row.State,
	}
	a.onevra.rowCursor = 0
	return a
}

func newOnevraTestTester(a *App) *ui.Tester {
	return newOnevraTestTesterSize(a, 1240, 820)
}

func newOnevraTestTesterSize(a *App, width, height int) *ui.Tester {
	return ui.NewTester(func(c *ui.Context) {
		c.SetTheme(theme.Onevra(c))
		a.onevraVaultView(c)
	}, width, height)
}

func resize(t *testing.T, tester *ui.Tester, label string, delta float32) {
	t.Helper()
	rect, ok := tester.Find(label)
	if !ok {
		t.Fatalf("missing split control %q", label)
	}
	x, y := rect.X-2, rect.Y+rect.H/2
	tester.Press(x, y)
	tester.Move(x+delta, y)
	tester.Release(x+delta, y)
	tester.Frame()
}
