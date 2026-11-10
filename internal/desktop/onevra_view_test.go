package desktop

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
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

func TestOnevraDetailSupportsAttachmentsDuplicateLargeTypeAndPurgeConfirm(t *testing.T) {
	a := newOnevraTestApp()
	a.v2.detail.Attachments = []vault.AttachmentMeta{
		{ID: "att-1", FileName: "recovery-codes.pdf", MIMEType: "application/pdf", Size: 4096},
	}
	a.v2.detailPlain = &personal.ItemDetail{
		ID:       a.v2.detail.ID,
		Revision: a.v2.detail.Revision,
		Password: "A9#x",
	}
	tester := newOnevraTestTesterSize(a, 1280, 1100)

	for _, want := range []string{
		"加密附件",
		"recovery-codes.pdf",
		"4.0 KB",
		"创建副本",
		"大号显示 密码",
		"大号显示 一次性验证码",
	} {
		if !tester.HasText(want) {
			t.Fatalf("Onevra detail missing %q", want)
		}
	}

	// Open Large Type on password and verify character index tiles.
	a.v2.largeTypeOpen = true
	a.v2.largeTypeKey = "password"
	a.v2.largeTypeLabel = "密码"
	a.v2.largeTypeValue = "A9#x"
	tester.Frame()
	for _, want := range []string{"大号显示 · 密码", "共 4 个字符", "A9#x", "关闭大号显示"} {
		if !tester.HasText(want) {
			t.Fatalf("large type view missing %q", want)
		}
	}
	if err := tester.Click("关闭大号显示"); err != nil {
		t.Fatal(err)
	}
	if a.v2.largeTypeOpen {
		t.Fatal("large type was not closed")
	}

	// Trashed item shows 恢复到金库 and two-step 永久删除 confirmation without 编辑.
	a.v2.detail.State = "trashed"
	tester.Frame()
	if !tester.HasText("恢复到金库") || !tester.HasText("永久删除") {
		t.Fatal("trashed Onevra detail missing restore or purge action")
	}
	if err := tester.Click("永久删除"); err != nil {
		t.Fatal(err)
	}
	if !a.v2.confirmPurge || !tester.HasText("确认永久删除") || !tester.HasText("取消删除") {
		t.Fatal("clicking 永久删除 did not enter two-step confirmation")
	}
	if err := tester.Click("取消删除"); err != nil {
		t.Fatal(err)
	}
	if a.v2.confirmPurge {
		t.Fatal("取消删除 did not reset confirmPurge")
	}
}

func TestOnevraEditorGeneratorSettingsAndWatchtowerViews(t *testing.T) {
	a := newOnevraTestApp()
	a.v2Mode = true

	// 1. Settings opens cleanly inside Onevra detail pane and closes back to detail.
	a.openSettings()
	tester := newOnevraTestTesterSize(a, 1280, 1000)
	for _, want := range []string{"安全与偏好设置", "自动锁定", "剪贴板防护", "关闭设置"} {
		if !tester.HasText(want) {
			t.Fatalf("Onevra settings pane missing %q", want)
		}
	}
	if err := tester.Click("关闭设置"); err != nil {
		t.Fatal(err)
	}
	if a.v2.settingsOpen {
		t.Fatal("settings remained open after 关闭设置")
	}

	// 2. Editor -> Generator ("生成密码") -> Fill Draft ("填入当前条目") returns to Editor!
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryLogin)
	a.v2.draft.Title = "Draft Login"
	tester = newOnevraTestTesterSize(a, 1280, 1200)
	for _, want := range []string{"编辑条目", "基本信息", "生成密码", "保存", "取消"} {
		if !tester.HasText(want) {
			t.Fatalf("Onevra editor missing %q", want)
		}
	}
	if err := tester.Click("生成密码"); err != nil {
		t.Fatal(err)
	}
	if !a.v2.generator.open || !tester.HasText("密码生成器") || !tester.HasText("填入当前条目") {
		t.Fatal("clicking 生成密码 inside editor did not display generatorView")
	}
	generated := a.v2.generator.preview
	if generated == "" {
		t.Fatal("generator preview was empty")
	}
	if err := tester.Click("填入当前条目"); err != nil {
		t.Fatal(err)
	}
	if a.v2.generator.open || a.v2.draft.Password != generated || !tester.HasText("编辑条目") {
		t.Fatal("填入当前条目 did not fill draft password and return to editor")
	}
	a.cancelEdit()

	// 3. Watchtower renders score hero, Chinese flag badges, and 打开条目 navigates out of Watchtower.
	a.v2.nav = navWatchtower
	a.v2.watchtower = &WatchtowerReport{
		OverallScore: 62,
		Checked:      3,
		Counts: watchtower.Counts{
			Vulnerable:    1,
			Reused:        1,
			Weak:          1,
			UnsecuredHTTP: 1,
			TOTPNotStored: 1,
		},
		Findings: []watchtower.Finding{
			{
				ID:            "item-1",
				Revision:      "revision-1",
				Title:         "Example Login",
				Origin:        "http://example.test",
				StrengthScore: 35,
				Flags:         []string{"vulnerable", "weak", "unsecured-http"},
				BreachCount:   42,
			},
		},
	}
	tester.Frame()
	for _, want := range []string{"Watchtower 安全体检", "安全评分 62 / 100", "已泄露", "弱密码", "非加密 HTTP", "该密码在公开泄露库中出现 42 次，请立即更换。", "打开条目"} {
		if !tester.HasText(want) {
			t.Fatalf("Watchtower view missing %q", want)
		}
	}
	if err := tester.Click("打开条目"); err != nil {
		t.Fatal(err)
	}
	if a.v2.nav == navWatchtower || a.v2.selectedID != "item-1" {
		t.Fatalf("打开条目 did not switch from Watchtower to item detail: nav=%q selected=%q", a.v2.nav, a.v2.selectedID)
	}
}

