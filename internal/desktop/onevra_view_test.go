package desktop

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/oneo-me/onevra/source/theme"
)

func TestOnevraVaultRendersThreePaneWorkspace(t *testing.T) {
	a := newOnevraTestApp()
	tester := newOnevraTestTester(a)

	for _, label := range []string{"全部", "全部条目", "Example Login", "用户名", "编辑"} {
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
		for _, label := range []string{"全部", "Example Login", "用户名", "编辑", "关闭详情"} {
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
	if len(a.v2.all) > 0 {
		a.v2.all[0].HasOTP = true
	}
	if len(a.v2.rows) > 0 {
		a.v2.rows[0].HasOTP = true
	}
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
		"大号显示 密码",
		"大号显示 一次性验证码",
	} {
		if !tester.HasText(want) {
			t.Fatalf("Onevra detail missing %q", want)
		}
	}
	if err := tester.Click("更多操作"); err != nil {
		t.Fatal(err)
	}
	if !tester.HasText("创建副本") {
		t.Fatal(`Onevra more menu missing "创建副本"`)
	}
	_ = tester.Click("更多操作")
	tester.Frame()

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

func TestOnevraEditorGeneratorAndSettingsViews(t *testing.T) {
	a := newOnevraTestApp()
	a.v2Mode = true

	// 1. Settings opens cleanly inside Onevra detail pane and closes back to detail.
	a.openSettings()
	tester := newOnevraTestTesterSize(a, 1280, 1000)
	for _, want := range []string{"安全与偏好设置", "自动锁定", "剪贴板防护", "应用更新", "检查更新…", "关闭设置"} {
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
	for _, want := range []string{"编辑条目", "登录信息", "生成密码", "保存", "取消"} {
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

}

func TestOnevraCustomFieldsDistinguishPlaintextAndEncrypted(t *testing.T) {
	a := newOnevraTestApp()
	a.v2.detail.Sections = []vault.ItemSection{{
		ID:    "sec-custom",
		Title: "自定义字段",
		Fields: []vault.CustomField{
			{ID: "env", Label: "Environment", Type: vault.FieldTypeString, Value: "production-us-east", Protected: false},
			{ID: "secret_key", Label: "Signing Secret", Type: vault.FieldTypeConcealed, Value: "super-secret-signing-value", Protected: true},
		},
	}}
	tester := newOnevraTestTesterSize(a, 1280, 1000)

	for _, want := range []string{
		"自定义字段",
		"Environment",
		"明文",
		"production-us-east",
		"Signing Secret",
		"加密",
	} {
		if !tester.HasText(want) {
			t.Fatalf("custom fields detail missing %q", want)
		}
	}
	if tester.HasText("super-secret-signing-value") {
		t.Fatal("encrypted custom field exposed unrevealed secret value")
	}

	draft := newItemDraft(vault.CategoryLogin)
	draft.Sections = []vault.ItemSection{{
		ID:    "sec-1",
		Title: "自定义字段",
		Fields: []vault.CustomField{
			{ID: "f-1", Label: "API Mode", Type: vault.FieldTypeString, Value: "sandbox", Protected: false},
		},
	}}
	draft.SetFieldProtection(0, 0, true)
	got := draft.Sections[0].Fields[0]
	if !got.Protected || got.Type != vault.FieldTypeConcealed {
		t.Fatalf("SetFieldProtection(true) = protected:%v type:%q, want concealed", got.Protected, got.Type)
	}
	draft.SetFieldProtection(0, 0, false)
	got = draft.Sections[0].Fields[0]
	if got.Protected || got.Type != vault.FieldTypeString {
		t.Fatalf("SetFieldProtection(false) = protected:%v type:%q, want plaintext string", got.Protected, got.Type)
	}
}

func TestOnevraLiveThemeAndCompactDensity(t *testing.T) {
	a := newOnevraTestApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.v2Mode = true
	a.openSettings()
	a.v2.settingsSection = settingsSectionAppearance
	tester := newOnevraTestTesterSize(a, 1280, 1000)

	if err := tester.Click("主题：深色"); err != nil {
		t.Fatal(err)
	}
	if err := tester.Click("密度：紧凑"); err != nil {
		t.Fatal(err)
	}
	snap := a.settingsSnapshot()
	if snap.Theme != "dark" || snap.InterfaceDensity != "compact" {
		t.Fatalf("appearance settings = theme:%q density:%q, want dark/compact", snap.Theme, snap.InterfaceDensity)
	}
	if !tester.HasText("Spacing 3.25 DIP · 深色") {
		t.Fatal("live compact dark preview text did not update immediately")
	}
}

func TestOnevraCustomIconRoundTripAndJSONOmission(t *testing.T) {
	baseSections := []vault.ItemSection{{
		ID:    "extra",
		Title: "Extra",
		Fields: []vault.CustomField{
			{ID: "env", Label: "Environment", Type: vault.FieldTypeString, Value: "prod"},
		},
	}}

	const iconSpec = "icon:shield:#1f7a68"
	withIcon := ApplyCustomIcon(baseSections, iconSpec)
	if got := ExtractCustomIcon(baseSections); got != "" {
		t.Fatalf("ApplyCustomIcon mutated input sections: %q", got)
	}
	if got := ExtractCustomIcon(withIcon); got != iconSpec {
		t.Fatalf("ExtractCustomIcon(icon) = %q, want %q", got, iconSpec)
	}
	metaCount := 0
	for _, sec := range withIcon {
		if IsInternalMetaSection(sec) {
			metaCount++
			if len(sec.Fields) != 1 || sec.Fields[0].Protected || sec.Fields[0].Type != vault.FieldTypeString {
				t.Fatalf("unexpected internal meta field: %+v", sec.Fields)
			}
		}
	}
	if metaCount != 1 {
		t.Fatalf("internal meta section count = %d, want 1", metaCount)
	}

	// Encode a non-square PNG image -> square 64x64 RGBA PNG base64 icon spec.
	src := image.NewRGBA(image.Rect(0, 0, 96, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 96; x++ {
			src.SetRGBA(x, y, color.RGBA{R: uint8(x * 2), G: uint8(y * 3), B: 180, A: 255})
		}
	}
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, src); err != nil {
		t.Fatal(err)
	}
	pngSpec, err := encodeCustomIconBytes(pngBuf.Bytes())
	if err != nil {
		t.Fatalf("encodeCustomIconBytes: %v", err)
	}
	if !strings.HasPrefix(pngSpec, customIconPNGPrefix) {
		t.Fatalf("pngSpec = %q, want prefix %q", pngSpec, customIconPNGPrefix)
	}
	if b64Len := len(strings.TrimPrefix(pngSpec, customIconPNGPrefix)); b64Len == 0 || b64Len > customIconMaxBase64Bytes {
		t.Fatalf("png base64 length = %d, want 1..%d", b64Len, customIconMaxBase64Bytes)
	}

	withPNG := ApplyCustomIcon(withIcon, pngSpec)
	if got := ExtractCustomIcon(withPNG); got != pngSpec {
		t.Fatalf("ExtractCustomIcon(png) = %q, want %q", got, pngSpec)
	}

	cleared := ApplyCustomIcon(withPNG, "")
	if got := ExtractCustomIcon(cleared); got != "" {
		t.Fatalf("ExtractCustomIcon(cleared) = %q, want empty", got)
	}
	if len(cleared) != 1 || cleared[0].ID != "extra" {
		t.Fatalf("clearing custom icon altered unrelated sections: %+v", cleared)
	}
	if emptyCleared := ApplyCustomIcon(ApplyCustomIcon(nil, iconSpec), ""); len(emptyCleared) != 0 {
		t.Fatalf("clearing meta-only sections left %+v", emptyCleared)
	}

	// Round-trip via unlocked personal session without leaking CustomIcon into JSON.
	a := v2ParitySaveApp(t)
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategoryLogin)
	a.v2.draft.Title = "Icon RoundTrip"
	a.v2.draft.Username = "alice@example.test"
	a.v2.draft.Password = "pw-secret"
	a.v2.draft.Icon = iconSpec
	if err := a.saveDraft(); err != nil {
		t.Fatalf("saveDraft(icon): %v", err)
	}
	rows, err := a.session.ListByFilter(personal.ItemFilter{State: "active"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("session.ListByFilter = rows:%d err:%v", len(rows), err)
	}
	if rows[0].CustomIcon != iconSpec {
		t.Fatalf("ItemSummary.CustomIcon = %q, want %q", rows[0].CustomIcon, iconSpec)
	}
	rawJSON, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"CustomIcon", "custom_icon", iconSpec, customIconMetaSectionID, customIconMetaFieldID} {
		if strings.Contains(string(rawJSON), forbidden) {
			t.Fatalf("ItemSummary JSON leaked %q: %s", forbidden, rawJSON)
		}
	}

	// Reopen draft, verify Icon extracted & meta section hidden from user sections, then update to PNG icon.
	if err := a.beginEdit(); err != nil {
		t.Fatalf("beginEdit: %v", err)
	}
	if a.v2.draft == nil || a.v2.draft.Icon != iconSpec {
		t.Fatalf("reopened draft icon = %v", a.v2.draft)
	}
	for _, sec := range a.v2.draft.Sections {
		if IsInternalMetaSection(sec) {
			t.Fatalf("draftFromDetail leaked internal meta section: %+v", sec)
		}
	}
	a.v2.draft.Icon = pngSpec
	if err := a.saveDraft(); err != nil {
		t.Fatalf("saveDraft(png): %v", err)
	}

	rows, err = a.session.ListByFilter(personal.ItemFilter{State: "active"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("session.ListByFilter(png) = rows:%d err:%v", len(rows), err)
	}
	if rows[0].CustomIcon != pngSpec {
		t.Fatalf("ItemSummary.CustomIcon(png) = %q, want %q", rows[0].CustomIcon, pngSpec)
	}
	rawJSON, err = json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawJSON), customIconPNGPrefix) || strings.Contains(string(rawJSON), "CustomIcon") {
		t.Fatalf("ItemSummary JSON leaked PNG icon: %s", rawJSON)
	}

	for _, g := range a.onevraDetailGroups(a.v2.detail, rows[0]) {
		if strings.EqualFold(g.title, "_meta") || strings.EqualFold(g.title, customIconMetaSectionID) {
			t.Fatalf("onevraDetailGroups exposed internal meta group: %+v", g)
		}
		for _, f := range g.fields {
			if strings.Contains(f.key, customIconMetaSectionID) || strings.Contains(f.key, customIconMetaFieldID) {
				t.Fatalf("onevraDetailGroups exposed internal meta field: %+v", f)
			}
		}
	}
	for _, f := range v2DetailFields(a.v2.detail) {
		if strings.Contains(f.Key, customIconMetaSectionID) || strings.Contains(f.Key, customIconMetaFieldID) {
			t.Fatalf("v2DetailFields exposed internal meta field: %+v", f)
		}
	}

	// Render vault list/detail and quick search with PNG avatar; verify bitmap caching and lock cleanup.
	a.showQuickSearch()
	tester := newOnevraTestTesterSize(a, 1280, 900)
	if !tester.HasText("Icon RoundTrip") {
		t.Fatal("Onevra vault missing item with custom PNG icon")
	}
	if tester.HasText("_meta") || tester.HasText(customIconMetaFieldID) {
		t.Fatal("rendered UI leaked internal icon metadata")
	}
	if bmp := a.onevra.iconBitmaps[pngSpec]; bmp == nil {
		t.Fatal("PNG custom icon bitmap was not decoded and cached")
	}
	a.Lock()
	if a.onevra.iconBitmaps != nil {
		t.Fatal("Lock did not release/clear cached icon bitmaps")
	}
}

func TestOnevraLocalizedTemplatesAndNoDuplicateDetailFields(t *testing.T) {
	hasHan := func(s string) bool {
		for _, r := range s {
			if unicode.Is(unicode.Han, r) {
				return true
			}
		}
		return false
	}

	wantStructuredSections := map[vault.ItemCategory][]string{
		vault.CategoryCreditCard:      {"卡片信息", "发卡与限额"},
		vault.CategoryIdentity:        {"基本信息", "证件信息", "联系方式与地址"},
		vault.CategorySSHKey:          {"SSH 密钥信息"},
		vault.CategoryAPICredential:   {"API 凭据"},
		vault.CategoryDatabase:        {"数据库连接"},
		vault.CategoryServer:          {"服务器访问", "管理控制台", "托管服务商"},
		vault.CategoryWirelessRouter:  {"无线网络 (Wi-Fi)", "路由器管理"},
		vault.CategorySoftwareLicense: {"许可证", "发行商与订单"},
		vault.CategoryBankAccount:     {"银行账户", "支行信息"},
		vault.CategoryCryptoWallet:    {"加密钱包"},
		vault.CategoryMedicalRecord:   {"医疗记录"},
		vault.CategoryMembership:      {"会员信息"},
	}

	for _, cat := range AllCategories() {
		secs := CategoryTemplate(cat)
		expectedTitles, structured := wantStructuredSections[cat]
		if !structured {
			if len(secs) != 0 {
				t.Fatalf("category %q expected empty template, got %d sections", cat, len(secs))
			}
			continue
		}
		if len(secs) != len(expectedTitles) {
			t.Fatalf("category %q section count = %d, want %d", cat, len(secs), len(expectedTitles))
		}
		for i, sec := range secs {
			if sec.Title != expectedTitles[i] {
				t.Fatalf("category %q section[%d].Title = %q, want %q", cat, i, sec.Title, expectedTitles[i])
			}
			if !hasHan(sec.Title) {
				t.Fatalf("category %q section %q is not localized in Chinese", cat, sec.Title)
			}
			if len(sec.Fields) == 0 {
				t.Fatalf("category %q section %q has no fields", cat, sec.Title)
			}
			for _, f := range sec.Fields {
				if strings.TrimSpace(f.ID) == "" || strings.TrimSpace(f.Label) == "" {
					t.Fatalf("category %q section %q has empty field id/label: %+v", cat, sec.Title, f)
				}
				if !hasHan(f.Label) && f.Label != "SWIFT / BIC" && f.Label != "IBAN" {
					t.Fatalf("category %q field %q label %q is not localized", cat, f.ID, f.Label)
				}
			}
		}
	}

	if got := localizedSectionTitle("Card Details"); got != "卡片信息" {
		t.Fatalf("localizedSectionTitle(Card Details) = %q", got)
	}
	if got := localizedSectionTitle("API Credential"); got != "API 凭据" {
		t.Fatalf("localizedSectionTitle(API Credential) = %q", got)
	}
	if got := localizedFieldLabel("api", "username", "username"); got != "用户名 / Access Key ID" {
		t.Fatalf("localizedFieldLabel(api/username) = %q", got)
	}
	if got := localizedFieldLabel("api", "credential", "credential"); got != "密钥 / Token" {
		t.Fatalf("localizedFieldLabel(api/credential) = %q", got)
	}

	a := newOnevraTestApp()

	// CreditCard with both typed struct and mirrored CategoryTemplate sections must not duplicate canonical fields.
	ccSections := CategoryTemplate(vault.CategoryCreditCard)
	ccSections[0].Fields[0].Value = "Ada Lovelace"
	ccSections[0].Fields[1].Value = "Visa"
	ccSections[0].Fields[2].Value = "4111111111111111"
	ccSections[0].Fields[3].Value = "123"
	ccSections[0].Fields[4].Value = "2030-01"
	ccSections[0].Fields[5].Value = "2025-01"
	ccSections[1].Fields[0].Value = "Issuer Bank"
	ccSections[1].Fields[1].Value = "9999"
	ccSections[1].Fields[2].Value = "50000"
	ccSections = append(ccSections, vault.ItemSection{
		ID:    "extra",
		Title: "Extra",
		Fields: []vault.CustomField{
			{ID: "recovery", Label: "Recovery", Type: vault.FieldTypeString, Value: "cc-extra"},
		},
	})
	ccDetail := &personal.ItemDetail{
		ID:       "cc-1",
		Revision: "rev-1",
		Category: vault.CategoryCreditCard,
		Title:    "Corp Card",
		State:    "active",
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Ada Lovelace",
			Type:           "Visa",
			Number:         "4111111111111111",
			Verification:   "123",
			ExpiryDate:     "2030-01",
			ValidFrom:      "2025-01",
			IssuingBank:    "Issuer Bank",
			PIN:            "9999",
		},
		Sections: ccSections,
	}
	ccGroups := a.onevraDetailGroups(ccDetail, personal.ItemSummary{ID: "cc-1", Category: vault.CategoryCreditCard})
	ccSeenKeys := map[string]int{}
	ccSeenLabels := map[string]int{}
	for _, g := range ccGroups {
		for _, f := range g.fields {
			ccSeenKeys[f.key]++
			ccSeenLabels[f.label]++
			if strings.HasPrefix(f.key, "card/") || f.key == "details/issuing_bank" || f.key == "details/pin" {
				t.Fatalf("onevraDetailGroups emitted duplicate canonical card section field %q", f.key)
			}
		}
	}
	for _, wantKey := range []string{
		"credit_card.name", "credit_card.type", "credit_card.number", "credit_card.verification",
		"credit_card.expiry", "credit_card.valid_from", "credit_card.issuing_bank", "credit_card.pin",
		"details/credit_limit", "extra/recovery",
	} {
		if ccSeenKeys[wantKey] != 1 {
			t.Fatalf("credit card field %q count = %d, want 1", wantKey, ccSeenKeys[wantKey])
		}
	}
	for label, count := range ccSeenLabels {
		if count != 1 {
			t.Fatalf("credit card label %q rendered %d times, want 1", label, count)
		}
	}

	// Identity with both typed struct and mirrored CategoryTemplate sections must not duplicate canonical fields.
	idSections := CategoryTemplate(vault.CategoryIdentity)
	for si := range idSections {
		for fi := range idSections[si].Fields {
			idSections[si].Fields[fi].Value = "val-" + idSections[si].Fields[fi].ID
		}
	}
	idSections = append(idSections, vault.ItemSection{
		ID:    "extra",
		Title: "Extra",
		Fields: []vault.CustomField{
			{ID: "badge", Label: "工号", Type: vault.FieldTypeString, Value: "E-42"},
		},
	})
	idDetail := &personal.ItemDetail{
		ID:       "id-1",
		Revision: "rev-1",
		Category: vault.CategoryIdentity,
		Title:    "My Identity",
		State:    "active",
		Identity: &vault.IdentityDetails{
			LastName:       "Lovelace",
			FirstName:      "Ada",
			MiddleName:     "Augusta",
			BirthDate:      "1815-12-10",
			Company:        "Analytical Engine",
			Department:     "R&D",
			JobTitle:       "Mathematician",
			SSN:            "110101199001010011",
			PassportNumber: "E12345678",
			LicenseNumber:  "DL-9988",
			Email:          "ada@example.com",
			Phone:          "+8613800138000",
			Country:        "CN",
			State:          "Shanghai",
			City:           "Shanghai",
			AddressLine1:   "100 Century Ave",
			AddressLine2:   "Suite 808",
			PostalCode:     "200120",
			Website:        "https://ada.example",
		},
		Sections: idSections,
	}
	idGroups := a.onevraDetailGroups(idDetail, personal.ItemSummary{ID: "id-1", Category: vault.CategoryIdentity})
	idSeenKeys := map[string]int{}
	idSeenLabels := map[string]int{}
	for _, g := range idGroups {
		for _, f := range g.fields {
			idSeenKeys[f.key]++
			idSeenLabels[f.label]++
			if strings.HasPrefix(f.key, "identification/") || strings.HasPrefix(f.key, "documents/") || strings.HasPrefix(f.key, "contact/") {
				t.Fatalf("onevraDetailGroups emitted duplicate canonical identity section field %q", f.key)
			}
		}
	}
	for _, wantKey := range []string{
		"identity.last_name", "identity.first_name", "identity.middle_name", "identity.birth_date",
		"identity.company", "identity.department", "identity.job_title",
		"identity.ssn", "identity.passport_number", "identity.license_number",
		"identity.email", "identity.phone", "identity.country", "identity.state", "identity.city",
		"identity.address_line1", "identity.address_line2", "identity.postal_code", "identity.website",
		"extra/badge",
	} {
		if idSeenKeys[wantKey] != 1 {
			t.Fatalf("identity field %q count = %d, want 1", wantKey, idSeenKeys[wantKey])
		}
	}
	for label, count := range idSeenLabels {
		if count != 1 {
			t.Fatalf("identity label %q rendered %d times, want 1", label, count)
		}
	}
}

func TestCLICachedPathDetectionDoesNotRescanRepeatedFrames(t *testing.T) {
	programDir := t.TempDir()
	ghPath := writeFakeCLIExecutable(t, programDir, "gh")
	t.Setenv("PATH", programDir)

	a := newOnevraTestApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.v2Mode = true
	a.openSettings()
	a.v2.settingsSection = settingsSectionCLI

	tester := newOnevraTestTesterSize(a, 1280, 1000)
	if !a.cliSettings.detectedReady || a.cliSettings.detectedPathEnv != programDir {
		t.Fatalf("initial CLI PATH cache not populated: ready=%v pathEnv=%q", a.cliSettings.detectedReady, a.cliSettings.detectedPathEnv)
	}
	if got := a.cliDetectedProgram("gh"); got != ghPath {
		t.Fatalf("cliDetectedProgram(gh) = %q, want %q", got, ghPath)
	}
	if got := a.cliDetectedProgram("vercel"); got != "" {
		t.Fatalf("cliDetectedProgram(vercel) = %q, want empty", got)
	}
	if !tester.HasText("已检测 1") || !tester.HasText("重新扫描 PATH") {
		t.Fatal("CLI workbench did not render initial cached detection metrics")
	}

	// Delete the binary from disk while keeping PATH identical; repeated UI frames must use the cache.
	if err := os.Remove(ghPath); err != nil {
		t.Fatal(err)
	}
	tester.Frame()
	tester.Frame()
	tester.Frame()
	if got := a.cliDetectedProgram("gh"); got != ghPath {
		t.Fatalf("repeated frames rescanned PATH unexpectedly: got %q, want cached %q", got, ghPath)
	}
	if !tester.HasText("已检测 1") {
		t.Fatal("cached detected count changed without rescan")
	}

	// Explicit rescan clears the cache and picks up the removal.
	if err := tester.Click("重新扫描 PATH"); err != nil {
		t.Fatal(err)
	}
	if got := a.cliDetectedProgram("gh"); got != "" {
		t.Fatalf("cliDetectedProgram(gh) after rescan = %q, want empty", got)
	}
	if !tester.HasText("已检测 0") {
		t.Fatal("detected count did not update to 0 after rescan")
	}

	// Changing PATH env triggers automatic refresh.
	programDir2 := t.TempDir()
	vercelPath := writeFakeCLIExecutable(t, programDir2, "vercel")
	t.Setenv("PATH", programDir2)
	tester.Frame()
	if got := a.cliDetectedProgram("vercel"); got != vercelPath {
		t.Fatalf("cliDetectedProgram(vercel) after PATH change = %q, want %q", got, vercelPath)
	}
	if !tester.HasText("已检测 1") {
		t.Fatal("detected count did not update after PATH change")
	}

	// Invalid bindingPath load failure is cached per path across frames until explicitly reloaded.
	a.cliSettings.loaded = false
	a.cliSettings.bindingPath = "relative-invalid.json"
	a.cliSettings.storeAttemptedPath = ""
	tester.Frame()
	if a.cliSettings.loadErr == "" || a.cliSettings.storeAttemptedPath != "relative-invalid.json" {
		t.Fatalf("invalid bindingPath load error not recorded: err=%q attempted=%q", a.cliSettings.loadErr, a.cliSettings.storeAttemptedPath)
	}
	a.cliSettings.loadErr = "sentinel-no-rescan"
	tester.Frame()
	if a.cliSettings.loadErr != "sentinel-no-rescan" {
		t.Fatalf("cliIntegrationsView retried failed binding load on repeated frame: err=%q", a.cliSettings.loadErr)
	}
	if err := tester.Click("重新载入绑定"); err != nil {
		t.Fatal(err)
	}
	if a.cliSettings.loadErr == "sentinel-no-rescan" || a.cliSettings.loadErr == "" {
		t.Fatalf("重新载入绑定 did not re-evaluate bindingPath: err=%q", a.cliSettings.loadErr)
	}

	// Responsive stacked layout (< 760px) renders cleanly without panic.
	narrowTester := newOnevraTestTesterSize(a, 700, 1000)
	if !narrowTester.HasText("全部 CLI 工具 (24)") || !narrowTester.HasText("保存 gh 绑定") {
		t.Fatal("narrow CLI workbench layout missing expected controls")
	}
}

func TestOnevraDeviceSecretCacheAvoidsRepeatedStoreLookups(t *testing.T) {
	a, _, secret := createDeviceSecretTestVault(t)
	secrets := newFakeDeviceSecretStore()
	a.deviceSecrets = secrets
	if err := a.storeDeviceSecret(a.path, secret); err != nil {
		t.Fatal(err)
	}
	secrets.getCalls = 0

	tester := ui.NewTester(a.lockView, 640, 600)
	tester.Frame()
	tester.Frame()
	if secrets.getCalls != 1 {
		t.Fatalf("deviceSecrets.Get called %d times across repeated lockView frames, want 1", secrets.getCalls)
	}
	if !a.hasDeviceSecretCached(a.path) || secrets.getCalls != 1 {
		t.Fatalf("hasDeviceSecretCached failed or re-queried store: calls=%d", secrets.getCalls)
	}
	if err := a.deleteDeviceSecret(a.path); err != nil {
		t.Fatal(err)
	}
	if a.hasDeviceSecretCached(a.path) {
		t.Fatal("deleteDeviceSecret did not invalidate device secret cache")
	}
	if secrets.getCalls != 2 {
		t.Fatalf("expected 1 re-query after invalidation, got %d", secrets.getCalls)
	}
}

func TestOnevraModalEditorSSHKeygenAndFieldDragReorder(t *testing.T) {
	// 1. Floating modal renders over detail pane while keeping underlying detail intact.
	a := newOnevraTestApp()
	a.v2.editing = true
	a.v2.draft = newItemDraft(vault.CategorySSHKey)
	a.v2.draft.Title = "Prod Bastion"
	tester := newOnevraTestTesterSize(a, 1280, 960)
	for _, want := range []string{"Example Login", "编辑条目", "自动生成 SSH 密钥对", "生成 SSH 密钥对"} {
		if !tester.HasText(want) {
			t.Fatalf("floating modal editor missing %q", want)
		}
	}

	// 2. One-click SSH Ed25519 keygen populates fields, saves into Session, and registers for SSH Agent.
	b := v2ParitySaveApp(t)
	b.newItem(vault.CategorySSHKey)
	b.v2.draft.Title = "Prod Bastion"
	bt := newOnevraTestTesterSize(b, 1280, 960)
	if err := bt.Click("生成 SSH 密钥对"); err != nil {
		t.Fatalf("click 生成 SSH 密钥对: %v", err)
	}
	if got := sectionFieldValue(b.v2.draft.Sections, "ssh", "key_type"); got != "Ed25519" {
		t.Fatalf("generated key_type = %q, want Ed25519", got)
	}
	pub := sectionFieldValue(b.v2.draft.Sections, "ssh", "public_key")
	priv := sectionFieldValue(b.v2.draft.Sections, "ssh", "private_key")
	fp := sectionFieldValue(b.v2.draft.Sections, "ssh", "fingerprint")
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.Contains(priv, "-----BEGIN OPENSSH PRIVATE KEY-----") || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("unexpected generated SSH fields pub=%q privLen=%d fp=%q", pub, len(priv), fp)
	}
	if !bt.HasText("复制公钥") {
		t.Fatal("missing 复制公钥 button after SSH key generation")
	}
	if err := b.saveDraft(); err != nil {
		t.Fatalf("saveDraft(Ed25519 SSH): %v", err)
	}
	sshRows, err := b.session.ListSSHKeys()
	if err != nil {
		t.Fatalf("ListSSHKeys: %v", err)
	}
	if len(sshRows) != 1 || sshRows[0].Title != "Prod Bastion" || sshRows[0].Fingerprint != fp {
		t.Fatalf("saved SSH key rows = %+v, want title %q fp %q", sshRows, "Prod Bastion", fp)
	}

	// Non-Ed25519 (ECDSA) and empty SSH items also save cleanly without triggering Ed25519 seed validation failure.
	b.newItem(vault.CategorySSHKey)
	b.v2.draft.Title = "Staging ECDSA"
	b.generateDraftSSHKey("ECDSA")
	if got := sectionFieldValue(b.v2.draft.Sections, "ssh", "key_type"); got != "ECDSA" {
		t.Fatalf("generated ECDSA key_type = %q, want ECDSA", got)
	}
	if err := b.saveDraft(); err != nil {
		t.Fatalf("saveDraft(ECDSA SSH): %v", err)
	}

	// 3. Splice-insertion reorderField and pointer drag with floating ghost preview.
	d := newOnevraTestApp()
	d.v2.editing = true
	d.v2.draft = newItemDraft(vault.CategoryLogin)
	d.v2.draft.Title = "DnD Test"
	d.v2.draft.Sections = []vault.ItemSection{{
		ID:    "sec-dnd",
		Title: "排序测试",
		Fields: []vault.CustomField{
			{ID: "f1", Label: "字段A", Type: vault.FieldTypeString, Value: "val-a"},
			{ID: "f2", Label: "字段B", Type: vault.FieldTypeString, Value: "val-b"},
			{ID: "f3", Label: "字段C", Type: vault.FieldTypeString, Value: "val-c"},
			{ID: "f4", Label: "字段D", Type: vault.FieldTypeString, Value: "val-d"},
		},
	}}
	d.reorderField(0, 0, 2)
	gotOrder := []string{
		d.v2.draft.Sections[0].Fields[0].ID,
		d.v2.draft.Sections[0].Fields[1].ID,
		d.v2.draft.Sections[0].Fields[2].ID,
		d.v2.draft.Sections[0].Fields[3].ID,
	}
	if strings.Join(gotOrder, ",") != "f2,f3,f1,f4" {
		t.Fatalf("reorderField(0,0,2) order = %v, want [f2 f3 f1 f4]", gotOrder)
	}
	d.reorderField(0, 3, 1)
	gotOrder = []string{
		d.v2.draft.Sections[0].Fields[0].ID,
		d.v2.draft.Sections[0].Fields[1].ID,
		d.v2.draft.Sections[0].Fields[2].ID,
		d.v2.draft.Sections[0].Fields[3].ID,
	}
	if strings.Join(gotOrder, ",") != "f2,f4,f3,f1" {
		t.Fatalf("reorderField(0,3,1) order = %v, want [f2 f4 f3 f1]", gotOrder)
	}

	// Pointer drag over the modal editor: drag first field ("字段B") onto third field ("字段C").
	dt := newOnevraTestTesterSize(d, 1280, 960)
	rStart, ok := dt.Find("拖动排序 字段B")
	if !ok {
		t.Fatal("missing drag grip for 字段B")
	}
	rTarget, ok := dt.Find("拖动排序 字段C")
	if !ok {
		t.Fatal("missing drag grip for 字段C")
	}
	startX, startY := rStart.X+rStart.W/2, rStart.Y+rStart.H/2
	endY := rTarget.Y + rTarget.H/2
	dt.Press(startX, startY)
	dt.Move(startX, endY)
	dt.Frame()
	if !d.onevra.editor.dragging {
		t.Fatal("pointer drag did not enter dragging state")
	}
	if d.onevra.editor.dragOverField != 2 {
		t.Fatalf("dragOverField = %d, want 2 (字段C index)", d.onevra.editor.dragOverField)
	}
	if _, ok := dt.Find("editor-drag-ghost"); !ok && !dt.HasText("val-b") {
		t.Fatal("floating drag ghost did not render during pointer drag")
	}
	dt.Release(startX, endY)
	dt.Frame()
	if d.onevra.editor.dragging {
		t.Fatal("drag state did not clear after release")
	}
	finalOrder := []string{
		d.v2.draft.Sections[0].Fields[0].ID,
		d.v2.draft.Sections[0].Fields[1].ID,
		d.v2.draft.Sections[0].Fields[2].ID,
		d.v2.draft.Sections[0].Fields[3].ID,
	}
	if strings.Join(finalOrder, ",") != "f4,f3,f2,f1" {
		t.Fatalf("pointer drag release order = %v, want [f4 f3 f2 f1]", finalOrder)
	}
}

func TestOnevraFastReadSuppressesToolbarBusyFlicker(t *testing.T) {
	a, q := v2ParityBusyApp(t)
	bugfixAddLogin(t, a, "Alpha", "user", "password")
	a.status = "就绪"

	a.reloadV2(false)
	if !a.busy {
		t.Fatal("reloadV2 did not mark a.busy for concurrency serialization")
	}
	if a.uiBusy(nil) {
		t.Fatal("fast background read immediately toggled uiBusy true, causing toolbar opacity flicker")
	}
	tester := newOnevraTestTesterSize(a, 1280, 900)
	if !tester.HasText("就绪") || !tester.HasText("＋ 新建") {
		t.Fatalf("workspace status/toolbar missing during fast read: status=%q steadyStatus=%q", a.status, a.steadyStatus)
	}

	a.busySince = time.Now().Add(-uiBusyGrace - 10*time.Millisecond)
	if !a.uiBusy(nil) {
		t.Fatal("long-running read past uiBusyGrace did not become uiBusy")
	}

	if len(q.work) != 1 {
		t.Fatalf("reloadV2 queued %d workers, want 1", len(q.work))
	}
	q.work[0]()
	if len(q.complete) != 1 {
		t.Fatalf("reloadV2 queued %d completions, want 1", len(q.complete))
	}
	q.complete[0]()
	if a.busy || a.uiBusy(nil) {
		t.Fatalf("completed read left busy=%v uiBusy=%v", a.busy, a.uiBusy(nil))
	}

	if _, err := a.createVault("Infra", "", ""); err != nil {
		t.Fatalf("createVault: %v", err)
	}
	if !a.busy || !a.busyImmediate || !a.uiBusy(nil) {
		t.Fatalf("mutation should immediately mark uiBusy: busy=%v immediate=%v uiBusy=%v", a.busy, a.busyImmediate, a.uiBusy(nil))
	}
	if len(q.work) != 2 {
		t.Fatalf("createVault queued %d total workers, want 2", len(q.work))
	}
	q.work[1]()
	if len(q.complete) != 2 {
		t.Fatalf("createVault queued %d total completions, want 2", len(q.complete))
	}
	q.complete[1]()
	if !a.busy || a.uiBusy(nil) {
		t.Fatalf("createVault follow-up reloadV2 should keep busy=true uiBusy=false, got busy=%v uiBusy=%v", a.busy, a.uiBusy(nil))
	}
	if len(q.work) != 3 {
		t.Fatalf("createVault follow-up reload queued %d total workers, want 3", len(q.work))
	}
	q.work[2]()
	q.complete[2]()
	if a.busy || a.uiBusy(nil) {
		t.Fatalf("completed mutation + reload left busy=%v uiBusy=%v", a.busy, a.uiBusy(nil))
	}
}

type enrollableTestSystemStore struct {
	slots    map[string][]byte
	storeErr error
}

func (s *enrollableTestSystemStore) Store(id string, b []byte) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	if s.slots == nil {
		s.slots = map[string][]byte{}
	}
	s.slots[id] = bytes.Clone(b)
	return nil
}

func (s *enrollableTestSystemStore) Load(id string) ([]byte, error) {
	b, ok := s.slots[id]
	if !ok {
		return nil, osunlock.ErrNotFound
	}
	return bytes.Clone(b), nil
}

func (s *enrollableTestSystemStore) Delete(id string) error {
	if _, ok := s.slots[id]; !ok {
		return osunlock.ErrNotFound
	}
	delete(s.slots, id)
	return nil
}

func TestLockViewSystemUnlockNotEnrolledOffersEnrollOnMasterUnlock(t *testing.T) {
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "")
	vaultPath := filepath.Join(t.TempDir(), "personal-hello.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if err := personal.Create(vaultPath, "fixture-pass", key); err != nil {
		t.Fatal(err)
	}

	store := &enrollableTestSystemStore{}
	a := New()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.path = vaultPath
	a.systemStore = store
	a.launch = func(f func()) { f() }
	a.dispatch = func(f func()) { f() }

	a.systemUnlock()
	if a.session != nil {
		t.Fatal("unenrolled systemUnlock succeeded unexpectedly")
	}
	if !a.systemUnlockNotEnrolled || !a.enrollSystemUnlockOnUnlock {
		t.Fatalf("unenrolled flags = notEnrolled:%v enrollOnUnlock:%v, want both true", a.systemUnlockNotEnrolled, a.enrollSystemUnlockOnUnlock)
	}
	if !strings.Contains(a.status, "尚未启用") {
		t.Fatalf("unenrolled status = %q, want 尚未启用 guidance", a.status)
	}

	tester := ui.NewTester(a.lockView, 1280, 900)
	wantEnrollLabel := "主密码解锁后立即启用 " + osunlock.Label()
	if !tester.HasText(wantEnrollLabel) {
		t.Fatalf("lockView missing enrollment checkbox %q", wantEnrollLabel)
	}

	a.password = "fixture-pass"
	a.secret = personal.FormatSecret(key)
	a.unlock()
	if a.session == nil {
		t.Fatalf("master unlock failed: status=%q", a.status)
	}
	if a.systemUnlockNotEnrolled || a.enrollSystemUnlockOnUnlock {
		t.Fatalf("enrollment flags not cleared after unlock: notEnrolled=%v enroll=%v", a.systemUnlockNotEnrolled, a.enrollSystemUnlockOnUnlock)
	}
	if len(store.slots) != 1 || !a.settingsSnapshot().SystemUnlockEnabled {
		t.Fatalf("master unlock did not enroll quick unlock: slots=%d enabled=%v", len(store.slots), a.settingsSnapshot().SystemUnlockEnabled)
	}

	a.Lock()
	a.systemUnlock()
	if a.session == nil {
		t.Fatalf("enrolled systemUnlock failed: status=%q", a.status)
	}
	a.Lock()

	// Also verify inline settings status/error banners in securitySettingsView:
	a.password = "fixture-pass"
	a.secret = personal.FormatSecret(key)
	a.unlock()
	if a.session == nil {
		t.Fatalf("second master unlock failed: status=%q", a.status)
	}
	a.v2Mode = true
	a.openSettings()
	a.v2.settingsSection = settingsSectionSecurity
	store.storeErr = osunlock.ErrCancelled
	a.markSystemUnlockDisabled()
	stTester := newOnevraTestTesterSize(a, 1280, 1400)
	if err := stTester.Click("启用系统快捷解锁"); err != nil {
		t.Fatalf("click 启用系统快捷解锁 (cancelled case): %v", err)
	}
	if !a.systemUnlockNoticeErr || !strings.Contains(a.systemUnlockNotice, "已取消") {
		t.Fatalf("cancelled settings enrollment = err:%v notice:%q", a.systemUnlockNoticeErr, a.systemUnlockNotice)
	}
	if !stTester.HasText("系统验证已取消") {
		t.Fatal("securitySettingsView did not render inline cancellation banner")
	}

	store.storeErr = nil
	if err := stTester.Click("启用系统快捷解锁"); err != nil {
		t.Fatalf("click 启用系统快捷解锁 (success case): %v", err)
	}
	if a.systemUnlockNoticeErr || !a.settingsSnapshot().SystemUnlockEnabled {
		t.Fatalf("successful settings enrollment = enabled:%v noticeErr:%v notice:%q", a.settingsSnapshot().SystemUnlockEnabled, a.systemUnlockNoticeErr, a.systemUnlockNotice)
	}
	if !stTester.HasText("系统快捷解锁已启用") || !stTester.HasText("重新授权快捷解锁") {
		t.Fatal("securitySettingsView did not update pill/button/inline banner after enrollment")
	}
	a.Lock()
}
