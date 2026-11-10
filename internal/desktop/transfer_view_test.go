package desktop

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// The desktop migration path must expose the official 1PUX import, including
// the full-category profile that is otherwise CLI-only. A bare text field is
// not enough for a local-file migration; the picker is the entry point users
// actually need.
func TestTransferViewShows1PUXMigration(t *testing.T) {
	a := New()
	tester := ui.NewTester(a.transferView, 1100, 820)
	for _, want := range []string{
		"1PUX 文件",
		"选择 1PUX 文件…",
		"完整类别（含卡片/身份/笔记，实验）",
		"生成导入计划",
		"确认整批导入",
		".opvault",
		"未加密",
		"拖到这里",
		"打开 1Password 导出…",
		"不接收 1Password 主密码",
	} {
		if !tester.HasText(want) {
			t.Fatalf("transfer page missing %q", want)
		}
	}
	small := ui.NewTester(a.transferView, 980, 680)
	for _, label := range []string{"生成导入计划", "确认整批导入", "确认加密导出"} {
		rect, ok := small.Find(label)
		if !ok {
			t.Fatalf("transfer page at minimum size missing %q", label)
		}
		if rect.Y+rect.H > 680 {
			t.Fatalf("transfer page at minimum size clips %q at y=%.1f h=%.1f", label, rect.Y, rect.H)
		}
	}
}
