package desktop

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
)

func TestEditorFieldRowShowsLabelAndFieldMenu(t *testing.T) {
	password := "synthetic field value"
	removed := false
	tester := ui.NewTester(func(c *ui.Context) {
		editorFieldRow(c, editorFieldSpec{
			Key:         "password",
			Label:       "密码",
			Placeholder: "输入密码",
			Value:       &password,
			Concealed:   true,
			MenuLabel:   "字段选项：密码",
			BuildMenu: func(menu *oneui.Menu) {
				if menu.Item("删除字段").Chosen() {
					removed = true
				}
			},
		})
	}, 520, 160)

	if !tester.HasText("密码") {
		t.Fatal("field label was not visible")
	}
	if tester.HasText(password) {
		t.Fatal("concealed field value was rendered as text")
	}
	if err := tester.Click("字段选项：密码"); err != nil {
		t.Fatal(err)
	}
	if !tester.HasText("删除字段") {
		t.Fatal("field menu did not open")
	}
	if err := tester.Click("删除字段"); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("field menu action did not run")
	}
}

func TestEditorFieldGroupConnectsFieldsAndAddMenu(t *testing.T) {
	title := "Example"
	username := "alice@example.test"
	added := ""
	tester := ui.NewTester(func(c *ui.Context) {
		editorFieldGroup(c, editorFieldGroupSpec{
			Key:   "login-fields",
			Title: "登录信息",
			Badge: "登录",
			Fields: []editorFieldSpec{
				{Key: "title", Label: "标题", Value: &title, MenuLabel: "字段选项：标题"},
				{Key: "username", Label: "用户名", Value: &username, MenuLabel: "字段选项：用户名"},
			},
			AddLabel: "添加更多",
			BuildAddMenu: func(menu *oneui.Menu) {
				if menu.Item("安全问题").Chosen() {
					added = "security-question"
				}
			},
		})
	}, 760, 360)

	for _, label := range []string{"登录信息", "登录", "标题", "用户名", "添加更多"} {
		if !tester.HasText(label) {
			t.Fatalf("field group missing %q", label)
		}
	}
	if err := tester.Click("添加更多"); err != nil {
		t.Fatal(err)
	}
	if !tester.HasText("安全问题") {
		t.Fatal("add-field menu did not open")
	}
	if err := tester.Click("安全问题"); err != nil {
		t.Fatal(err)
	}
	if added != "security-question" {
		t.Fatal("add-field menu did not reach the page")
	}
}

func TestEditorPageUsesGroupedFields(t *testing.T) {
	a := New()
	a.v2.draft = newItemDraft("login")
	a.v2.editing = true
	a.v2Mode = true
	tester := ui.NewTester(a.v2EditorView, 1200, 1200)

	for _, label := range []string{
		"编辑条目",
		"登录信息",
		"标题",
		"用户名",
		"密码",
		"一次性验证码",
		"网站",
		"备注",
		"添加更多",
		"保存",
		"取消",
	} {
		if !tester.HasText(label) {
			t.Fatalf("editor page missing %q", label)
		}
	}
}

func TestEditorPageSnapshot(t *testing.T) {
	target := os.Getenv("LOCKLARK_EDITOR_SNAPSHOT")
	if target == "" {
		t.Skip("set LOCKLARK_EDITOR_SNAPSHOT to render the grouped editor")
	}
	a := New()
	a.v2.draft = newItemDraft(vault.CategoryLogin)
	a.v2.draft.Title = "Example"
	a.v2.draft.Username = "alice@example.test"
	a.v2.draft.URL = "https://example.test"
	a.v2.editing = true
	a.v2Mode = true
	tester := ui.NewTester(a.v2EditorView, 960, 1240)
	f, err := os.Create(filepath.Join(target, "editor-page.png"))
	if err != nil {
		t.Fatal(err)
	}
	err = png.Encode(f, tester.Image())
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
