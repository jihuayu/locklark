package desktop

import (
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// quickMatches filters the already loaded, non-secret item summaries. It is
// metadata only, like the list column; secrets are read only when the user
// chooses a result.
func (a *App) quickMatches() []personal.ItemSummary {
	q := strings.ToLower(strings.TrimSpace(a.onevra.quickQuery))
	var out []personal.ItemSummary
	for _, row := range a.v2.all {
		if row.State != "active" {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(row.Title+" "+row.Subtitle+" "+row.PrimaryURL), q) {
			continue
		}
		out = append(out, row)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func (a *App) chooseQuick(row personal.ItemSummary, copyPassword bool) {
	a.closeQuickSearch()
	a.onevra.quickQuery, a.onevra.quickCursor = "", 0
	a.v2.settingsOpen = false
	a.withItem(row, func() {
		if copyPassword && itemHasSecretLogin(row) {
			a.copyField("password")
		}
	})
}

// onevraQuickSearch is a command-palette overlay above the vault: results
// update while typing, Enter copies the password, Ctrl+Enter opens the item.
func (a *App) onevraQuickSearch(c *ui.Context) {
	t := c.Theme()
	open := true
	matches := a.quickMatches()
	if a.onevra.quickCursor >= len(matches) {
		a.onevra.quickCursor = len(matches) - 1
	}
	if a.onevra.quickCursor < 0 {
		a.onevra.quickCursor = 0
	}
	oneui.Dialog(c.Key("quick-search"), &open, oneui.DialogOptions{Label: "快捷搜索"}, func(panel ui.Element) {
		panel.Width(600).Padding(t.Space(2.5)).Gap(t.Space(2))
		panel.Children(func() {
			input := oneui.TextBox(c.Key("quick-query"), &a.onevra.quickQuery, oneui.TextBoxOptions{LeadingIcon: lucide.Search()}).
				Label("快捷搜索标题").Placeholder("搜索标题、用户名或网址").FillWidth().FontSize(t.Rem(1.05))
			if a.quick.focus {
				input.Focus()
				a.quick.focus = false
			}
			if input.Changed() {
				a.onevra.quickCursor = 0
			}
			switch {
			case input.Shortcut(0, ui.KeyDown):
				if a.onevra.quickCursor < len(matches)-1 {
					a.onevra.quickCursor++
				}
			case input.Shortcut(0, ui.KeyUp):
				if a.onevra.quickCursor > 0 {
					a.onevra.quickCursor--
				}
			case input.Shortcut(ui.Ctrl, ui.KeyEnter):
				if len(matches) > 0 {
					a.chooseQuick(matches[a.onevra.quickCursor], false)
					return
				}
			case input.Submitted():
				if len(matches) > 0 {
					a.chooseQuick(matches[a.onevra.quickCursor], true)
					return
				}
			}
			ui.Column(c).FillWidth().Gap(t.Space(.5)).Children(func() {
				if len(matches) == 0 {
					oneui.Text(c, "没有匹配的条目").TextColor(t.TextMuted).Padding(t.Space(3))
				}
				for i, row := range matches {
					i, row := i, row
					el := ui.Row(c.Key("quick:"+row.ID)).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).
						Padding(t.Space(1.75), t.Space(2)).Radius(t.Radius).Cursor(ui.CursorPointer)
					if i == a.onevra.quickCursor {
						el.Background(t.Selection)
					} else if el.Hovered() {
						el.Background(t.Text.Alpha(.04))
					}
					el.Children(func() {
						a.onevraItemAvatar(c, row.Title, row.Category, row.CustomIcon, t.Space(7))
						ui.Column(c).Grow(1).MinWidth(0).Children(func() {
							oneui.Text(c, visible(row.Title)).Bold().SingleLine().Ellipsis("…")
							oneui.Text(c, visible(a.onevraListSubtitle(row))).FontSize(t.Rem(.76)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
						})
						if i == a.onevra.quickCursor && itemHasSecretLogin(row) {
							oneui.Text(c, "Enter 复制密码").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
						}
					})
					if el.Clicked() {
						a.chooseQuick(row, false)
					}
				}
			})
			ui.Box(c).FillWidth().Height(1).Background(t.Border)
			oneui.Text(c, "↑↓ 选择 · Enter 复制密码 · Ctrl+Enter 打开 · Esc 关闭").FontSize(t.Rem(.72)).TextColor(t.TextMuted).Padding(0, t.Space(1))
		})
	})
	if !open {
		a.closeQuickSearch()
		a.onevra.quickQuery, a.onevra.quickCursor = "", 0
	}
}
