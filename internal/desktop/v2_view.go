package desktop

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
)

// WatchtowerReport is the desktop projection of the shared Watchtower report.
// It is a distinct name so the v2 state does not expose the browser package's
// wire types.
type WatchtowerReport = watchtower.Report

// v2View renders the three-pane desktop vault. Model mutations live in
// v2_state.go, item_detail.go and item_editor.go; this file stays a thin view
// over that state so every native action remains audited by the same methods.
func (a *App) v2View(c *ui.Context) {
	if a.v2.largeTypeOpen {
		a.largeTypeView(c)
		return
	}
	ui.Row(c).Gap(16).Grow(1).Children(func() {
		a.v2SidebarView(c)
		a.v2ListView(c)
		ui.Scroll(c).Grow(1).FillHeight().Children(func() {
			ui.Column(c).Gap(10).Children(func() {
				switch {
				case a.v2.nav == navWatchtower:
					a.v2WatchtowerView(c)
				case a.v2.editing && a.v2.draft != nil:
					a.v2EditorView(c)
				case a.v2.generator.open:
					a.generatorView(c)
				default:
					a.v2DetailView(c)
				}
			})
		})
	})
}

func (a *App) v2SidebarView(c *ui.Context) {
	ui.Scroll(c).Width(210).FillHeight().Children(func() {
		ui.Column(c).Gap(4).Children(func() {
			ui.Text(c, "金库").FontSize(18).Bold()
			for _, view := range []struct{ nav, label string }{
				{navAllItems, "全部条目"},
				{navFavorites, "收藏"},
				{navWatchtower, "Watchtower 安全体检"},
				{navRecentlyDelete, "最近删除"},
				{navArchive, "归档"},
			} {
				view := view
				ui.Button(c, view.label).FillWidth().OnClick(func() { a.navigate(view.nav) })
			}
			ui.Text(c, "保险库").FontSize(13).Bold()
			ui.Button(c, "全部保险库").FillWidth().OnClick(func() { a.selectVault("all") })
			for _, v := range a.v2.vaults {
				v := v
				ui.Button(c, v.Name).FillWidth().OnClick(func() { a.selectVault(v.ID) })
			}
			ui.Text(c, "类别").FontSize(13).Bold()
			for _, category := range AllCategories() {
				category := category
				label := fmt.Sprintf("%s (%d)", CategoryDisplayName(category), a.v2.categoryCount[category])
				ui.Button(c, label).FillWidth().OnClick(func() { a.FilterByCategory(category) })
			}
			if len(a.v2.tags) > 0 {
				ui.Text(c, "标签").FontSize(13).Bold()
				for _, tag := range a.v2.tags {
					tag := tag
					ui.Button(c, fmt.Sprintf("%s (%d)", tag.Tag, tag.Count)).FillWidth().OnClick(func() { a.FilterByTag(tag.Tag) })
				}
			}
		})
	})
}

func (a *App) v2ListView(c *ui.Context) {
	ui.Scroll(c).Width(330).FillHeight().Children(func() {
		ui.Column(c).Gap(8).Children(func() {
			input := ui.TextInput(c, &a.query).Label("搜索").Placeholder("标题、用户名、标签").Grow(1)
			if input.Changed() {
				a.SetSearchQuery(a.query)
			}
			ui.Row(c).Gap(6).Children(func() {
				for _, sortBy := range []struct{ id, label string }{{"title", "标题"}, {"updated_at", "更新"}, {"created_at", "创建"}} {
					sortBy := sortBy
					ui.Button(c, sortBy.label).OnClick(func() { a.SetSort(sortBy.id) })
				}
				ui.Button(c, "新建").OnClick(func() { a.newItem(vault.CategoryLogin) })
				ui.Button(c, "生成器").OnClick(func() { a.openGenerator("password") })
			})
			if len(a.v2.rows) == 0 {
				ui.Text(c, "此视图没有条目").FontSize(13)
			}
			for _, row := range a.v2.rows {
				row := row
				label := row.Title
				if row.Subtitle != "" {
					label += " · " + row.Subtitle
				}
				ui.Button(c, label).FillWidth().OnClick(func() { a.selectItem(row.ID, row.Revision) })
			}
		})
	})
}

func (a *App) v2DetailView(c *ui.Context) {
	detail := a.detailForView()
	if detail == nil {
		ui.Text(c, "选择一个条目查看详情").FontSize(20).Bold()
		ui.Text(c, "所有显示与复制操作都会记录审计。密码默认遮蔽。")
		return
	}
	ui.Row(c).Gap(8).Children(func() {
		ui.Text(c, visible(detail.Title)).FontSize(24).Bold().Grow(1)
		ui.Button(c, "编辑").Disabled(a.busy).OnClick(func() {
			if err := a.beginEdit(); err != nil {
				a.status = message(err)
			}
		})
		ui.Button(c, "关闭").OnClick(a.clearSelection)
	})
	ui.Text(c, CategoryDisplayName(detail.Category)+" · "+detail.ID).FontSize(12)
	if detail.State == "trashed" {
		ui.Text(c, "条目在回收站中；恢复后才能查看或使用字段。").Bold()
		ui.Button(c, "恢复").Disabled(a.busy).OnClick(a.restoreSelected)
		return
	}
	plain := a.plainDetail()
	show := func(key string) string {
		source := detail
		if a.v2.revealed[key] && plain != nil {
			source = plain
		}
		value, _ := fieldValue(source, key)
		if value == "" {
			return "—"
		}
		if isConcealedKey(detail, key) && !a.v2.revealed[key] {
			return "••••••••"
		}
		return value
	}
	for _, key := range []string{"username", "password", "otp", "url", "notes"} {
		key := key
		ui.Row(c).Gap(8).Children(func() {
			ui.Text(c, fieldLabel(key)).Width(90)
			ui.Text(c, show(key)).Grow(1)
			if isConcealedKey(detail, key) {
				label := "显示"
				if a.v2.revealed[key] {
					label = "隐藏"
				}
				ui.Button(c, label).Disabled(a.busy).OnClick(func() { a.revealField(key) })
			}
			ui.Button(c, "复制").Disabled(a.busy).OnClick(func() { a.copyField(key) })
			if key == "otp" {
				ui.Button(c, "大号显示").Disabled(a.busy).OnClick(func() { a.showLargeType(key) })
			}
		})
	}
	if len(detail.Tags) > 0 {
		ui.Text(c, "标签："+strings.Join(detail.Tags, "、")).FontSize(13)
	}
	if len(detail.History) > 0 {
		ui.Button(c, fmt.Sprintf("历史版本 (%d)", len(detail.History))).OnClick(a.openHistory)
		if a.v2.historyOpen {
			ui.Column(c).Gap(4).Children(func() {
				for i, entry := range detail.History {
					i, entry := i, entry
					ui.Row(c).Gap(8).Children(func() {
						label := entry.Action
						if label == "" {
							label = fmt.Sprintf("版本 %d", i+1)
						}
						ui.Text(c, label).Grow(1)
						ui.Button(c, "还原").Disabled(a.busy).OnClick(func() {
							if err := a.restoreHistory(i); err != nil {
								a.status = message(err)
							}
						})
					})
				}
				ui.Button(c, "关闭历史").OnClick(a.closeHistory)
			})
		}
	}
	ui.Row(c).Gap(8).Children(func() {
		ui.Button(c, "收藏 / 取消收藏").Disabled(a.busy).OnClick(a.toggleSelectedFavorite)
		if detail.State == "archived" {
			ui.Button(c, "取消归档").Disabled(a.busy).OnClick(a.unarchiveSelected)
		} else {
			ui.Button(c, "归档").Disabled(a.busy).OnClick(a.archiveSelected)
		}
		ui.Button(c, "移入回收站").Disabled(a.busy).OnClick(a.trashSelected)
	})
}

func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	ui.Text(c, "编辑条目").FontSize(22).Bold()
	ui.Text(c, "修改会生成新的修订版本；原值写入历史。")
	ui.TextInput(c, &draft.Title).Label("标题").Disabled(a.busy)
	ui.TextInput(c, &draft.Username).Label("用户名").Disabled(a.busy)
	ui.TextInput(c, &draft.Password).Label("密码").Password().Disabled(a.busy)
	ui.TextInput(c, &draft.OTP).Label("一次性验证码配置").Disabled(a.busy)
	ui.TextInput(c, &draft.URL).Label("网站").Disabled(a.busy)
	ui.TextInput(c, &draft.Notes).Label("备注").Password().Disabled(a.busy)
	ui.Row(c).Gap(8).Children(func() {
		ui.PrimaryButton(c, "保存").Disabled(a.busy || strings.TrimSpace(draft.Title) == "").OnClick(func() {
			if err := a.saveDraft(); err != nil {
				a.status = message(err)
			}
		})
		ui.Button(c, "取消").Disabled(a.busy).OnClick(a.cancelEdit)
		ui.Button(c, "生成密码").Disabled(a.busy).OnClick(func() { a.openGenerator("password") })
	})
}

func (a *App) v2WatchtowerView(c *ui.Context) {
	ui.Row(c).Gap(8).Children(func() {
		ui.Text(c, "Watchtower 安全体检").FontSize(22).Bold().Grow(1)
		ui.Button(c, "运行本地检查").Disabled(a.busy).OnClick(func() {
			s := a.session
			a.run(func() outcome {
				report, err := s.Watchtower("", false)
				return outcome{err: err, apply: func() { a.v2.watchtower = &report }}
			})
		})
	})
	ui.Text(c, "本地检查完全离线；HIBP 泄露库检查需在浏览器扩展中显式启用。")
	report := a.v2.watchtower
	if report == nil {
		ui.Text(c, "尚未运行安全体检。")
		return
	}
	ui.Text(c, fmt.Sprintf("安全评分 %d/100 · 已检查 %d 项 · 跳过 %d 项", report.OverallScore, report.Checked, report.Skipped)).FontSize(18).Bold()
	ui.Row(c).Gap(8).Children(func() {
		ui.Text(c, fmt.Sprintf("已泄露 %d", report.Counts.Vulnerable))
		ui.Text(c, fmt.Sprintf("重复 %d", report.Counts.Reused))
		ui.Text(c, fmt.Sprintf("弱密码 %d", report.Counts.Weak))
		ui.Text(c, fmt.Sprintf("HTTP %d", report.Counts.UnsecuredHTTP))
		ui.Text(c, fmt.Sprintf("未设 2FA %d", report.Counts.TOTPNotStored))
		ui.Text(c, fmt.Sprintf("即将过期 %d", report.Counts.Expiring))
	})
	if len(report.Findings) == 0 {
		ui.Text(c, "未发现已知问题。")
		return
	}
	for _, finding := range report.Findings {
		finding := finding
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, fmt.Sprintf("%s · 强度 %d · %s", visible(finding.Title), finding.StrengthScore, strings.Join(finding.Flags, ", "))).Bold()
			if finding.BreachCount > 0 {
				ui.Text(c, fmt.Sprintf("公开泄露库出现 %d 次，请立即更新密码。", finding.BreachCount))
			}
			ui.Button(c, "打开条目").OnClick(func() { a.selectItem(finding.ID, finding.Revision) })
		})
	}
}
