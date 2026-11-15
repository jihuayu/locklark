package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// onevraHeaderLeading is the persistent application identity and context in
// the Onevra native title bar. It stays visible while the vault is locked so
// the shell does not jump between authentication and unlocked states.
func (a *App) onevraHeaderLeading(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).FillHeight().MinWidth(0).AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
		mark := ui.Box(c).Size(t.Space(7), t.Space(7)).Shrink(0).Radius(t.Space(1.75)).
			Background(t.Accent).AlignItems(ui.Center).Justify(ui.Center)
		mark.Children(func() {
			oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.AccentText)
		})
		oneui.Text(c, "Locklark").Bold().SingleLine()
		ui.Box(c).Width(1).Height(t.Space(4)).Background(t.Border)
		label := "本地金库"
		if a.session != nil {
			label = a.onevraVaultLabel()
		}
		oneui.Text(c, label).FontSize(t.Rem(.875)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
	})
}

// onevraHeaderActions keeps high-frequency actions at the trailing edge of the
// draggable title bar, ahead of the native caption buttons.
func (a *App) onevraHeaderActions(c *ui.Context) {
	if a.browser == nil && oneui.IconButton(c, lucide.Search(), "快捷搜索", oneui.IconButtonPlain).Clicked() {
		a.showQuickSearch()
	}
	// The classic layout keeps its own security tab. Showing the shell gear as
	// well would create two controls with the same accessible name, which the
	// native acceptance driver rejects as ambiguous.
	if !classicLayoutRequested() {
		settings := oneui.IconButton(c, lucide.Settings(), "安全设置", oneui.IconButtonPlain)
		settings.Disabled(a.session == nil)
		if settings.Clicked() {
			if a.v2Mode {
				a.page = "vault"
				if a.v2.settingsOpen {
					a.closeSettings()
					a.status = "已关闭设置"
				} else {
					a.openSettings()
					a.status = "安全与偏好设置"
				}
			} else {
				a.page = "security"
				a.status = "安全设置"
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		}
	}
	if a.session != nil && oneui.Button(c, "立即锁定", oneui.ButtonGhost).Clicked() {
		a.Lock()
		if a.win != nil {
			a.win.Invalidate()
		}
	}
}

// onevraVaultView composes the 1Password-style three-column workspace:
// navigation, item collection, and a focused detail/editor surface. The two
// Onevra splitters preserve keyboard resizing and native accessibility.
func (a *App) onevraVaultView(c *ui.Context) {
	c.SetTheme(a.onevraTheme(c))
	if a.v2.largeTypeOpen {
		a.largeTypeView(c)
		return
	}
	a.drainPendingV2Reload()
	ui.Column(c).Key(a.generation).Fill().Children(func() {
		if a.v2.settingsOpen {
			ui.Column(c).Grow(1).FillWidth().MinHeight(0).Children(func() {
				a.settingsView(c)
			})
			a.onevraStatusBar(c)
			return
		}
		outer := oneui.Split(c, &a.onevra.sidebarWidth, func() {
			a.onevraSidebarView(c)
		}, func() {
			inner := oneui.Split(c, &a.onevra.listWidth, func() {
				a.onevraListView(c)
			}, func() {
				a.onevraDetailPane(c)
			},
				oneui.SplitOptions{FirstMin: 300, SecondMin: 360, Default: onevraListDefaultWidth},
			)
			inner.Label("调整条目列表和详情宽度")
			inner.Fill()
		}, oneui.SplitOptions{FirstMin: 176, SecondMin: 620, Default: onevraSidebarDefaultWidth})
		outer.Label("调整导航和内容宽度")
		outer.Fill()
		a.onevraStatusBar(c)
		a.onevraVaultDialogs(c)
	})
}

func (a *App) onevraVaultDialogs(c *ui.Context) {
	t := c.Theme()
	ui.Column(c.Key("dialog-new-vault")).Children(func() {
		oneui.Dialog(c, &a.v2.newVaultOpen, oneui.DialogOptions{Label: "新建子保险库"}, func(panel ui.Element) {
			panel.Width(420).Background(t.Surface).Border(1, t.Border).Radius(t.Radius).Padding(t.Space(4))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
					oneui.Text(c, "新建保险库").FontSize(t.Rem(1.12)).Bold()
					oneui.Text(c, "子保险库存储在同一加密 .ll 金库文件内，用于按工作/个人/项目分组管理凭据。").
						FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
					oneui.TextBox(c, &a.v2.newVaultName, oneui.TextBoxOptions{}).
						Label("保险库名称").Placeholder("例如：工作基础设施、开源维护").Disabled(a.busy)
					oneui.TextBox(c, &a.v2.newVaultDesc, oneui.TextBoxOptions{}).
						Label("备注说明（可选）").Placeholder("用途或访问边界说明").Disabled(a.busy)
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
							a.v2.newVaultOpen = false
						}
						if oneui.Button(c, "创建保险库", oneui.ButtonPrimary).
							Disabled(a.busy || strings.TrimSpace(a.v2.newVaultName) == "").Clicked() {
							if _, err := a.createVault(a.v2.newVaultName, a.v2.newVaultDesc, a.v2.newVaultIcon); err != nil {
								a.status = message(err)
							} else {
								a.v2.newVaultOpen = false
							}
						}
					})
				})
			})
		})
	})

	ui.Column(c.Key("dialog-move-vault")).Children(func() {
		oneui.Dialog(c, &a.onevra.moveDialogOpen, oneui.DialogOptions{Label: "移动或复制到其他保险库"}, func(panel ui.Element) {
			panel.Width(440).Background(t.Surface).Border(1, t.Border).Radius(t.Radius).Padding(t.Space(4))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
					oneui.Text(c, "跨保险库整理条目").FontSize(t.Rem(1.12)).Bold()
					ui.Row(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						moveVariant := oneui.ButtonOutline
						copyVariant := oneui.ButtonOutline
						if !a.onevra.moveCopyMode {
							moveVariant = oneui.ButtonSecondary
						} else {
							copyVariant = oneui.ButtonSecondary
						}
						if oneui.Button(c, "移动条目", moveVariant).Grow(1).Clicked() {
							a.onevra.moveCopyMode = false
						}
						if oneui.Button(c, "复制副本", copyVariant).Grow(1).Clicked() {
							a.onevra.moveCopyMode = true
						}
					})
					if len(a.v2.vaults) > 0 {
						if a.onevra.moveTargetVaultID == "" {
							a.onevra.moveTargetVaultID = a.v2.vaults[0].ID
						}
						options := make([]oneui.NativeSelectOption[string], 0, len(a.v2.vaults))
						for _, v := range a.v2.vaults {
							options = append(options, oneui.NativeSelectOption[string]{Value: v.ID, Label: v.Name})
						}
						sel := oneui.NativeSelect(c, &a.onevra.moveTargetVaultID, options)
						sel.Trigger.Label("目标保险库").FillWidth()
					} else {
						oneui.Text(c, "当前只有一个默认保险库；可先通过「+ 新建保险库」创建分组。").
							FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					}
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
							a.onevra.moveDialogOpen = false
						}
						actionLabel := "确认移动"
						if a.onevra.moveCopyMode {
							actionLabel = "确认复制"
						}
						if oneui.Button(c, actionLabel, oneui.ButtonPrimary).
							Disabled(a.busy || a.onevra.moveTargetVaultID == "").Clicked() {
							if _, _, err := a.moveSelectedToVault(a.onevra.moveTargetVaultID, a.onevra.moveCopyMode); err != nil {
								a.status = message(err)
							} else {
								a.onevra.moveDialogOpen = false
							}
						}
					})
				})
			})
		})
	})
}

func (a *App) onevraSidebarStateCounts() (archived, trashed int) {
	for _, row := range a.v2.all {
		switch row.State {
		case "archived":
			archived++
		case "trashed":
			trashed++
		}
	}
	return archived, trashed
}

func isCoreSidebarCategory(category vault.ItemCategory) bool {
	switch category {
	case vault.CategoryLogin, vault.CategorySecureNote, vault.CategoryAPICredential, vault.CategorySSHKey:
		return true
	default:
		return false
	}
}

func (a *App) onevraSidebarView(c *ui.Context) {
	t := c.Theme()
	archivedCount, trashedCount := a.onevraSidebarStateCounts()
	ui.Column(c).Fill().MinWidth(0).Background(t.Background.Mix(t.Text, .035)).
		Padding(t.Space(2.5)).Gap(t.Space(2)).Children(func() {
		// Top current-vault switcher
		switcherBtn := oneui.Button(c, "当前："+a.onevraVaultLabel(), oneui.ButtonOutline).FillWidth()
		oneui.MenuButton(c, switcherBtn, func(m *oneui.Menu) {
			if m.Item("全部保险库").Chosen() {
				a.SelectVault("all")
			}
			for _, v := range a.v2.vaults {
				v := v
				if m.Item(v.Name).Chosen() {
					a.SelectVault(v.ID)
				}
			}
			m.Separator()
			if m.Item("+ 新建保险库…").Chosen() {
				a.beginNewVault()
			}
		})

		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Grow(1).Fill().Children(func() {
			oneui.Sidebar(c).Children(func() {
				oneui.SidebarSection(c, "浏览", func() {
					a.onevraSidebarItem(c, "全部", lucide.List(), a.v2.nav == navAllItems && a.v2.vaultID == "all", len(a.v2.rows), func() { a.navigate(navAllItems) })
					a.onevraSidebarItem(c, "收藏", lucide.Star(), a.v2.nav == navFavorites, a.onevraFavoriteCount(), func() { a.navigate(navFavorites) })
					a.onevraSidebarItem(c, "Watchtower 安全体检", lucide.Shield(), a.v2.nav == navWatchtower, 0, func() { a.navigate(navWatchtower) })
					a.onevraSidebarItem(c, "归档", lucide.Archive(), a.v2.nav == navArchive, archivedCount, func() { a.navigate(navArchive) })
					a.onevraSidebarItem(c, "回收站", lucide.Trash(), a.v2.nav == navRecentlyDelete, trashedCount, func() { a.navigate(navRecentlyDelete) })
				})

				oneui.SidebarSection(c, "整理 · 保险库", func() {
					a.onevraSidebarItem(c, "全部保险库", lucide.Vault(), a.v2.vaultID == "all", a.onevraVaultCount(), func() { a.SelectVault("all") })
					for _, v := range a.v2.vaults {
						v := v
						a.onevraSidebarItem(c, v.Name, lucide.FolderKey(), a.v2.vaultID == v.ID, a.v2.vaultCount[v.ID], func() { a.SelectVault(v.ID) })
					}
					a.onevraSidebarItem(c, "+ 新建保险库", lucide.Plus(), false, 0, a.beginNewVault)
				})

				oneui.SidebarSection(c, "类型", func() {
					hiddenCount := 0
					for _, category := range AllCategories() {
						category := category
						count := a.v2.categoryCount[category]
						selected := a.v2.nav == navCategory && a.v2.category == category
						show := a.onevra.showAllCategories || selected || count > 0 || (len(a.v2.all) == 0 && isCoreSidebarCategory(category))
						if !show {
							hiddenCount++
							continue
						}
						a.onevraSidebarItem(c, CategoryDisplayName(category), onevraCategoryIcon(category), selected, count, func() {
							a.FilterByCategory(category)
						})
					}
					if hiddenCount > 0 {
						a.onevraSidebarItem(c, "展开全部类别", lucide.ChevronDown(), false, 0, func() {
							a.onevra.showAllCategories = true
						})
					} else if a.onevra.showAllCategories {
						a.onevraSidebarItem(c, "收起空类别", lucide.ChevronUp(), false, 0, func() {
							a.onevra.showAllCategories = false
						})
					}
				})

				if len(a.v2.tags) > 0 {
					oneui.SidebarSection(c, "标签", func() {
						for _, tag := range a.v2.tags {
							tag := tag
							a.onevraSidebarItem(c, tag.Tag, lucide.Tags(), a.v2.nav == navTag && a.v2.tag == tag.Tag, tag.Count, func() {
								a.FilterByTag(tag.Tag)
							})
						}
					})
				}
			})
		})

		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		if oneui.Button(c, "设置", oneui.ButtonGhost).FillWidth().Clicked() {
			a.openSettings()
		}
	})
}

func (a *App) onevraSidebarItem(c *ui.Context, label string, icon *ui.SVG, selected bool, count int, action func()) {
	t := c.Theme()
	item := oneui.SidebarItemWithSlots(c, label, selected,
		func(c *ui.Context, size float32) {
			if icon != nil {
				oneui.Icon(c, icon).Size(size, size).TextColor(c.Theme().Accent)
			}
		},
		func(c *ui.Context, size float32) {
			if count > 0 {
				oneui.Text(c, fmt.Sprintf("%d", count)).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			}
		},
	)
	item.Key("onevra-nav:" + label)
	if item.Clicked() {
		action()
	}
}

func (a *App) onevraListView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().MinWidth(0).Background(t.Surface).Children(func() {
		ui.Column(c).Padding(t.Space(4), t.Space(4), t.Space(3), t.Space(4)).Gap(t.Space(2.5)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
				oneui.Text(c, a.onevraNavTitle()).FontSize(t.Rem(1.2)).Bold().Grow(1).SingleLine().Ellipsis("…")
				oneui.Text(c, fmt.Sprintf("%d", len(a.v2.rows))).FontSize(t.Rem(.8)).TextColor(t.TextMuted)
			})
			search := oneui.TextBox(c, &a.query, oneui.TextBoxOptions{
				LeadingIcon: lucide.Search(),
			}).Label("搜索").Placeholder("搜索标题、用户名或网址")
			search.Grow(1)
			if search.Changed() {
				a.SetSearchQuery(a.query)
			}
			if a.v2.searchError != "" {
				oneui.Text(c, a.v2.searchError).FontSize(t.Rem(.75)).TextColor(t.Danger).Wrap()
			}
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
				for _, sortBy := range []struct{ id, label string }{{"title", "标题"}, {"updated_at", "更新"}, {"created_at", "创建"}} {
					variant := oneui.ButtonGhost
					if a.v2.sortBy == sortBy.id {
						variant = oneui.ButtonSecondary
					}
					sortBy := sortBy
					if oneui.Button(c, sortBy.label, variant).Clicked() {
						a.SetSort(sortBy.id)
					}
				}
				ui.Spacer(c)
				if oneui.IconButton(c, lucide.Sparkles(), "生成器", oneui.IconButtonPlain).Clicked() {
					a.openGenerator("password")
				}
				if oneui.IconButton(c, lucide.Plus(), "新建登录", oneui.IconButtonToolbar).Clicked() {
					a.newItem(vault.CategoryLogin)
				}
				newMore := oneui.Button(c, "新建…", oneui.ButtonOutline).Disabled(a.busy)
				oneui.MenuButton(c, newMore, func(m *oneui.Menu) {
					for _, cat := range AllCategories() {
						cat := cat
						if m.Item(CategoryDisplayName(cat)).Chosen() {
							a.newItem(cat)
						}
					}
				})
			})
		})
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		if len(a.v2.rows) == 0 {
			ui.Column(c).Fill().Grow(1).AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(2)).Children(func() {
				oneui.Icon(c, lucide.Vault()).Size(t.Space(8), t.Space(8)).TextColor(t.TextMuted)
				oneui.Text(c, "此视图没有条目").FontSize(t.Rem(.9)).TextColor(t.TextMuted)
			})
			return
		}
		a.prepareOnevraList()
		oneui.List(c, a.onevra.list, len(a.v2.rows), func(i int) {
			a.onevraListRow(c, i)
		}).Fill()
	})
}

func (a *App) prepareOnevraList() {
	list := a.onevra.list
	a.onevra.rowCursor = -1
	for i := range a.v2.rows {
		if a.v2.rows[i].ID == a.v2.selectedID {
			a.onevra.rowCursor = i
			break
		}
	}
	list.Selected = &a.onevra.rowCursor
	list.Key = func(i int) any { return a.v2.rows[i].ID }
	list.Label = func(i int) string {
		row := a.v2.rows[i]
		if row.Subtitle == "" {
			return row.Title
		}
		return row.Title + ", " + row.Subtitle
	}
	list.OnChange = a.onevraSelectRow
	list.OnSubmit = func(int) { a.onevraSelectRow() }
}

func (a *App) onevraSelectRow() {
	if a.onevra.rowCursor < 0 || a.onevra.rowCursor >= len(a.v2.rows) {
		return
	}
	row := a.v2.rows[a.onevra.rowCursor]
	a.selectItem(row.ID, row.Revision)
}

func (a *App) onevraListRow(c *ui.Context, index int) {
	if index < 0 || index >= len(a.v2.rows) {
		return
	}
	t := c.Theme()
	row := a.v2.rows[index]
	selected := row.ID == a.v2.selectedID
	ui.Row(c).Key("onevra-row:"+row.ID).FillWidth().MinWidth(0).
		Padding(t.Space(2.25), t.Space(3)).Gap(t.Space(2.25)).AlignItems(ui.Center).Children(func() {
		icon := ui.Box(c).Size(t.Space(8), t.Space(8)).Shrink(0).Radius(t.Space(2)).
			Background(t.Accent.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center)
		icon.Children(func() {
			oneui.Icon(c, onevraCategoryIcon(row.Category)).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			ui.Row(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
				oneui.Text(c, visible(row.Title)).FontSize(t.Rem(.88)).Bold().Grow(1).SingleLine().Ellipsis("…")
				if row.Favorite {
					oneui.Icon(c, lucide.Star()).Size(t.Space(3), t.Space(3)).TextColor(t.Warning)
				}
			})
			oneui.Text(c, visible(a.onevraListSubtitle(row))).FontSize(t.Rem(.74)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
		})
		if selected {
			ui.Box(c).Width(3).Height(t.Space(6)).Shrink(0).Radius(2).Background(t.Accent)
		}
	})
}

func (a *App) onevraDetailPane(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().MinWidth(0).Background(t.Background).Children(func() {
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().ScrollbarInsets(16, 0, 16).Children(func() {
			ui.Column(c).FillWidth().MinWidth(0).Padding(t.Space(5), t.Space(5), t.Space(5), t.Space(5)).Gap(t.Space(3)).Children(func() {
				switch {
				case a.v2.settingsOpen:
					a.settingsView(c)
				case a.v2.generator.open:
					a.generatorView(c)
				case a.v2.nav == navWatchtower:
					a.v2WatchtowerView(c)
				case a.v2.editing && a.v2.draft != nil:
					a.v2EditorView(c)
				default:
					a.onevraDetailView(c)
				}
			})
		})
	})
}

func (a *App) onevraDetailView(c *ui.Context) {
	t := c.Theme()
	detail := a.detailForView()
	if detail == nil {
		ui.Column(c).Fill().Grow(1).MinHeight(420).AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(2)).Children(func() {
			box := ui.Box(c).Size(t.Space(14), t.Space(14)).Radius(t.Space(4)).Background(t.Accent.Alpha(.10)).
				AlignItems(ui.Center).Justify(ui.Center)
			box.Children(func() {
				oneui.Icon(c, lucide.LockKeyhole()).Size(t.Space(6), t.Space(6)).TextColor(t.Accent)
			})
			oneui.Text(c, "选择一个条目").FontSize(t.Rem(1.35)).Bold()
			oneui.Text(c, "详情、字段操作和历史记录会显示在这里").TextColor(t.TextMuted).Wrap()
		})
		return
	}

	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
		iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
			Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
		iconBox.Children(func() {
			oneui.Icon(c, onevraCategoryIcon(detail.Category)).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, visible(detail.Title)).FontSize(t.Rem(1.35)).Bold().SingleLine().Ellipsis("…")
			oneui.Text(c, CategoryDisplayName(detail.Category)+" · "+a.onevraVaultLabel()).FontSize(t.Rem(.78)).TextColor(t.TextMuted).SingleLine()
		})
		if detail.State != "trashed" {
			if oneui.Button(c, "编辑", oneui.ButtonSecondary).Disabled(a.busy).Clicked() {
				if err := a.beginEdit(); err != nil {
					a.status = message(err)
				}
			}
		}
		if oneui.IconButton(c, lucide.FileClock(), "历史", oneui.IconButtonPlain).Disabled(a.busy || len(detail.History) == 0).Clicked() {
			a.openHistory()
		}
		moreBtn := oneui.IconButton(c, lucide.Ellipsis(), "更多操作", oneui.IconButtonPlain).Disabled(a.busy)
		oneui.MenuButton(c, moreBtn, func(m *oneui.Menu) {
			if detail.State != "trashed" {
				if m.Item("复制副本").Chosen() {
					_, _, _ = a.duplicateSelected()
				}
				if m.Item("移动到其他保险库…").Chosen() {
					a.openMoveVaultDialog(false)
				}
				if m.Item("复制到其他保险库…").Chosen() {
					a.openMoveVaultDialog(true)
				}
				m.Separator()
				if detail.State == "archived" {
					if m.Item("取消归档条目").Chosen() {
						a.unarchiveSelected()
					}
				} else {
					if m.Item("归档条目").Chosen() {
						a.archiveSelected()
					}
				}
				if m.Item("移至回收站").Chosen() {
					a.trashSelected()
				}
			} else if m.Item("恢复到金库").Chosen() {
				a.restoreSelected()
			}
		})
		if oneui.IconButton(c, lucide.X(), "关闭详情", oneui.IconButtonPlain).Clicked() {
			a.clearSelection()
		}
	})

	// 3-cell protection & boundary summary strip
	encCount, plainCount := customFieldProtectionStats(detail)
	customSummary := "无自定义字段"
	if encCount+plainCount > 0 {
		customSummary = fmt.Sprintf("%d 加密 · %d 明文", encCount, plainCount)
	}
	ui.Row(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
		cells := []struct{ label, value string }{
			{"所属保险库", a.vaultNameForID(detail.VaultID)},
			{"敏感保护", "密码默认遮蔽"},
			{"自定义字段", customSummary},
		}
		for _, cell := range cells {
			ui.Column(c).Grow(1).MinWidth(0).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
				Padding(t.Space(1.5), t.Space(2)).Gap(t.Space(.25)).Children(func() {
				oneui.Text(c, cell.label).FontSize(t.Rem(.68)).TextColor(t.TextMuted).SingleLine()
				oneui.Text(c, cell.value).FontSize(t.Rem(.78)).Bold().TextColor(t.Text).SingleLine().Ellipsis("…")
			})
		}
	})

	if detail.State == "trashed" {
		a.onevraNoticeCard(c, "条目在回收站中", "恢复后才能显示、复制或使用字段。", t.Danger)
		if a.v2.confirmPurge {
			a.onevraNoticeCard(c, "确认永久删除", "永久删除后无法恢复该条目及其任何历史修订版本。", t.Danger)
		}
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			if oneui.Button(c, "恢复到金库", oneui.ButtonPrimary).Disabled(a.busy).Clicked() {
				a.restoreSelected()
			}
			if !a.v2.confirmPurge {
				if oneui.Button(c, "永久删除", oneui.ButtonOutline).Disabled(a.busy).Clicked() {
					a.purgeSelected()
				}
			} else {
				if oneui.Button(c, "确认永久删除", oneui.ButtonSecondary).Disabled(a.busy).Clicked() {
					a.purgeSelected()
				}
				if oneui.Button(c, "取消删除", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
					a.v2.confirmPurge = false
					a.v2.editorError = ""
				}
			}
		})
		return
	}

	a.onevraFieldCard(c, detail)
	a.onevraCustomFieldsCard(c, detail)
	a.onevraAttachmentsCard(c, detail)

	if len(detail.Tags) > 0 {
		ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "标签").FontSize(t.Rem(.78)).Bold().TextColor(t.TextMuted)
			ui.Row(c).Wrap().Gap(t.Space(1)).Children(func() {
				for _, tag := range detail.Tags {
					oneui.Button(c, tag, oneui.ButtonSecondary).Label(tag)
				}
			})
		})
	}

	if len(detail.History) > 0 {
		oneui.Button(c, fmt.Sprintf("历史版本 (%d)", len(detail.History)), oneui.ButtonGhost).OnClick(a.openHistory)
		if a.v2.historyOpen {
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
				Padding(t.Space(2)).Gap(t.Space(1)).Children(func() {
				for i, entry := range detail.History {
					i, entry := i, entry
					label := entry.Action
					if label == "" {
						label = fmt.Sprintf("版本 %d", i+1)
					}
					ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
						oneui.Text(c, label).Grow(1).SingleLine().Ellipsis("…")
						if oneui.Button(c, "还原", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
							if err := a.restoreHistory(i); err != nil {
								a.status = message(err)
							}
						}
					})
				}
				if oneui.Button(c, "关闭历史", oneui.ButtonGhost).Clicked() {
					a.closeHistory()
				}
			})
		}
	}

	ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
		if oneui.Button(c, "收藏 / 取消收藏", oneui.ButtonOutline).Disabled(a.busy).Clicked() {
			a.toggleSelectedFavorite()
		}
		if oneui.Button(c, "创建副本", oneui.ButtonOutline).Disabled(a.busy).Clicked() {
			_, _, _ = a.duplicateSelected()
		}
		if detail.State == "archived" {
			if oneui.Button(c, "取消归档", oneui.ButtonOutline).Disabled(a.busy).Clicked() {
				a.unarchiveSelected()
			}
		} else if oneui.Button(c, "归档", oneui.ButtonOutline).Disabled(a.busy).Clicked() {
			a.archiveSelected()
		}
		if oneui.Button(c, "移入回收站", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
			a.trashSelected()
		}
	})
}

func (a *App) onevraAttachmentsCard(c *ui.Context, detail *personal.ItemDetail) {
	if detail == nil || len(detail.Attachments) == 0 {
		return
	}
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "加密附件").Bold().Grow(1)
			oneui.Badge(c, fmt.Sprintf("%d", len(detail.Attachments)), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
			oneui.Icon(c, lucide.Paperclip()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
		})
		for _, att := range detail.Attachments {
			att := att
			ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).
				Padding(t.Space(2), t.Space(2.5)).AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
				iconBox := ui.Box(c).Size(t.Space(8), t.Space(8)).Shrink(0).Radius(t.Space(1.75)).
					Background(t.Accent.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center)
				iconBox.Children(func() {
					oneui.Icon(c, lucide.FileLock()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
				})
				ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
					name := visible(att.FileName)
					if name == "" {
						name = "未命名附件"
					}
					oneui.Text(c, name).FontSize(t.Rem(.86)).Bold().SingleLine().Ellipsis("…")
					metaParts := []string{formatAttachmentBytes(att.Size)}
					if att.MIMEType != "" {
						metaParts = append(metaParts, visible(att.MIMEType))
					}
					if len(att.SHA256) >= 12 {
						metaParts = append(metaParts, "SHA-256 "+att.SHA256[:12]+"…")
					} else if att.SHA256 != "" {
						metaParts = append(metaParts, "SHA-256 "+att.SHA256)
					}
					oneui.Text(c, strings.Join(metaParts, " · ")).FontSize(t.Rem(.74)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
				})
				if att.Protected {
					oneui.Badge(c, "内存保护", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
				}
			})
		}
	})
}

func formatAttachmentBytes(size int64) string {
	switch {
	case size < 1024:
		return fmt.Sprintf("%d B", size)
	case size < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
}

func (a *App) onevraFieldCard(c *ui.Context, detail *personal.ItemDetail) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "登录信息").Bold().Grow(1)
			oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
		})
		for _, key := range []string{"username", "password", "otp", "notes"} {
			a.v2DetailFieldRow(c, detail, key, fieldLabel(key))
		}
	})
}

func (a *App) openMoveVaultDialog(copyMode bool) {
	a.onevra.moveCopyMode = copyMode
	target := ""
	if detail := a.detailForView(); detail != nil {
		for _, v := range a.v2.vaults {
			if v.ID != detail.VaultID {
				target = v.ID
				break
			}
		}
	}
	if target == "" && len(a.v2.vaults) > 0 {
		target = a.v2.vaults[0].ID
	}
	a.onevra.moveTargetVaultID = target
	a.onevra.moveDialogOpen = true
}

func (a *App) vaultNameForID(vaultID string) string {
	targetID := vaultID
	if targetID == "" {
		targetID = vault.DefaultVaultID
	}
	for _, v := range a.v2.vaults {
		if v.ID == targetID {
			return v.Name
		}
	}
	if targetID == vault.DefaultVaultID {
		return "Personal"
	}
	return "默认保险库"
}

func customFieldIsEncrypted(f vault.CustomField) bool {
	return f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP
}

func customFieldProtectionStats(detail *personal.ItemDetail) (encCount, plainCount int) {
	if detail == nil {
		return 0, 0
	}
	for _, s := range detail.Sections {
		for _, f := range s.Fields {
			if customFieldIsEncrypted(f) {
				encCount++
			} else {
				plainCount++
			}
		}
	}
	return encCount, plainCount
}

func (a *App) onevraCustomFieldsCard(c *ui.Context, detail *personal.ItemDetail) {
	if detail == nil {
		return
	}
	t := c.Theme()

	// 1. Dedicated 自定义字段 card with explicit 加密 vs 明文 badges
	encCount, plainCount := customFieldProtectionStats(detail)
	if encCount+plainCount > 0 {
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, "自定义字段").Bold().Grow(1)
				if encCount > 0 {
					oneui.Badge(c, fmt.Sprintf("%d 加密", encCount), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
				}
				if plainCount > 0 {
					oneui.Badge(c, fmt.Sprintf("%d 明文", plainCount), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
				}
			})
			for _, s := range detail.Sections {
				for _, f := range s.Fields {
					key := s.ID + "/" + f.ID
					label := strings.TrimSpace(f.Label)
					if label == "" {
						label = f.ID
					}
					if s.Title != "" && s.Title != "自定义字段" && s.Title != "常规" {
						label = s.Title + " · " + label
					}
					encrypted := customFieldIsEncrypted(f)
					if !encrypted {
						val := visible(f.Value)
						if val == "" {
							val = "（空）"
						}
						ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(.5)).Children(func() {
							ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
								oneui.Text(c, label).FontSize(t.Rem(.74)).Bold().TextColor(t.TextMuted).Width(110).SingleLine().Ellipsis("…")
								oneui.Badge(c, "明文", oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
								if f.Type == vault.FieldTypeText {
									ui.Spacer(c)
								} else {
									oneui.Text(c, val).FontSize(t.Rem(.86)).TextColor(t.Text).Grow(1).MinWidth(0)
								}
								if oneui.IconButton(c, lucide.Copy(), "复制 "+label, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
									a.copyField(key)
								}
							})
							if f.Type == vault.FieldTypeText && f.Value != "" {
								oneui.Text(c, visible(f.Value)).FontSize(t.Rem(.82)).Wrap()
							}
						})
					} else {
						plain := a.plainDetail()
						revealed := a.v2.revealed[key]
						value := v2FieldDisplay(detail, plain, key, revealed)
						ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(.5)).Children(func() {
							ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
								oneui.Text(c, label).FontSize(t.Rem(.74)).Bold().TextColor(t.TextMuted).Width(110).SingleLine().Ellipsis("…")
								oneui.Badge(c, "加密", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
								if f.Type == vault.FieldTypeText {
									ui.Spacer(c)
								} else {
									oneui.Text(c, visible(value)).FontSize(t.Rem(.86)).TextColor(t.Text).Grow(1).MinWidth(0)
								}
								btnLabel := "显示 " + label
								if revealed {
									btnLabel = "隐藏 " + label
								}
								if oneui.IconButton(c, onevraRevealIcon(revealed), btnLabel, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
									a.revealField(key)
								}
								if oneui.IconButton(c, lucide.Copy(), "复制 "+label, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
									a.copyField(key)
								}
							})
							if f.Type == vault.FieldTypeText && revealed {
								oneui.Text(c, visible(value)).FontSize(t.Rem(.82)).Wrap()
							}
						})
					}
				}
			}
		})
	}

	// 2. 附加信息 card (extra URLs, credit card, identity fields)
	var extra []v2DetailField
	for _, f := range v2DetailFields(detail) {
		if !strings.Contains(f.Key, "/") {
			extra = append(extra, f)
		}
	}
	if len(extra) == 0 {
		return
	}
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, "附加信息").Bold()
		for _, f := range extra {
			a.v2DetailFieldRow(c, detail, f.Key, f.Label)
		}
	})
}

// v2DetailFieldRow renders one detail row through the existing reveal/copy
// actions. Values are masked unless the user explicitly revealed that key.
func (a *App) v2DetailFieldRow(c *ui.Context, detail *personal.ItemDetail, key, label string) {
	t := c.Theme()
	plain := a.plainDetail()
	revealed := a.v2.revealed[key]
	concealed := isConcealedKey(detail, key)
	var narrow func() string
	if key == "password" {
		narrow = a.revealPasswordValue
	}
	value := v2FieldDisplayWith(detail, plain, key, revealed, narrow)
	ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(.75)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
			oneui.Text(c, label).FontSize(t.Rem(.72)).Bold().TextColor(t.TextMuted).Width(110)
			if key != "notes" {
				oneui.Text(c, visible(value)).FontSize(t.Rem(.86)).Grow(1).MinWidth(0)
			} else {
				ui.Spacer(c)
			}
			if concealed {
				buttonLabel := "显示 " + label
				if revealed {
					buttonLabel = "隐藏 " + label
				}
				if oneui.IconButton(c, onevraRevealIcon(revealed), buttonLabel, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
					a.revealField(key)
				}
			}
			if oneui.IconButton(c, lucide.Copy(), "复制 "+label, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
				a.copyField(key)
			}
			if (key == "password" || key == "otp") && oneui.IconButton(c, lucide.ScanText(), "大号显示 "+label, oneui.IconButtonCompact).Disabled(a.busy).Clicked() {
				a.showLargeType(key)
			}
		})
		if key == "notes" && (!concealed || revealed) {
			// Keep a visible note on its own line so long text remains readable.
			oneui.Text(c, visible(value)).FontSize(t.Rem(.82)).Wrap()
		}
	})
}

func (a *App) onevraStatusBar(c *ui.Context) {
	t := c.Theme()
	status := a.status
	color := t.TextMuted
	if a.mutationUnknown || a.clipboardWarning || strings.Contains(status, "未确认") || strings.Contains(status, "失败") {
		color = t.Danger
	}
	ui.Row(c).FillWidth().Height(30).Shrink(0).Padding(0, t.Space(3)).Gap(t.Space(1.5)).
		Background(t.Surface).AlignItems(ui.Center).Children(func() {
		oneui.Icon(c, lucide.LockKeyhole()).Size(t.Space(3), t.Space(3)).TextColor(t.Success)
		oneui.Text(c, status).FontSize(t.Rem(.72)).TextColor(color).Grow(1).SingleLine().Ellipsis("…")
		if a.busy {
			oneui.Text(c, "处理中").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
		}
		oneui.Text(c, quickSearchAcceleratorLabel()).FontSize(t.Rem(.68)).TextColor(t.TextMuted)
		oneui.Text(c, "快捷搜索").FontSize(t.Rem(.68)).TextColor(t.TextMuted)
	})
}

func (a *App) onevraNoticeCard(c *ui.Context, title, body string, color ui.Color) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, color.Alpha(.55)).Radius(t.Radius).Background(color.Alpha(.08)).
		Padding(t.Space(3)).Gap(t.Space(1)).Children(func() {
		oneui.Text(c, title).Bold().TextColor(color)
		oneui.Text(c, body).Wrap().TextColor(t.TextMuted)
	})
}

func (a *App) onevraVaultLabel() string {
	if a.v2.vaultID == "" || a.v2.vaultID == "all" {
		return "全部保险库"
	}
	for _, v := range a.v2.vaults {
		if v.ID == a.v2.vaultID {
			return v.Name
		}
	}
	return "保险库"
}

func (a *App) onevraNavTitle() string {
	switch a.v2.nav {
	case navFavorites:
		return "收藏"
	case navWatchtower:
		return "Watchtower"
	case navRecentlyDelete:
		return "回收站"
	case navArchive:
		return "归档"
	case navCategory:
		return CategoryDisplayName(a.v2.category)
	case navTag:
		return "# " + a.v2.tag
	default:
		if a.v2.vaultID != "" && a.v2.vaultID != "all" {
			return a.onevraVaultLabel()
		}
		return "全部条目"
	}
}

func (a *App) onevraFavoriteCount() int {
	n := 0
	for _, row := range a.v2.all {
		if row.Favorite && row.State != "trashed" {
			n++
		}
	}
	return n
}

func (a *App) onevraVaultCount() int {
	n := 0
	for _, count := range a.v2.vaultCount {
		n += count
	}
	return n
}

func (a *App) onevraListSubtitle(row personal.ItemSummary) string {
	if row.Subtitle != "" {
		return row.Subtitle
	}
	if row.PrimaryURL != "" {
		return row.PrimaryURL
	}
	if row.UpdatedAt > 0 {
		return onevraRelativeTime(time.Unix(row.UpdatedAt, 0))
	}
	return CategoryDisplayName(row.Category)
}

func onevraRelativeTime(then time.Time) string {
	d := time.Since(then)
	switch {
	case d < time.Minute:
		return "刚刚更新"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前更新", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前更新", int(d/time.Hour))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%d 天前更新", int(d/(24*time.Hour)))
	default:
		return then.Local().Format("2006-01-02")
	}
}

func onevraCategoryIcon(category vault.ItemCategory) *ui.SVG {
	switch category {
	case vault.CategoryLogin:
		return lucide.KeyRound()
	case vault.CategoryPassword:
		return lucide.Key()
	case vault.CategorySecureNote:
		return lucide.NotebookPen()
	case vault.CategoryCreditCard:
		return lucide.CreditCard()
	case vault.CategoryIdentity:
		return lucide.User()
	case vault.CategorySSHKey:
		return lucide.Terminal()
	case vault.CategoryAPICredential:
		return lucide.Braces()
	case vault.CategoryDatabase:
		return lucide.Database()
	case vault.CategoryServer:
		return lucide.Server()
	case vault.CategoryDocument:
		return lucide.FileText()
	case vault.CategoryBankAccount:
		return lucide.Landmark()
	case vault.CategoryWirelessRouter:
		return lucide.Wifi()
	case vault.CategorySoftwareLicense:
		return lucide.BadgeCheck()
	case vault.CategoryMembership:
		return lucide.IdCard()
	case vault.CategoryCryptoWallet:
		return lucide.WalletCards()
	case vault.CategoryMedicalRecord:
		return lucide.HeartPulse()
	default:
		return lucide.File()
	}
}

func onevraRevealIcon(revealed bool) *ui.SVG {
	if revealed {
		return lucide.EyeOff()
	}
	return lucide.Eye()
}
