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
		mark := ui.Box(c).Size(t.Space(6.5), t.Space(6.5)).Shrink(0).Radius(t.Space(1.75)).
			Background(t.Accent).AlignItems(ui.Center).Justify(ui.Center)
		mark.Children(func() {
			oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.AccentText)
		})
		oneui.Text(c, "Locklark").Bold().SingleLine()
		ui.Box(c).Width(1).Height(t.Space(3.5)).Background(t.Border)
		label := "本地金库"
		if a.session != nil {
			label = a.onevraVaultLabel()
		}
		oneui.Text(c, label).FontSize(t.Rem(.84)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
	})
}

// onevraIconButton wraps oneui.IconButton so callers can give a richer hover
// tooltip without registering a duplicate MyGo .Tooltip overlay on top of the
// single tooltip that oneui.IconButton already attaches.
func onevraIconButton(c *ui.Context, icon *ui.SVG, label, tip string, style oneui.IconButtonStyle) ui.Element {
	if tip == "" {
		tip = label
	}
	b := oneui.IconButton(c, icon, tip, style)
	if label != "" && label != tip {
		b.Label(label)
	}
	return b
}

// onevraHeaderActions keeps high-frequency, global actions at the trailing
// edge of the draggable title bar, ahead of the native caption buttons.
func (a *App) onevraHeaderActions(c *ui.Context) {
	if a.browser == nil && onevraIconButton(c.Key("hdr-search"), lucide.Search(), "快捷搜索", "快捷搜索 "+quickSearchAcceleratorLabel(), oneui.IconButtonPlain).Clicked() {
		a.showQuickSearch()
	}
	if a.session != nil && a.v2Mode && !classicLayoutRequested() {
		if oneui.IconButton(c.Key("hdr-generator"), lucide.Sparkles(), "密码生成器", oneui.IconButtonPlain).Clicked() {
			a.page = "vault"
			a.v2.settingsOpen = false
			if a.v2.nav == navWatchtower {
				a.v2.nav = navAllItems
			}
			if a.v2.generator.open {
				a.closeGenerator()
			} else {
				a.openGenerator("password")
			}
		}
	}
	// The classic layout keeps its own security tab. Showing the shell gear as
	// well would create two controls with the same accessible name, which the
	// native acceptance driver rejects as ambiguous.
	if !classicLayoutRequested() {
		settings := onevraIconButton(c.Key("hdr-settings"), lucide.Settings(), "安全设置", "设置", oneui.IconButtonPlain)
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
	if a.session != nil && onevraIconButton(c.Key("hdr-lock"), lucide.Lock(), "立即锁定", "立即锁定 Ctrl+L", oneui.IconButtonPlain).Clicked() {
		a.Lock()
		if a.win != nil {
			a.win.Invalidate()
		}
	}
}

// onevraVaultView composes the three-column workspace: navigation, item
// collection, and a focused detail/editor surface. Settings and Watchtower
// take over the workspace cleanly instead of squeezing into narrow panes.
func (a *App) onevraVaultView(c *ui.Context) {
	c.SetTheme(a.onevraTheme(c))
	if a.v2.largeTypeOpen {
		a.largeTypeView(c)
		return
	}
	a.drainPendingV2Reload()
	a.drainPendingAction()
	a.emitPendingToast(c)
	a.syncEditorBaseline(a.v2.draft)

	root := ui.Column(c).Key(a.generation).Fill()
	if !a.v2.settingsOpen && !a.v2.editing {
		a.onevraShortcuts(root)
	}
	root.Children(func() {
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
			if a.v2.nav == navWatchtower && !a.v2.editing && !a.v2.generator.open {
				oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().Children(func() {
					ui.Column(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Children(func() {
						ui.Column(c).FillWidth().MinWidth(0).MaxWidth(980).Padding(c.Theme().Space(6)).Gap(c.Theme().Space(4)).Children(func() {
							a.v2WatchtowerView(c)
						})
					})
				})
				return
			}
			inner := oneui.Split(c, &a.onevra.listWidth, func() {
				a.onevraListView(c)
			}, func() {
				a.onevraDetailPane(c)
			},
				oneui.SplitOptions{FirstMin: 280, SecondMin: 360, Default: onevraListDefaultWidth},
			)
			inner.Label("调整条目列表和详情宽度")
			inner.Fill()
		}, oneui.SplitOptions{FirstMin: 184, SecondMin: 620, Default: onevraSidebarDefaultWidth})
		outer.Label("调整导航和内容宽度")
		outer.Fill()
		a.onevraStatusBar(c)
		a.onevraVaultDialogs(c)
	})
	if a.quick.open {
		a.onevraQuickSearch(c)
	}
}

func (a *App) onevraVaultDialogs(c *ui.Context) {
	t := c.Theme()
	a.onevraEditorDialog(c)
	ui.Column(c.Key("dialog-new-vault")).Children(func() {
		oneui.Dialog(c, &a.v2.newVaultOpen, oneui.DialogOptions{Label: "新建子保险库"}, func(panel ui.Element) {
			panel.Width(420).Background(t.Surface).Border(1, t.Border).Radius(t.Radius*1.5).Padding(t.Space(5))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(3)).Children(func() {
					oneui.Text(c, "新建保险库").FontSize(t.Rem(1.15)).Bold()
					oneui.Text(c, "子保险库存储在同一加密 .ll 金库文件内，用于按工作、个人或项目分组管理凭据。").
						FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					oneui.TextBox(c, &a.v2.newVaultName, oneui.TextBoxOptions{}).
						Label("保险库名称").Placeholder("例如：工作基础设施、开源维护").Disabled(a.uiBusy(c))
					oneui.TextBox(c, &a.v2.newVaultDesc, oneui.TextBoxOptions{}).
						Label("备注说明（可选）").Placeholder("用途或访问边界说明").Disabled(a.uiBusy(c))
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
							a.v2.newVaultOpen = false
						}
						if oneui.Button(c, "创建保险库", oneui.ButtonPrimary).
							Disabled(a.uiBusy(c) || strings.TrimSpace(a.v2.newVaultName) == "").Clicked() {
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
			panel.Width(440).Background(t.Surface).Border(1, t.Border).Radius(t.Radius*1.5).Padding(t.Space(5))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(3)).Children(func() {
					oneui.Text(c, "跨保险库整理条目").FontSize(t.Rem(1.15)).Bold()
					mode := "move"
					if a.onevra.moveCopyMode {
						mode = "copy"
					}
					if next, changed := onevraSegmented(c, mode, [][2]string{{"move", "移动条目"}, {"copy", "复制副本"}}); changed {
						a.onevra.moveCopyMode = next == "copy"
					}
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
						oneui.Text(c, "当前只有一个默认保险库；可先在左侧新建保险库分组。").
							FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					}
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
							a.onevra.moveDialogOpen = false
						}
						actionLabel := "确认移动"
						if a.onevra.moveCopyMode {
							actionLabel = "确认复制"
						}
						if oneui.Button(c, actionLabel, oneui.ButtonPrimary).
							Disabled(a.uiBusy(c) || a.onevra.moveTargetVaultID == "").Clicked() {
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

func (a *App) onevraSidebarStateCounts() (active, archived, trashed int) {
	for _, row := range a.v2.all {
		switch row.State {
		case "archived":
			archived++
		case "trashed":
			trashed++
		default:
			active++
		}
	}
	return active, archived, trashed
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
	activeCount, archivedCount, trashedCount := a.onevraSidebarStateCounts()
	ui.Column(c).Fill().MinWidth(0).Background(onevraSidebarSurface(t)).
		Padding(t.Space(2.5)).Children(func() {
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().Children(func() {
			oneui.Sidebar(c).Children(func() {
				oneui.SidebarSection(c, "条目", func() {
					a.onevraSidebarItem(c, "全部", lucide.LayoutList(), a.v2.nav == navAllItems && a.v2.vaultID == "all", activeCount, func() { a.navigate(navAllItems) })
					a.onevraSidebarItem(c, "收藏", lucide.Star(), a.v2.nav == navFavorites, a.onevraFavoriteCount(), func() { a.navigate(navFavorites) })
					a.onevraSidebarItem(c, "归档", lucide.Archive(), a.v2.nav == navArchive, archivedCount, func() { a.navigate(navArchive) })
					a.onevraSidebarItem(c, "回收站", lucide.Trash(), a.v2.nav == navRecentlyDelete, trashedCount, func() { a.navigate(navRecentlyDelete) })
				})

				oneui.SidebarSection(c, "保险库", func() {
					if len(a.v2.vaults) > 1 {
						a.onevraSidebarItem(c, "全部保险库", lucide.Vault(), a.v2.vaultID == "all" && a.v2.nav != navAllItems, a.onevraVaultCount(), func() { a.SelectVault("all") })
					}
					for _, v := range a.v2.vaults {
						v := v
						a.onevraSidebarItem(c, v.Name, lucide.FolderKey(), a.v2.nav != navWatchtower && a.v2.vaultID == v.ID, a.v2.vaultCount[v.ID], func() { a.SelectVault(v.ID) })
					}
					a.onevraSidebarItem(c, "新建保险库", lucide.Plus(), false, 0, a.beginNewVault)
				})

				oneui.SidebarSection(c, "类别", func() {
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
						a.onevraSidebarItem(c, fmt.Sprintf("更多类别（%d）", hiddenCount), lucide.ChevronDown(), false, 0, func() {
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
							a.onevraSidebarItem(c, tag.Tag, lucide.Hash(), a.v2.nav == navTag && a.v2.tag == tag.Tag, tag.Count, func() {
								a.FilterByTag(tag.Tag)
							})
						}
					})
				}

				oneui.SidebarSection(c, "工具", func() {
					a.onevraSidebarItem(c, "Watchtower 安全体检", lucide.ShieldCheck(), a.v2.nav == navWatchtower, 0, func() { a.navigate(navWatchtower) })
					a.onevraSidebarItem(c, "SSH 与 Agent", lucide.Terminal(), false, 0, func() {
						a.openSettings()
						a.selectSettingsSection(settingsSectionSSH)
						a.ensureSSHKeysLoaded()
					})
					a.onevraSidebarItem(c, "CLI 集成", lucide.SquareTerminal(), false, len(a.cliSettings.store.Bindings), func() {
						a.openSettings()
						a.selectSettingsSection(settingsSectionCLI)
					})
					a.onevraSidebarItem(c, "导入与导出", lucide.ArrowLeftRight(), false, 0, func() {
						a.openSettings()
						a.selectSettingsSection(settingsSectionTransfer)
					})
				})
			})
		})
	})
}

func (a *App) onevraSidebarItem(c *ui.Context, label string, icon *ui.SVG, selected bool, count int, action func()) {
	t := c.Theme()
	item := oneui.SidebarItemWithSlots(c, label, selected,
		func(c *ui.Context, size float32) {
			if icon != nil {
				color := c.Theme().TextMuted
				if selected {
					color = c.Theme().Accent
				}
				oneui.Icon(c, icon).Size(size, size).TextColor(color)
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

var onevraSortOptions = []struct{ id, label string }{
	{"title", "按标题"},
	{"updated_at", "最近修改"},
	{"created_at", "最近创建"},
}

func (a *App) onevraListView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().MinWidth(0).Background(t.Surface).Children(func() {
		ui.Column(c).Padding(t.Space(3.5), t.Space(3.5), t.Space(2.5), t.Space(3.5)).Gap(t.Space(2.5)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				ui.Row(c).Grow(1).MinWidth(0).AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, a.onevraNavTitle()).FontSize(t.Rem(1.15)).Bold().SingleLine().Ellipsis("…").Shrink(1)
					oneui.Text(c, fmt.Sprintf("%d", len(a.v2.rows))).FontSize(t.Rem(.8)).TextColor(t.TextMuted)
				})
				sortBtn := onevraIconButton(c.Key("list-sort"), lucide.ArrowUpDown(), "排序", "排序方式", oneui.IconButtonPlain)
				oneui.MenuButton(c, sortBtn, func(m *oneui.Menu) {
					for _, opt := range onevraSortOptions {
						opt := opt
						if m.Item(opt.label).Checked(a.v2.sortBy == opt.id).Chosen() {
							a.SetSort(opt.id)
						}
					}
				})
				addBtn := oneui.Button(c.Key("list-add"), "＋ 新建", oneui.ButtonPrimary).Label("新建条目").Disabled(a.uiBusy(c) || a.v2.editing)
				oneui.MenuButton(c, addBtn, func(m *oneui.Menu) {
					if m.Item(CategoryDisplayName(vault.CategoryLogin)).Shortcut("Ctrl+N").Chosen() {
						a.newItem(vault.CategoryLogin)
					}
					m.Separator()
					for _, cat := range AllCategories() {
						if cat == vault.CategoryLogin {
							continue
						}
						cat := cat
						if m.Item(CategoryDisplayName(cat)).Chosen() {
							a.newItem(cat)
						}
					}
				})
			})
			search := oneui.TextBox(c, &a.query, oneui.TextBoxOptions{
				LeadingIcon: lucide.Search(),
			}).Label("搜索").Placeholder("搜索标题、用户名或网址")
			search.FillWidth()
			if search.Changed() {
				a.SetSearchQuery(a.query)
			}
			if a.v2.searchError != "" {
				oneui.Text(c, a.v2.searchError).FontSize(t.Rem(.75)).TextColor(t.Danger).Wrap()
			}
		})
		if len(a.v2.rows) == 0 {
			a.onevraEmptyList(c)
			return
		}
		a.prepareOnevraList()
		oneui.List(c, a.onevra.list, len(a.v2.rows), func(i int) {
			a.onevraListRow(c, i)
		}).Fill()
	})
}

func (a *App) onevraEmptyList(c *ui.Context) {
	title, body, icon := "此视图没有条目", "点击右上角「新建条目」，或从 1Password 导入。", lucide.Vault()
	switch {
	case strings.TrimSpace(a.query) != "":
		title, body, icon = "没有匹配的条目", "试试更短的关键词，或清除搜索。", lucide.SearchX()
	case a.v2.nav == navFavorites:
		title, body, icon = "还没有收藏", "在条目上点星标，就会出现在这里。", lucide.Star()
	case a.v2.nav == navArchive:
		title, body, icon = "没有归档的条目", "归档的条目不会出现在搜索和自动填充中。", lucide.Archive()
	case a.v2.nav == navRecentlyDelete:
		title, body, icon = "回收站是空的", "移入回收站的条目会保留在这里，直到永久删除。", lucide.Trash()
	}
	onevraEmpty(c, icon, title, body, func() {
		switch {
		case strings.TrimSpace(a.query) != "":
			if oneui.Button(c, "清除搜索", oneui.ButtonOutline).Clicked() {
				a.query = ""
				a.SetSearchQuery("")
			}
		case a.v2.nav == navAllItems || a.v2.nav == navCategory:
			if oneui.Button(c, "新建登录", oneui.ButtonPrimary).Disabled(a.uiBusy(c) || a.v2.editing).Clicked() {
				cat := vault.CategoryLogin
				if a.v2.nav == navCategory && a.v2.category != "" {
					cat = a.v2.category
				}
				a.newItem(cat)
			}
		}
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
	if a.v2.editing && a.onevraDraftDirty() && row.ID != a.v2.selectedID {
		a.status = "请先保存或取消当前编辑"
		return
	}
	a.selectItem(row.ID, row.Revision)
}

func onevraStarIcon(filled bool) *ui.SVG {
	if filled {
		return onevraStarFilled()
	}
	return lucide.Star()
}

func (a *App) onevraListRow(c *ui.Context, index int) {
	if index < 0 || index >= len(a.v2.rows) {
		return
	}
	t := c.Theme()
	row := a.v2.rows[index]
	selected := row.ID == a.v2.selectedID
	padY := t.Space(2)
	if a.compactDensity() {
		padY = t.Space(1.25)
	}
	el := ui.Row(c).Key("onevra-row:"+row.ID).FillWidth().MinWidth(0).
		Padding(padY, t.Space(2.5)).Gap(t.Space(2.5)).AlignItems(ui.Center)
	hovered := el.Hovered()
	el.Children(func() {
		a.onevraItemAvatar(c, row.Title, row.Category, row.CustomIcon, t.Space(8))
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
			oneui.Text(c, visible(row.Title)).FontSize(t.Rem(.9)).Bold().SingleLine().Ellipsis("…")
			oneui.Text(c, visible(a.onevraListSubtitle(row))).FontSize(t.Rem(.76)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
		})
		if row.State != "trashed" && (row.Favorite || hovered || selected) {
			label := "加入收藏"
			if row.Favorite {
				label = "取消收藏"
			}
			star := oneui.IconButton(c.Key("star:"+row.ID), onevraStarIcon(row.Favorite), label, oneui.IconButtonCompact).Disabled(a.uiBusy(c))
			if row.Favorite {
				star.TextColor(t.Warning)
			}
			if star.Clicked() {
				a.toggleFavoriteRow(row)
			}
		}
	})
	oneui.ContextMenu(c, el, func(m *oneui.Menu) { a.onevraItemMenu(c, m, row) })
}

func (a *App) onevraDetailPane(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().MinWidth(0).Background(t.Background).Children(func() {
		showStandaloneGen := a.v2.generator.open && !a.v2.editing
		if !showStandaloneGen && a.detailForView() == nil {
			a.onevraDetailView(c)
			return
		}
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().ScrollbarInsets(16, 0, 16).Children(func() {
			ui.Column(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Children(func() {
				ui.Column(c).FillWidth().MinWidth(0).MaxWidth(860).Padding(t.Space(5), t.Space(6), t.Space(6), t.Space(6)).Gap(t.Space(4)).Children(func() {
					if showStandaloneGen {
						a.generatorView(c)
						return
					}
					a.onevraDetailView(c)
				})
			})
		})
	})
}

func (a *App) onevraDetailView(c *ui.Context) {
	t := c.Theme()
	detail := a.detailForView()
	if detail == nil {
		onevraEmpty(c, lucide.LockKeyhole(), "选择一个条目", "点击字段即可复制；右键条目可查看更多操作", func() {
			ui.Row(c).Wrap().Justify(ui.Center).Gap(t.Space(2)).Children(func() {
				if oneui.Button(c, "新建登录", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).Clicked() {
					a.newItem(vault.CategoryLogin)
				}
				if oneui.Button(c, "密码生成器", oneui.ButtonOutline).Clicked() {
					a.openGenerator("password")
				}
			})
			ui.Row(c).Wrap().Justify(ui.Center).AlignItems(ui.Center).Gap(t.Space(1.5)).Padding(t.Space(2), 0, 0, 0).Children(func() {
				onevraKeyCap(c, "Ctrl+K")
				oneui.Text(c, "快捷搜索").FontSize(t.Rem(.74)).TextColor(t.TextMuted)
				onevraKeyCap(c, "Ctrl+N")
				oneui.Text(c, "新建").FontSize(t.Rem(.74)).TextColor(t.TextMuted)
				onevraKeyCap(c, "Ctrl+L")
				oneui.Text(c, "锁定").FontSize(t.Rem(.74)).TextColor(t.TextMuted)
			})
		})
		return
	}
	row, _ := a.selectedSummary()

	// Header: identity on the left, high-frequency actions on the right.
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
		a.onevraItemAvatar(c, detail.Title, detail.Category, ExtractCustomIcon(detail.Sections), t.Space(12))
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, visible(detail.Title)).FontSize(t.Rem(1.4)).Bold().Selectable().SingleLine().Ellipsis("…")
			oneui.Text(c, CategoryDisplayName(detail.Category)+" · "+a.vaultNameForID(detail.VaultID)).FontSize(t.Rem(.8)).TextColor(t.TextMuted).SingleLine()
		})
		if detail.State != "trashed" {
			label := "加入收藏"
			if detail.Favorite {
				label = "取消收藏"
			}
			star := onevraIconButton(c.Key("detail-star"), onevraStarIcon(detail.Favorite), label, label+" Ctrl+D", oneui.IconButtonPlain).Disabled(a.uiBusy(c))
			if detail.Favorite {
				star.TextColor(t.Warning)
			}
			if star.Clicked() {
				a.toggleFavoriteRow(row)
			}
			editBtn := oneui.Button(c.Key("detail-edit"), "编辑", oneui.ButtonSecondary).Disabled(a.uiBusy(c))
			oneui.Tooltip(c, editBtn, "编辑 Ctrl+E")
			if editBtn.Clicked() {
				if err := a.beginEdit(); err != nil {
					a.status = message(err)
				}
			}
		}
		more := oneui.IconButton(c.Key("detail-more"), lucide.Ellipsis(), "更多操作", oneui.IconButtonPlain).Disabled(a.uiBusy(c))
		oneui.MenuButton(c, more, func(m *oneui.Menu) {
			if detail.State != "trashed" {
				if itemHasSecretLogin(row) && m.Item("大号显示 密码").Chosen() {
					a.showLargeType("password")
				}
				if (row.HasOTP || detail.OTP != "") && m.Item("大号显示 一次性验证码").Chosen() {
					a.showLargeType("otp")
				}
				if len(detail.History) > 0 && m.Item(fmt.Sprintf("历史版本（%d）", len(detail.History))).Chosen() {
					a.openHistory()
				}
				m.Separator()
			}
			a.onevraItemMenu(c, m, row)
		})
		if oneui.IconButton(c.Key("detail-close"), lucide.X(), "关闭详情", oneui.IconButtonPlain).Clicked() {
			a.clearSelection()
		}
	})

	switch detail.State {
	case "trashed":
		onevraBanner(c, lucide.Trash(), "在回收站中：恢复后才能查看、复制或使用字段。", t.Danger, func() {
			if oneui.Button(c, "恢复到金库", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).Clicked() {
				a.moveItemState(row, "item.untrash")
			}
			if !a.v2.confirmPurge {
				if oneui.Button(c, "永久删除", oneui.ButtonOutline).Disabled(a.uiBusy(c)).Clicked() {
					a.purgeSelected()
				}
			}
		})
		if a.v2.confirmPurge {
			onevraBanner(c, lucide.TriangleAlert(), "确认永久删除：该条目及其所有历史版本将无法恢复。", t.Danger, func() {
				if oneui.Button(c, "确认永久删除", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).Clicked() {
					a.purgeSelected()
				}
				if oneui.Button(c, "取消删除", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
					a.v2.confirmPurge = false
					a.v2.editorError = ""
				}
			})
		}
		return
	case "archived":
		onevraBanner(c, lucide.Archive(), "已归档：不会出现在搜索、快捷搜索和自动填充中。", t.TextMuted, func() {
			if oneui.Button(c, "取消归档", oneui.ButtonOutline).Disabled(a.uiBusy(c)).Clicked() {
				a.moveItemState(row, "item.unarchive")
			}
		})
	}

	for _, group := range a.onevraDetailGroups(detail, row) {
		a.onevraFieldGroup(c, detail, group)
	}
	a.onevraAttachmentsCard(c, detail)

	if len(detail.Tags) > 0 {
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			for _, tag := range detail.Tags {
				tag := tag
				chip := ui.Row(c.Key("tag:"+tag)).AlignItems(ui.Center).Gap(t.Space(1)).Padding(t.Space(.75), t.Space(2.5)).
					Radius(t.Space(4)).Border(1, t.Border).Background(t.Surface).Cursor(ui.CursorPointer).
					Role(ui.RoleButton).Label("筛选标签 "+tag).Focusable()
				if chip.Hovered() {
					chip.Background(t.Text.Alpha(.05))
				}
				chip.Children(func() {
					oneui.Icon(c, lucide.Hash()).Size(t.Space(3), t.Space(3)).TextColor(t.TextMuted)
					oneui.Text(c, visible(tag)).FontSize(t.Rem(.8))
				})
				if chip.Clicked() {
					a.FilterByTag(tag)
				}
			}
		})
	}

	// Metadata footer and expandable history drawer.
	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
		if detail.UpdatedAt > 0 {
			oneui.Text(c, "修改于 "+onevraTimeLabel(detail.UpdatedAt)).FontSize(t.Rem(.76)).TextColor(t.TextMuted)
		}
		if detail.CreatedAt > 0 {
			oneui.Text(c, "创建于 "+time.Unix(detail.CreatedAt, 0).Local().Format("2006-01-02")).FontSize(t.Rem(.76)).TextColor(t.TextMuted)
		}
		if len(detail.History) > 0 {
			label := fmt.Sprintf("历史版本 (%d)", len(detail.History))
			if oneui.Button(c, label, oneui.ButtonGhost).Clicked() {
				if a.v2.historyOpen {
					a.closeHistory()
				} else {
					a.openHistory()
				}
			}
		}
	})
	if a.v2.historyOpen && len(detail.History) > 0 {
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius*1.25).Background(t.Surface).Children(func() {
			for i, entry := range detail.History {
				i, entry := i, entry
				if i > 0 {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				ui.Row(c).FillWidth().AlignItems(ui.Center).Padding(t.Space(2), t.Space(3)).Gap(t.Space(2)).Children(func() {
					oneui.Icon(c, lucide.RotateCcwClock()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
					label := entry.Action
					if label == "" {
						label = fmt.Sprintf("版本 %d", i+1)
					}
					oneui.Text(c, label).Grow(1).SingleLine().Ellipsis("…")
					if oneui.Button(c, "还原", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
						if err := a.restoreHistory(i); err != nil {
							a.status = message(err)
						}
					}
				})
			}
		})
	}
}

type detailFieldSpec struct {
	key, label string
	concealed  bool
	url        bool
	multiline  bool
	isCustom   bool
}

type detailGroup struct {
	title  string
	fields []detailFieldSpec
}

// onevraDetailGroups groups item fields as a document: primary credentials,
// websites, typed card/identity records, custom sections and notes. Empty plain
// fields are omitted; concealed fields remain because a masked read cannot prove
// absence.
func (a *App) onevraDetailGroups(detail *personal.ItemDetail, row personal.ItemSummary) []detailGroup {
	present := func(key string) bool {
		v, ok := fieldValue(detail, key)
		return ok && strings.TrimSpace(v) != ""
	}
	var groups []detailGroup
	var primary []detailFieldSpec
	if present("username") {
		primary = append(primary, detailFieldSpec{key: "username", label: fieldLabel("username")})
	}
	if itemHasSecretLogin(row) {
		primary = append(primary, detailFieldSpec{key: "password", label: fieldLabel("password"), concealed: true})
	}
	if row.HasOTP || present("otp") {
		primary = append(primary, detailFieldSpec{key: "otp", label: fieldLabel("otp"), concealed: true})
	}
	if len(primary) > 0 {
		groups = append(groups, detailGroup{fields: primary})
	}
	urlList := detailURLs(*detail)
	var urls []detailFieldSpec
	for i, u := range urlList {
		label := u.Label
		if label == "" {
			label = "网站"
		}
		if u.Primary && (len(urlList) > 1 || u.Label != "") {
			label += "（主）"
		}
		urls = append(urls, detailFieldSpec{key: fmt.Sprintf("url:%d", i), label: label, url: true})
	}
	if len(urls) > 0 {
		groups = append(groups, detailGroup{title: "网站", fields: urls})
	}
	addTyped := func(title string, alwaysConcealed bool, entries []struct {
		key, label string
		isURL      bool
	}) {
		var fields []detailFieldSpec
		for _, f := range entries {
			concealed := isConcealedKey(detail, f.key)
			if (alwaysConcealed && concealed) || present(f.key) {
				fields = append(fields, detailFieldSpec{key: f.key, label: f.label, concealed: concealed, url: f.isURL})
			}
		}
		if len(fields) > 0 {
			groups = append(groups, detailGroup{title: title, fields: fields})
		}
	}
	if detail.CreditCard != nil {
		addTyped("卡片信息", true, []struct {
			key, label string
			isURL      bool
		}{
			{key: "credit_card.name", label: "持卡人姓名"},
			{key: "credit_card.type", label: "卡组织 / 类型"},
			{key: "credit_card.number", label: "卡号"},
			{key: "credit_card.verification", label: "安全码 (CVV/CVC)"},
			{key: "credit_card.expiry", label: "有效期"},
			{key: "credit_card.valid_from", label: "生效日期"},
			{key: "credit_card.issuing_bank", label: "发卡银行"},
			{key: "credit_card.pin", label: "取现 / 交易 PIN"},
		})
	}
	if detail.Identity != nil {
		addTyped("基本信息", false, []struct {
			key, label string
			isURL      bool
		}{
			{key: "identity.last_name", label: "姓"},
			{key: "identity.first_name", label: "名"},
			{key: "identity.middle_name", label: "中间名"},
			{key: "identity.birth_date", label: "出生日期"},
			{key: "identity.company", label: "公司 / 单位"},
			{key: "identity.department", label: "部门"},
			{key: "identity.job_title", label: "职位"},
		})
		addTyped("证件信息", false, []struct {
			key, label string
			isURL      bool
		}{
			{key: "identity.ssn", label: "身份证 / 证件号"},
			{key: "identity.passport_number", label: "护照号"},
			{key: "identity.license_number", label: "驾驶证号"},
		})
		addTyped("联系方式与地址", false, []struct {
			key, label string
			isURL      bool
		}{
			{key: "identity.email", label: "电子邮箱"},
			{key: "identity.phone", label: "手机 / 电话"},
			{key: "identity.country", label: "国家 / 地区"},
			{key: "identity.state", label: "省 / 直辖市 / 州"},
			{key: "identity.city", label: "城市"},
			{key: "identity.address_line1", label: "街道地址"},
			{key: "identity.address_line2", label: "详细地址（楼栋/门牌）"},
			{key: "identity.postal_code", label: "邮政编码"},
			{key: "identity.website", label: "个人网站", isURL: true},
		})
	}
	for _, s := range detail.Sections {
		if IsInternalMetaSection(s) {
			continue
		}
		var fields []detailFieldSpec
		for _, f := range s.Fields {
			if isCanonicalDetailDuplicate(detail, s.ID, f) {
				continue
			}
			key := s.ID + "/" + f.ID
			concealed := customFieldIsEncrypted(f) || isConcealedKey(detail, key)
			if !concealed && !present(key) {
				continue
			}
			label := localizedFieldLabel(s.ID, f.ID, f.Label)
			fields = append(fields, detailFieldSpec{
				key:       key,
				label:     label,
				concealed: concealed,
				url:       f.Type == vault.FieldTypeURL,
				multiline: f.Type == vault.FieldTypeText,
				isCustom:  true,
			})
		}
		if len(fields) > 0 {
			secTitle := localizedSectionTitle(s.Title)
			if strings.TrimSpace(secTitle) == "" {
				secTitle = "自定义字段"
			}
			groups = append(groups, detailGroup{title: secTitle, fields: fields})
		}
	}
	if strings.TrimSpace(detail.Notes) != "" {
		notesTitle := "备注"
		if detail.Category == vault.CategorySecureNote {
			notesTitle = "笔记内容"
		}
		groups = append(groups, detailGroup{title: notesTitle, fields: []detailFieldSpec{{key: "notes", label: notesTitle, concealed: true, multiline: true}}})
	}
	return groups
}

func isCanonicalDetailDuplicate(detail *personal.ItemDetail, sectionID string, f vault.CustomField) bool {
	if detail == nil {
		return false
	}
	if detail.CreditCard != nil {
		tmp := ItemDraft{Category: vault.CategoryCreditCard}
		if _, ok := v2DraftCanonicalField(&tmp, sectionID, f); ok {
			return true
		}
	}
	if detail.Identity != nil {
		tmp := ItemDraft{Category: vault.CategoryIdentity}
		if _, ok := v2DraftCanonicalField(&tmp, sectionID, f); ok {
			return true
		}
	}
	return false
}

var legacySectionTitleMap = map[string]string{
	"card details":       "卡片信息",
	"additional details": "发卡与限额",
	"identification":     "基本信息",
	"contact":            "联系方式与地址",
	"document":           "文档",
	"ssh key":            "SSH 密钥信息",
	"api credential":     "API 凭据",
	"database":           "数据库连接",
	"server":             "服务器访问",
	"admin console":      "管理控制台",
	"hosting provider":   "托管服务商",
	"wireless router":    "无线路由器",
	"license":            "许可证",
	"publisher":          "发行商",
	"order":              "订单",
	"bank account":       "银行账户",
	"branch information": "支行信息",
	"crypto wallet":      "加密钱包",
	"medical record":     "医疗记录",
	"membership":         "会员信息",
}

func localizedSectionTitle(title string) string {
	trimmed := strings.TrimSpace(title)
	if trimmed == "" {
		return ""
	}
	if zh, ok := legacySectionTitleMap[strings.ToLower(trimmed)]; ok {
		return zh
	}
	return trimmed
}

var legacyFieldLabelMap = map[string]string{
	"cardholder name":           "持卡人姓名",
	"verification number":       "安全码 (CVV/CVC)",
	"expiry date":               "有效期",
	"valid from":                "生效日期",
	"issuing bank":              "发卡银行",
	"credit limit":              "信用额度",
	"first name":                "名",
	"middle name":               "中间名",
	"last name":                 "姓",
	"birth date":                "出生日期",
	"department":                "部门",
	"job title":                 "职位",
	"email":                     "电子邮箱",
	"address":                   "地址",
	"city":                      "城市",
	"state":                     "省 / 直辖市 / 州",
	"postal code":               "邮政编码",
	"country":                   "国家 / 地区",
	"private key":               "私钥",
	"public key":                "公钥",
	"fingerprint":               "指纹",
	"key type":                  "密钥类型",
	"passphrase":                "私钥口令",
	"credential":                "密钥 / Token",
	"hostname / url":            "服务端点 / URL",
	"expires":                   "过期日期",
	"server":                    "主机 / 地址",
	"port":                      "端口",
	"database":                  "数据库名",
	"sid":                       "实例 / SID",
	"connection options":        "连接参数 / URI",
	"url":                       "服务器地址",
	"admin console url":         "控制台网址",
	"admin console username":    "管理员账号",
	"admin console password":    "管理员密码",
	"support url":               "技术支持网址",
	"support phone":             "客服电话",
	"base station name":         "路由器 / 基站名称",
	"base station password":     "管理后台密码",
	"server / ip address":       "管理后台 IP / 地址",
	"network name (ssid)":       "网络名称 (SSID)",
	"wireless security":         "加密安全类型",
	"wireless network password": "Wi-Fi 密码",
	"version":                   "软件版本",
	"license key":               "激活码 / 序列号",
	"licensed to":               "授权对象",
	"registered email":          "注册邮箱",
	"download page":             "下载地址",
	"publisher":                 "发行商",
	"retail price":              "零售价",
	"order number":              "订单号",
	"purchase date":             "购买日期",
	"order total":               "订单金额",
	"bank name":                 "开户银行",
	"name on account":           "开户人姓名",
	"routing number":            "联行号 / Routing",
	"account number":            "银行账号 / 卡号",
	"branch phone":              "支行 / 客服电话",
	"branch address":            "开户支行地址",
	"wallet type":               "钱包类型",
	"network":                   "主网 / 网络",
	"seed phrase":               "助记词 (Seed Phrase)",
	"patient name":              "姓名",
	"blood type":                "血型",
	"allergies":                 "过敏史",
	"medications":               "当前用药",
	"conditions":                "病史 / 诊断",
	"doctor":                    "主治医生 / 医院",
	"insurance provider":        "医保 / 保险机构",
	"policy number":             "医保 / 保单号",
	"organization":              "机构 / 品牌",
	"member name":               "会员姓名",
	"member since":              "入会年月",
	"membership number":         "会员卡号 / ID",
	"file":                      "文件",
}

func localizedFieldLabel(sectionID, fieldID, rawLabel string) string {
	trimmed := strings.TrimSpace(rawLabel)
	if trimmed == "" {
		return fieldID
	}
	lower := strings.ToLower(trimmed)
	sec := strings.ToLower(strings.TrimSpace(sectionID))
	fid := strings.ToLower(strings.TrimSpace(fieldID))
	switch lower {
	case "username":
		if sec == "api" {
			return "用户名 / Access Key ID"
		}
		return "用户名"
	case "password":
		switch sec {
		case "router":
			return "管理后台密码"
		case "wallet":
			return "钱包密码"
		default:
			return "密码"
		}
	case "type":
		switch {
		case sec == "card":
			return "卡组织 / 类型"
		case sec == "api":
			return "凭证类型"
		case sec == "database" || fid == "database_type":
			return "数据库类型"
		case sec == "bank":
			return "账户类型"
		default:
			return "类型"
		}
	case "company":
		if sec == "identification" {
			return "公司 / 单位"
		}
		return "所属公司"
	case "name":
		switch sec {
		case "hosting":
			return "服务商名称"
		case "router":
			return "路由器 / 基站名称"
		default:
			return "名称"
		}
	case "website":
		switch sec {
		case "hosting":
			return "服务商官网"
		case "contact":
			return "个人网站"
		default:
			return "官方网站"
		}
	case "phone":
		switch sec {
		case "membership":
			return "客服电话"
		case "contact":
			return "手机 / 电话"
		default:
			return "联系电话"
		}
	}
	if zh, ok := legacyFieldLabelMap[lower]; ok {
		return zh
	}
	return trimmed
}

func (a *App) onevraFieldGroup(c *ui.Context, detail *personal.ItemDetail, group detailGroup) {
	onevraGroup(c, visible(group.title), func(row func(func())) {
		for _, f := range group.fields {
			f := f
			row(func() { a.v2DetailFieldRow(c, detail, f) })
		}
	})
}

// v2DetailFieldRow renders one detail field. Clicking the value copies it
// through the audited clipboard path; reveal and large type remain explicit
// actions. Inline copy countdown and default-password disclosure preserve all
// runtime security invariants.
func (a *App) v2DetailFieldRow(c *ui.Context, detail *personal.ItemDetail, f detailFieldSpec) {
	t := c.Theme()
	now := time.Now()
	key, label := f.key, f.label
	plain := a.plainDetail()
	revealed := a.v2.revealed[key]
	concealed := f.concealed || isConcealedKey(detail, key)
	var narrow func() string
	if key == "password" {
		narrow = a.revealPasswordValue
	}
	narrowRevealed := key == "password" && narrow != nil && narrow() != ""
	shown := revealed || narrowRevealed
	value := v2FieldDisplayWith(detail, plain, key, revealed, narrow)
	left, frac, copied := a.copiedRemaining(detail.ID, key, now)

	row := ui.Column(c.Key("field:"+key)).FillWidth().MinWidth(0)
	hovered := row.Hovered()
	if hovered {
		row.Background(t.Text.Alpha(.03))
	}
	row.Children(func() {
		ui.Row(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
			area := ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Cursor(ui.CursorPointer)
			area.Children(func() {
				ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					switch {
					case copied:
						text := "✓ 已复制"
						if a.clipboardTimeout() > 0 {
							text = fmt.Sprintf("✓ 已复制 · 剪贴板 %d 秒后清除", int(left.Seconds()+.99))
						}
						oneui.Text(c, text).FontSize(t.Rem(.74)).TextColor(t.Success).SingleLine()
					case revealed && !a.v2.revealUntil.IsZero():
						secs := int(a.v2.revealUntil.Sub(now).Seconds() + .99)
						oneui.Text(c, fmt.Sprintf("%s · %d 秒后隐藏", label, secs)).FontSize(t.Rem(.74)).TextColor(t.TextMuted).SingleLine()
					default:
						oneui.Text(c, label).FontSize(t.Rem(.74)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
					}
					if f.isCustom {
						if concealed {
							onevraPill(c, "加密", t.Accent)
						} else {
							onevraPill(c, "明文", t.TextMuted)
						}
					}
				})
				switch {
				case concealed && !shown:
					oneui.Text(c, v2MaskedValue).Font(onevraMonoFont).FontSize(t.Rem(.92)).TextColor(t.TextMuted).SingleLine()
				case concealed && f.multiline:
					oneui.Text(c, visible(value)).FontSize(t.Rem(.9)).Wrap()
				case concealed:
					onevraSecretText(c, visible(value))
				case f.url:
					oneui.Text(c, visible(value)).FontSize(t.Rem(.92)).TextColor(t.Accent).SingleLine().Ellipsis("…")
				case f.multiline:
					oneui.Text(c, visible(value)).FontSize(t.Rem(.92)).Wrap()
				default:
					oneui.Text(c, visible(value)).FontSize(t.Rem(.92)).SingleLine().Ellipsis("…")
				}
			})
			if area.Clicked() && !a.busy {
				a.copyField(key)
			}
			opacity := float32(0)
			if hovered || shown || copied || key == "password" || key == "otp" {
				opacity = 1
			}
			ui.Row(c).Shrink(0).AlignItems(ui.Center).Gap(t.Space(.5)).Opacity(opacity).Children(func() {
				if concealed {
					buttonLabel := "显示 " + label
					if revealed {
						buttonLabel = "隐藏 " + label
					}
					if oneui.IconButton(c, onevraRevealIcon(revealed), buttonLabel, oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
						a.revealField(key)
					}
				}
				if f.url {
					if u, ok := fieldValue(detail, key); ok && u != "" {
						if oneui.IconButton(c, lucide.ExternalLink(), "打开 "+label, oneui.IconButtonCompact).Clicked() {
							c.OpenURL(u)
						}
					}
				}
				copyIcon := lucide.Copy()
				if copied {
					copyIcon = lucide.Check()
				}
				if oneui.IconButton(c, copyIcon, "复制 "+label, oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
					a.copyField(key)
				}
				if (key == "password" || key == "otp") && oneui.IconButton(c, lucide.ScanText(), "大号显示 "+label, oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
					a.showLargeType(key)
				}
			})
		})
		if copied {
			ui.Row(c).FillWidth().Height(2).Margin(t.Space(1), 0, 0, 0).Children(func() {
				ui.Box(c).Grow(frac).Height(2).Background(t.Success)
				ui.Box(c).Grow(1 - frac).Height(2)
			})
		}
	})
}

func (a *App) onevraAttachmentsCard(c *ui.Context, detail *personal.ItemDetail) {
	if detail == nil || len(detail.Attachments) == 0 {
		return
	}
	t := c.Theme()
	onevraGroup(c, fmt.Sprintf("加密附件 · %d", len(detail.Attachments)), func(row func(func())) {
		for _, att := range detail.Attachments {
			att := att
			row(func() {
				oneui.Icon(c, lucide.FileLock()).Size(t.Space(4.5), t.Space(4.5)).TextColor(t.Accent)
				ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
					name := visible(att.FileName)
					if name == "" {
						name = "未命名附件"
					}
					oneui.Text(c, name).FontSize(t.Rem(.88)).SingleLine().Ellipsis("…")
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
					onevraPill(c, "内存保护", t.Accent)
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

func (a *App) onevraStatusBar(c *ui.Context) {
	t := c.Theme()
	uiBusy := a.uiBusy(c)
	if !a.busy || uiBusy || a.status != "处理中…" {
		a.steadyStatus = a.status
	}
	status := a.status
	if a.busy && !uiBusy && status == "处理中…" && a.steadyStatus != "" {
		status = a.steadyStatus
	}
	color := t.TextMuted
	if a.mutationUnknown || a.clipboardWarning || strings.Contains(status, "未确认") || strings.Contains(status, "失败") {
		color = t.Danger
	}
	now := time.Now()
	ui.Box(c).FillWidth().Height(1).Background(t.Border)
	ui.Row(c).FillWidth().Height(28).Shrink(0).Padding(0, t.Space(3)).Gap(t.Space(2)).
		Background(onevraSidebarSurface(t)).AlignItems(ui.Center).Children(func() {
		oneui.Icon(c, lucide.LockKeyholeOpen()).Size(t.Space(3), t.Space(3)).TextColor(t.Success)
		oneui.Text(c, status).FontSize(t.Rem(.72)).TextColor(color).Grow(1).SingleLine().Ellipsis("…")
		if uiBusy {
			oneui.Text(c, "处理中").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
		}
		if left, _, ok := a.copiedRemaining(a.onevra.copiedItem, a.onevra.copiedKey, now); ok && a.clipboardTimeout() > 0 {
			oneui.Text(c, fmt.Sprintf("剪贴板 %d 秒后清除", int(left.Seconds()+.99))).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
		}
		if idle := a.idleTimeout(); idle > 0 && !a.lastActivity.IsZero() && a.session != nil {
			left := idle - now.Sub(a.lastActivity)
			if left < 0 {
				left = 0
			}
			secs := int(left.Seconds())
			oneui.Text(c, fmt.Sprintf("%d:%02d 后自动锁定", secs/60, secs%60)).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
		}
		oneui.Text(c, quickSearchAcceleratorLabel()+" 快捷搜索").FontSize(t.Rem(.68)).TextColor(t.TextMuted)
	})
}

func (a *App) onevraNoticeCard(c *ui.Context, title, body string, color ui.Color) {
	t := c.Theme()
	ui.Column(c).FillWidth().Radius(t.Radius).Background(color.Alpha(.08)).
		Padding(t.Space(3)).Gap(t.Space(1)).Children(func() {
		oneui.Text(c, title).Bold().TextColor(color)
		oneui.Text(c, body).Wrap().TextColor(t.TextMuted)
	})
}

func (a *App) onevraVaultLabel() string {
	if a.v2.vaultID == "" || a.v2.vaultID == "all" {
		if len(a.v2.vaults) == 1 {
			return a.v2.vaults[0].Name
		}
		return "全部保险库"
	}
	return a.vaultNameForID(a.v2.vaultID)
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

func onevraTimeLabel(unix int64) string {
	return strings.TrimSuffix(onevraRelativeTime(time.Unix(unix, 0)), "更新")
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
