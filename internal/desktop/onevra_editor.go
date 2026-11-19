package desktop

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	pwgen "github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// onevraEditorState tracks presentation-only dirty-detection and drag-reorder
// state for the active draft. The draft itself remains owned by v2State and
// cleared on Lock.
type onevraEditorState struct {
	draftRef       *ItemDraft
	draftSig       [32]byte
	confirmDiscard bool
	dragging       bool
	dragSec        int
	dragField      int
	dragOverField  int
	dragStartRect  ui.Rect
	dragStartPtrX  float32
	dragStartPtrY  float32
	dragHasPtr     bool
	dragOffsetX    float32
	dragOffsetY    float32
	rowBounds      map[string]ui.Rect
}

func (e *onevraEditorState) clearDrag() {
	e.dragging = false
	e.dragSec = -1
	e.dragField = -1
	e.dragOverField = -1
	e.dragStartRect = ui.Rect{}
	e.dragStartPtrX = 0
	e.dragStartPtrY = 0
	e.dragHasPtr = false
	e.dragOffsetX = 0
	e.dragOffsetY = 0
}

func (e *onevraEditorState) setRowBound(key string, r ui.Rect) {
	if e.rowBounds == nil {
		e.rowBounds = map[string]ui.Rect{}
	}
	e.rowBounds[key] = r
}

func (e *onevraEditorState) rowHeight(key string) float32 {
	if r, ok := e.rowBounds[key]; ok && r.H > 0 {
		return r.H
	}
	return 52
}

// draftSignature fingerprints the persisted portion of a draft so the editor
// can warn before discarding unsaved edits. Only the SHA-256 hash is kept; the
// temporary serialization buffer is wiped immediately.
func draftSignature(d *ItemDraft) [32]byte {
	if d == nil {
		return [32]byte{}
	}
	persisted := *d
	persisted.NewTag = ""
	persisted.NewSectionTitle = ""
	persisted.NewFieldLabel = ""
	persisted.NewFieldType = ""
	persisted.NewFieldValue = ""
	persisted.NewFieldSection = 0
	persisted.NewFieldProtected = false
	persisted.FieldDialogOpen = false
	persisted.NewURL = ""
	persisted.NewURLLabel = ""
	persisted.NewURLMatch = ""
	persisted.NewAttachment = ""
	persisted.SSHKeyGenType = ""
	persisted.SSHSeed = nil
	persisted.SSHPublicKey = nil
	raw, err := json.Marshal(persisted)
	if err != nil {
		return [32]byte{}
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	return sum
}

func (a *App) syncEditorBaseline(d *ItemDraft) {
	if a.onevra.editor.draftRef == d {
		return
	}
	a.onevra.editor = onevraEditorState{
		draftRef:      d,
		draftSig:      draftSignature(d),
		dragSec:       -1,
		dragField:     -1,
		dragOverField: -1,
		rowBounds:     map[string]ui.Rect{},
	}
}

func (a *App) onevraDraftDirty() bool {
	d := a.v2.draft
	if d == nil || a.onevra.editor.draftRef != d {
		return false
	}
	return draftSignature(d) != a.onevra.editor.draftSig
}

// requestCancelEdit prompts once when the draft has unsaved edits.
func (a *App) requestCancelEdit() {
	if a.onevraDraftDirty() && !a.onevra.editor.confirmDiscard {
		a.onevra.editor.confirmDiscard = true
		return
	}
	a.onevra.editor = onevraEditorState{}
	a.v2.generator.open = false
	a.cancelEdit()
}

var onevraFieldTypes = []struct {
	typ   vault.FieldType
	label string
}{
	{vault.FieldTypeString, "文本"},
	{vault.FieldTypeText, "多行文本"},
	{vault.FieldTypeConcealed, "密码"},
	{vault.FieldTypeOTP, "一次性验证码"},
	{vault.FieldTypeURL, "网址"},
	{vault.FieldTypeEmail, "邮箱"},
	{vault.FieldTypePhone, "电话"},
	{vault.FieldTypeDate, "日期"},
	{vault.FieldTypeMonthYear, "年月"},
	{vault.FieldTypeAddress, "地址"},
}

func setDraftFieldType(f *vault.CustomField, typ vault.FieldType) {
	f.Type = typ
	f.Protected = typ == vault.FieldTypeConcealed || typ == vault.FieldTypeOTP || typ == vault.FieldTypeTOTP
}

// onevraEditorDialog presents the item editor as a spacious floating modal over
// the workspace so wide/narrow panes do not squeeze the editing form.
func (a *App) onevraEditorDialog(c *ui.Context) {
	if !a.v2.editing || a.v2.draft == nil {
		return
	}
	t := c.Theme()
	open := true
	ui.Column(c.Key("dialog-item-editor")).Children(func() {
		oneui.Dialog(c, &open, oneui.DialogOptions{
			Label:                "编辑条目",
			DisableBackdropClose: true,
			DisableEscapeClose:   true,
			Inset:                24,
		}, func(panel ui.Element) {
			winW, winH := c.Size()
			modalW := float32(800)
			if winW > 0 && winW-48 < modalW {
				modalW = max(500, winW-48)
			}
			modalH := float32(760)
			if winH > 0 {
				modalH = min(max(460, winH-56), 860)
			}
			panel.Width(modalW).Height(modalH).Padding(0).
				Background(t.Surface).Border(1, t.Border).Radius(t.Radius * 1.75).
				Shadow(0, 24, 56, -12, ui.RGBA(0, 0, 0, .32))
			panel.Children(func() {
				a.v2EditorView(c)
			})
		})
	})
}

// v2EditorView edits an item with a sticky header bar and scrollable body,
// both inside onevraEditorDialog and standalone in editor tests.
func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	a.syncEditorBaseline(draft)
	t := c.Theme()
	dirty := a.onevraDraftDirty()

	saveDraftNow := func() {
		if err := a.saveDraft(); err != nil {
			a.status = message(err)
			return
		}
		a.onevra.editor = onevraEditorState{}
	}

	root := ui.Column(c.Key("editor")).Fill().MinWidth(0).Background(t.Background)
	if root.Shortcut(ui.Ctrl, ui.KeyS) && !a.busy && strings.TrimSpace(draft.Title) != "" {
		saveDraftNow()
	} else if root.Shortcut(0, ui.KeyEscape) && !a.busy {
		a.requestCancelEdit()
	}

	root.Children(func() {
		// Sticky single-line action bar
		ui.Row(c).FillWidth().Shrink(0).Justify(ui.Center).Background(t.Surface).Children(func() {
			availW, _ := c.Size()
			ui.Row(c).FillWidth().MinWidth(0).MaxWidth(860).
				Padding(t.Space(3), t.Space(5)).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
				oneui.Text(c, "编辑条目").FontSize(t.Rem(1.02)).Bold().SingleLine()
				if draft.ID == "" {
					if v, changed := onevraSelect(c, "条目类别", draft.Category, v2CategoryValues(), func(v vault.ItemCategory) string { return CategoryDisplayName(v) }); changed && !a.busy {
						a.setDraftCategory(v)
					}
					if len(a.v2.vaults) > 1 {
						vaultIDs := make([]string, 0, len(a.v2.vaults))
						for _, v := range a.v2.vaults {
							vaultIDs = append(vaultIDs, v.ID)
						}
						if draft.VaultID == "" {
							draft.VaultID = vault.DefaultVaultID
						}
						if v, changed := onevraSelect(c, "目标保险库", draft.VaultID, vaultIDs, a.vaultNameForID); changed && !a.busy {
							draft.VaultID = v
						}
					}
				} else {
					onevraPill(c, CategoryDisplayName(draft.Category), t.TextMuted)
				}
				if dirty {
					onevraPill(c, "未保存", t.Accent)
				}
				ui.Spacer(c)
				if availW == 0 || availW >= 680 {
					oneui.Text(c, "Esc 取消 · Ctrl+S 保存").FontSize(t.Rem(.72)).TextColor(t.TextMuted).SingleLine()
				}
				if oneui.Button(c, "取消", oneui.ButtonOutline).Disabled(a.uiBusy(c)).Clicked() {
					a.requestCancelEdit()
				}
				if oneui.Button(c, "保存", oneui.ButtonPrimary).Disabled(a.uiBusy(c) || strings.TrimSpace(draft.Title) == "").Clicked() {
					saveDraftNow()
				}
			})
		})
		ui.Box(c).FillWidth().Height(1).Background(t.Border)

		if a.onevra.editor.confirmDiscard {
			ui.Column(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Column(c).FillWidth().MinWidth(0).MaxWidth(860).Padding(t.Space(2), t.Space(5), 0, t.Space(5)).Children(func() {
					onevraBanner(c, lucide.TriangleAlert(), "有未保存的更改，确定放弃吗？", t.Warning, func() {
						if oneui.Button(c, "放弃更改", oneui.ButtonPrimary).Clicked() {
							a.requestCancelEdit()
						}
						if oneui.Button(c, "继续编辑", oneui.ButtonGhost).Clicked() {
							a.onevra.editor.confirmDiscard = false
						}
					})
				})
			})
		}

		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().ScrollbarInsets(14, 0, 14).Children(func() {
			ui.Column(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Children(func() {
				ui.Column(c).FillWidth().MinWidth(0).MaxWidth(860).Padding(t.Space(4.5), t.Space(5), t.Space(7), t.Space(5)).
					Gap(t.Space(4)).Children(func() {
					a.onevraEditorBody(c, draft)
				})
			})
		})

		if a.onevra.editor.dragging {
			a.renderEditorDragGhost(c, root, draft)
		}
	})

	a.editorAddCustomFieldDialog(c, draft)
}

func (a *App) onevraEditorBody(c *ui.Context, draft *ItemDraft) {
	t := c.Theme()

	// Title row mirrors the detail header
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
		a.onevraEditorAvatarPicker(c, draft.Title, draft.Category, &draft.Icon, t.Space(12))
		title := oneui.TextBox(c, &draft.Title, oneui.TextBoxOptions{}).
			Label("标题").Placeholder("标题，例如：GitHub、公司邮箱").Disabled(a.uiBusy(c))
		title.Grow(1).FontSize(t.Rem(1.15))
		favLabel := "加入收藏"
		if draft.Favorite {
			favLabel = "取消收藏"
		}
		star := oneui.IconButton(c, onevraStarIcon(draft.Favorite), favLabel, oneui.IconButtonPlain).Disabled(a.uiBusy(c))
		if draft.Favorite {
			star.TextColor(t.Warning)
		}
		if star.Clicked() {
			draft.Favorite = !draft.Favorite
		}
	})

	// Primary fields / category hero guidance
	addMoreRow := func(row func(func())) {
		row(func() {
			addMore := oneui.Button(c, "添加更多", oneui.ButtonGhost).Disabled(a.uiBusy(c))
			oneui.MenuButton(c, addMore, func(menu *oneui.Menu) {
				if menu.Item("安全问题").Chosen() {
					a.addEditorCustomField("安全问题", vault.FieldTypeConcealed)
				}
				if menu.Item("恢复码").Chosen() {
					a.addEditorCustomField("恢复码", vault.FieldTypeConcealed)
				}
				if menu.Item("自定义字段").Chosen() {
					a.openAddCustomFieldDialog(-1)
				}
				if menu.Item("网址").Chosen() {
					a.appendEditorURL()
				}
			})
			ui.Spacer(c)
		})
	}

	switch draft.Category {
	case vault.CategoryLogin:
		onevraGroup(c, "登录信息", func(row func(func())) {
			row(func() { a.onevraEditorField(c, "用户名", &draft.Username, "用户名、邮箱或账号标识", false, "", nil) })
			row(func() { a.onevraEditorField(c, "密码", &draft.Password, "输入密码，或点击右侧生成", true, "password", nil) })
			if a.v2.generator.open && (a.v2.generator.target == "" || a.v2.generator.target == "password") {
				row(func() { a.onevraInlineGenerator(c) })
			}
			row(func() { a.onevraEditorField(c, "一次性验证码", &draft.OTP, "otpauth://totp/… 或 Base32 密钥", true, "", nil) })
			row(func() { a.onevraEditorField(c, "网站", &draft.URL, "https://example.com", false, "", nil) })
			addMoreRow(row)
		})
	case vault.CategoryPassword:
		onevraGroup(c, "密码信息", func(row func(func())) {
			if draft.Username != "" {
				row(func() { a.onevraEditorField(c, "用户名", &draft.Username, "用户名、邮箱或账号标识", false, "", nil) })
			}
			row(func() { a.onevraEditorField(c, "密码", &draft.Password, "输入密码，或点击右侧生成", true, "password", nil) })
			if a.v2.generator.open && (a.v2.generator.target == "" || a.v2.generator.target == "password") {
				row(func() { a.onevraInlineGenerator(c) })
			}
			row(func() { a.onevraEditorField(c, "网站", &draft.URL, "https://example.com", false, "", nil) })
			addMoreRow(row)
		})
	case vault.CategorySecureNote:
		onevraGroup(c, "笔记内容", func(row func(func())) {
			row(func() {
				oneui.TextBox(c, &draft.Notes, oneui.TextBoxOptions{Multiline: true}).
					Label("笔记内容").Placeholder("在此输入加密安全笔记…").Lines(10, 22).Grow(1).Disabled(a.uiBusy(c))
			})
		})
		if draft.Username != "" || draft.Password != "" {
			onevraGroup(c, "附加凭据", func(row func(func())) {
				if draft.Username != "" {
					row(func() { a.onevraEditorField(c, "用户名", &draft.Username, "用户名或账号", false, "", nil) })
				}
				if draft.Password != "" {
					row(func() { a.onevraEditorField(c, "密码", &draft.Password, "密码或凭据", true, "password", nil) })
					if a.v2.generator.open && (a.v2.generator.target == "" || a.v2.generator.target == "password") {
						row(func() { a.onevraInlineGenerator(c) })
					}
				}
			})
		}
	default:
		if draft.Category == vault.CategoryDocument {
			onevraBanner(c, lucide.FileLock(), "文档条目支持保存加密附件（.pdf / 证书 / 配置文件等），保存条目后可在详情页查看或上传加密附件。", t.Accent, nil)
		} else if draft.Category == vault.CategorySSHKey {
			a.onevraEditorSSHGenCard(c, draft)
		}
		if draft.Username != "" || draft.Password != "" {
			onevraGroup(c, CategoryDisplayName(draft.Category), func(row func(func())) {
				if draft.Username != "" {
					row(func() { a.onevraEditorField(c, "用户名", &draft.Username, "用户名或账号", false, "", nil) })
				}
				if draft.Password != "" {
					row(func() { a.onevraEditorField(c, "密码", &draft.Password, "密码或凭据", true, "password", nil) })
					if a.v2.generator.open && (a.v2.generator.target == "" || a.v2.generator.target == "password") {
						row(func() { a.onevraInlineGenerator(c) })
					}
				}
			})
		}
	}

	// Typed Card / Identity canonical fields grouped by section title
	if bindings := v2DraftCanonicalFields(draft.Category); len(bindings) > 0 {
		var groupOrder []string
		grouped := map[string][]v2CanonicalField{}
		for _, b := range bindings {
			title := b.SectionTitle
			if title == "" {
				title = CategoryDisplayName(draft.Category)
			}
			if _, exists := grouped[title]; !exists {
				groupOrder = append(groupOrder, title)
			}
			grouped[title] = append(grouped[title], b)
		}
		for _, groupTitle := range groupOrder {
			groupBindings := grouped[groupTitle]
			onevraGroup(c, groupTitle, func(row func(func())) {
				for _, b := range groupBindings {
					b := b
					if ptr := v2DraftFieldValue(draft, b.SectionID, b.FieldID); ptr != nil {
						var presets []string
						if draft.Category == vault.CategoryCreditCard && b.FieldID == "type" {
							presets = presetOptionsForField(draft.Category, b.SectionID, b.FieldID)
						}
						row(func() { a.onevraEditorField(c, b.Label, ptr, b.Placeholder, b.Concealed, "", presets) })
					}
				}
			})
		}
	}

	// Websites group
	showURLsGroup := len(draft.URLs) > 0 || strings.TrimSpace(draft.URL) != ""
	switch draft.Category {
	case vault.CategoryLogin, vault.CategoryPassword, vault.CategoryAPICredential,
		vault.CategoryServer, vault.CategorySoftwareLicense, vault.CategoryMembership:
		showURLsGroup = true
	}
	if showURLsGroup {
		onevraGroup(c, "网址", func(row func(func())) {
			for i := range draft.URLs {
				i := i
				row(func() {
					u := &draft.URLs[i]
					primaryLabel := "设为主网址"
					if u.Primary {
						primaryLabel = "主网址"
					}
					star := oneui.IconButton(c.Key(fmt.Sprintf("url-primary-%d", i)), onevraStarIcon(u.Primary), primaryLabel, oneui.IconButtonCompact).Disabled(a.uiBusy(c) || u.Primary)
					if u.Primary {
						star.TextColor(t.Warning)
					}
					if star.Clicked() {
						a.setPrimaryURL(i)
					}
					oneui.TextBox(c.Key(fmt.Sprintf("url-%d", i)), &u.URL, oneui.TextBoxOptions{}).Label("网址").Placeholder("https://example.com").Grow(1).MinWidth(160).Disabled(a.uiBusy(c))
					oneui.TextBox(c.Key(fmt.Sprintf("url-label-%d", i)), &u.Label, oneui.TextBoxOptions{}).Label("标签").Placeholder("标签").Width(100).Disabled(a.uiBusy(c))
					if mode, changed := onevraSelect(c, "自动填充匹配", u.MatchMode, append([]string{""}, v2MatchModes...), v2MatchModeLabel); changed {
						a.setURLMatchMode(i, mode)
					}
					if oneui.IconButton(c.Key(fmt.Sprintf("url-remove-%d", i)), lucide.X(), "移除网址", oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
						a.removeURL(i)
					}
				})
			}
			row(func() {
				oneui.Icon(c, lucide.Plus()).Size(t.Space(4), t.Space(4)).TextColor(t.TextMuted)
				input := oneui.TextBox(c.Key("url-new"), &draft.NewURL, oneui.TextBoxOptions{}).
					Label("新网址").Placeholder("https://example.com（输入后添加网址）").Grow(1).Disabled(a.uiBusy(c))
				add := oneui.Button(c, "添加网址", oneui.ButtonGhost).Disabled(a.uiBusy(c) || strings.TrimSpace(draft.NewURL) == "")
				if add.Clicked() || (input.Submitted() && strings.TrimSpace(draft.NewURL) != "") {
					a.addURL(draft.NewURL, draft.NewURLLabel, draft.NewURLMatch)
				}
			})
		})
	}

	// Custom sections (each real section renders cleanly; empty state stays compact)
	visibleCustomSections := 0
	for i := range draft.Sections {
		i := i
		sec := draft.Sections[i]
		if IsInternalMetaSection(sec) {
			continue
		}
		visibleFields := 0
		for _, f := range sec.Fields {
			if _, canonical := v2DraftCanonicalField(draft, sec.ID, f); !canonical {
				visibleFields++
			}
		}
		if len(sec.Fields) > 0 && visibleFields == 0 {
			continue
		}
		visibleCustomSections++
		ui.Column(c.Key("section:"+sec.ID)).FillWidth().Gap(t.Space(1.5)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
				oneui.TextBox(c, &draft.Sections[i].Title, oneui.TextBoxOptions{}).
					Label("分区标题").Placeholder("分区名称").Grow(1).Disabled(a.uiBusy(c))
				menu := oneui.IconButton(c, lucide.Ellipsis(), "分区选项", oneui.IconButtonCompact).Disabled(a.uiBusy(c))
				oneui.MenuButton(c, menu, func(m *oneui.Menu) {
					if m.Item("上移分区").Disabled(i == 0).Chosen() {
						a.moveSection(i, -1)
					}
					if m.Item("下移分区").Disabled(i == len(draft.Sections)-1).Chosen() {
						a.moveSection(i, 1)
					}
					m.Separator()
					if m.Item("删除分区").Chosen() {
						a.removeSection(i)
					}
				})
			})

			visIndices := make([]int, 0, len(sec.Fields))
			for j := range sec.Fields {
				if _, canonical := v2DraftCanonicalField(draft, sec.ID, sec.Fields[j]); !canonical {
					visIndices = append(visIndices, j)
				}
			}
			activeDrag := a.onevra.editor.dragging && a.onevra.editor.dragSec == i
			srcPos, overPos := -1, -1
			if activeDrag {
				for p, idx := range visIndices {
					if idx == a.onevra.editor.dragField {
						srcPos = p
					}
					if idx == a.onevra.editor.dragOverField {
						overPos = p
					}
				}
				if overPos < 0 {
					overPos = srcPos
				}
			}
			commitFrom, commitTo := -1, -1
			shouldCommit := false
			ui.Column(c.Key("section-card:"+sec.ID)).FillWidth().MinWidth(0).
				Border(1, t.Border).Radius(t.Radius*1.25).Background(t.Surface).Children(func() {
				for p, j := range visIndices {
					j := j
					f := sec.Fields[j]
					if p > 0 {
						ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
					}
					key := sec.ID + "/" + f.ID
					isDragged := activeDrag && a.onevra.editor.dragField == j
					shiftY := float32(0)
					if activeDrag && srcPos >= 0 && overPos >= 0 {
						if p == srcPos {
							if overPos > srcPos {
								for k := srcPos + 1; k <= overPos; k++ {
									shiftY += a.onevra.editor.rowHeight(sec.ID+"/"+sec.Fields[visIndices[k]].ID) + 1
								}
							} else if overPos < srcPos {
								for k := overPos; k < srcPos; k++ {
									shiftY -= a.onevra.editor.rowHeight(sec.ID+"/"+sec.Fields[visIndices[k]].ID) + 1
								}
							}
						} else if srcPos < overPos && p > srcPos && p <= overPos {
							shiftY = -(a.onevra.editor.rowHeight(sec.ID+"/"+sec.Fields[visIndices[srcPos]].ID) + 1)
						} else if overPos < srcPos && p >= overPos && p < srcPos {
							shiftY = a.onevra.editor.rowHeight(sec.ID+"/"+sec.Fields[visIndices[srcPos]].ID) + 1
						}
					}
					rowEl := ui.Row(c.Key("row:"+key)).FillWidth().MinWidth(0).
						AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), t.Space(3))
					if f.Type == vault.FieldTypeText {
						rowEl.AlignItems(ui.Start)
					}
					if lb := rowEl.LayoutBounds(); lb.W > 0 && lb.H > 0 {
						a.onevra.editor.setRowBound(key, lb)
					} else if b := rowEl.Bounds(); b.W > 0 && b.H > 0 {
						a.onevra.editor.setRowBound(key, b)
					}
					animY := rowEl.Animate("dnd:"+key, shiftY, 130*time.Millisecond)
					if animY != 0 {
						rowEl.Translate(0, animY)
					}
					if isDragged {
						rowEl.Background(t.Accent.Alpha(.06)).
							Border(1.5, t.Accent.Alpha(.55)).BorderStyle(ui.BorderDashed).
							Radius(t.Radius).Opacity(0.28)
					}
					rowEl.Children(func() {
						fromIdx, toIdx, commit := a.onevraEditorCustomField(c, draft, i, j, visIndices, rowEl)
						if commit {
							commitFrom, commitTo, shouldCommit = fromIdx, toIdx, true
						}
					})
					if a.v2.generator.open && a.v2.generator.target == key {
						ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
						ui.Row(c.Key("gen:"+key)).FillWidth().MinWidth(0).Padding(t.Space(2.5), t.Space(3)).Children(func() {
							a.onevraInlineGenerator(c)
						})
					}
				}
				if len(visIndices) > 0 {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				ui.Row(c.Key("footer:"+sec.ID)).FillWidth().MinWidth(0).Wrap().
					AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2), t.Space(3)).Children(func() {
					addFieldBtn := oneui.Button(c, "＋ 添加字段", oneui.ButtonGhost).Label("添加字段").Disabled(a.uiBusy(c))
					oneui.MenuButton(c, addFieldBtn, func(m *oneui.Menu) {
						a.editorAddFieldMenu(m, i)
					})
					if oneui.Button(c, "+ 自定义字段…", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
						a.openAddCustomFieldDialog(i)
					}
					ui.Spacer(c)
				})
			})
			if shouldCommit && commitFrom >= 0 && commitTo >= 0 && commitFrom != commitTo {
				a.reorderField(i, commitFrom, commitTo)
			}
		})
	}

	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
		if visibleCustomSections == 0 {
			addFieldGlobal := oneui.Button(c, "＋ 添加字段", oneui.ButtonOutline).Label("添加字段").Disabled(a.uiBusy(c))
			oneui.MenuButton(c, addFieldGlobal, func(m *oneui.Menu) {
				a.editorAddFieldMenu(m, -1)
			})
			if oneui.Button(c, "+ 添加自定义字段…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).Clicked() {
				a.openAddCustomFieldDialog(-1)
			}
			if oneui.Button(c, "＋ 新建分区", oneui.ButtonGhost).Label("添加分区").Disabled(a.uiBusy(c)).Clicked() {
				a.addSection(fmt.Sprintf("分区 %d", visibleCustomSections+1))
			}
		} else {
			if oneui.Button(c, "＋ 新建分区", oneui.ButtonOutline).Label("添加分区").Disabled(a.uiBusy(c)).Clicked() {
				a.addSection(fmt.Sprintf("分区 %d", visibleCustomSections+1))
			}
		}
		if !showURLsGroup {
			if oneui.Button(c, "＋ 添加网址", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
				a.appendEditorURL()
			}
		}
	})

	// Notes (SecureNote renders Notes as its hero editor at the top)
	if draft.Category != vault.CategorySecureNote {
		onevraGroup(c, "备注", func(row func(func())) {
			row(func() {
				notes := oneui.TextBox(c, &draft.Notes, oneui.TextBoxOptions{Multiline: true}).
					Label("备注").Grow(1).Disabled(a.uiBusy(c))
				if draft.Category == vault.CategoryDocument {
					notes.Placeholder("记录文档说明、用途或补充信息").Lines(6, 14)
				} else {
					notes.Placeholder("加密备注、恢复码或补充说明").Lines(3, 8)
				}
			})
		})
	}

	// Tags
	ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
		oneui.Text(c, "标签").FontSize(t.Rem(.76)).Bold().TextColor(t.TextMuted).Padding(0, t.Space(1))
		oneui.TagInput(c, &draft.Tags).Label("标签").Placeholder("输入标签后按回车添加").Disabled(a.uiBusy(c))
	})

	if a.v2.editorError != "" {
		onevraBanner(c, lucide.TriangleAlert(), a.v2.editorError, t.Danger, nil)
	}
	oneui.Text(c, "保存后会生成新的修订版本，旧值加密保存在历史版本中。").FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
}

func findAdjacentVisibleField(draft *ItemDraft, secIdx, fieldIdx, delta int) int {
	if draft == nil || secIdx < 0 || secIdx >= len(draft.Sections) {
		return -1
	}
	fields := draft.Sections[secIdx].Fields
	step := 1
	if delta < 0 {
		step = -1
	}
	for k := fieldIdx + step; k >= 0 && k < len(fields); k += step {
		if _, canonical := v2DraftCanonicalField(draft, draft.Sections[secIdx].ID, fields[k]); !canonical {
			return k
		}
	}
	return -1
}

func presetOptionsForField(category vault.ItemCategory, sectionID, fieldID string) []string {
	switch category {
	case vault.CategoryCreditCard:
		if fieldID == "type" {
			return []string{"Visa", "Mastercard", "UnionPay 银联", "American Express", "JCB", "Discover", "其他"}
		}
	case vault.CategoryAPICredential:
		if fieldID == "type" {
			return []string{"Bearer Token", "API Key", "Access Key", "OAuth 2.0", "Webhook Secret", "PAT"}
		}
	case vault.CategoryDatabase:
		if fieldID == "database_type" {
			return []string{"PostgreSQL", "MySQL", "Redis", "MongoDB", "SQLite", "SQL Server", "ClickHouse"}
		}
	case vault.CategoryWirelessRouter:
		if fieldID == "security" {
			return []string{"WPA3", "WPA2-WPA3", "WPA2 个人", "WPA2 企业", "开放网络"}
		}
	case vault.CategorySSHKey:
		if fieldID == "key_type" {
			return []string{"Ed25519", "RSA-4096", "ECDSA", "SK-Ed25519"}
		}
	case vault.CategoryBankAccount:
		if fieldID == "type" {
			return []string{"储蓄卡", "支票账户", "对公账户", "外币账户"}
		}
	case vault.CategoryCryptoWallet:
		switch fieldID {
		case "wallet_type":
			return []string{"助记词钱包", "硬件钱包", "多签钱包", "单私钥"}
		case "network":
			return []string{"Ethereum", "Bitcoin", "Solana", "Tron", "L2", "多链"}
		}
	case vault.CategoryMedicalRecord:
		if fieldID == "blood_type" {
			return []string{"A 型", "B 型", "AB 型", "O 型", "Rh 阴性", "未知"}
		}
	}
	_ = sectionID
	return nil
}

func v2FieldPlaceholder(typ vault.FieldType) string {
	switch typ {
	case vault.FieldTypeDate:
		return "YYYY-MM-DD"
	case vault.FieldTypeMonthYear:
		return "YYYY-MM"
	case vault.FieldTypeURL:
		return "https://example.com"
	case vault.FieldTypeEmail:
		return "name@example.com"
	case vault.FieldTypeOTP, vault.FieldTypeTOTP:
		return "otpauth://totp/… 或 Base32 密钥"
	case vault.FieldTypeMenu:
		return "输入或右侧选择预设"
	default:
		return v2FieldTypeLabel(typ)
	}
}

func (a *App) onevraEditorPresetMenu(c *ui.Context, key, label string, value *string, presets []string) {
	if value == nil || len(presets) == 0 {
		return
	}
	btn := onevraIconButton(c.Key("preset:"+key), lucide.ChevronDown(), "选择预设 "+label, "选择预设选项", oneui.IconButtonCompact).
		Disabled(a.uiBusy(c))
	oneui.MenuButton(c, btn, func(m *oneui.Menu) {
		for _, opt := range presets {
			opt := opt
			if m.Item(opt).Checked(strings.EqualFold(strings.TrimSpace(*value), opt)).Chosen() {
				*value = opt
			}
		}
	})
}

func (a *App) onevraEditorField(c *ui.Context, label string, value *string, placeholder string, concealed bool, generateTarget string, presets []string) {
	t := c.Theme()
	oneui.Text(c, label).FontSize(t.Rem(.8)).TextColor(t.TextMuted).Width(148).SingleLine().Ellipsis("…")
	input := oneui.TextBox(c.Key("edit:"+label), value, oneui.TextBoxOptions{}).
		Label(label).Placeholder(placeholder).Grow(1).MinWidth(160).Disabled(a.uiBusy(c))
	if concealed {
		input.Password()
	}
	if len(presets) > 0 {
		if placeholder == "" {
			input.Placeholder("输入或右侧选择预设")
		}
		a.onevraEditorPresetMenu(c, "canon:"+label, label, value, presets)
	}
	if generateTarget != "" {
		if oneui.IconButton(c.Key("gen:"+generateTarget), lucide.Dices(), "生成密码", oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
			if a.v2.generator.open && a.v2.generator.target == generateTarget {
				a.closeGenerator()
			} else {
				a.openGenerator(generateTarget)
			}
		}
	}
}

func (a *App) onevraEditorSSHGenCard(c *ui.Context, draft *ItemDraft) {
	t := c.Theme()
	if strings.TrimSpace(draft.SSHKeyGenType) == "" {
		draft.SSHKeyGenType = "Ed25519"
	}
	hasPriv := strings.TrimSpace(sectionFieldValue(draft.Sections, "ssh", "private_key")) != ""
	pubVal := strings.TrimSpace(sectionFieldValue(draft.Sections, "ssh", "public_key"))

	ui.Column(c.Key("ssh-keygen-card")).FillWidth().Gap(t.Space(2.5)).Padding(t.Space(3)).
		Radius(t.Radius*1.25).Border(1, t.Border).Background(t.Surface).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Start).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.KeyRound()).Size(t.Space(4.25), t.Space(4.25)).TextColor(t.Accent)
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
				oneui.Text(c, "自动生成 SSH 密钥对").FontSize(t.Rem(.88)).Bold()
				oneui.Text(c, "一键生成标准 OpenSSH 密钥对并自动填入公钥、私钥与 SHA-256 指纹；Ed25519 保存后可直接用于本地 SSH Agent 按次授权签名。").
					FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			})
		})
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			if next, changed := onevraSelect(c, "SSH 密钥算法", draft.SSHKeyGenType, []string{"Ed25519", "RSA-4096", "ECDSA"}, func(v string) string {
				switch v {
				case "RSA-4096":
					return "RSA-4096"
				case "ECDSA":
					return "ECDSA P-256"
				default:
					return "Ed25519（推荐）"
				}
			}); changed && !a.busy {
				draft.SSHKeyGenType = next
			}
			genLabel := "生成 SSH 密钥对"
			if hasPriv {
				genLabel = "重新生成 SSH 密钥对"
			}
			if oneui.Button(c, genLabel, oneui.ButtonSecondary).Disabled(a.uiBusy(c)).Clicked() {
				a.generateDraftSSHKey(draft.SSHKeyGenType)
			}
			if pubVal != "" {
				if oneui.Button(c, "复制公钥", oneui.ButtonOutline).Disabled(a.uiBusy(c)).Clicked() {
					c.WriteClipboard(pubVal)
					a.status = "已复制 SSH 公钥"
				}
			}
		})
	})
}

func (a *App) onevraEditorCustomField(c *ui.Context, draft *ItemDraft, i, j int, visIndices []int, rowEl ui.Element) (commitFrom, commitTo int, shouldCommit bool) {
	t := c.Theme()
	sec := draft.Sections[i]
	f := &draft.Sections[i].Fields[j]
	key := sec.ID + "/" + f.ID
	encrypted := v2FieldTypeConcealed(*f)
	isDragged := a.onevra.editor.dragging && a.onevra.editor.dragSec == i && a.onevra.editor.dragField == j

	buildGrip := func() {
		grip := ui.Box(c.Key("grip:"+key)).
			Size(t.Space(5.5), t.Space(6.5)).Shrink(0).
			AlignItems(ui.Center).Justify(ui.Center).
			Radius(t.Radius).
			Cursor(ui.CursorGrab).
			Tooltip("上下拖动调整顺序").
			Role(ui.RoleButton).
			Label("拖动排序 " + f.Label)
		if isDragged {
			grip.Cursor(ui.CursorGrabbing).Background(t.Accent.Alpha(.14))
		} else if grip.Hovered() {
			grip.Background(t.Text.Alpha(.06))
		}
		grip.Children(func() {
			iconColor := t.TextMuted
			if isDragged {
				iconColor = t.Accent
			}
			oneui.Icon(c, lucide.GripVertical()).Size(t.Space(3.75), t.Space(3.75)).TextColor(iconColor)
		})
		dx, dy, dragged := grip.Dragged()
		_, _, ended := grip.DragEnded()
		if dragged && !a.busy {
			px, py, overRoot := c.Root().PointerPosition()
			if !a.onevra.editor.dragging || a.onevra.editor.dragSec != i || a.onevra.editor.dragField != j {
				a.onevra.editor.dragging = true
				a.onevra.editor.dragSec = i
				a.onevra.editor.dragField = j
				a.onevra.editor.dragOverField = j
				if r, ok := a.onevra.editor.rowBounds[key]; ok && r.W > 0 && r.H > 0 {
					a.onevra.editor.dragStartRect = r
				} else if r := rowEl.LayoutBounds(); r.W > 0 && r.H > 0 {
					a.onevra.editor.dragStartRect = r
				} else {
					a.onevra.editor.dragStartRect = rowEl.Bounds()
				}
				if overRoot {
					a.onevra.editor.dragStartPtrX = px - dx
					a.onevra.editor.dragStartPtrY = py - dy
					a.onevra.editor.dragHasPtr = true
					a.onevra.editor.dragOffsetX = dx
					a.onevra.editor.dragOffsetY = dy
				} else {
					a.onevra.editor.dragHasPtr = false
					a.onevra.editor.dragOffsetX = dx
					a.onevra.editor.dragOffsetY = dy
				}
			} else if overRoot && a.onevra.editor.dragHasPtr {
				a.onevra.editor.dragOffsetX = px - a.onevra.editor.dragStartPtrX
				a.onevra.editor.dragOffsetY = py - a.onevra.editor.dragStartPtrY
			} else {
				a.onevra.editor.dragOffsetX += dx
				a.onevra.editor.dragOffsetY += dy
			}

			// Compute closest drop index by comparing ghost center Y to resting row midpoints.
			sr := a.onevra.editor.dragStartRect
			ghostCenterY := sr.Y + a.onevra.editor.dragOffsetY + sr.H*0.5
			if len(visIndices) > 0 {
				bestIdx := a.onevra.editor.dragField
				bestDist := float32(1e9)
				for _, candIdx := range visIndices {
					candKey := sec.ID + "/" + sec.Fields[candIdx].ID
					if r, ok := a.onevra.editor.rowBounds[candKey]; ok && r.H > 0 {
						dist := ghostCenterY - (r.Y + r.H*0.5)
						if dist < 0 {
							dist = -dist
						}
						if dist < bestDist {
							bestDist = dist
							bestIdx = candIdx
						}
					}
				}
				a.onevra.editor.dragOverField = bestIdx
			}
			c.Invalidate()
		} else if (ended || (!dragged && isDragged)) && a.onevra.editor.dragging && a.onevra.editor.dragSec == i && a.onevra.editor.dragField == j {
			fromIdx, toIdx := a.onevra.editor.dragField, a.onevra.editor.dragOverField
			a.onevra.editor.clearDrag()
			if fromIdx >= 0 && toIdx >= 0 && fromIdx != toIdx {
				commitFrom, commitTo, shouldCommit = fromIdx, toIdx, true
			}
		}
	}

	buildTrailingControls := func() {
		if f.Type == vault.FieldTypeMenu {
			if presets := presetOptionsForField(draft.Category, sec.ID, f.ID); len(presets) > 0 {
				a.onevraEditorPresetMenu(c, key, f.Label, &f.Value, presets)
			}
		}
		if encrypted && f.Type != vault.FieldTypeOTP && f.Type != vault.FieldTypeTOTP {
			if onevraIconButton(c.Key("gen:"+key), lucide.Dices(), "为 "+f.Label+" 生成密码", "生成密码", oneui.IconButtonCompact).Disabled(a.uiBusy(c)).Clicked() {
				if a.v2.generator.open && a.v2.generator.target == key {
					a.closeGenerator()
				} else {
					a.openGenerator(key)
				}
			}
		}
		prot := "plain"
		if encrypted {
			prot = "enc"
		}
		if next, changed := onevraSegmented(c, prot, [][2]string{{"plain", "明文"}, {"enc", "加密"}}); changed && !a.busy {
			if next == "plain" && (f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP) {
				a.status = "验证码字段必须保持加密"
			} else {
				draft.SetFieldProtection(i, j, next == "enc")
			}
		}
		prevIdx := findAdjacentVisibleField(draft, i, j, -1)
		nextIdx := findAdjacentVisibleField(draft, i, j, 1)
		menu := oneui.IconButton(c.Key("menu:"+key), lucide.Ellipsis(), "字段选项", oneui.IconButtonCompact).Disabled(a.uiBusy(c))
		oneui.MenuButton(c, menu, func(m *oneui.Menu) {
			if encrypted && m.Item("生成密码").Chosen() {
				a.openGenerator(key)
			}
			m.Group("更改类型", func(m *oneui.Menu) {
				for _, ft := range onevraFieldTypes {
					ft := ft
					if m.Item(ft.label).Checked(f.Type == ft.typ).Chosen() {
						setDraftFieldType(f, ft.typ)
					}
				}
			})
			if m.Item("上移").Disabled(prevIdx < 0).Chosen() {
				a.moveField(i, j, prevIdx-j)
			}
			if m.Item("下移").Disabled(nextIdx < 0).Chosen() {
				a.moveField(i, j, nextIdx-j)
			}
			m.Separator()
			if m.Item("删除字段").Chosen() {
				a.removeField(i, j)
			}
		})
	}

	if f.Type == vault.FieldTypeText {
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(1.5)).Children(func() {
			ui.Row(c).FillWidth().MinWidth(0).AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				buildGrip()
				oneui.TextBox(c.Key("label:"+key), &f.Label, oneui.TextBoxOptions{}).
					Label("字段名").Placeholder("字段名").Width(160).Disabled(a.uiBusy(c))
				ui.Spacer(c)
				buildTrailingControls()
			})
			valBox := oneui.TextBox(c.Key("value:"+key), &f.Value, oneui.TextBoxOptions{Multiline: true}).
				Label(v2FieldTypeLabel(f.Type)).Placeholder(v2FieldPlaceholder(f.Type)).FillWidth().Lines(3, 6).Disabled(a.uiBusy(c))
			if encrypted {
				valBox.Password()
			}
		})
		return commitFrom, commitTo, shouldCommit
	}

	buildGrip()
	oneui.TextBox(c.Key("label:"+key), &f.Label, oneui.TextBoxOptions{}).
		Label("字段名").Placeholder("字段名").Width(136).Disabled(a.uiBusy(c))
	input := oneui.TextBox(c.Key("value:"+key), &f.Value, oneui.TextBoxOptions{}).
		Label(v2FieldTypeLabel(f.Type)).Placeholder(v2FieldPlaceholder(f.Type)).Grow(1).MinWidth(120).Disabled(a.uiBusy(c))
	if encrypted {
		input.Password()
	}
	buildTrailingControls()
	return commitFrom, commitTo, shouldCommit
}

func (a *App) renderEditorDragGhost(c *ui.Context, root ui.Element, draft *ItemDraft) {
	e := a.onevra.editor
	if !e.dragging || e.dragSec < 0 || e.dragSec >= len(draft.Sections) {
		return
	}
	fields := draft.Sections[e.dragSec].Fields
	if e.dragField < 0 || e.dragField >= len(fields) {
		return
	}
	f := fields[e.dragField]
	t := c.Theme()

	clampedX := max(float32(-16), min(float32(16), e.dragOffsetX*0.18))
	ghostWinX := e.dragStartRect.X + clampedX
	ghostWinY := e.dragStartRect.Y + e.dragOffsetY
	lx, ly, ok := root.WindowToLocal(ghostWinX, ghostWinY)
	if !ok {
		rb := root.LayoutBounds()
		if rb.W == 0 && rb.H == 0 {
			rb = root.Bounds()
		}
		lx = ghostWinX - rb.X
		ly = ghostWinY - rb.Y
	}
	ghostW := max(float32(280), e.dragStartRect.W)

	preview := f.Value
	previewMuted := false
	if v2FieldTypeConcealed(f) {
		if preview != "" {
			preview = "••••••••"
		} else {
			preview = "（空密码字段）"
			previewMuted = true
		}
	} else if strings.TrimSpace(preview) == "" {
		preview = v2FieldPlaceholder(f.Type)
		previewMuted = true
	}
	label := strings.TrimSpace(f.Label)
	if label == "" {
		label = "未命名字段"
	}

	ghost := ui.Row(c.Key("editor-drag-ghost")).Absolute().Left(lx).Top(ly).Width(ghostW).
		AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), t.Space(3)).
		Radius(t.Radius*1.15).Background(t.Surface).Border(1.5, t.Accent).
		Shadow(0, 16, 36, -6, ui.RGBA(0, 0, 0, .28)).Opacity(0.95).Scale(1.015, 1.015).
		PassThrough()
	ghost.Children(func() {
		oneui.Icon(c, lucide.GripVertical()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
		oneui.Text(c, label).Bold().FontSize(t.Rem(.84)).Width(136).SingleLine().Ellipsis("…")
		valTxt := oneui.Text(c, preview).FontSize(t.Rem(.82)).Grow(1).MinWidth(0).SingleLine().Ellipsis("…")
		if previewMuted {
			valTxt.TextColor(t.TextMuted)
		}
		if v2FieldTypeConcealed(f) {
			onevraPill(c, "加密", t.Accent)
		} else {
			onevraPill(c, "明文", t.TextMuted)
		}
	})
}

// onevraInlineGenerator expands under the password or secret field it fills.
func (a *App) onevraInlineGenerator(c *ui.Context) {
	t := c.Theme()
	g := &a.v2.generator
	if g.preview == "" && g.status == "" {
		a.regenerateGenerator()
	}
	ui.Column(c.Key("inline-generator")).Role(ui.RoleGroup).Label("密码生成器").FillWidth().Gap(t.Space(2)).
		Padding(t.Space(3)).Radius(t.Radius).Background(t.Background).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Children(func() {
				shown := g.preview
				if shown == "" {
					shown = "—"
				}
				onevraSecretText(c, shown)
			})
			if g.entropy > 0 {
				onevraPill(c, fmt.Sprintf("%s · %d bits", generatorStrength(g.entropy), g.entropy), t.Accent)
			}
		})
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
			if next, changed := onevraSegmented(c, string(g.mode), [][2]string{
				{string(pwgen.ModeRandom), "随机密码"},
				{string(pwgen.ModeMemorable), "易记短语"},
				{string(pwgen.ModePIN), "PIN 码"},
			}); changed {
				a.setGeneratorMode(pwgen.Mode(next))
			}
			ui.Spacer(c)
			switch g.mode {
			case pwgen.ModeMemorable:
				a.onevraStepper(c, fmt.Sprintf("%d 个词", g.wordCount), &g.wordCount, 3, 15)
			case pwgen.ModePIN:
				a.onevraStepper(c, fmt.Sprintf("%d 位", g.pinLength), &g.pinLength, 3, 12)
			default:
				a.onevraStepper(c, fmt.Sprintf("%d 位", g.length), &g.length, 8, 64)
			}
		})
		if g.mode == pwgen.ModeRandom || g.mode == "" {
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(3)).Children(func() {
				oneui.Checkbox(c, &g.digits, "包含数字").OnChange(a.regenerateGenerator)
				oneui.Checkbox(c, &g.symbols, "包含符号").OnChange(a.regenerateGenerator)
			})
		}
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			if oneui.Button(c, "换一个", oneui.ButtonOutline).Clicked() {
				a.regenerateGenerator()
			}
			ui.Spacer(c)
			if oneui.Button(c, "关闭", oneui.ButtonGhost).Clicked() {
				a.closeGenerator()
			}
			if oneui.Button(c, "填入当前条目", oneui.ButtonPrimary).Disabled(g.preview == "").Clicked() {
				a.useGenerator()
			}
		})
	})
}

func (a *App) onevraStepper(c *ui.Context, label string, value *int, lo, hi int) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(t.Space(.5)).Children(func() {
		if oneui.IconButton(c, lucide.Minus(), "减少", oneui.IconButtonCompact).Disabled(*value <= lo).Clicked() {
			*value--
			a.regenerateGenerator()
		}
		oneui.Text(c, label).FontSize(t.Rem(.82)).Width(52).SingleLine()
		if oneui.IconButton(c, lucide.Plus(), "增加", oneui.IconButtonCompact).Disabled(*value >= hi).Clicked() {
			*value++
			a.regenerateGenerator()
		}
	})
}

func (a *App) editorAddCustomFieldDialog(c *ui.Context, draft *ItemDraft) {
	t := c.Theme()
	ui.Column(c.Key("dialog-add-custom-field")).Children(func() {
		oneui.Dialog(c, &draft.FieldDialogOpen, oneui.DialogOptions{Label: "添加自定义字段"}, func(panel ui.Element) {
			panel.Width(440).Background(t.Surface).Border(1, t.Border).Radius(t.Radius*1.5).Padding(t.Space(5))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
					oneui.Text(c, "添加自定义字段").FontSize(t.Rem(1.15)).Bold()
					oneui.Text(c, "选择字段是随条目明文显示（如环境名、Region），还是默认遮蔽保护（如备用 Token、API Secret）。").
						FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					oneui.TextBox(c, &draft.NewFieldLabel, oneui.TextBoxOptions{}).
						Label("字段名称").Placeholder("例如：Environment、Region、Secondary Token").Disabled(a.uiBusy(c))
					protMode := "plain"
					if draft.NewFieldProtected {
						protMode = "enc"
					}
					if next, changed := onevraSegmented(c, protMode, [][2]string{
						{"plain", "明文 · 详情直接显示"},
						{"enc", "加密 · 默认遮蔽"},
					}); changed {
						draft.NewFieldProtected = next == "enc"
					}
					valBox := oneui.TextBox(c, &draft.NewFieldValue, oneui.TextBoxOptions{}).
						Label("字段值").Placeholder("输入字段内容").Disabled(a.uiBusy(c))
					if draft.NewFieldProtected {
						valBox.Password()
					}
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.uiBusy(c)).Clicked() {
							draft.FieldDialogOpen = false
						}
						if oneui.Button(c, "确认添加", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).Clicked() {
							a.confirmAddCustomField()
						}
					})
				})
			})
		})
	})
}

func v2CategoryValues() []vault.ItemCategory {
	out := make([]vault.ItemCategory, 0, len(AllCategories()))
	out = append(out, AllCategories()...)
	return out
}
