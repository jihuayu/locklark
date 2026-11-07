package desktop

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
)

// WatchtowerReport is the desktop projection of the shared Watchtower report.
// It is a distinct name so the v2 state does not expose the browser package's
// wire types.
type WatchtowerReport = watchtower.Report

// Placeholders used by the v2 detail pane. A masked read returns empty values
// for concealed fields, so "no value" and "withheld value" must not share a
// glyph: emptiness is only claimed for fields whose absence is known.
const (
	v2EmptyValue  = "—"
	v2MaskedValue = "••••••••"
)

// v2FieldDisplay resolves one field for display. Concealment is applied before
// the emptiness check: a masked detail clears protected values, so rendering
// them as empty would claim the item has no password or one-time code. An
// unmasked value is used only for an explicit reveal of that field.
func v2FieldDisplay(masked, plain *personal.ItemDetail, key string, revealed bool) string {
	if revealed && plain != nil {
		if value, ok := fieldValue(plain, key); ok {
			if value == "" {
				return v2EmptyValue
			}
			return value
		}
	}
	value, ok := fieldValue(masked, key)
	if isConcealedKey(masked, key) {
		// Masking happens before the emptiness check: the masked read strips
		// protected values, so an empty string here is not proof of absence.
		return v2MaskedValue
	}
	if !ok || value == "" {
		return v2EmptyValue
	}
	return value
}

// v2FieldTypeConcealed reports whether a custom field must be masked in the
// UI: protected fields and concealed/OTP types never render in clear text
// unless the user reveals them explicitly.
func v2FieldTypeConcealed(f vault.CustomField) bool {
	switch f.Type {
	case vault.FieldTypeConcealed, vault.FieldTypeOTP, vault.FieldTypeTOTP:
		return true
	}
	return f.Protected
}

// v2DetailField is one extra detail row (URL, typed card/identity value or
// custom section field) rendered next to the built-in login fields. Keys are
// the stable keys resolved by fieldValue/revealField/copyField.
type v2DetailField struct {
	Key       string
	Label     string
	Concealed bool
}

// v2DetailFields maps a rich ItemModelV2 detail onto display rows without
// copying values: every row still resolves through fieldValue so detail,
// reveal and copy all address the same stable key.
func v2DetailFields(detail *personal.ItemDetail) []v2DetailField {
	if detail == nil {
		return nil
	}
	var out []v2DetailField
	for i, u := range detailURLs(*detail) {
		label := u.Label
		if label == "" {
			label = fmt.Sprintf("网址 %d", i+1)
		}
		if u.Primary {
			label += "（主）"
		}
		key := fmt.Sprintf("url:%d", i)
		out = append(out, v2DetailField{Key: key, Label: label, Concealed: isConcealedKey(detail, key)})
	}
	if detail.CreditCard != nil {
		for _, f := range []struct{ key, label string }{
			{"credit_card.name", "持卡人"},
			{"credit_card.type", "卡类型"},
			{"credit_card.number", "卡号"},
			{"credit_card.verification", "安全码"},
			{"credit_card.expiry", "有效期"},
			{"credit_card.valid_from", "生效日期"},
			{"credit_card.pin", "PIN"},
			{"credit_card.issuing_bank", "发卡行"},
		} {
			out = append(out, v2DetailField{Key: f.key, Label: f.label, Concealed: isConcealedKey(detail, f.key)})
		}
	}
	if detail.Identity != nil {
		for _, f := range []struct{ key, label string }{
			{"identity.first_name", "名"},
			{"identity.middle_name", "中间名"},
			{"identity.last_name", "姓"},
			{"identity.birth_date", "出生日期"},
			{"identity.company", "公司"},
			{"identity.job_title", "职位"},
			{"identity.email", "邮箱"},
			{"identity.phone", "电话"},
			{"identity.address", "地址"},
			{"identity.website", "网站"},
		} {
			out = append(out, v2DetailField{Key: f.key, Label: f.label, Concealed: isConcealedKey(detail, f.key)})
		}
	}
	for _, s := range detail.Sections {
		for _, f := range s.Fields {
			key := s.ID + "/" + f.ID
			label := s.Title + " · " + f.Label
			if f.Label == "" {
				label = s.Title + " · " + f.ID
			}
			out = append(out, v2DetailField{Key: key, Label: label, Concealed: isConcealedKey(detail, key)})
		}
	}
	return out
}

// v2View renders the three-pane desktop vault. Model mutations live in
// v2_state.go, item_detail.go and item_editor.go; this file stays a thin view
// over that state so every native action remains audited by the same methods.
func (a *App) v2View(c *ui.Context) {
	if a.v2.largeTypeOpen {
		a.largeTypeView(c)
		return
	}
	// A reload requested while the UI was busy is replayed here, on the UI
	// goroutine, so a search change never leaves the list permanently stale.
	a.drainPendingV2Reload()
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
			ui.Button(c, "全部保险库").FillWidth().OnClick(func() { a.SelectVault("all") })
			for _, v := range a.v2.vaults {
				v := v
				// Use the public SelectVault so the list reloads for the new
				// vault; the private helper only records the id.
				ui.Button(c, v.Name).FillWidth().OnClick(func() { a.SelectVault(v.ID) })
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
			if a.v2.searchError != "" {
				ui.Text(c, a.v2.searchError).FontSize(12)
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
				if row.Favorite {
					label += " ★"
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
	for _, key := range []string{"username", "password", "otp", "url", "notes"} {
		a.v2DetailFieldRow(c, detail, key, fieldLabel(key))
	}
	for _, f := range v2DetailFields(detail) {
		a.v2DetailFieldRow(c, detail, f.Key, f.Label)
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

// v2DetailFieldRow renders one detail row through the existing reveal/copy
// actions. Values are masked unless the user explicitly revealed that key.
func (a *App) v2DetailFieldRow(c *ui.Context, detail *personal.ItemDetail, key, label string) {
	plain := a.plainDetail()
	revealed := a.v2.revealed[key]
	concealed := isConcealedKey(detail, key)
	value := v2FieldDisplay(detail, plain, key, revealed)
	ui.Row(c).Gap(8).Children(func() {
		ui.Text(c, label).Width(120)
		ui.Text(c, visible(value)).Grow(1)
		if concealed {
			button := "显示"
			if revealed {
				button = "隐藏"
			}
			ui.Button(c, button).Disabled(a.busy).OnClick(func() { a.revealField(key) })
		}
		ui.Button(c, "复制").Disabled(a.busy).OnClick(func() { a.copyField(key) })
		if key == "otp" {
			ui.Button(c, "大号显示").Disabled(a.busy).OnClick(func() { a.showLargeType(key) })
		}
	})
}

func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	ui.Text(c, "编辑条目").FontSize(22).Bold()
	ui.Text(c, "修改会生成新的修订版本；原值写入历史。")
	category := string(draft.Category)
	sel := ui.Select(c, &category, v2CategoryOptions()).Disabled(a.busy)
	if sel.Changed() {
		a.setDraftCategory(vault.ItemCategory(category))
	}
	ui.TextInput(c, &draft.Title).Label("标题").Disabled(a.busy)
	ui.TextInput(c, &draft.Username).Label("用户名").Disabled(a.busy)
	ui.TextInput(c, &draft.Password).Label("密码").Password().Disabled(a.busy)
	ui.TextInput(c, &draft.OTP).Label("一次性验证码配置").Disabled(a.busy)
	ui.TextInput(c, &draft.URL).Label("网站").Disabled(a.busy)
	ui.TextInput(c, &draft.Notes).Label("备注").Password().Disabled(a.busy)
	ui.Checkbox(c, &draft.Favorite, "收藏").Disabled(a.busy)

	// Tags: the add/remove helpers keep drafts de-duplicated and trimmed.
	ui.Text(c, "标签").FontSize(14).Bold()
	if len(draft.Tags) == 0 {
		ui.Text(c, "尚无标签").FontSize(12)
	}
	ui.Row(c).Gap(6).Children(func() {
		for _, tag := range draft.Tags {
			tag := tag
			ui.Button(c, visible(tag)+" ✕").Disabled(a.busy).OnClick(func() { a.removeTag(tag) })
		}
	})
	ui.Row(c).Gap(6).Children(func() {
		ui.TextInput(c, &draft.NewTag).Label("新标签").Disabled(a.busy)
		ui.Button(c, "添加标签").Disabled(a.busy || strings.TrimSpace(draft.NewTag) == "").OnClick(func() { a.addTag(draft.NewTag) })
	})

	// Multiple URLs with the stored autofill match mode.
	ui.Text(c, "网址").FontSize(14).Bold()
	if len(draft.URLs) == 0 {
		ui.Text(c, "尚无网址").FontSize(12)
	}
	for i := range draft.URLs {
		i := i
		url := draft.URLs[i]
		ui.Row(c).Gap(6).Children(func() {
			ui.Text(c, visible(url.URL)).Grow(1)
			ui.TextInput(c, &draft.URLs[i].Label).Label("标签").Width(110).Disabled(a.busy)
			primary := "设为主网址"
			if url.Primary {
				primary = "主网址"
			}
			ui.Button(c, primary).Disabled(a.busy || url.Primary).OnClick(func() { a.setPrimaryURL(i) })
			ui.Button(c, "匹配："+v2MatchModeLabel(url.MatchMode)).Disabled(a.busy).OnClick(func() { a.cycleURLMatchMode(i) })
			ui.Button(c, "移除").Disabled(a.busy).OnClick(func() { a.removeURL(i) })
		})
	}
	ui.Row(c).Gap(6).Children(func() {
		ui.TextInput(c, &draft.NewURL).Label("新网址").Disabled(a.busy)
		ui.TextInput(c, &draft.NewURLLabel).Label("网址标签").Disabled(a.busy)
		ui.Button(c, "匹配："+v2MatchModeLabel(draft.NewURLMatch)).Disabled(a.busy).OnClick(func() { a.cycleNewURLMatchMode() })
		ui.Button(c, "添加网址").Disabled(a.busy || strings.TrimSpace(draft.NewURL) == "").OnClick(func() {
			a.addURL(draft.NewURL, draft.NewURLLabel, draft.NewURLMatch)
		})
	})

	// Canonical card/identity inputs write the typed draft structs, which are
	// what normalization, detail and autofill prefer. The equivalent template
	// section fields are hidden below so there is exactly one input per value.
	if bindings := v2DraftCanonicalFields(draft.Category); len(bindings) > 0 {
		title := "卡片信息"
		if draft.Category == vault.CategoryIdentity {
			title = "身份信息"
		}
		ui.Text(c, title).FontSize(14).Bold()
		for _, b := range bindings {
			b := b
			ui.Row(c).Gap(6).Children(func() {
				input := ui.TextInput(c, v2DraftFieldValue(draft, b.SectionID, b.FieldID)).Label(b.Label).Grow(1).Disabled(a.busy)
				if b.Concealed {
					input.Password()
				}
			})
		}
		ui.Text(c, "以上结构化字段与下面的默认分区字段同步保存。").FontSize(12)
	}

	// Sections and custom fields, including concealed/OTP field types which
	// render through Password() inputs.
	ui.Text(c, "分区与自定义字段").FontSize(14).Bold()
	for i := range draft.Sections {
		i := i
		sec := draft.Sections[i]
		ui.Column(c).Gap(4).Children(func() {
			ui.Row(c).Gap(6).Children(func() {
				ui.TextInput(c, &draft.Sections[i].Title).Label("分区标题").Grow(1).Disabled(a.busy)
				ui.Button(c, "上移").Disabled(a.busy || i == 0).OnClick(func() { a.moveSection(i, -1) })
				ui.Button(c, "下移").Disabled(a.busy || i == len(draft.Sections)-1).OnClick(func() { a.moveSection(i, 1) })
				ui.Button(c, "删除分区").Disabled(a.busy).OnClick(func() { a.removeSection(i) })
			})
			for j := range sec.Fields {
				j := j
				f := sec.Fields[j]
				if _, canonical := v2DraftCanonicalField(draft, sec.ID, f); canonical {
					// Edited through the typed control above; hidden here to avoid a
					// second divergent copy of the same value.
					continue
				}
				ui.Row(c).Gap(6).Children(func() {
					ui.TextInput(c, &draft.Sections[i].Fields[j].Label).Label("字段名").Width(120).Disabled(a.busy)
					input := ui.TextInput(c, &draft.Sections[i].Fields[j].Value).Label(v2FieldTypeLabel(f.Type)).Grow(1).Disabled(a.busy)
					if v2FieldTypeConcealed(f) {
						input.Password()
					}
					ui.Button(c, "上移").Disabled(a.busy || j == 0).OnClick(func() { a.moveField(i, j, -1) })
					ui.Button(c, "下移").Disabled(a.busy || j == len(sec.Fields)-1).OnClick(func() { a.moveField(i, j, 1) })
					ui.Button(c, "删除字段").Disabled(a.busy).OnClick(func() { a.removeField(i, j) })
				})
			}
		})
	}

	// New field composer; the section and type are chosen with the buttons so
	// the existing addField helper stays the single mutation path.
	ui.Text(c, "添加字段").FontSize(14).Bold()
	sectionLabel := "未选择分区"
	if draft.NewFieldSection >= 0 && draft.NewFieldSection < len(draft.Sections) {
		sectionLabel = draft.Sections[draft.NewFieldSection].Title
	}
	ui.Row(c).Gap(6).Children(func() {
		ui.TextInput(c, &draft.NewFieldLabel).Label("字段名").Disabled(a.busy)
		newValue := ui.TextInput(c, &draft.NewFieldValue).Label("字段值").Disabled(a.busy)
		if draft.NewFieldType == vault.FieldTypeConcealed || draft.NewFieldType == vault.FieldTypeOTP || draft.NewFieldType == vault.FieldTypeTOTP {
			newValue.Password()
		}
		ui.Button(c, "分区："+sectionLabel).Disabled(a.busy).OnClick(a.cycleDraftFieldSection)
		ui.Button(c, "类型："+v2FieldTypeLabel(draft.NewFieldType)).Disabled(a.busy).OnClick(a.cycleDraftFieldType)
		ui.Button(c, "添加字段").Disabled(a.busy || len(draft.Sections) == 0).OnClick(func() {
			a.addField(draft.NewFieldSection, draft.NewFieldLabel, string(draft.NewFieldType), draft.NewFieldValue)
		})
		ui.Button(c, "添加分区").Disabled(a.busy).OnClick(func() { a.addSection(draft.NewSectionTitle) })
	})
	ui.TextInput(c, &draft.NewSectionTitle).Label("新分区标题").Disabled(a.busy)
	if a.v2.editorError != "" {
		ui.Text(c, a.v2.editorError).FontSize(12)
	}
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

// ---------- editor helpers (view-only, draft is UI state) ----------

// v2CategoryOptions lists the selectable categories for the editor.
func v2CategoryOptions() []string {
	categories := AllCategories()
	out := make([]string, 0, len(categories))
	for _, category := range categories {
		out = append(out, string(category))
	}
	return out
}

// setDraftCategory switches the draft category. A new item is re-provisioned
// with the category template; an existing item keeps its custom sections so no
// stored value is silently dropped.
func (a *App) setDraftCategory(category vault.ItemCategory) {
	draft := a.v2.draft
	if draft == nil || !vault.ValidCategory(category) || draft.Category == category {
		return
	}
	draft.Category = category
	if draft.ID == "" {
		draft.Sections = CategoryTemplate(category)
		draft.NewFieldSection = 0
	}
	a.v2.editorError = ""
}

var v2FieldTypes = []vault.FieldType{
	vault.FieldTypeString,
	vault.FieldTypeConcealed,
	vault.FieldTypeOTP,
	vault.FieldTypeTOTP,
	vault.FieldTypeURL,
	vault.FieldTypeEmail,
	vault.FieldTypeDate,
	vault.FieldTypeMonthYear,
	vault.FieldTypePhone,
	vault.FieldTypeAddress,
	vault.FieldTypeMenu,
	vault.FieldTypeText,
}

func v2FieldTypeLabel(t vault.FieldType) string {
	switch t {
	case vault.FieldTypeString:
		return "文本"
	case vault.FieldTypeConcealed:
		return "密码（遮蔽）"
	case vault.FieldTypeOTP, vault.FieldTypeTOTP:
		return "一次性验证码"
	case vault.FieldTypeURL:
		return "网址"
	case vault.FieldTypeEmail:
		return "邮箱"
	case vault.FieldTypeDate:
		return "日期"
	case vault.FieldTypeMonthYear:
		return "年月"
	case vault.FieldTypePhone:
		return "电话"
	case vault.FieldTypeAddress:
		return "地址"
	case vault.FieldTypeMenu:
		return "选项"
	case vault.FieldTypeText:
		return "多行文本"
	}
	return string(t)
}

// cycleDraftFieldType advances the new-field type through the supported set.
func (a *App) cycleDraftFieldType() {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	next := 0
	for i, t := range v2FieldTypes {
		if t == draft.NewFieldType {
			next = (i + 1) % len(v2FieldTypes)
			break
		}
	}
	draft.NewFieldType = v2FieldTypes[next]
}

// cycleDraftFieldSection advances the target section for a new field.
func (a *App) cycleDraftFieldSection() {
	draft := a.v2.draft
	if draft == nil || len(draft.Sections) == 0 {
		return
	}
	draft.NewFieldSection = (draft.NewFieldSection + 1) % len(draft.Sections)
}

// v2MatchModeLabel renders a stored URL autofill match mode.
func v2MatchModeLabel(mode string) string {
	switch mode {
	case vault.URLMatchOrigin:
		return "同源"
	case vault.URLMatchHost:
		return "同主机"
	case vault.URLMatchDomain:
		return "同域名"
	case vault.URLMatchExact:
		return "精确"
	case vault.URLMatchNever:
		return "不填充"
	}
	return "默认"
}

var v2MatchModes = []string{
	vault.URLMatchOrigin,
	vault.URLMatchHost,
	vault.URLMatchDomain,
	vault.URLMatchExact,
	vault.URLMatchNever,
}

func nextMatchMode(current string) string {
	for i, mode := range v2MatchModes {
		if mode == current {
			return v2MatchModes[(i+1)%len(v2MatchModes)]
		}
	}
	return v2MatchModes[0]
}

// cycleURLMatchMode advances one stored URL's match mode through setURLMatchMode.
func (a *App) cycleURLMatchMode(index int) {
	draft := a.v2.draft
	if draft == nil || index < 0 || index >= len(draft.URLs) {
		return
	}
	a.setURLMatchMode(index, nextMatchMode(draft.URLs[index].MatchMode))
}

// cycleNewURLMatchMode advances the match mode of the URL being composed.
func (a *App) cycleNewURLMatchMode() {
	if a.v2.draft == nil {
		return
	}
	a.v2.draft.NewURLMatch = nextMatchMode(a.v2.draft.NewURLMatch)
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
