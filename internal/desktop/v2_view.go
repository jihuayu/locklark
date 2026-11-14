package desktop

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

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

// v2View renders the Onevra-backed three-pane desktop vault. Model mutations
// live in v2_state.go, item_detail.go and item_editor.go; this file remains the
// editor and report view layer while onevra_view.go owns the vault shell.
func (a *App) v2View(c *ui.Context) { a.onevraVaultView(c) }

func (a *App) v2EditorViewLegacy(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	t := c.Theme()

	// Editor header
	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
		iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
			Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
		iconBox.Children(func() {
			oneui.Icon(c, onevraCategoryIcon(draft.Category)).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, "编辑条目").FontSize(t.Rem(1.35)).Bold().SingleLine()
			oneui.Text(c, "保存后将生成新修订版本，原有字段值自动加密归入历史版本。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		})
		if oneui.IconButton(c, lucide.X(), "关闭编辑", oneui.IconButtonPlain).Disabled(a.busy).Clicked() {
			a.cancelEdit()
		}
	})

	// 1. Basic Info Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2.5)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Text(c, "基本信息").Bold().Grow(1)
			oneui.Badge(c, CategoryDisplayName(draft.Category), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Text(c, "条目类别").FontSize(t.Rem(.82)).TextColor(t.TextMuted)
			category := string(draft.Category)
			sel := ui.Select(c, &category, v2CategoryOptions()).Disabled(a.busy)
			if sel.Changed() {
				a.setDraftCategory(vault.ItemCategory(category))
			}
		})
		oneui.TextBox(c, &draft.Title, oneui.TextBoxOptions{}).Label("标题").Placeholder("例如：GitHub、公司邮箱、主力信用卡").Disabled(a.busy)
		oneui.TextBox(c, &draft.Username, oneui.TextBoxOptions{}).Label("用户名").Placeholder("用户名、邮箱或账号标识").Disabled(a.busy)
		oneui.TextBox(c, &draft.Password, oneui.TextBoxOptions{}).Label("密码").Placeholder("输入或使用下方生成器创建高强度密码").Password().Disabled(a.busy)
		oneui.TextBox(c, &draft.OTP, oneui.TextBoxOptions{}).Label("一次性验证码配置").Placeholder("otpauth://totp/... 或 Base32 密钥").Disabled(a.busy)
		oneui.TextBox(c, &draft.URL, oneui.TextBoxOptions{}).Label("网站").Placeholder("https://example.com").Disabled(a.busy)
		oneui.TextBox(c, &draft.Notes, oneui.TextBoxOptions{}).Label("备注").Placeholder("加密安全备注、恢复码或补充说明").Password().Disabled(a.busy)
		oneui.Checkbox(c, &draft.Favorite, "收藏").Disabled(a.busy)

		ui.Box(c).FillWidth().Height(1).Background(t.Border)

		// Tags: the add/remove helpers keep drafts de-duplicated and trimmed.
		ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "标签").FontSize(t.Rem(.88)).Bold()
			if len(draft.Tags) == 0 {
				oneui.Text(c, "尚无标签").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
			} else {
				ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
					for _, tag := range draft.Tags {
						tag := tag
						oneui.Button(c, visible(tag)+" ✕", oneui.ButtonSecondary).Disabled(a.busy).OnClick(func() { a.removeTag(tag) })
					}
				})
			}
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.End).Gap(t.Space(1.5)).Children(func() {
				oneui.TextBox(c, &draft.NewTag, oneui.TextBoxOptions{}).Label("新标签").Placeholder("输入标签名称").Grow(1).Disabled(a.busy)
				oneui.Button(c, "添加标签", oneui.ButtonOutline).Disabled(a.busy || strings.TrimSpace(draft.NewTag) == "").OnClick(func() { a.addTag(draft.NewTag) })
			})
		})
	})

	// 2. URLs Card: Multiple URLs with the stored autofill match mode.
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "网址").Bold().Grow(1)
			oneui.Icon(c, lucide.Globe()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
		})
		if len(draft.URLs) == 0 {
			oneui.Text(c, "尚无网址").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
		}
		for i := range draft.URLs {
			i := i
			url := draft.URLs[i]
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).
				Padding(t.Space(2)).Gap(t.Space(1.5)).Children(func() {
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, visible(url.URL)).FontSize(t.Rem(.85)).Bold().Grow(1).MinWidth(0).Wrap()
					primary := "设为主网址"
					primaryVariant := oneui.ButtonOutline
					if url.Primary {
						primary = "主网址"
						primaryVariant = oneui.ButtonSecondary
					}
					oneui.Button(c, primary, primaryVariant).Disabled(a.busy || url.Primary).OnClick(func() { a.setPrimaryURL(i) })
					oneui.Button(c, "匹配："+v2MatchModeLabel(url.MatchMode), oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.cycleURLMatchMode(i) })
					oneui.Button(c, "移除", oneui.ButtonGhost).Disabled(a.busy).OnClick(func() { a.removeURL(i) })
				})
				oneui.TextBox(c, &draft.URLs[i].Label, oneui.TextBoxOptions{}).Label("标签").Placeholder("例如：登录页、控制台").Disabled(a.busy)
			})
		}
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.End).Gap(t.Space(1.5)).Children(func() {
			oneui.TextBox(c, &draft.NewURL, oneui.TextBoxOptions{}).Label("新网址").Placeholder("https://example.com").Grow(1).Disabled(a.busy)
			oneui.TextBox(c, &draft.NewURLLabel, oneui.TextBoxOptions{}).Label("网址标签").Placeholder("例如：官网").Width(140).Disabled(a.busy)
			oneui.Button(c, "匹配："+v2MatchModeLabel(draft.NewURLMatch), oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.cycleNewURLMatchMode() })
			oneui.Button(c, "添加网址", oneui.ButtonSecondary).Disabled(a.busy || strings.TrimSpace(draft.NewURL) == "").OnClick(func() {
				a.addURL(draft.NewURL, draft.NewURLLabel, draft.NewURLMatch)
			})
		})
	})

	// 3. Typed Card / Identity Card: canonical inputs write the typed draft
	// structs, which normalization, detail and autofill prefer. The equivalent
	// template section fields are hidden below so there is one input per value.
	if bindings := v2DraftCanonicalFields(draft.Category); len(bindings) > 0 {
		title := "卡片信息"
		cardIcon := lucide.CreditCard()
		if draft.Category == vault.CategoryIdentity {
			title = "身份信息"
			cardIcon = lucide.User()
		}
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				oneui.Text(c, title).Bold().Grow(1)
				oneui.Icon(c, cardIcon).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
			})
			for _, b := range bindings {
				b := b
				input := oneui.TextBox(c, v2DraftFieldValue(draft, b.SectionID, b.FieldID), oneui.TextBoxOptions{}).Label(b.Label).Grow(1).Disabled(a.busy)
				if b.Concealed {
					input.Password()
				}
			}
			oneui.Text(c, "以上结构化字段与下面的默认分区字段同步保存。").FontSize(t.Rem(.75)).TextColor(t.TextMuted).Wrap()
		})
	}

	// 4. Custom Sections Card: sections and custom fields, including
	// concealed/OTP field types which render through Password() inputs.
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "分区与自定义字段").Bold().Grow(1)
			oneui.Icon(c, lucide.Layers()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
		})
		if len(draft.Sections) == 0 {
			oneui.Text(c, "当前条目尚无自定义分区，可在下方新建分区并添加字段。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		}
		for i := range draft.Sections {
			i := i
			sec := draft.Sections[i]
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).
				Padding(t.Space(2.5)).Gap(t.Space(2)).Children(func() {
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.End).Gap(t.Space(1)).Children(func() {
					oneui.TextBox(c, &draft.Sections[i].Title, oneui.TextBoxOptions{}).Label("分区标题").Grow(1).Disabled(a.busy)
					oneui.Button(c, "上移", oneui.ButtonGhost).Disabled(a.busy || i == 0).OnClick(func() { a.moveSection(i, -1) })
					oneui.Button(c, "下移", oneui.ButtonGhost).Disabled(a.busy || i == len(draft.Sections)-1).OnClick(func() { a.moveSection(i, 1) })
					oneui.Button(c, "删除分区", oneui.ButtonGhost).Disabled(a.busy).OnClick(func() { a.removeSection(i) })
				})
				for j := range sec.Fields {
					j := j
					f := sec.Fields[j]
					if _, canonical := v2DraftCanonicalField(draft, sec.ID, f); canonical {
						continue
					}
					ui.Row(c).FillWidth().Wrap().AlignItems(ui.End).Gap(t.Space(1)).Children(func() {
						oneui.TextBox(c, &draft.Sections[i].Fields[j].Label, oneui.TextBoxOptions{}).Label("字段名").Width(130).Disabled(a.busy)
						input := oneui.TextBox(c, &draft.Sections[i].Fields[j].Value, oneui.TextBoxOptions{}).Label(v2FieldTypeLabel(f.Type)).Grow(1).Disabled(a.busy)
						if v2FieldTypeConcealed(f) {
							input.Password()
						}
						oneui.Button(c, "上移", oneui.ButtonGhost).Disabled(a.busy || j == 0).OnClick(func() { a.moveField(i, j, -1) })
						oneui.Button(c, "下移", oneui.ButtonGhost).Disabled(a.busy || j == len(sec.Fields)-1).OnClick(func() { a.moveField(i, j, 1) })
						oneui.Button(c, "删除字段", oneui.ButtonGhost).Disabled(a.busy).OnClick(func() { a.removeField(i, j) })
					})
				}
			})
		}
	})

	// 5. New Field & Section Composer Card
	sectionLabel := "未选择分区"
	if draft.NewFieldSection >= 0 && draft.NewFieldSection < len(draft.Sections) {
		sectionLabel = draft.Sections[draft.NewFieldSection].Title
	}
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "添加字段").Bold().Grow(1)
			oneui.Icon(c, lucide.Plus()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
		})
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.TextBox(c, &draft.NewFieldLabel, oneui.TextBoxOptions{}).Label("字段名").Placeholder("例如：安全问题、恢复码").Grow(1).Disabled(a.busy)
			newValue := oneui.TextBox(c, &draft.NewFieldValue, oneui.TextBoxOptions{}).Label("字段值").Placeholder("输入字段内容").Grow(1).Disabled(a.busy)
			if draft.NewFieldType == vault.FieldTypeConcealed || draft.NewFieldType == vault.FieldTypeOTP || draft.NewFieldType == vault.FieldTypeTOTP {
				newValue.Password()
			}
		})
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "分区："+sectionLabel, oneui.ButtonOutline).Disabled(a.busy).OnClick(a.cycleDraftFieldSection)
			oneui.Button(c, "类型："+v2FieldTypeLabel(draft.NewFieldType), oneui.ButtonOutline).Disabled(a.busy).OnClick(a.cycleDraftFieldType)
			oneui.Button(c, "添加字段", oneui.ButtonSecondary).Disabled(a.busy || len(draft.Sections) == 0).OnClick(func() {
				a.addField(draft.NewFieldSection, draft.NewFieldLabel, string(draft.NewFieldType), draft.NewFieldValue)
			})
		})
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.End).Gap(t.Space(1.5)).Children(func() {
			oneui.TextBox(c, &draft.NewSectionTitle, oneui.TextBoxOptions{}).Label("新分区标题").Placeholder("例如：恢复信息、备用凭据").Grow(1).Disabled(a.busy)
			oneui.Button(c, "添加分区", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.addSection(draft.NewSectionTitle) })
		})
	})

	if a.v2.editorError != "" {
		a.onevraNoticeCard(c, "保存提示", a.v2.editorError, t.Danger)
	}

	// 6. Sticky / Bottom Action Bar
	ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(2.5), t.Space(3)).Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
		oneui.Button(c, "保存", oneui.ButtonPrimary).Disabled(a.busy || strings.TrimSpace(draft.Title) == "").OnClick(func() {
			if err := a.saveDraft(); err != nil {
				a.status = message(err)
			}
		})
		oneui.Button(c, "取消", oneui.ButtonOutline).Disabled(a.busy).OnClick(a.cancelEdit)
		ui.Spacer(c)
		oneui.Button(c, "生成密码", oneui.ButtonSecondary).Disabled(a.busy).OnClick(func() { a.openGenerator("password") })
	})
}

// v2EditorView is the item editor page. The page is assembled from the same
// compact field-row component and field-group surface used by other native
// dialogs, so every editable value has a stable label and one menu location.
func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	t := c.Theme()

	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
		iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
			Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
		iconBox.Children(func() {
			oneui.Icon(c, onevraCategoryIcon(draft.Category)).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, "编辑条目").FontSize(t.Rem(1.35)).Bold().SingleLine()
			oneui.Text(c, "保存后将生成新修订版本，原有字段值自动加密归入历史版本。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		})
		oneui.Button(c, "生成密码", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
			a.openGenerator("password")
		})
		oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.busy).OnClick(a.cancelEdit)
		oneui.Button(c, "保存", oneui.ButtonPrimary).Disabled(a.busy || strings.TrimSpace(draft.Title) == "").OnClick(func() {
			if err := a.saveDraft(); err != nil {
				a.status = message(err)
			}
		})
		if oneui.IconButton(c, lucide.X(), "关闭编辑", oneui.IconButtonPlain).Disabled(a.busy).Clicked() {
			a.cancelEdit()
		}
	})

	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, "条目类别").FontSize(t.Rem(.82)).TextColor(t.TextMuted)
		category := string(draft.Category)
		sel := ui.Select(c, &category, v2CategoryOptions()).Label("条目类别").Disabled(a.busy)
		sel.Width(180)
		if sel.Changed() {
			a.setDraftCategory(vault.ItemCategory(category))
		}
	})

	a.editorPrimaryGroup(c, draft)
	a.editorURLGroups(c, draft)
	a.editorStructuredSectionGroups(c, draft)
	a.editorTagGroup(c, draft)
	a.editorNewSectionGroup(c, draft)

	if a.v2.editorError != "" {
		a.onevraNoticeCard(c, "保存提示", a.v2.editorError, t.Danger)
	}

	ui.Column(c.Key("dialog-add-custom-field")).Children(func() {
		oneui.Dialog(c, &draft.FieldDialogOpen, oneui.DialogOptions{Label: "添加自定义字段"}, func(panel ui.Element) {
			panel.Width(440).Background(t.Surface).Border(1, t.Border).Radius(t.Radius).Padding(t.Space(4))
			panel.Children(func() {
				ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
					oneui.Text(c, "添加自定义字段").FontSize(t.Rem(1.12)).Bold()
					oneui.Text(c, "明确选择该字段是随条目明文直显（如环境名、Region），还是默认遮蔽保护（如备用 Token、API Secret）。").
						FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
					oneui.TextBox(c, &draft.NewFieldLabel, oneui.TextBoxOptions{}).
						Label("字段名称").Placeholder("例如：Environment、Region、Secondary Token").Disabled(a.busy)
					ui.Row(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						plainVariant := oneui.ButtonOutline
						encVariant := oneui.ButtonOutline
						if !draft.NewFieldProtected {
							plainVariant = oneui.ButtonSecondary
						} else {
							encVariant = oneui.ButtonSecondary
						}
						if oneui.Button(c, "明文 · 详情直接显示", plainVariant).Grow(1).Clicked() {
							draft.NewFieldProtected = false
						}
						if oneui.Button(c, "加密 · 默认遮蔽", encVariant).Grow(1).Clicked() {
							draft.NewFieldProtected = true
						}
					})
					valBox := oneui.TextBox(c, &draft.NewFieldValue, oneui.TextBoxOptions{}).
						Label("字段值").Placeholder("输入字段内容").Disabled(a.busy)
					if draft.NewFieldProtected {
						valBox.Password()
					}
					ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
						if oneui.Button(c, "取消", oneui.ButtonGhost).Disabled(a.busy).Clicked() {
							draft.FieldDialogOpen = false
						}
						if oneui.Button(c, "确认添加", oneui.ButtonPrimary).Disabled(a.busy).Clicked() {
							a.confirmAddCustomField()
						}
					})
				})
			})
		})
	})
}

func (a *App) editorPrimaryGroup(c *ui.Context, draft *ItemDraft) {
	title := "登录信息"
	switch draft.Category {
	case vault.CategorySecureNote:
		title = "安全笔记"
	case vault.CategoryAPICredential:
		title = "API 凭据"
	}

	fields := []editorFieldSpec{
		a.editorTextSpec("title", "标题", "例如：GitHub、公司邮箱、主力信用卡", &draft.Title, false, false),
	}
	switch draft.Category {
	case vault.CategoryLogin, vault.CategoryPassword:
		fields = append(fields,
			a.editorTextSpec("username", "用户名", "用户名、邮箱或账号标识", &draft.Username, false, false),
			a.editorTextSpec("password", "密码", "输入或使用生成器创建高强度密码", &draft.Password, true, false),
			a.editorTextSpec("otp", "一次性验证码", "otpauth://totp/… 或 Base32 密钥", &draft.OTP, true, false),
			a.editorTextSpec("url", "网站", "https://example.com", &draft.URL, false, false),
			a.editorTextSpec("notes", "备注", "加密安全备注、恢复码或补充说明", &draft.Notes, true, true),
		)
	case vault.CategorySecureNote:
		fields = append(fields, a.editorTextSpec("notes", "备注", "输入安全笔记", &draft.Notes, true, true))
	default:
		fields = append(fields, a.editorTextSpec("notes", "备注", "补充说明", &draft.Notes, true, true))
	}

	editorFieldGroup(c, editorFieldGroupSpec{
		Key:      "item-primary",
		Title:    title,
		Badge:    CategoryDisplayName(draft.Category),
		Fields:   fields,
		AddLabel: "添加更多",
		BuildAddMenu: func(menu *oneui.Menu) {
			if menu.Item("安全问题").Chosen() {
				a.addEditorCustomField("安全问题", vault.FieldTypeConcealed)
			}
			if menu.Item("恢复码").Chosen() {
				a.addEditorCustomField("恢复码", vault.FieldTypeConcealed)
			}
			if menu.Item("自定义字段").Chosen() {
				a.addEditorCustomField("自定义字段", vault.FieldTypeString)
			}
			if menu.Item("网址").Chosen() {
				a.appendEditorURL()
			}
		},
	})
}

func (a *App) editorTextSpec(key, label, placeholder string, value *string, concealed, multiline bool) editorFieldSpec {
	return editorFieldSpec{
		Key:         key,
		Label:       label,
		Placeholder: placeholder,
		Value:       value,
		Concealed:   concealed,
		Multiline:   multiline,
		Busy:        a.busy,
		MenuLabel:   "字段选项：" + label,
		BuildMenu: func(menu *oneui.Menu) {
			if key == "password" {
				if menu.Item("生成密码").Chosen() {
					a.openGenerator("password")
				}
			}
			clear := menu.Item("清空字段").Disabled(value == nil || strings.TrimSpace(*value) == "")
			if clear.Chosen() && value != nil {
				*value = ""
			}
		},
	}
}

func (a *App) editorURLGroups(c *ui.Context, draft *ItemDraft) {
	var fields []editorFieldSpec
	for i := range draft.URLs {
		i := i
		url := &draft.URLs[i]
		fields = append(fields,
			editorFieldSpec{
				Key:         fmt.Sprintf("url-%d-address", i),
				Label:       "网站",
				Placeholder: "https://example.com",
				Value:       &url.URL,
				Busy:        a.busy,
				MenuLabel:   fmt.Sprintf("网址选项：%d", i+1),
				BuildMenu: func(menu *oneui.Menu) {
					if menu.Item("设为主网址").Disabled(url.Primary).Chosen() {
						a.setPrimaryURL(i)
					}
					if menu.Item("移除网址").Chosen() {
						a.removeURL(i)
					}
				},
			},
			editorFieldSpec{
				Key:         fmt.Sprintf("url-%d-label", i),
				Label:       "标签",
				Placeholder: "例如：登录页、控制台",
				Value:       &url.Label,
				Busy:        a.busy,
				MenuLabel:   fmt.Sprintf("网址标签选项：%d", i+1),
				BuildMenu: func(menu *oneui.Menu) {
					clear := menu.Item("清空标签").Disabled(strings.TrimSpace(url.Label) == "")
					if clear.Chosen() {
						url.Label = ""
					}
				},
			},
		)
	}

	var rows []func(*ui.Context)
	for i := range draft.URLs {
		i := i
		rows = append(rows, func(c *ui.Context) {
			t := c.Theme()
			selected := v2MatchModeLabel(draft.URLs[i].MatchMode)
			options := []string{"默认", "同源", "同主机", "同域名", "精确", "不填充"}
			ui.Row(c).FillWidth().MinWidth(0).Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).
				Padding(t.Space(1.5), t.Space(7)).Children(func() {
				oneui.Text(c, "自动填充匹配").FontSize(t.Rem(.74)).Bold().TextColor(t.Accent).Width(110)
				matchSelect := ui.Select(c, &selected, options).Label("自动填充匹配")
				matchSelect.Width(180)
				if matchSelect.Changed() {
					a.setURLMatchMode(i, v2MatchModeFromLabel(selected))
				}
				ui.Spacer(c)
				if draft.URLs[i].Primary {
					oneui.Badge(c, "主网址", oneui.BadgeOptions{Tone: oneui.BadgeSuccess})
				}
			})
		})
	}

	editorFieldGroup(c, editorFieldGroupSpec{
		Key:       "item-urls",
		Title:     "网址",
		Badge:     fmt.Sprintf("%d", len(draft.URLs)),
		Fields:    fields,
		ExtraRows: rows,
		AddLabel:  "添加网址",
		BuildAddMenu: func(menu *oneui.Menu) {
			if menu.Item("新网址").Chosen() {
				a.appendEditorURL()
			}
		},
	})
}

func (a *App) editorStructuredSectionGroups(c *ui.Context, draft *ItemDraft) {
	t := c.Theme()
	oneui.Text(c, "分区与自定义字段").FontSize(t.Rem(.94)).Bold()
	if len(draft.Sections) == 0 {
		editorFieldGroup(c, editorFieldGroupSpec{
			Key:               "item-section-empty",
			Title:             "自定义字段",
			SecondaryAddLabel: "+ 添加自定义字段…",
			OnSecondaryAdd: func() {
				a.openAddCustomFieldDialog(-1)
			},
			AddLabel: "添加字段",
			BuildAddMenu: func(menu *oneui.Menu) {
				a.editorAddFieldMenu(menu, -1)
			},
		})
	}
	for i := range draft.Sections {
		i := i
		section := &draft.Sections[i]
		var fields []editorFieldSpec
		for j := range section.Fields {
			j := j
			f := section.Fields[j]
			label := f.Label
			if label == "" {
				label = v2FieldTypeLabel(f.Type)
			}
			if binding, canonical := v2DraftCanonicalField(draft, section.ID, f); canonical {
				fields = append(fields, a.editorTextSpec(
					fmt.Sprintf("%s/%s", section.ID, f.ID),
					binding.Label,
					"",
					binding.resolve(draft),
					binding.Concealed,
					f.Type == vault.FieldTypeText,
				))
				continue
			}
			encrypted := v2FieldTypeConcealed(f)
			protSuffix := "plain"
			if encrypted {
				protSuffix = "enc"
			}
			fields = append(fields, editorFieldSpec{
				Key:         section.ID + "/" + f.ID + "/" + protSuffix,
				Label:       v2FieldTypeLabel(f.Type),
				LabelValue:  &section.Fields[j].Label,
				Placeholder: "字段值",
				Value:       &section.Fields[j].Value,
				Concealed:   encrypted,
				Multiline:   f.Type == vault.FieldTypeText,
				Busy:        a.busy,
				MenuLabel:   "字段选项：" + label,
				Trailing: func(c *ui.Context) {
					ui.Row(c).Gap(t.Space(.5)).AlignItems(ui.Center).Children(func() {
						plainVariant := oneui.ButtonGhost
						encVariant := oneui.ButtonGhost
						if !encrypted {
							plainVariant = oneui.ButtonSecondary
						} else {
							encVariant = oneui.ButtonSecondary
						}
						if oneui.Button(c, "明文", plainVariant).Disabled(a.busy || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP).Clicked() {
							draft.SetFieldProtection(i, j, false)
						}
						if oneui.Button(c, "加密", encVariant).Disabled(a.busy).Clicked() {
							draft.SetFieldProtection(i, j, true)
						}
					})
				},
				BuildMenu: func(menu *oneui.Menu) {
					if menu.Item("上移字段").Disabled(j == 0).Chosen() {
						a.moveField(i, j, -1)
					}
					if menu.Item("下移字段").Disabled(j == len(section.Fields)-1).Chosen() {
						a.moveField(i, j, 1)
					}
					menu.Separator()
					if menu.Item("删除字段").Chosen() {
						a.removeField(i, j)
					}
				},
			})
		}

		editorFieldGroup(c, editorFieldGroupSpec{
			Key:               fmt.Sprintf("item-section-%s", section.ID),
			Title:             section.Title,
			Badge:             fmt.Sprintf("%d 个字段", len(fields)),
			Fields:            fields,
			SecondaryAddLabel: "+ 添加自定义字段…",
			OnSecondaryAdd: func() {
				a.openAddCustomFieldDialog(i)
			},
			AddLabel: "添加字段",
			BuildAddMenu: func(menu *oneui.Menu) {
				a.editorAddFieldMenu(menu, i)
			},
			HeaderAction: func() {
				if oneui.IconButton(c, lucide.ChevronUp(), "上移分区", oneui.IconButtonPlain).Disabled(a.busy || i == 0).Clicked() {
					a.moveSection(i, -1)
				}
				if oneui.IconButton(c, lucide.ChevronDown(), "下移分区", oneui.IconButtonPlain).Disabled(a.busy || i == len(draft.Sections)-1).Clicked() {
					a.moveSection(i, 1)
				}
				if oneui.IconButton(c, lucide.Trash(), "删除分区", oneui.IconButtonPlain).Disabled(a.busy).Clicked() {
					a.removeSection(i)
				}
			},
		})
	}
}

func (a *App) editorAddFieldMenu(menu *oneui.Menu, sectionIndex int) {
	options := []struct {
		label string
		kind  vault.FieldType
	}{
		{"文本", vault.FieldTypeString},
		{"密码", vault.FieldTypeConcealed},
		{"一次性密码", vault.FieldTypeOTP},
		{"网址", vault.FieldTypeURL},
		{"邮箱", vault.FieldTypeEmail},
		{"日期", vault.FieldTypeDate},
		{"多行文本", vault.FieldTypeText},
	}
	for _, option := range options {
		option := option
		if menu.Item(option.label).Chosen() {
			if sectionIndex < 0 {
				a.addEditorCustomField(option.label, option.kind)
			} else {
				a.addField(sectionIndex, option.label, string(option.kind), "")
			}
		}
	}
}

func (a *App) editorTagGroup(c *ui.Context, draft *ItemDraft) {
	editorFieldGroup(c, editorFieldGroupSpec{
		Key:   "item-tags",
		Title: "标签",
		Fields: []editorFieldSpec{
			{
				Key:         "new-tag",
				Label:       "新标签",
				Placeholder: "输入标签名称",
				Value:       &draft.NewTag,
				Busy:        a.busy,
			},
		},
		ExtraRows: []func(*ui.Context){
			func(c *ui.Context) {
				t := c.Theme()
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).
					Padding(t.Space(1.5), t.Space(7)).Children(func() {
					if len(draft.Tags) == 0 {
						oneui.Text(c, "尚无标签").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Grow(1)
					} else {
						for _, tag := range draft.Tags {
							tag := tag
							if oneui.Button(c, visible(tag)+" ✕", oneui.ButtonSecondary).Disabled(a.busy).Clicked() {
								a.removeTag(tag)
							}
						}
					}
					oneui.Button(c, "添加标签", oneui.ButtonOutline).
						Disabled(a.busy || strings.TrimSpace(draft.NewTag) == "").
						OnClick(func() { a.addTag(draft.NewTag) })
				})
				oneui.Checkbox(c, &draft.Favorite, "收藏").Disabled(a.busy).
					Padding(t.Space(1), t.Space(7))
			},
		},
	})
}

func (a *App) editorNewSectionGroup(c *ui.Context, draft *ItemDraft) {
	editorFieldGroup(c, editorFieldGroupSpec{
		Key:   "item-new-section",
		Title: "添加分区",
		Fields: []editorFieldSpec{
			{
				Key:         "new-section-title",
				Label:       "分区标题",
				Placeholder: "例如：恢复信息、备用凭据",
				Value:       &draft.NewSectionTitle,
				Busy:        a.busy,
			},
		},
		ExtraRows: []func(*ui.Context){
			func(c *ui.Context) {
				t := c.Theme()
				ui.Row(c).FillWidth().Padding(t.Space(1.5), t.Space(7)).Children(func() {
					oneui.Button(c, "添加分区", oneui.ButtonSecondary).
						Disabled(a.busy || strings.TrimSpace(draft.NewSectionTitle) == "").
						OnClick(func() { a.addSection(draft.NewSectionTitle) })
				})
			},
		},
	})
}

func (a *App) addEditorCustomField(label string, kind vault.FieldType) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	sectionIndex := -1
	for i := range draft.Sections {
		if draft.Sections[i].Title == "附加字段" {
			sectionIndex = i
			break
		}
	}
	if sectionIndex < 0 {
		a.addSection("附加字段")
		sectionIndex = len(draft.Sections) - 1
	}
	a.addField(sectionIndex, label, string(kind), "")
}

func (a *App) appendEditorURL() {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	draft.URLs = append(draft.URLs, vault.ItemURL{Primary: len(draft.URLs) == 0, MatchMode: vault.URLMatchOrigin})
}

func v2MatchModeFromLabel(label string) string {
	switch label {
	case "同源":
		return vault.URLMatchOrigin
	case "同主机":
		return vault.URLMatchHost
	case "同域名":
		return vault.URLMatchDomain
	case "精确":
		return vault.URLMatchExact
	case "不填充":
		return vault.URLMatchNever
	default:
		return ""
	}
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
