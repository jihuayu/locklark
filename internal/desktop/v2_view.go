package desktop

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
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
// unmasked value is used only for an explicit reveal of that field, or for the
// narrow password-only disclosure supplied to v2FieldDisplayWith.
func v2FieldDisplay(masked, plain *personal.ItemDetail, key string, revealed bool) string {
	return v2FieldDisplayWith(masked, plain, key, revealed, nil)
}

// v2FieldDisplayWith is v2FieldDisplay with a narrow fallback for the
// password-only revealPasswords disclosure. The fallback is consulted only
// when the field is concealed, not explicitly revealed, and no plaintext
// detail is loaded (the masked detail itself is being rendered).
func v2FieldDisplayWith(masked, plain *personal.ItemDetail, key string, revealed bool, narrow func() string) string {
	if !revealed && masked != nil && plain == nil && isConcealedKey(masked, key) && narrow != nil {
		if value := narrow(); value != "" {
			return value
		}
	}
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

func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	t := c.Theme()

	// Editor header
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

func watchtowerFlagBadge(flag string, reuseCount int) (string, oneui.BadgeTone) {
	switch flag {
	case "vulnerable":
		return "已泄露", oneui.BadgeDanger
	case "expired":
		return "已过期", oneui.BadgeDanger
	case "empty":
		return "空密码", oneui.BadgeDanger
	case "weak":
		return "弱密码", oneui.BadgeDanger
	case "common-pattern":
		return "常见模式", oneui.BadgeWarning
	case "short":
		return "长度过短", oneui.BadgeWarning
	case "low-variety":
		return "字符单一", oneui.BadgeWarning
	case "reused":
		if reuseCount > 1 {
			return fmt.Sprintf("重复密码 (%d 处)", reuseCount), oneui.BadgeWarning
		}
		return "重复密码", oneui.BadgeWarning
	case "unsecured-http":
		return "非加密 HTTP", oneui.BadgeWarning
	case "expiring-soon":
		return "即将过期", oneui.BadgeWarning
	case "totp-not-stored":
		return "未设 2FA", oneui.BadgeNeutral
	case "passkey-not-stored":
		return "未存通行密钥", oneui.BadgeNeutral
	default:
		return flag, oneui.BadgeNeutral
	}
}

func (a *App) v2WatchtowerView(c *ui.Context) {
	t := c.Theme()

	// Header
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
		iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
			Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
		iconBox.Children(func() {
			oneui.Icon(c, lucide.Shield()).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, "Watchtower 安全体检").FontSize(t.Rem(1.35)).Bold().SingleLine()
			oneui.Text(c, "本地检查全程离线运行；HIBP 泄露前缀核验需在浏览器扩展或 CLI 中显式启用。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		})
		oneui.Button(c, "运行本地检查", oneui.ButtonPrimary).Disabled(a.busy || a.session == nil).OnClick(func() {
			s := a.session
			if s == nil {
				return
			}
			a.run(func() outcome {
				report, err := s.Watchtower("", false)
				return outcome{err: err, apply: func() { a.v2.watchtower = &report }}
			})
		})
	})

	report := a.v2.watchtower
	if report == nil {
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(5)).AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(2)).Children(func() {
			badgeBox := ui.Box(c).Size(t.Space(12), t.Space(12)).Radius(t.Space(3)).
				Background(t.Accent.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center)
			badgeBox.Children(func() {
				oneui.Icon(c, lucide.ShieldCheck()).Size(t.Space(6), t.Space(6)).TextColor(t.Accent)
			})
			oneui.Text(c, "尚未运行安全扫描").FontSize(t.Rem(1.05)).Bold()
			oneui.Text(c, "点击右上角「运行本地检查」开始扫描弱密码、重复密码及 2FA 配置缺失。").FontSize(t.Rem(.85)).TextColor(t.TextMuted).Wrap()
		})
		return
	}

	// Security Score Hero Card
	scoreColor := t.Success
	scoreStatus := "安全状态良好"
	scoreTone := oneui.BadgeSuccess
	switch {
	case report.OverallScore < 50:
		scoreColor = t.Danger
		scoreStatus = "存在高危风险"
		scoreTone = oneui.BadgeDanger
	case report.OverallScore < 80:
		scoreColor = t.Warning
		scoreStatus = "建议尽快加固"
		scoreTone = oneui.BadgeWarning
	}

	ui.Row(c).FillWidth().Border(1, scoreColor.Alpha(.45)).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3.5)).Wrap().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
		scoreBadge := ui.Column(c).MinWidth(110).Padding(t.Space(2), t.Space(3)).Radius(t.Radius).
			Background(scoreColor.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(.25))
		scoreBadge.Children(func() {
			oneui.Text(c, fmt.Sprintf("%d", report.OverallScore)).FontSize(t.Rem(2.1)).Bold().TextColor(scoreColor)
			oneui.Text(c, "满分 100").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
		})
		ui.Column(c).Grow(1).MinWidth(180).Gap(t.Space(1)).Children(func() {
			ui.Row(c).Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, fmt.Sprintf("安全评分 %d / 100", report.OverallScore)).FontSize(t.Rem(1.15)).Bold()
				oneui.Badge(c, scoreStatus, oneui.BadgeOptions{Tone: scoreTone})
			})
			oneui.Text(c, fmt.Sprintf("已检查 %d 项 · 跳过 %d 项", report.Checked, report.Skipped)).FontSize(t.Rem(.84)).TextColor(t.TextMuted)
		})
	})

	// Summary Stat Pills / Boxes
	stats := []struct {
		label string
		count int
		color ui.Color
	}{
		{"已泄露", report.Counts.Vulnerable, t.Danger},
		{"重复密码", report.Counts.Reused, t.Warning},
		{"弱密码", report.Counts.Weak, t.Danger},
		{"非加密 HTTP", report.Counts.UnsecuredHTTP, t.Warning},
		{"未设 2FA", report.Counts.TOTPNotStored, t.Warning},
		{"即将过期", report.Counts.Expiring, t.Warning},
	}
	ui.Row(c).FillWidth().Wrap().Gap(t.Space(2)).Children(func() {
		for _, stat := range stats {
			stat := stat
			borderColor := t.Border
			numColor := t.Text
			bgColor := t.Surface
			if stat.count > 0 {
				borderColor = stat.color.Alpha(.5)
				numColor = stat.color
				bgColor = stat.color.Alpha(.06)
			}
			ui.Column(c).Grow(1).MinWidth(120).Border(1, borderColor).Radius(t.Radius).Background(bgColor).
				Padding(t.Space(2), t.Space(2.5)).Gap(t.Space(.5)).Children(func() {
				oneui.Text(c, stat.label).FontSize(t.Rem(.76)).TextColor(t.TextMuted).SingleLine()
				oneui.Text(c, fmt.Sprintf("%d", stat.count)).FontSize(t.Rem(1.25)).Bold().TextColor(numColor)
			})
		}
	})

	if len(report.Findings) == 0 {
		a.onevraNoticeCard(c, "全部检查通过", "未发现已知安全隐患，当前保险库状态良好。", t.Success)
		return
	}

	// Findings Cards
	oneui.Text(c, fmt.Sprintf("待处理风险条目 (%d)", len(report.Findings))).FontSize(t.Rem(.92)).Bold().TextColor(t.TextMuted)
	for _, finding := range report.Findings {
		finding := finding
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
				ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
					oneui.Text(c, visible(finding.Title)).FontSize(t.Rem(1.0)).Bold().SingleLine().Ellipsis("…")
					meta := fmt.Sprintf("密码强度 %d / 100", finding.StrengthScore)
					if finding.Origin != "" {
						meta = visible(finding.Origin) + " · " + meta
					}
					oneui.Text(c, meta).FontSize(t.Rem(.76)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
				})
				oneui.Button(c, "打开条目", oneui.ButtonSecondary).Disabled(a.busy).OnClick(func() {
					a.selectItem(finding.ID, finding.Revision)
				})
			})
			if len(finding.Flags) > 0 {
				ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
					for _, flag := range finding.Flags {
						label, tone := watchtowerFlagBadge(flag, finding.ReuseCount)
						oneui.Badge(c, label, oneui.BadgeOptions{Tone: tone})
					}
				})
			}
			if finding.BreachCount > 0 {
				ui.Row(c).FillWidth().Border(1, t.Danger.Alpha(.45)).Radius(t.Radius).Background(t.Danger.Alpha(.08)).
					Padding(t.Space(1.5), t.Space(2)).AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Icon(c, lucide.TriangleAlert()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Danger)
					oneui.Text(c, fmt.Sprintf("该密码在公开泄露库中出现 %d 次，请立即更换。", finding.BreachCount)).
						FontSize(t.Rem(.8)).TextColor(t.Danger).Grow(1).Wrap()
				})
			}
		})
	}
}
