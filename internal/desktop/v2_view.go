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

// v2View renders the Onevra-backed three-pane desktop vault. Model mutations
// live in v2_state.go, item_detail.go and item_editor.go; this file remains the
// editor and report view layer while onevra_view.go owns the vault shell.
func (a *App) v2View(c *ui.Context) { a.onevraVaultView(c) }

func (a *App) v2EditorView(c *ui.Context) {
	draft := a.v2.draft
	if draft == nil {
		return
	}
	ui.Text(c, "编辑条目").FontSize(22).Bold()
	ui.Text(c, "保存后将生成新修订版本，原有字段值自动加密归入历史版本。").FontSize(12)
	category := string(draft.Category)
	sel := ui.Select(c, &category, v2CategoryOptions()).Disabled(a.busy)
	if sel.Changed() {
		a.setDraftCategory(vault.ItemCategory(category))
	}
	ui.TextInput(c, &draft.Title).Label("标题").Placeholder("例如：GitHub、公司邮箱、主力信用卡").Disabled(a.busy)
	ui.TextInput(c, &draft.Username).Label("用户名").Placeholder("用户名、邮箱或账号标识").Disabled(a.busy)
	ui.TextInput(c, &draft.Password).Label("密码").Placeholder("输入或使用下方生成器创建高强度密码").Password().Disabled(a.busy)
	ui.TextInput(c, &draft.OTP).Label("一次性验证码配置").Placeholder("otpauth://totp/... 或 Base32 密钥").Disabled(a.busy)
	ui.TextInput(c, &draft.URL).Label("网站").Placeholder("https://example.com").Disabled(a.busy)
	ui.TextInput(c, &draft.Notes).Label("备注").Placeholder("加密安全备注、恢复码或补充说明").Password().Disabled(a.busy)
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
	ui.Text(c, "本地检查全程离线运行；HIBP 泄露前缀核验需在浏览器扩展或 CLI 中显式启用。").FontSize(12)
	report := a.v2.watchtower
	if report == nil {
		ui.Text(c, "点击右上角「运行本地检查」开始扫描弱密码、重复密码及 2FA 配置缺失。").FontSize(13)
		return
	}
	ui.Text(c, fmt.Sprintf("安全评分 %d / 100 · 已检查 %d 项 · 跳过 %d 项", report.OverallScore, report.Checked, report.Skipped)).FontSize(18).Bold()
	ui.Row(c).Gap(12).Children(func() {
		ui.Text(c, fmt.Sprintf("已泄露：%d", report.Counts.Vulnerable))
		ui.Text(c, fmt.Sprintf("重复密码：%d", report.Counts.Reused))
		ui.Text(c, fmt.Sprintf("弱密码：%d", report.Counts.Weak))
		ui.Text(c, fmt.Sprintf("非加密 HTTP：%d", report.Counts.UnsecuredHTTP))
		ui.Text(c, fmt.Sprintf("未设 2FA：%d", report.Counts.TOTPNotStored))
		ui.Text(c, fmt.Sprintf("即将过期：%d", report.Counts.Expiring))
	})
	if len(report.Findings) == 0 {
		ui.Text(c, "未发现已知安全隐患，当前保险库状态良好。").FontSize(13)
		return
	}
	for _, finding := range report.Findings {
		finding := finding
		ui.Column(c).Gap(4).Children(func() {
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, fmt.Sprintf("%s · 强度 %d · %s", visible(finding.Title), finding.StrengthScore, strings.Join(finding.Flags, ", "))).Bold().Grow(1)
				ui.Button(c, "打开条目").OnClick(func() { a.selectItem(finding.ID, finding.Revision) })
			})
			if finding.BreachCount > 0 {
				ui.Text(c, fmt.Sprintf("该密码在公开泄露库中出现 %d 次，请立即更换。", finding.BreachCount)).FontSize(12)
			}
		})
	}
}

