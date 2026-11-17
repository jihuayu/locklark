package desktop

import (
	"fmt"

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
			{"identity.last_name", "姓"},
			{"identity.first_name", "名"},
			{"identity.middle_name", "中间名"},
			{"identity.birth_date", "出生日期"},
			{"identity.company", "公司 / 单位"},
			{"identity.department", "部门"},
			{"identity.job_title", "职位"},
			{"identity.ssn", "身份证 / 证件号"},
			{"identity.passport_number", "护照号"},
			{"identity.license_number", "驾驶证号"},
			{"identity.email", "电子邮箱"},
			{"identity.phone", "手机 / 电话"},
			{"identity.country", "国家 / 地区"},
			{"identity.state", "省 / 直辖市 / 州"},
			{"identity.city", "城市"},
			{"identity.address", "地址"},
			{"identity.address_line1", "街道地址"},
			{"identity.address_line2", "详细地址（楼栋/门牌）"},
			{"identity.postal_code", "邮政编码"},
			{"identity.website", "个人网站"},
		} {
			out = append(out, v2DetailField{Key: f.key, Label: f.label, Concealed: isConcealedKey(detail, f.key)})
		}
	}
	for _, s := range detail.Sections {
		if IsInternalMetaSection(s) {
			continue
		}
		secTitle := localizedSectionTitle(s.Title)
		for _, f := range s.Fields {
			if isCanonicalDetailDuplicate(detail, s.ID, f) {
				continue
			}
			key := s.ID + "/" + f.ID
			fieldName := localizedFieldLabel(s.ID, f.ID, f.Label)
			label := secTitle + " · " + fieldName
			out = append(out, v2DetailField{Key: key, Label: label, Concealed: isConcealedKey(detail, key)})
		}
	}
	return out
}

// v2View renders the Onevra-backed three-pane desktop vault. Model mutations
// live in v2_state.go, item_detail.go and item_editor.go; this file remains the
// editor and report view layer while onevra_view.go owns the vault shell.
func (a *App) v2View(c *ui.Context) { a.onevraVaultView(c) }

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
		clear(draft.SSHSeed)
		clear(draft.SSHPublicKey)
		draft.SSHSeed = nil
		draft.SSHPublicKey = nil
		draft.SSHKeyGenType = "Ed25519"
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

func watchtowerFlagStyle(t *ui.Theme, flag string, reuseCount int) (string, ui.Color) {
	switch flag {
	case "vulnerable":
		return "已泄露", t.Danger
	case "expired":
		return "已过期", t.Danger
	case "empty":
		return "空密码", t.Danger
	case "weak":
		return "弱密码", t.Danger
	case "common-pattern":
		return "常见模式", t.Warning
	case "short":
		return "长度过短", t.Warning
	case "low-variety":
		return "字符单一", t.Warning
	case "reused":
		if reuseCount > 1 {
			return fmt.Sprintf("重复密码 (%d 处)", reuseCount), t.Warning
		}
		return "重复密码", t.Warning
	case "unsecured-http":
		return "非加密 HTTP", t.Warning
	case "expiring-soon":
		return "即将过期", t.Warning
	case "totp-not-stored":
		return "未设 2FA", t.TextMuted
	case "passkey-not-stored":
		return "未存通行密钥", t.TextMuted
	default:
		return flag, t.TextMuted
	}
}

func (a *App) v2WatchtowerView(c *ui.Context) {
	t := c.Theme()

	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Children(func() {
			onevraPageHeader(c, "Watchtower 安全体检", "本地检查全程离线运行；HIBP 泄露前缀核验需在浏览器扩展或 CLI 中显式启用。")
		})
		oneui.Button(c, "运行本地检查", oneui.ButtonPrimary).Disabled(a.uiBusy(c) || a.session == nil).OnClick(func() {
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
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius*1.25).Background(t.Surface).Children(func() {
			onevraEmpty(c, lucide.ShieldCheck(), "尚未运行安全扫描", "点击右上角「运行本地检查」开始扫描弱密码、重复密码及 2FA 配置缺失。", nil)
		})
		return
	}

	scoreColor := t.Success
	scoreStatus := "安全状态良好"
	switch {
	case report.OverallScore < 50:
		scoreColor = t.Danger
		scoreStatus = "存在高危风险"
	case report.OverallScore < 80:
		scoreColor = t.Warning
		scoreStatus = "建议尽快加固"
	}

	onevraGroup(c, "总体评估", func(row func(func())) {
		row(func() {
			scoreBadge := ui.Column(c).MinWidth(96).Padding(t.Space(2), t.Space(3)).Radius(t.Radius).
				Background(scoreColor.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(.25))
			scoreBadge.Children(func() {
				oneui.Text(c, fmt.Sprintf("%d", report.OverallScore)).FontSize(t.Rem(2.0)).Bold().TextColor(scoreColor)
				oneui.Text(c, "满分 100").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			ui.Column(c).Grow(1).MinWidth(180).Gap(t.Space(1)).Children(func() {
				ui.Row(c).Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, fmt.Sprintf("安全评分 %d / 100", report.OverallScore)).FontSize(t.Rem(1.1)).Bold()
					onevraPill(c, scoreStatus, scoreColor)
				})
				oneui.Text(c, fmt.Sprintf("已检查 %d 项 · 跳过 %d 项", report.Checked, report.Skipped)).FontSize(t.Rem(.82)).TextColor(t.TextMuted)
			})
		})
		row(func() {
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
					numColor := t.TextMuted
					if stat.count > 0 {
						numColor = stat.color
					}
					ui.Column(c).Grow(1).MinWidth(96).Padding(t.Space(1.5), t.Space(2)).Radius(t.Radius).
						Background(t.Background).Gap(t.Space(.25)).Children(func() {
						oneui.Text(c, stat.label).FontSize(t.Rem(.72)).TextColor(t.TextMuted).SingleLine()
						oneui.Text(c, fmt.Sprintf("%d", stat.count)).FontSize(t.Rem(1.2)).Bold().TextColor(numColor)
					})
				}
			})
		})
	})

	if len(report.Findings) == 0 {
		onevraBanner(c, lucide.ShieldCheck(), "全部检查通过：未发现已知安全隐患，当前保险库状态良好。", t.Success, nil)
		return
	}

	onevraGroup(c, fmt.Sprintf("待处理风险条目 (%d)", len(report.Findings)), func(row func(func())) {
		for _, finding := range report.Findings {
			finding := finding
			row(func() {
				ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(1.5)).Children(func() {
					ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
						ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
							oneui.Text(c, visible(finding.Title)).FontSize(t.Rem(.96)).Bold().SingleLine().Ellipsis("…")
							meta := fmt.Sprintf("密码强度 %d / 100", finding.StrengthScore)
							if finding.Origin != "" {
								meta = visible(finding.Origin) + " · " + meta
							}
							oneui.Text(c, meta).FontSize(t.Rem(.76)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
						})
						if len(finding.Flags) > 0 {
							ui.Row(c).Wrap().Gap(t.Space(1)).Children(func() {
								for _, flag := range finding.Flags {
									label, color := watchtowerFlagStyle(t, flag, finding.ReuseCount)
									onevraPill(c, label, color)
								}
							})
						}
						oneui.Button(c, "打开条目", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
							a.selectItem(finding.ID, finding.Revision)
						})
					})
					if finding.BreachCount > 0 {
						onevraBanner(c, lucide.TriangleAlert(), fmt.Sprintf("该密码在公开泄露库中出现 %d 次，请立即更换。", finding.BreachCount), t.Danger, nil)
					}
				})
			})
		}
	})
}
