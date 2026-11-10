package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
	"unicode"
)

// detailURLs returns the ordered URLs of a detail, including the legacy
// top-level URL first and de-duplicating a matching primary URL.
func detailURLs(detail personal.ItemDetail) []vault.ItemURL {
	var out []vault.ItemURL
	if detail.URL != "" {
		out = append(out, vault.ItemURL{URL: detail.URL, Primary: true, MatchMode: vault.URLMatchOrigin})
	}
	for _, u := range detail.URLs {
		if u.URL == "" {
			continue
		}
		if len(out) > 0 && out[0].URL == u.URL && u.Primary {
			out[0] = u
			continue
		}
		out = append(out, u)
	}
	return out
}

func (a *App) detailForView() *personal.ItemDetail {
	if a.v2.detail == nil {
		return nil
	}
	return a.v2.detail
}

func (a *App) plainDetail() *personal.ItemDetail {
	if a.v2.detailPlain != nil &&
		a.v2.detail != nil &&
		a.v2.detailPlain.ID == a.v2.detail.ID {
		return a.v2.detailPlain
	}
	return nil
}

// loadPlainDetail reads the unmasked item for an explicit reveal/copy. It is
// intentionally asynchronous and audited through GetItemDetail(reveal=true).
func (a *App) loadPlainDetail(then func(*personal.ItemDetail)) {
	if a.session == nil || a.v2.detail == nil {
		return
	}
	s, target := a.session, *a.v2.detail
	generation := a.generation
	a.run(func() outcome {
		plain, err := s.GetItemDetail(target.ID, target.Revision, true)
		return outcome{err: err, apply: func() {
			if a.session != s || a.generation != generation || a.v2.detail == nil || a.v2.detail.ID != target.ID {
				return
			}
			a.v2.detailPlain = &plain
			if then != nil {
				then(&plain)
			}
		}}
	})
}

// fieldValue resolves a stable field key against a detail:
//
//	title, username, password, otp, notes, url, url:<index>
//	<sectionID>/<fieldID>
//	credit_card.<name> and identity.<name>
func fieldValue(detail *personal.ItemDetail, key string) (string, bool) {
	if detail == nil {
		return "", false
	}
	switch key {
	case "title":
		return detail.Title, true
	case "username":
		return detail.Username, true
	case "password":
		return detail.Password, true
	case "otp":
		return otpCode(detail.OTP), detail.OTP != ""
	case "notes":
		return detail.Notes, true
	case "url":
		urls := detailURLs(*detail)
		if len(urls) > 0 {
			return urls[0].URL, true
		}
		return "", false
	}
	if strings.HasPrefix(key, "url:") {
		var index int
		if _, err := fmt.Sscanf(key, "url:%d", &index); err == nil {
			urls := detailURLs(*detail)
			if index >= 0 && index < len(urls) {
				return urls[index].URL, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(key, "credit_card.") && detail.CreditCard != nil {
		switch strings.TrimPrefix(key, "credit_card.") {
		case "name":
			return detail.CreditCard.CardholderName, true
		case "type":
			return detail.CreditCard.Type, true
		case "number":
			return detail.CreditCard.Number, true
		case "verification":
			return detail.CreditCard.Verification, true
		case "expiry":
			return detail.CreditCard.ExpiryDate, true
		case "valid_from":
			return detail.CreditCard.ValidFrom, true
		case "pin":
			return detail.CreditCard.PIN, true
		case "issuing_bank":
			return detail.CreditCard.IssuingBank, true
		}
		return "", false
	}
	if strings.HasPrefix(key, "identity.") && detail.Identity != nil {
		switch strings.TrimPrefix(key, "identity.") {
		case "first_name":
			return detail.Identity.FirstName, true
		case "middle_name":
			return detail.Identity.MiddleName, true
		case "last_name":
			return detail.Identity.LastName, true
		case "birth_date":
			return detail.Identity.BirthDate, true
		case "company":
			return detail.Identity.Company, true
		case "job_title":
			return detail.Identity.JobTitle, true
		case "email":
			return detail.Identity.Email, true
		case "phone":
			return detail.Identity.Phone, true
		case "address":
			return joinNonEmpty(" ", detail.Identity.AddressLine1, detail.Identity.AddressLine2, detail.Identity.City, detail.Identity.State, detail.Identity.PostalCode, detail.Identity.Country), true
		case "website":
			return detail.Identity.Website, true
		}
		return "", false
	}
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 {
		for _, s := range detail.Sections {
			if s.ID != parts[0] {
				continue
			}
			for _, f := range s.Fields {
				if f.ID != parts[1] {
					continue
				}
				value := f.Value
				if f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP || strings.EqualFold(string(f.Type), "otp") {
					value = otpCode(value)
				}
				return value, true
			}
		}
	}
	return "", false
}

func joinNonEmpty(sep string, parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// otpCode renders a live TOTP code for an otpauth URI or base32 seed. Invalid
// or empty values are returned unchanged so a plain stored value remains
// visible rather than being silently replaced by an error string.
func otpCode(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	config, err := totp.Parse(value)
	if err != nil {
		return value
	}
	code, err := config.At(time.Now().Unix())
	if err != nil {
		return value
	}
	return code.Value()
}

func isConcealedKey(detail *personal.ItemDetail, key string) bool {
	if detail == nil {
		return false
	}
	switch key {
	case "password", "otp", "notes":
		return true
	}
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 {
		for _, s := range detail.Sections {
			if s.ID != parts[0] {
				continue
			}
			for _, f := range s.Fields {
				if f.ID == parts[1] {
					return f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP
				}
			}
		}
	}
	switch key {
	case "credit_card.number", "credit_card.verification", "credit_card.pin":
		return true
	}
	return false
}

func fieldLabel(key string) string {
	switch key {
	case "title":
		return "标题"
	case "username":
		return "用户名"
	case "password":
		return "密码"
	case "otp":
		return "一次性验证码"
	case "notes":
		return "备注"
	case "url":
		return "网站"
	}
	if strings.HasPrefix(key, "url:") {
		return "网站 " + strings.TrimPrefix(key, "url:")
	}
	if strings.HasPrefix(key, "credit_card.") {
		return "信用卡 " + strings.TrimPrefix(key, "credit_card.")
	}
	if strings.HasPrefix(key, "identity.") {
		return "身份 " + strings.TrimPrefix(key, "identity.")
	}
	if parts := strings.SplitN(key, "/", 2); len(parts) == 2 {
		return parts[1]
	}
	return key
}

// revealField toggles a concealed field. The unmasked value is held only in
// detailPlain and is dropped when the exposure timer fires or the vault locks.
func (a *App) revealField(key string) {
	if a.v2.detail == nil {
		return
	}
	if a.v2.revealed[key] {
		delete(a.v2.revealed, key)
		a.v2.revealUntil = time.Time{}
		a.status = "字段已隐藏"
		return
	}
	a.loadPlainDetail(func(plain *personal.ItemDetail) {
		if _, ok := fieldValue(plain, key); !ok {
			a.status = "字段不存在"
			return
		}
		a.v2.revealed[key] = true
		a.v2.revealUntil = time.Now().Add(15 * time.Second)
		a.status = "字段显示 15 秒"
	})
}

func (a *App) RevealField(key string) { a.revealField(key) }

func (a *App) hideRevealed() {
	a.v2.revealed = map[string]bool{}
	a.v2.revealUntil = time.Time{}
	a.v2.detailPlain = nil
}

// copyField copies a field with an owned clipboard lease. The background
// ticker performs the clear even when no View is rendering.
func (a *App) copyField(key string) {
	if a.v2.detail == nil {
		return
	}
	a.loadPlainDetail(func(plain *personal.ItemDetail) {
		value, ok := fieldValue(plain, key)
		if !ok {
			a.status = "字段不存在"
			return
		}
		if value == "" {
			a.status = "字段为空"
			return
		}
		s, generation := a.session, a.generation
		valid := func() bool {
			return a.session == s && a.generation == generation && a.v2.detail != nil
		}
		timeout := a.clipboardTimeout()
		if err := a.writeClipboard([]byte(value), clipboardDeadline(timeout), valid); err != nil {
			a.status = message(err)
			return
		}
		a.status = clipboardStatus(timeout)
	})
}

func (a *App) CopyField(key string) { a.copyField(key) }

// otpForDetail returns the current live code for the item's top-level OTP or
// the first OTP-typed custom field.
func otpForDetail(detail *personal.ItemDetail) string {
	if detail == nil {
		return ""
	}
	if detail.OTP != "" {
		return otpCode(detail.OTP)
	}
	for _, s := range detail.Sections {
		for _, f := range s.Fields {
			if f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP {
				return otpCode(f.Value)
			}
		}
	}
	return ""
}

// ---------- Item history ----------

func (a *App) openHistory() {
	if a.v2.detail == nil {
		return
	}
	a.v2.historyOpen = true
	a.v2.editing = false
	a.v2.generator.open = false
	a.touchActivity()
}

func (a *App) OpenHistory() { a.openHistory() }

func (a *App) closeHistory() { a.v2.historyOpen = false }

func (a *App) CloseHistory() { a.closeHistory() }

// restoreHistory restores the value snapshot at historyIndex (newest first as
// stored by personal). The store appends the replaced value back to history.
func (a *App) restoreHistory(index int) error {
	if a.v2.detail == nil || a.session == nil {
		return personal.ErrMutationRefused
	}
	if index < 0 || index >= len(a.v2.detail.History) {
		return personal.ErrMutationRefused
	}
	s := a.session
	id, revision := a.v2.detail.ID, a.v2.detail.Revision
	filter := a.currentFilter()
	query := a.currentV2Query()
	var opErr error
	var saved personal.ItemDetail
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		newRevision, err := s.RestoreHistory(id, revision, index, g)
		if err != nil {
			opErr = err
			return nativeResult{err: err}
		}
		saved, err = s.GetItemDetail(id, newRevision, false)
		if err != nil {
			opErr = err
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
		a.v2.detail = &saved
		a.v2.selectedID, a.v2.selectedRevision = saved.ID, saved.Revision
		a.v2.historyOpen = true
		a.status = "条目历史已还原"
	})
	if !ok {
		if opErr == nil {
			opErr = personal.ErrMutationRefused
		}
		return opErr
	}
	return opErr
}

func (a *App) RestoreHistory(index int) error { return a.restoreHistory(index) }

// ---------- Large Type ----------

func (a *App) showLargeType(key string) {
	a.loadPlainDetail(func(plain *personal.ItemDetail) {
		value, ok := fieldValue(plain, key)
		if !ok {
			a.status = "字段不存在"
			return
		}
		a.v2.largeTypeOpen = true
		a.v2.largeTypeKey = key
		a.v2.largeTypeLabel = fieldLabel(key)
		a.v2.largeTypeValue = value
	})
}

func (a *App) ShowLargeType(key string) { a.showLargeType(key) }

func (a *App) closeLargeType() {
	a.v2.largeTypeOpen = false
	a.v2.largeTypeKey = ""
	a.v2.largeTypeLabel = ""
	a.v2.largeTypeValue = ""
}

func (a *App) CloseLargeType() { a.closeLargeType() }

func (a *App) largeTypeView(c *ui.Context) {
	if !a.v2.largeTypeOpen {
		return
	}
	t := c.Theme()
	runes := []rune(a.v2.largeTypeValue)

	ui.Column(c.Key("large-type")).Role(ui.RoleGroup).Label("大号显示").Fill().Background(t.Background).Children(func() {
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().Children(func() {
			ui.Column(c).FillWidth().MinWidth(0).Padding(t.Space(5)).Gap(t.Space(3)).Children(func() {
				// Header
				ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
					iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
						Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
					iconBox.Children(func() {
						oneui.Icon(c, lucide.ScanText()).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
					})
					ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
						oneui.Text(c, "大号显示 · "+a.v2.largeTypeLabel).FontSize(t.Rem(1.35)).Bold().SingleLine()
						oneui.Text(c, "逐字核对长密码或一次性验证码；关闭后将立即从界面清除。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					})
					oneui.Button(c, "关闭大号显示", oneui.ButtonPrimary).OnClick(a.closeLargeType)
				})

				// Full value hero card
				ui.Column(c).FillWidth().Border(1, t.Accent.Alpha(.45)).Radius(t.Radius).Background(t.Surface).
					Padding(t.Space(3.5)).Gap(t.Space(1.5)).Children(func() {
					ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
						oneui.Text(c, "完整内容").FontSize(t.Rem(.76)).Bold().TextColor(t.TextMuted).Grow(1)
						oneui.Badge(c, fmt.Sprintf("共 %d 个字符", len(runes)), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
					})
					oneui.Text(c, visible(a.v2.largeTypeValue)).FontSize(t.Rem(1.65)).Bold().Wrap()
				})

				// Character index / grouping cards
				if len(runes) > 0 {
					ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
						Padding(t.Space(3)).Gap(t.Space(2.5)).Children(func() {
						ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
							oneui.Text(c, "逐字符索引对照").Bold().Grow(1)
							oneui.Text(c, "数字以强调色标出 · 符号以警示色标出").FontSize(t.Rem(.75)).TextColor(t.TextMuted)
						})
						ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.25)).Children(func() {
							for i, r := range runes {
								charColor := t.Text
								borderColor := t.Border
								switch {
								case unicode.IsDigit(r):
									charColor = t.Accent
									borderColor = t.Accent.Alpha(.45)
								case !unicode.IsLetter(r):
									charColor = t.Warning
									borderColor = t.Warning.Alpha(.45)
								}
								glyph := visible(string(r))
								if r == ' ' {
									glyph = "␣"
								}
								tile := ui.Column(c).MinWidth(44).Border(1, borderColor).Radius(t.Radius).
									Background(t.Background).Padding(t.Space(1.25), t.Space(1.5)).
									AlignItems(ui.Center).Justify(ui.Center).Gap(t.Space(.5))
								tile.Children(func() {
									oneui.Text(c, glyph).FontSize(t.Rem(1.25)).Bold().TextColor(charColor)
									oneui.Text(c, fmt.Sprintf("%d", i+1)).FontSize(t.Rem(.68)).TextColor(t.TextMuted)
								})
							}
						})
					})
				}
			})
		})
	})
}


