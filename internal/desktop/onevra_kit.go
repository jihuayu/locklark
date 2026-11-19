package desktop

import (
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/theme"
)

// onevra_kit.go is the shared visual language of the desktop: palettes,
// typography helpers and the small building blocks (groups, rows, pills,
// banners, approval cards) every surface composes. Views should use these
// instead of hand-rolled borders and colors.

const onevraMonoFont = "Cascadia Mono, Consolas, SF Mono, Menlo, monospace"

// Accent themes offered in Settings → Appearance. Terracotta is the default.
const (
	accentTerracotta = "terracotta"
	accentTeal       = "teal"
)

// onevraTheme is the per-frame theme: a complete light or dark palette for
// the chosen accent family, the explicit light/dark override, density, and
// the desktop's contrast preference.
func (a *App) onevraTheme(c *ui.Context) *ui.Theme {
	s := a.settingsSnapshot()
	var base *ui.Theme
	switch s.Theme {
	case "light":
		base = theme.LightPalette()
	case "dark":
		base = theme.DarkPalette()
	default:
		base = theme.Onevra(c)
	}
	t := *base
	applyAccent(&t, s.Accent)
	if c.Preferences().HighContrast {
		t.Border = t.Border.Mix(t.Text, 0.45)
		t.TextMuted = t.TextMuted.Mix(t.Text, 0.4)
		t.Focus.A = 255
	}
	if scale := c.Preferences().TextScale; s.Theme != "system" && scale > 0 && scale != 1 {
		t.FontSize *= scale
	}
	if s.InterfaceDensity == "compact" {
		t.Spacing = 3.25
	}
	return &t
}

// SetAccent validates, applies and persists appearance.accent.
func (a *App) SetAccent(accent string) error {
	s := a.settingsSnapshot()
	s.Accent = accent
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	a.refreshClipboardClearSeconds(validated)
	a.applyAppearanceToRuntime()
	return a.SaveSettings()
}

func (a *App) compactDensity() bool {
	return a.settingsSnapshot().InterfaceDensity == "compact"
}

type palette struct {
	background, surface, hover, pressed, border, text, muted string
	accent, accentText, danger, warning, success             string
}

// Terracotta pairs warm paper and ember neutrals with the accent so it reads
// as part of the surface; teal pairs with cooler slate neutrals.
var (
	terracottaLight = palette{
		background: "#fbf8f5", surface: "#ffffff", hover: "#f3ece6", pressed: "#e9dfd7", border: "#e8ddd3",
		text: "#2e2622", muted: "#7c6f66", accent: "#bd481b", accentText: "#ffffff",
		danger: "#b4444c", warning: "#b45309", success: "#2f855a",
	}
	terracottaDark = palette{
		background: "#1d1815", surface: "#27201c", hover: "#322924", pressed: "#3c312b", border: "#43372f",
		text: "#f2eae3", muted: "#b8a99e", accent: "#e98a5e", accentText: "#2a150b",
		danger: "#e58f95", warning: "#e6b567", success: "#79bea1",
	}
	tealLight = palette{
		background: "#f7f9f8", surface: "#ffffff", hover: "#edf1ef", pressed: "#e0e7e4", border: "#dde4e1",
		text: "#1f2523", muted: "#66716e", accent: "#1f7a68", accentText: "#ffffff",
		danger: "#b4444c", warning: "#b45309", success: "#2f855a",
	}
	tealDark = palette{
		background: "#151a19", surface: "#1e2422", hover: "#28302d", pressed: "#313a37", border: "#333c39",
		text: "#e8eeec", muted: "#a3adaa", accent: "#5cc2a8", accentText: "#0f2621",
		danger: "#e58f95", warning: "#e6b567", success: "#79bea1",
	}
)

func applyAccent(t *ui.Theme, accent string) {
	p := terracottaLight
	switch {
	case accent == accentTeal && t.Dark:
		p = tealDark
	case accent == accentTeal:
		p = tealLight
	case t.Dark:
		p = terracottaDark
	}
	black := ui.RGB(0, 0, 0)
	white := ui.RGB(255, 255, 255)
	t.Background = ui.Hex(p.background)
	t.Surface = ui.Hex(p.surface)
	t.SurfaceHover = ui.Hex(p.hover)
	t.SurfacePressed = ui.Hex(p.pressed)
	t.Border = ui.Hex(p.border)
	t.Text = ui.Hex(p.text)
	t.TextMuted = ui.Hex(p.muted)
	c := ui.Hex(p.accent)
	t.Accent = c
	if t.Dark {
		t.AccentHover = c.Mix(white, 0.12)
		t.AccentPressed = c.Mix(black, 0.12)
		t.Selection = c.Alpha(0.22)
		t.Focus = c.Alpha(0.8)
		t.Scrollbar = t.Text.Alpha(.35)
	} else {
		t.AccentHover = c.Mix(black, 0.12)
		t.AccentPressed = c.Mix(black, 0.25)
		t.Selection = c.Alpha(0.16)
		t.Focus = c.Alpha(0.55)
		t.Scrollbar = t.Text.Alpha(.30)
	}
	t.AccentText = ui.Hex(p.accentText)
	t.Danger = ui.Hex(p.danger)
	t.Warning = ui.Hex(p.warning)
	t.Success = ui.Hex(p.success)
}

// onevraSidebarSurface is the tinted navigation surface.
func onevraSidebarSurface(t *ui.Theme) ui.Color { return t.Background.Mix(t.Text, .035) }

// ---------- identity helpers ----------

// avatarColor derives a stable, non-secret color from an item title so rows
// are recognizable at a glance without fetching remote icons.
func avatarColor(title string) ui.Color {
	colors := []string{"#c2410c", "#b45309", "#4d7c0f", "#047857", "#0e7490", "#1d4ed8", "#6d28d9", "#a21caf", "#be123c", "#475569"}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(title))))
	return ui.Hex(colors[h.Sum32()%uint32(len(colors))])
}

func avatarInitial(title string) string {
	for _, r := range strings.TrimSpace(visible(title)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return strings.ToUpper(string(r))
		}
	}
	if r, _ := utf8.DecodeRuneInString(title); r != utf8.RuneError && r != 0 {
		return string(r)
	}
	return "?"
}

// usesMonogram reports whether the category is identified by its title.
func usesMonogram(category vault.ItemCategory) bool {
	switch category {
	case vault.CategoryLogin, vault.CategoryPassword, vault.CategoryAPICredential, vault.CategoryDatabase, vault.CategoryServer:
		return true
	}
	return false
}

// onevraAvatarBox returns the standard rounded square container used by all item avatars.
func onevraAvatarBox(c *ui.Context, size float32, bg ui.Color) ui.Element {
	return ui.Box(c).Size(size, size).Shrink(0).Radius(size * .28).Background(bg).
		AlignItems(ui.Center).Justify(ui.Center)
}

// onevraAvatar identifies an item: a colored monogram for accounts, or the
// category glyph for structured records.
func onevraAvatar(c *ui.Context, title string, category vault.ItemCategory, size float32) {
	t := c.Theme()
	if usesMonogram(category) {
		onevraAvatarBox(c, size, avatarColor(title)).Children(func() {
			oneui.Text(c, avatarInitial(title)).FontSize(size * .44).Bold().TextColor(ui.RGB(255, 255, 255)).SingleLine()
		})
		return
	}
	onevraAvatarBox(c, size, t.Accent.Alpha(.12)).Children(func() {
		oneui.Icon(c, onevraCategoryIcon(category)).Size(size*.5, size*.5).TextColor(t.Accent)
	})
}

var (
	starFilledOnce sync.Once
	starFilledSVG  *ui.SVG
)

// onevraStarFilled is Lucide's star path filled with currentColor.
func onevraStarFilled() *ui.SVG {
	starFilledOnce.Do(func() {
		starFilledSVG = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/></svg>`))
	})
	return starFilledSVG
}

// ---------- text helpers ----------

// onevraSecretText renders a revealed secret in monospace with digits and
// symbols tinted, so look-alike characters (0/O, l/1) are distinguishable.
func onevraSecretText(c *ui.Context, value string) {
	t := c.Theme()
	digit := ui.Hex("#2563eb")
	if t.Dark {
		digit = ui.Hex("#7aa7ff")
	}
	var spans []ui.Span
	for _, r := range value {
		color := t.Text
		switch {
		case r >= '0' && r <= '9':
			color = digit
		case r < 128 && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && r != ' ':
			color = t.Danger
		}
		if n := len(spans); n > 0 && spans[n-1].Color == color {
			spans[n-1].Text += string(r)
			continue
		}
		spans = append(spans, ui.Span{Text: string(r), Color: color})
	}
	ui.RichText(c, spans...).Font(onevraMonoFont).FontSize(t.Rem(.95)).Wrap()
}

// onevraPill is a small tinted status label.
func onevraPill(c *ui.Context, text string, color ui.Color) {
	t := c.Theme()
	ui.Row(c).Shrink(0).AlignItems(ui.Center).Padding(t.Space(.5), t.Space(2)).Radius(t.Space(3)).Background(color.Alpha(.12)).Children(func() {
		oneui.Text(c, text).FontSize(t.Rem(.72)).Bold().TextColor(color).SingleLine()
	})
}

// onevraBanner is a full-width tinted state notice with trailing actions.
func onevraBanner(c *ui.Context, icon *ui.SVG, text string, color ui.Color, actions func()) {
	t := c.Theme()
	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), t.Space(3)).
		Radius(t.Radius).Background(color.Alpha(.10)).Children(func() {
		if icon != nil {
			oneui.Icon(c, icon).Size(t.Space(4), t.Space(4)).TextColor(color)
		}
		oneui.Text(c, text).FontSize(t.Rem(.86)).Grow(1).MinWidth(0).Wrap()
		if actions != nil {
			actions()
		}
	})
}

// onevraPageHeader is the title block of a full page (settings, tools).
func onevraPageHeader(c *ui.Context, title, description string) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(t.Space(1)).Children(func() {
		oneui.Text(c, title).FontSize(t.Rem(1.45)).Bold()
		if description != "" {
			oneui.Text(c, description).FontSize(t.Rem(.82)).TextColor(t.TextMuted).Wrap()
		}
	})
}

// onevraSelect is a compact drop-down with display labels.
func onevraSelect[T comparable](c *ui.Context, label string, value T, options []T, text func(T) string) (T, bool) {
	v := value
	sel := oneui.Select(c, &v)
	sel.Trigger.Label(label)
	sel.Trigger.Children(func() { oneui.Text(c, text(v)).SingleLine() })
	sel.Popup(func(panel ui.Element) {
		for _, o := range options {
			o := o
			sel.Item(o).Children(func() { oneui.Text(c, text(o)).SingleLine() })
		}
	})
	return v, v != value
}

// ---------- grouped rows (settings, editors, tools) ----------

// onevraGroup is one bordered surface with an optional caption above it and
// hairline-divided rows inside: the basic unit of every form-like page.
func onevraGroup(c *ui.Context, title string, build func(row func(content func()))) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
		if title != "" {
			oneui.Text(c, title).FontSize(t.Rem(.76)).Bold().TextColor(t.TextMuted).Padding(0, t.Space(1))
		}
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius * 1.25).Background(t.Surface).Children(func() {
			n := 0
			build(func(content func()) {
				if n > 0 {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				n++
				ui.Row(c).FillWidth().MinWidth(0).Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.75), t.Space(4)).Children(content)
			})
		})
	})
}

// onevraSettingRow is the label / description | control layout.
func onevraSettingRow(c *ui.Context, title, desc string, control func()) {
	t := c.Theme()
	ui.Column(c).Grow(1).MinWidth(220).Gap(t.Space(.5)).Children(func() {
		oneui.Text(c, title).FontSize(t.Rem(.92))
		if desc != "" {
			oneui.Text(c, desc).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		}
	})
	if control != nil {
		ui.Row(c).Shrink(0).AlignItems(ui.Center).Gap(t.Space(1.5)).Children(control)
	}
}

// onevraSettingsGroup is onevraGroup whose rows are setting rows.
func onevraSettingsGroup(c *ui.Context, title string, build func(row func(title, desc string, control func()))) {
	onevraGroup(c, title, func(row func(func())) {
		build(func(title, desc string, control func()) {
			row(func() { onevraSettingRow(c, title, desc, control) })
		})
	})
}

// onevraSwitch is a switch bound to a setting; it reports the new value.
func onevraSwitch(c *ui.Context, label string, value bool) (bool, bool) {
	v := value
	oneui.Switch(c, &v, label, oneui.SwitchOptions{HideLabel: true})
	return v, v != value
}

// onevraSegmented is a small segmented control for 2–4 exclusive options.
func onevraSegmented(c *ui.Context, value string, options [][2]string) (string, bool) {
	t := c.Theme()
	chosen := value
	ui.Row(c).AlignItems(ui.Center).Gap(t.Space(.5)).Padding(t.Space(.5)).Radius(t.Radius).Background(t.Text.Alpha(.05)).Children(func() {
		for _, o := range options {
			o := o
			variant := oneui.ButtonGhost
			if value == o[0] {
				variant = oneui.ButtonSecondary
			}
			if oneui.Button(c, o[1], variant).Clicked() {
				chosen = o[0]
			}
		}
	})
	return chosen, chosen != value
}

// onevraKeyCap renders a keyboard shortcut.
func onevraKeyCap(c *ui.Context, text string) {
	t := c.Theme()
	oneui.Text(c, text).Font(onevraMonoFont).FontSize(t.Rem(.78)).Padding(t.Space(.5), t.Space(2)).
		Radius(t.Space(1)).Border(1, t.Border).Background(t.Background)
}

// onevraEmpty is a centered empty state.
func onevraEmpty(c *ui.Context, icon *ui.SVG, title, body string, actions func()) {
	t := c.Theme()
	ui.Column(c).Fill().Grow(1).AlignItems(ui.Center).Justify(ui.Center).Padding(t.Space(6)).Gap(t.Space(2)).Children(func() {
		oneui.Icon(c, icon).Size(t.Space(8), t.Space(8)).TextColor(t.TextMuted.Alpha(.6))
		oneui.Text(c, title).Bold()
		if body != "" {
			oneui.Text(c, body).FontSize(t.Rem(.8)).TextColor(t.TextMuted).Wrap()
		}
		if actions != nil {
			actions()
		}
	})
}

func minutesLabel(m int) string {
	switch {
	case m == 0:
		return "从不"
	case m >= 60 && m%60 == 0:
		return fmt.Sprintf("%d 小时", m/60)
	default:
		return fmt.Sprintf("%d 分钟", m)
	}
}

func secondsLabel(s int) string {
	switch {
	case s == 0:
		return "从不"
	case s >= 60 && s%60 == 0:
		return fmt.Sprintf("%d 分钟", s/60)
	default:
		return fmt.Sprintf("%d 秒", s)
	}
}

// ---------- approvals ----------

// Approval surfaces share one template: who is asking (origin), what for
// (facts), why it matters (notices) and an explicit decision. Each fact stays
// one text node ("标签：值") for automation and screen readers.

func approvalCentered(c *ui.Context, build func()) {
	t := c.Theme()
	oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().Grow(1).Children(func() {
		ui.Column(c).FillWidth().AlignItems(ui.Center).Padding(t.Space(6), t.Space(4)).Children(func() {
			ui.Column(c).Width(620).MaxWidth(620).Gap(t.Space(3)).Children(build)
		})
	})
}

func approvalCard(c *ui.Context, icon *ui.SVG, tone ui.Color, heading string, build func()) {
	approvalCardWith(c, icon, tone, heading, false, nil, build)
}

// approvalCardWith adds a compact density for dense reviews and an optional
// trailing header control that therefore never scrolls out of view.
func approvalCardWith(c *ui.Context, icon *ui.SVG, tone ui.Color, heading string, compact bool, trailing func(), build func()) {
	t := c.Theme()
	pad, gap, iconBox := t.Space(5), t.Space(3), t.Space(10)
	if compact {
		pad, gap, iconBox = t.Space(3), t.Space(1.75), t.Space(8)
	}
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius*1.75).Background(t.Surface).
		Padding(pad).Gap(gap).Shadow(0, t.Space(1.5), t.Space(6), 0, ui.RGBA(0, 0, 0, .07)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
			box := ui.Box(c).Size(iconBox, iconBox).Shrink(0).Radius(iconBox * .28).Background(tone.Alpha(.14)).
				AlignItems(ui.Center).Justify(ui.Center)
			box.Children(func() { oneui.Icon(c, icon).Size(iconBox*.5, iconBox*.5).TextColor(tone) })
			oneui.Text(c, heading).FontSize(t.Rem(1.3)).Bold().Grow(1).MinWidth(0).Wrap()
			if trailing != nil {
				trailing()
			}
		})
		build()
	})
}

func approvalOrigin(c *ui.Context, text string) {
	t := c.Theme()
	oneui.Text(c, text).FontSize(t.Rem(1.02)).Bold().TextColor(t.Accent).Wrap()
}

func approvalFacts(c *ui.Context, build func()) {
	t := c.Theme()
	ui.Column(c).FillWidth().Radius(t.Radius).Background(t.Background).Border(1, t.Border.Alpha(.7)).
		Padding(t.Space(2.5), t.Space(3)).Gap(t.Space(1)).Children(build)
}

func approvalFact(c *ui.Context, text string) {
	t := c.Theme()
	oneui.Text(c, text).FontSize(t.Rem(.86)).Wrap()
}

func approvalMeta(c *ui.Context, text string) {
	t := c.Theme()
	oneui.Text(c, text).Font(onevraMonoFont).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
}

func approvalNote(c *ui.Context, text string) {
	t := c.Theme()
	oneui.Text(c, text).FontSize(t.Rem(.8)).TextColor(t.TextMuted).Wrap()
}

func approvalNotice(c *ui.Context, text string, tone ui.Color) {
	t := c.Theme()
	ui.Row(c).FillWidth().Radius(t.Radius).Background(tone.Alpha(.10)).Padding(t.Space(2), t.Space(3)).Children(func() {
		oneui.Text(c, text).FontSize(t.Rem(.82)).Bold().TextColor(tone).Wrap().Grow(1).MinWidth(0)
	})
}

func approvalActions(c *ui.Context, build func()) {
	t := c.Theme()
	ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(build)
}
