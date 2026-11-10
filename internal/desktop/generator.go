package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	pwgen "github.com/jihuayu/locklark/internal/password"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// generatorState is the desktop Password Generator popover state. It is part
// of v2State so a lock drops the preview immediately.
type generatorState struct {
	open       bool
	mode       pwgen.Mode
	length     int
	digits     bool
	symbols    bool
	wordCount  int
	separator  string
	capitalize bool
	fullWords  bool
	pinLength  int
	preview    string
	entropy    int
	status     string
	target     string // "password", "otp", or "<section>/<field>"
}

func defaultGeneratorState() generatorState {
	opts := pwgen.DefaultGeneratorOptions()
	return generatorState{
		mode:       opts.Mode,
		length:     opts.Length,
		digits:     opts.Digits,
		symbols:    opts.Symbols,
		wordCount:  opts.WordCount,
		separator:  opts.Separator,
		capitalize: opts.Capitalize,
		fullWords:  opts.FullWords,
		pinLength:  opts.PINLength,
		status:     "选择模式并生成候选密码",
	}
}

func (g generatorState) options() pwgen.GeneratorOptions {
	return pwgen.GeneratorOptions{
		Mode:       g.mode,
		Length:     g.length,
		Digits:     g.digits,
		Symbols:    g.symbols,
		WordCount:  g.wordCount,
		Separator:  g.separator,
		Capitalize: g.capitalize,
		FullWords:  g.fullWords,
		PINLength:  g.pinLength,
	}
}

// openGenerator opens the standalone generator. The target is the field that
// "Use" fills when an editor draft is active.
func (a *App) openGenerator(target string) {
	a.v2.settingsOpen = false
	a.v2.generator.open = true
	a.v2.generator.target = target
	a.touchActivity()
	a.regenerateGenerator()
}

func (a *App) OpenGenerator() { a.openGenerator("password") }

func (a *App) closeGenerator() {
	a.v2.generator.open = false
	a.v2.generator.preview = ""
	a.v2.generator.status = ""
}

func (a *App) CloseGenerator() { a.closeGenerator() }

func (a *App) setGeneratorMode(mode pwgen.Mode) {
	switch mode {
	case pwgen.ModeRandom, pwgen.ModeMemorable, pwgen.ModePIN:
	default:
		a.v2.generator.status = "未知生成模式"
		return
	}
	a.v2.generator.mode = mode
	a.touchActivity()
	a.regenerateGenerator()
}

func (a *App) SetGeneratorMode(mode string) {
	a.setGeneratorMode(pwgen.Mode(strings.ToLower(strings.TrimSpace(mode))))
}

// regenerateGenerator draws a fresh candidate using the current controls.
// It is safe to call while no vault is unlocked: the candidate is only a
// random string and is never persisted.
func (a *App) regenerateGenerator() {
	g := &a.v2.generator
	if g.length < 8 || g.length > 64 {
		// The slider offers 8-64; the numeric API accepts up to 256.
		g.length = 24
	}
	if g.wordCount < 3 || g.wordCount > 15 {
		g.wordCount = 5
	}
	if g.pinLength < 3 || g.pinLength > 12 {
		g.pinLength = 6
	}
	generated, err := pwgen.GeneratePassword(g.options())
	if err != nil {
		g.preview = ""
		g.entropy = 0
		g.status = generatorErrorMessage(err)
		return
	}
	g.preview = generated.Value()
	g.entropy = generated.EntropyBits()
	g.status = fmt.Sprintf("%s · %d bits", generatorStrength(g.entropy), g.entropy)
}

// GeneratePassword regenerates and returns the current candidate. It is
// primarily a test/automation entry point; the UI uses regenerateGenerator.
func (a *App) GeneratePassword() (string, int, error) {
	a.regenerateGenerator()
	return a.v2.generator.preview, a.v2.generator.entropy, nil
}

// GeneratePasswordWithMode selects a mode and regenerates.
func (a *App) GeneratePasswordWithMode(mode string) (string, int, error) {
	m := pwgen.Mode(strings.ToLower(strings.TrimSpace(mode)))
	switch m {
	case pwgen.ModeRandom, pwgen.ModeMemorable, pwgen.ModePIN:
		a.v2.generator.mode = m
	default:
		return "", 0, pwgen.ErrInvalid
	}
	a.regenerateGenerator()
	return a.v2.generator.preview, a.v2.generator.entropy, nil
}

func generatorErrorMessage(err error) string {
	switch {
	case err == pwgen.ErrInvalid:
		return "生成参数无效"
	case err == pwgen.ErrRandom:
		return "安全随机源不可用"
	case err == pwgen.ErrEntropy:
		return "参数强度不足"
	default:
		return "密码生成未完成"
	}
}

func generatorStrength(entropy int) string {
	switch {
	case entropy >= 128:
		return "极强"
	case entropy >= 100:
		return "很强"
	case entropy >= 75:
		return "良好"
	case entropy >= 50:
		return "较弱"
	default:
		return "极弱"
	}
}

// copyGeneratorPassword copies the current candidate with the configured
// owned-clipboard lease and clears it from memory after the copy.
func (a *App) copyGeneratorPassword() {
	value := a.v2.generator.preview
	if value == "" {
		a.regenerateGenerator()
		value = a.v2.generator.preview
	}
	if value == "" {
		return
	}
	timeout := a.clipboardTimeout()
	until := clipboardDeadline(timeout)
	if err := a.writeClipboard([]byte(value), until, func() bool { return a.session != nil || a.v2.generator.open }); err != nil {
		a.v2.generator.status = message(err)
		return
	}
	a.v2.generator.status = clipboardStatus(timeout)
}

// useGenerator fills the active editor draft and closes the popover.
func (a *App) useGenerator() {
	if a.v2.generator.preview == "" {
		a.regenerateGenerator()
	}
	a.fillGeneratorPassword(a.v2.generator.preview)
}

func (a *App) UseGenerator() { a.useGenerator() }

func clipboardDeadline(timeout time.Duration) time.Time {
	if timeout <= 0 {
		return time.Now().Add(100 * 365 * 24 * time.Hour)
	}
	return time.Now().Add(timeout)
}

func generatorStrengthTone(entropy int) oneui.BadgeTone {
	switch {
	case entropy >= 100:
		return oneui.BadgeSuccess
	case entropy >= 75:
		return oneui.BadgeAccent
	case entropy >= 50:
		return oneui.BadgeWarning
	default:
		return oneui.BadgeDanger
	}
}

func (a *App) generatorView(c *ui.Context) {
	t := c.Theme()
	g := &a.v2.generator
	ui.Column(c.Key("generator")).Role(ui.RoleGroup).Label("密码生成器").FillWidth().MinWidth(0).Gap(t.Space(3)).Children(func() {
		// Header
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
			iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
				Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
			iconBox.Children(func() {
				oneui.Icon(c, lucide.Sparkles()).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
			})
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
				oneui.Text(c, "密码生成器").FontSize(t.Rem(1.35)).Bold().SingleLine()
				oneui.Text(c, "基于系统级加密随机源生成高强度随机密码、易记短语或 PIN 码。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
			})
		})

		// Segmented mode selector
		ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(1.5)).Wrap().Gap(t.Space(1)).Children(func() {
			for _, mode := range []struct {
				id    pwgen.Mode
				label string
			}{
				{pwgen.ModeRandom, "随机密码"},
				{pwgen.ModeMemorable, "易记短语"},
				{pwgen.ModePIN, "PIN 码"},
			} {
				mode := mode
				variant := oneui.ButtonGhost
				if g.mode == mode.id {
					variant = oneui.ButtonPrimary
				}
				oneui.Button(c, mode.label, variant).OnClick(func() { a.setGeneratorMode(mode.id) })
			}
		})

		// Prominent preview card
		ui.Column(c).FillWidth().Border(1, t.Accent.Alpha(.45)).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3.5)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, "候选密码预览").FontSize(t.Rem(.76)).Bold().TextColor(t.TextMuted).Grow(1)
				if g.entropy > 0 {
					oneui.Badge(c, fmt.Sprintf("%s · %d bits", generatorStrength(g.entropy), g.entropy), oneui.BadgeOptions{
						Tone: generatorStrengthTone(g.entropy),
					})
				}
			})
			previewBox := ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).
				Background(t.Background).Padding(t.Space(2.5), t.Space(3))
			previewBox.Children(func() {
				shown := g.preview
				if shown == "" {
					shown = "—"
				}
				oneui.Text(c, shown).FontSize(t.Rem(1.25)).Bold().Wrap()
			})
			if g.status != "" {
				oneui.Text(c, g.status).FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
			}
		})

		// Mode options card
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2.5)).Children(func() {
			oneui.Text(c, "生成参数").Bold()
			switch g.mode {
			case pwgen.ModeMemorable:
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, fmt.Sprintf("词数：%d", g.wordCount)).Bold().Grow(1)
					oneui.Button(c, "减少词数", oneui.ButtonOutline).Disabled(g.wordCount <= 3).OnClick(func() {
						if g.wordCount > 3 {
							g.wordCount--
							a.regenerateGenerator()
						}
					})
					oneui.Button(c, "增加词数", oneui.ButtonOutline).Disabled(g.wordCount >= 15).OnClick(func() {
						if g.wordCount < 15 {
							g.wordCount++
							a.regenerateGenerator()
						}
					})
				})
				sep := oneui.TextBox(c, &g.separator, oneui.TextBoxOptions{}).Label("分隔符").Placeholder("hyphens, spaces, periods, commas, underscores, numbers")
				if sep.Changed() {
					a.regenerateGenerator()
				}
				oneui.Checkbox(c, &g.capitalize, "首字母大写").OnChange(a.regenerateGenerator)
			case pwgen.ModePIN:
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, fmt.Sprintf("PIN 长度：%d", g.pinLength)).Bold().Grow(1)
					oneui.Button(c, "缩短 PIN", oneui.ButtonOutline).Disabled(g.pinLength <= 3).OnClick(func() {
						if g.pinLength > 3 {
							g.pinLength--
							a.regenerateGenerator()
						}
					})
					oneui.Button(c, "加长 PIN", oneui.ButtonOutline).Disabled(g.pinLength >= 12).OnClick(func() {
						if g.pinLength < 12 {
							g.pinLength++
							a.regenerateGenerator()
						}
					})
				})
			default:
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					oneui.Text(c, fmt.Sprintf("密码长度：%d", g.length)).Bold().Grow(1)
					oneui.Button(c, "缩短长度", oneui.ButtonOutline).Disabled(g.length <= 8).OnClick(func() {
						if g.length > 8 {
							g.length--
							a.regenerateGenerator()
						}
					})
					oneui.Button(c, "加长长度", oneui.ButtonOutline).Disabled(g.length >= 64).OnClick(func() {
						if g.length < 64 {
							g.length++
							a.regenerateGenerator()
						}
					})
				})
				ui.Row(c).FillWidth().Wrap().Gap(t.Space(3)).Children(func() {
					oneui.Checkbox(c, &g.digits, "包含数字").OnChange(a.regenerateGenerator)
					oneui.Checkbox(c, &g.symbols, "包含符号").OnChange(a.regenerateGenerator)
				})
			}
		})

		// Action bar
		ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(2.5), t.Space(3)).Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "重新生成", oneui.ButtonSecondary).OnClick(a.regenerateGenerator)
			oneui.Button(c, "复制密码", oneui.ButtonSecondary).OnClick(a.copyGeneratorPassword)
			if a.v2.draft != nil {
				oneui.Button(c, "填入当前条目", oneui.ButtonPrimary).OnClick(a.useGenerator)
			}
			ui.Spacer(c)
			oneui.Button(c, "关闭生成器", oneui.ButtonOutline).OnClick(a.closeGenerator)
		})
	})
}


