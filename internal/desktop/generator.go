package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	pwgen "github.com/jihuayu/locklark/internal/password"
	oneui "github.com/oneo-me/onevra/source/components"
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

func generatorStrengthColor(t *ui.Theme, entropy int) ui.Color {
	switch {
	case entropy >= 100:
		return t.Success
	case entropy >= 75:
		return t.Accent
	case entropy >= 50:
		return t.Warning
	default:
		return t.Danger
	}
}

func (a *App) generatorView(c *ui.Context) {
	t := c.Theme()
	g := &a.v2.generator
	if g.preview == "" && g.status == "" {
		a.regenerateGenerator()
	}
	ui.Column(c.Key("generator")).Role(ui.RoleGroup).Label("密码生成器").FillWidth().MinWidth(0).AlignItems(ui.Center).Children(func() {
		ui.Column(c).FillWidth().MaxWidth(600).MinWidth(0).Gap(t.Space(4)).Children(func() {
			onevraPageHeader(c, "密码生成器", "基于系统级加密随机源生成高强度随机密码、易记短语或 PIN 码。")

			if next, changed := onevraSegmented(c, string(g.mode), [][2]string{
				{string(pwgen.ModeRandom), "随机密码"},
				{string(pwgen.ModeMemorable), "易记短语"},
				{string(pwgen.ModePIN), "PIN 码"},
			}); changed {
				a.setGeneratorMode(pwgen.Mode(next))
			}

			// Candidate preview surface
			onevraGroup(c, "候选密码预览", func(row func(func())) {
				row(func() {
					ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(2)).Children(func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
							ui.Column(c).Grow(1).MinWidth(0).Children(func() {
								shown := g.preview
								if shown == "" {
									shown = "—"
								}
								onevraSecretText(c, shown)
							})
							if g.entropy > 0 {
								onevraPill(c, fmt.Sprintf("%s · %d bits", generatorStrength(g.entropy), g.entropy), generatorStrengthColor(t, g.entropy))
							}
						})
						if g.status != "" {
							oneui.Text(c, g.status).FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
						}
					})
				})
			})

			// Mode parameters
			onevraSettingsGroup(c, "生成参数", func(row func(string, string, func())) {
				switch g.mode {
				case pwgen.ModeMemorable:
					row("词数", "短语中包含的单词数量（3–15）", func() {
						a.onevraStepper(c, fmt.Sprintf("%d 个词", g.wordCount), &g.wordCount, 3, 15)
					})
					row("分隔符", "单词之间的分隔符类型", func() {
						sep := oneui.TextBox(c, &g.separator, oneui.TextBoxOptions{}).Label("分隔符").
							Placeholder("hyphens, spaces, periods").Width(180)
						if sep.Changed() {
							a.regenerateGenerator()
						}
					})
					row("首字母大写", "", func() {
						if v, changed := onevraSwitch(c, "首字母大写", g.capitalize); changed {
							g.capitalize = v
							a.regenerateGenerator()
						}
					})
				case pwgen.ModePIN:
					row("PIN 长度", "数字位数（3–12）", func() {
						a.onevraStepper(c, fmt.Sprintf("%d 位", g.pinLength), &g.pinLength, 3, 12)
					})
				default:
					row("密码长度", "总字符长度（8–64）", func() {
						a.onevraStepper(c, fmt.Sprintf("%d 位", g.length), &g.length, 8, 64)
					})
					row("包含数字", "", func() {
						if v, changed := onevraSwitch(c, "包含数字", g.digits); changed {
							g.digits = v
							a.regenerateGenerator()
						}
					})
					row("包含符号", "", func() {
						if v, changed := onevraSwitch(c, "包含符号", g.symbols); changed {
							g.symbols = v
							a.regenerateGenerator()
						}
					})
				}
			})

			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Button(c, "重新生成", oneui.ButtonOutline).OnClick(a.regenerateGenerator)
				oneui.Button(c, "复制密码", oneui.ButtonSecondary).OnClick(a.copyGeneratorPassword)
				if a.v2.draft != nil {
					oneui.Button(c, "填入当前条目", oneui.ButtonPrimary).OnClick(a.useGenerator)
				}
				ui.Spacer(c)
				oneui.Button(c, "关闭生成器", oneui.ButtonGhost).OnClick(a.closeGenerator)
			})
		})
	})
}


