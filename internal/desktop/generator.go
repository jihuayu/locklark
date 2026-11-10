package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	pwgen "github.com/jihuayu/locklark/internal/password"
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

func (a *App) generatorView(c *ui.Context) {
	g := &a.v2.generator
	ui.Column(c.Key("generator")).Role(ui.RoleGroup).Label("密码生成器").Gap(10).Children(func() {
		ui.Text(c, "密码生成器").FontSize(22).Bold()
		ui.Text(c, "基于系统级加密随机源生成高强度随机密码、易记短语或 PIN 码。").FontSize(12)
		ui.Row(c).Gap(6).Children(func() {
			for _, mode := range []struct {
				id    pwgen.Mode
				label string
			}{
				{pwgen.ModeRandom, "随机密码"},
				{pwgen.ModeMemorable, "易记短语"},
				{pwgen.ModePIN, "PIN 码"},
			} {
				mode := mode
				button := ui.Button(c, mode.label)
				if g.mode == mode.id {
					button = ui.PrimaryButton(c, mode.label)
				}
				button.OnClick(func() { a.setGeneratorMode(mode.id) })
			}
		})
		switch g.mode {
		case pwgen.ModeMemorable:
			ui.Text(c, fmt.Sprintf("词数：%d", g.wordCount)).Bold()
			ui.Row(c).Gap(6).Children(func() {
				ui.Button(c, "减少词数").OnClick(func() {
					if g.wordCount > 3 {
						g.wordCount--
						a.regenerateGenerator()
					}
				})
				ui.Button(c, "增加词数").OnClick(func() {
					if g.wordCount < 15 {
						g.wordCount++
						a.regenerateGenerator()
					}
				})
			})
			ui.TextInput(c, &g.separator).Label("分隔符").Placeholder("hyphens, spaces, periods, commas, underscores, numbers")
			ui.Checkbox(c, &g.capitalize, "首字母大写").OnChange(a.regenerateGenerator)
		case pwgen.ModePIN:
			ui.Text(c, fmt.Sprintf("PIN 长度：%d", g.pinLength)).Bold()
			ui.Row(c).Gap(6).Children(func() {
				ui.Button(c, "缩短 PIN").OnClick(func() {
					if g.pinLength > 3 {
						g.pinLength--
						a.regenerateGenerator()
					}
				})
				ui.Button(c, "加长 PIN").OnClick(func() {
					if g.pinLength < 12 {
						g.pinLength++
						a.regenerateGenerator()
					}
				})
			})
		default:
			ui.Text(c, fmt.Sprintf("密码长度：%d", g.length)).Bold()
			ui.Row(c).Gap(6).Children(func() {
				ui.Button(c, "缩短长度").OnClick(func() {
					if g.length > 8 {
						g.length--
						a.regenerateGenerator()
					}
				})
				ui.Button(c, "加长长度").OnClick(func() {
					if g.length < 64 {
						g.length++
						a.regenerateGenerator()
					}
				})
			})
			ui.Checkbox(c, &g.digits, "包含数字").OnChange(a.regenerateGenerator)
			ui.Checkbox(c, &g.symbols, "包含符号").OnChange(a.regenerateGenerator)
		}
		if g.preview != "" {
			ui.Text(c, g.preview).FontSize(18).Bold()
		}
		ui.Text(c, g.status).FontSize(12)
		ui.Row(c).Gap(8).Children(func() {
			ui.Button(c, "重新生成").OnClick(a.regenerateGenerator)
			ui.Button(c, "复制密码").OnClick(a.copyGeneratorPassword)
			if a.v2.draft != nil {
				ui.PrimaryButton(c, "填入当前条目").OnClick(a.useGenerator)
			}
			ui.Button(c, "关闭生成器").OnClick(a.closeGenerator)
		})
	})
}

