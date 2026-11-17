package desktop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

const emergencyKitFileName = "Locklark-Emergency-Kit.txt"

// DefaultVaultPath returns the default local vault path under the user's Documents folder.
func DefaultVaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join("Locklark", "personal.ll")
	}
	return filepath.Join(home, "Documents", "Locklark", "personal.ll")
}

func vaultDisplayBaseName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func displayVaultLocation(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "未指定位置"
	}
	dir := filepath.Dir(path)
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		cleanHome := filepath.Clean(home)
		cleanDir := filepath.Clean(dir)
		if cleanDir == cleanHome {
			return "~"
		}
		if rel, relErr := filepath.Rel(cleanHome, cleanDir); relErr == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return filepath.Join("~", rel)
		}
	}
	return dir
}

func emergencyKitCandidate(dir string, index int) string {
	if index <= 1 {
		return filepath.Join(dir, emergencyKitFileName)
	}
	return filepath.Join(dir, fmt.Sprintf("Locklark-Emergency-Kit-%d.txt", index))
}

// nextEmergencyKitPath picks the first non-existing Emergency Kit filename in vaultPath's directory.
func nextEmergencyKitPath(vaultPath string) string {
	dir := filepath.Dir(strings.TrimSpace(vaultPath))
	if dir == "" || dir == "." {
		dir = filepath.Dir(DefaultVaultPath())
	}
	for i := 1; i <= 100; i++ {
		candidate := emergencyKitCandidate(dir, i)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
	return emergencyKitCandidate(dir, 100)
}

// autoSaveEmergencyKit creates the parent folder if needed and writes a collision-free
// unencrypted Emergency Kit next to the vault being created.
func autoSaveEmergencyKit(vaultPath, key string) (string, error) {
	if strings.TrimSpace(vaultPath) == "" || key == "" {
		return "", errors.New("missing vault path or key")
	}
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	for i := 1; i <= 100; i++ {
		candidate := emergencyKitCandidate(dir, i)
		err := saveEmergencyKit(candidate, key)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", os.ErrExist
}

// saveNewVaultKit uses the production Emergency Kit writer unless a test
// injects a failed backup.
func (a *App) saveNewVaultKit(vaultPath, key string) (string, error) {
	if a.autoSaveKit != nil {
		return a.autoSaveKit(vaultPath, key)
	}
	return autoSaveEmergencyKit(vaultPath, key)
}

// syncInitialVaultState binds the persisted vault path or enters the 4-step first-launch guide
// without creating an empty .ll file on disk.
func (a *App) syncInitialVaultState() {
	if classicLayoutRequested() {
		if strings.TrimSpace(a.path) == "" {
			a.path = DefaultVaultPath()
		}
		a.onboarding = false
		return
	}
	saved := strings.TrimSpace(a.settingsSnapshot().VaultPath)
	if saved != "" {
		a.path = saved
		a.onboarding = false
		return
	}
	def := DefaultVaultPath()
	if info, err := os.Stat(def); err == nil && !info.IsDir() {
		a.path = def
		a.onboarding = false
		a.create = false
		_ = a.SetVaultPath(def)
		return
	}
	a.path = def
	a.onboarding = true
	a.create = false
}

func (a *App) ensureIssuedSecret() {
	if a.issued != "" {
		return
	}
	key, err := personal.NewSecret()
	if err != nil {
		a.status = "Secret Key 生成失败"
		return
	}
	defer clear(key)
	a.issued = personal.FormatSecret(key)
}

func (a *App) startCreateVault() {
	a.Lock()
	a.onboarding = false
	a.create = true
	a.confirmForgetDevice = false
	a.password = ""
	a.confirmation = ""
	a.secret = ""
	a.kitSavedPath = ""
	if strings.TrimSpace(a.path) == "" {
		a.path = DefaultVaultPath()
	}
	a.ensureIssuedSecret()
	a.status = ""
}

func (a *App) chooseCreateVaultLocation() {
	if a.busy || a.win == nil {
		return
	}
	defaultName := vaultDisplayBaseName(a.path)
	if defaultName == "" {
		defaultName = "personal.ll"
	}
	win := a.win
	a.runInteractive(func() outcome {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:      win,
			Title:       "选择新建金库保存位置",
			DefaultPath: defaultName,
			Filters:     []mygo.FileFilter{{Name: "Locklark 金库", Extensions: []string{"ll"}}},
		})
		return outcome{err: err, apply: func() {
			if strings.TrimSpace(path) != "" {
				a.path = path
				a.status = "已更新金库保存位置：" + vaultDisplayBaseName(path)
			}
		}}
	})
}

func (a *App) openExistingVault() {
	if a.busy {
		return
	}
	if a.win == nil {
		a.onboarding = false
		a.create = false
		a.confirmForgetDevice = false
		return
	}
	win := a.win
	a.runInteractive(func() outcome {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent:  win,
			Title:   "打开已有 Locklark 金库",
			Filters: []mygo.FileFilter{{Name: "Locklark 金库", Extensions: []string{"ll"}}},
		})
		return outcome{err: err, apply: func() {
			if len(paths) == 0 || strings.TrimSpace(paths[0]) == "" {
				return
			}
			a.Lock()
			a.path = paths[0]
			_ = a.SetVaultPath(a.path)
			a.onboarding = false
			a.create = false
			a.confirmForgetDevice = false
			if _, secretErr := a.loadDeviceSecret(a.path); secretErr != nil {
				a.showSecretFallback = true
				a.status = "已选择已有金库；首次在此设备解锁需从应急文件粘贴一次 Secret Key"
			} else {
				a.showSecretFallback = false
				a.status = "已切换到金库：" + vaultDisplayBaseName(a.path)
			}
		}}
	})
}

func (a *App) reexportEmergencyKit() {
	if a.busy {
		return
	}
	path := strings.TrimSpace(a.path)
	if path == "" || a.reexportPassword == "" {
		a.status = "请输入当前金库主密码后再导出应急文件"
		return
	}
	pw := []byte(a.reexportPassword)
	a.reexportPassword = ""
	win := a.win
	a.runInteractive(func() outcome {
		defer clear(pw)
		secret, err := a.loadDeviceSecret(path)
		if err != nil {
			return outcome{err: errors.New("当前设备没有保存此金库的 Secret Key；请先使用应急文件解锁后再导出")}
		}
		key, err := personal.ParseSecret(secret)
		if err != nil {
			return outcome{err: err}
		}
		defer clear(key)
		s, err := personal.UnlockSession(path, pw, key, time.Minute)
		if err != nil {
			return outcome{err: err}
		}
		s.Lock()

		var savedPath string
		if win != nil {
			chosen, dlgErr := mygo.Dialog.Save(mygo.SaveDialogOptions{
				Parent:      win,
				Title:       "重新导出 Locklark 应急文件",
				DefaultPath: emergencyKitFileName,
				Filters:     []mygo.FileFilter{{Name: "文本文件", Extensions: []string{"txt"}}},
			})
			if dlgErr != nil {
				return outcome{err: dlgErr}
			}
			if strings.TrimSpace(chosen) == "" {
				return outcome{apply: func() {
					a.status = "已取消导出应急文件"
				}}
			}
			if err := saveEmergencyKit(chosen, secret); err != nil {
				return outcome{err: err}
			}
			savedPath = chosen
		} else {
			chosen, err := autoSaveEmergencyKit(path, secret)
			if err != nil {
				return outcome{err: err}
			}
			savedPath = chosen
		}
		return outcome{apply: func() {
			a.kitSavedPath = savedPath
			a.status = "应急文件已重新导出；请离线妥善保管"
		}}
	})
}

// saveEmergencyKit never replaces an existing file; the caller chooses where
// to place this deliberately unencrypted recovery aid.
func saveEmergencyKit(path, key string) error {
	if path == "" || key == "" {
		return errors.New("missing path or key")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	content := "Locklark 应急文件\r\n\r\nSecret Key: " + key + "\r\n\r\n解锁金库还需要主密码和金库文件。此文件不包含主密码，也不是金库备份。\r\n请离线保存或打印此文件，并与金库文件分开保管。任何取得此文件的人都能看到 Secret Key。\r\n"
	_, err = fmt.Fprint(f, content)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func (a *App) copyIssuedSecret() {
	key := a.issued
	if !a.create || a.busy || key == "" {
		return
	}
	generation := a.generation
	valid := func() bool { return a.generation == generation && a.create && a.issued == key }
	if err := a.writeClipboard([]byte(key), time.Now().Add(30*time.Second), valid); err != nil {
		if valid() {
			a.status = message(err)
		}
		return
	}
	a.status = clipboardStatus(30 * time.Second)
}

func (a *App) chooseEmergencyKit() {
	if !a.create || a.busy || a.issued == "" {
		return
	}
	key, win := a.issued, a.win
	a.run(func() outcome {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: win, Title: "保存应急文件", DefaultPath: emergencyKitFileName, Filters: []mygo.FileFilter{{Name: "文本文件", Extensions: []string{"txt"}}}})
		return outcome{err: err, apply: func() {
			if path == "" {
				a.status = "已取消保存"
				return
			}
			if !a.create || a.issued != key {
				a.status = "密钥已变化，请重新保存"
				return
			}
			if err := saveEmergencyKit(path, key); err != nil {
				if errors.Is(err, os.ErrExist) {
					a.status = "文件已存在，请选择新的文件名"
				} else {
					a.status = "应急文件保存失败，请检查位置和权限"
				}
				return
			}
			a.kitSavedPath = path
			a.status = "应急文件已保存；请离线保管"
		}}
	})
}

func (a *App) onboardingView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c.Key("onboarding-guide")).Role(ui.RoleGroup).Label("欢迎使用 Locklark").
		FillWidth().MaxWidth(580).Border(1, t.Border).Radius(t.Radius*1.75).Background(t.Surface).
		Padding(t.Space(6)).Gap(t.Space(4)).Shadow(0, t.Space(1.5), t.Space(6), 0, ui.RGBA(0, 0, 0, .07)).Children(func() {
		// Hero section
		ui.Column(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			mark := ui.Box(c).Size(t.Space(12), t.Space(12)).Radius(t.Space(3)).Background(t.Accent).
				AlignItems(ui.Center).Justify(ui.Center)
			mark.Children(func() {
				oneui.Icon(c, lucide.ShieldCheck()).Size(t.Space(6), t.Space(6)).TextColor(t.AccentText)
			})
			onevraPill(c, "离线零知识 · 本机派生加密", t.Accent)
			oneui.Text(c, "欢迎使用 Locklark 本地金库").FontSize(t.Rem(1.5)).Bold().TextColor(t.Text)
			oneui.Text(c, "没有云账号、没有服务器同步。所有密码与敏感字段都在你的设备上用「主密码 + Secret Key」双因素加密保存。").
				FontSize(t.Rem(.82)).TextColor(t.TextMuted).Wrap()
		})

		// 4-step security architecture in one clean grouped sheet
		steps := []struct {
			title, desc, pill string
			icon              *ui.SVG
		}{
			{"1. 主密码（仅你记忆）", "由你自行设定，永不落盘也不写入应急文件，是日常解锁的唯一口令。", "零落盘", lucide.KeyRound()},
			{"2. Secret Key（本机系统凭据保护）", "建库时自动生成高熵本机密钥并存入系统凭据库，日常无需反复输入。", "自动保管", lucide.Shield()},
			{"3. 双因素派生与零知识加密", "主密码与 Secret Key 联合派生出金库主密钥（Argon2id + XChaCha20-Poly1305）。", "双因素", lucide.LockKeyhole()},
			{"4. Emergency Kit（跨设备/重装离线恢复）", "在金库同目录自动生成不可覆盖的应急文本副本，重装或换机后凭它恢复。", "离线备份", lucide.FileKey()},
		}
		onevraGroup(c, "安全架构", func(row func(func())) {
			for _, step := range steps {
				step := step
				row(func() {
					iconBox := ui.Box(c).Size(t.Space(7), t.Space(7)).Shrink(0).Radius(t.Space(2)).
						Background(t.Accent.Alpha(.10)).AlignItems(ui.Center).Justify(ui.Center)
					iconBox.Children(func() {
						oneui.Icon(c, step.icon).Size(t.Space(3.75), t.Space(3.75)).TextColor(t.Accent)
					})
					ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
						oneui.Text(c, step.title).FontSize(t.Rem(.9)).Bold().TextColor(t.Text).Wrap()
						oneui.Text(c, step.desc).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
					})
					onevraPill(c, step.pill, t.TextMuted)
				})
			}
		})

		// Primary & Secondary CTAs
		ui.Row(c).FillWidth().Justify(ui.Center).AlignItems(ui.Center).Wrap().Gap(t.Space(2)).Children(func() {
			oneui.Button(c, "打开已有金库…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(a.openExistingVault)
			oneui.Button(c, "创建金库", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).OnClick(a.startCreateVault)
		})
	})
}

func (a *App) createVaultView(c *ui.Context) {
	t := c.Theme()
	if strings.TrimSpace(a.path) == "" {
		a.path = DefaultVaultPath()
	}
	a.ensureIssuedSecret()

	ui.Column(c.Key("create-vault")).Role(ui.RoleGroup).Label("创建本地金库").
		FillWidth().MaxWidth(540).Border(1, t.Border).Radius(t.Radius*1.75).Background(t.Surface).
		Padding(t.Space(6)).Gap(t.Space(3.5)).Shadow(0, t.Space(1.5), t.Space(6), 0, ui.RGBA(0, 0, 0, .07)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
				oneui.Text(c, "创建本地金库").FontSize(t.Rem(1.35)).Bold().TextColor(t.Text)
				oneui.Text(c, "设定主密码即可；Secret Key 将自动存入本机凭据库并生成应急恢复文件。").
					FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
			})
			oneui.Button(c, "返回引导", oneui.ButtonGhost).Disabled(a.uiBusy(c)).OnClick(func() {
				a.create = false
				a.onboarding = true
				a.status = ""
			})
		})

		onevraGroup(c, "保存位置", func(row func(func())) {
			row(func() {
				oneui.Icon(c, lucide.FileLock()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
				ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
					base := vaultDisplayBaseName(a.path)
					if base == "" {
						base = "personal.ll"
					}
					oneui.Text(c, base+" · "+displayVaultLocation(a.path)).FontSize(t.Rem(.88)).Bold().TextColor(t.Text).Wrap()
					oneui.Text(c, a.path).FontSize(t.Rem(.72)).TextColor(t.TextMuted).Wrap()
				})
				oneui.Button(c, "更改…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(a.chooseCreateVaultLocation)
			})
		})

		onevraGroup(c, "设定主密码", func(row func(func())) {
			submit := func() {
				if !a.busy && a.issued != "" && a.password != "" && a.password == a.confirmation {
					a.createVaultFile()
				}
			}
			row(func() {
				oneui.TextBox(c, &a.password, oneui.TextBoxOptions{}).
					Label("主密码").Placeholder("设定高强度主密码").Password().Grow(1).Disabled(a.uiBusy(c)).OnSubmit(submit)
			})
			row(func() {
				ui.Column(c).FillWidth().Gap(t.Space(.75)).Children(func() {
					oneui.TextBox(c, &a.confirmation, oneui.TextBoxOptions{}).
						Label("确认主密码").Placeholder("再次输入主密码以确认").Password().FillWidth().Disabled(a.uiBusy(c)).OnSubmit(submit)
					if a.confirmation != "" && a.confirmation != a.password {
						oneui.Text(c, "两次输入的主密码不一致").FontSize(t.Rem(.74)).TextColor(t.Warning)
					} else if a.password != "" && len(a.password) < 8 {
						oneui.Text(c, "建议使用至少 8 位包含大小写、数字或符号的密码").FontSize(t.Rem(.74)).TextColor(t.TextMuted)
					}
				})
			})
		})

		onevraGroup(c, "本机 Secret Key 与应急备份", func(row func(func())) {
			row(func() {
				ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
					ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
						oneui.Text(c, "已自动生成 Secret Key").FontSize(t.Rem(.84)).Bold().TextColor(t.Text).Grow(1)
						onevraPill(c, "含离线应急备份", t.Accent)
					})
					onevraSecretText(c, a.issued)
					oneui.Text(c, "点击「创建并进入金库」后，系统会同时将 Secret Key 存入本机凭据库，并在金库目录自动保存不覆盖的 "+emergencyKitFileName+"。").
						FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
					ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
						oneui.Button(c, "复制 Secret Key", oneui.ButtonOutline).Disabled(a.uiBusy(c) || a.issued == "").OnClick(a.copyIssuedSecret)
						oneui.Button(c, "保存应急文件…", oneui.ButtonOutline).Disabled(a.uiBusy(c) || a.issued == "").OnClick(a.chooseEmergencyKit)
					})
				})
			})
		})

		ui.Row(c).FillWidth().AlignItems(ui.Center).Justify(ui.End).Gap(t.Space(2)).Children(func() {
			oneui.Button(c, "返回上一步", oneui.ButtonGhost).Disabled(a.uiBusy(c)).OnClick(func() {
				a.create = false
				a.onboarding = true
				a.status = ""
			})
			oneui.Button(c, "创建并进入金库", oneui.ButtonPrimary).
				Disabled(a.uiBusy(c) || a.issued == "" || a.password == "" || a.password != a.confirmation).
				OnClick(a.createVaultFile)
		})
	})
}
