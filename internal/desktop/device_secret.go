package desktop

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
)

const (
	deviceSecretService      = "app.locklark.device-secret-key.v1"
	forgetDeviceStatError    = "无法确认金库文件状态；已取消退出当前设备，未删除任何凭据。"
	forgetDeviceCleanupError = "退出当前设备未完成；本地凭据可能已部分移除，金库绑定仍保留，请检查权限后重试。磁盘上的 .ll 金库文件未被删除。"
)

// statVaultFile is a test seam for filesystem status failures. Only an
// explicit os.ErrNotExist may be treated as an absent vault.
var (
	statVaultFile          = os.Stat
	errVaultFileState      = errors.New("desktop: vault file state unavailable")
	errForgetDeviceCleanup = errors.New("desktop: forget-device cleanup incomplete")
)

func vaultFileExists(path string) (bool, error) {
	_, err := statVaultFile(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, errVaultFileState
	}
}

// deviceSecretStore is the small part of the OS credential store used by the
// desktop unlock flow. Tests use an in-memory implementation; production uses
// MyGo's macOS Keychain, Windows Credential Manager or Linux Secret Service
// adapter.
type deviceSecretStore interface {
	Set(string, []byte) error
	Get(string) ([]byte, error)
	Delete(string) error
}

func deviceSecretKey(path string) string {
	normalized := filepath.Clean(strings.TrimSpace(path))
	if absolute, err := filepath.Abs(normalized); err == nil {
		normalized = absolute
	}
	if runtime.GOOS == "windows" {
		normalized = strings.ToLower(normalized)
	}
	sum := sha256.Sum256([]byte(normalized))
	return "locklark-secret-key/" + stringHex(sum[:])
}

func stringHex(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

func (a *App) loadDeviceSecret(path string) (string, error) {
	if a.deviceSecrets == nil || strings.TrimSpace(path) == "" {
		return "", errors.New("device Secret Key is unavailable")
	}
	raw, err := a.deviceSecrets.Get(deviceSecretKey(path))
	if err != nil {
		return "", err
	}
	defer clear(raw)
	secret := string(raw)
	if _, err := personal.ParseSecret(secret); err != nil {
		return "", errors.New("stored Secret Key is invalid")
	}
	return secret, nil
}

func (a *App) storeDeviceSecret(path, secret string) error {
	if a.deviceSecrets == nil || strings.TrimSpace(path) == "" {
		return errors.New("device Secret Key store is unavailable")
	}
	if _, err := personal.ParseSecret(secret); err != nil {
		return err
	}
	return a.deviceSecrets.Set(deviceSecretKey(path), []byte(secret))
}

func (a *App) deleteDeviceSecret(path string) error {
	if a.deviceSecrets == nil || strings.TrimSpace(path) == "" {
		return errors.New("device Secret Key store is unavailable")
	}
	return a.deviceSecrets.Delete(deviceSecretKey(path))
}

func (a *App) forgetDeviceSecret() {
	path := a.path
	a.run(func() outcome {
		err := a.deleteDeviceSecret(path)
		return outcome{err: err, apply: func() {
			a.showSecretFallback = true
			a.confirmForgetDevice = false
			a.status = "已从此设备移除 Secret Key；金库文件未被删除"
		}}
	})
}

func (a *App) forgetDeviceNeedsSecret() bool {
	path := strings.TrimSpace(a.path)
	if path == "" {
		return false
	}
	exists, err := vaultFileExists(path)
	if err != nil {
		// A stat error is not evidence that the vault is absent. Keep the
		// emergency Secret Key field available; submission will abort before
		// any credential or binding change.
		return true
	}
	if !exists {
		return false
	}
	_, err = a.loadDeviceSecret(path)
	return err != nil
}

// forgetDeviceWithPassword verifies the vault master password before removing
// this device's saved Secret Key, system quick unlock, and VaultPath binding.
// The .ll vault file on disk is never deleted.
func (a *App) forgetDeviceWithPassword() {
	if a.busy {
		return
	}
	path := strings.TrimSpace(a.path)
	if path == "" {
		a.status = "当前没有绑定的金库文件"
		return
	}
	vaultExists, statErr := vaultFileExists(path)
	if statErr != nil {
		a.forgetPassword = ""
		a.status = forgetDeviceStatError
		return
	}
	if vaultExists && a.forgetPassword == "" {
		a.status = "请输入当前金库主密码以确认退出当前设备"
		return
	}
	pw := []byte(a.forgetPassword)
	typedSecret := strings.TrimSpace(a.secret)
	a.forgetPassword = ""
	sysStore := a.systemStore

	a.run(func() outcome {
		defer clear(pw)
		if vaultExists {
			secret, loadErr := a.loadDeviceSecret(path)
			if loadErr != nil {
				secret = typedSecret
			}
			if secret == "" {
				return outcome{err: errors.New("当前设备未保存 Secret Key；请输入应急文件中的 Secret Key 与主密码以确认")}
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
		}

		// Cleanup is ordered and intentionally not transactional. Remove quick
		// unlock first, then the device Secret Key, then the persisted binding.
		// This keeps the UI bound on every failure and preserves the local
		// Secret Key when quick-unlock removal fails. A later failure can leave
		// earlier cleanup applied: after a device-key failure quick unlock is
		// gone but the Secret Key and binding remain; after a binding-save
		// failure both credentials may be gone while the UI restores the old
		// in-memory binding and reports incomplete cleanup rather than success.
		// A late settings-file error can already have replaced the file, so a
		// retry or relaunch may still be required. The .ll file is never touched.
		if sysStore != nil {
			// An already-absent quick-unlock item is a successful removal.
			if err := personal.DisableSystemUnlock(path, sysStore); err != nil && !errors.Is(err, osunlock.ErrNotFound) {
				return outcome{err: errForgetDeviceCleanup}
			}
		}
		if err := a.deleteDeviceSecret(path); err != nil {
			return outcome{err: errForgetDeviceCleanup}
		}
		return outcome{apply: func() {
			// SetVaultPath changes in-memory settings before persisting. Restore
			// the old binding if the owned settings file cannot be saved so the
			// UI remains truthfully bound and the operation can be retried.
			previousSettings := a.settings
			if err := a.SetVaultPath(""); err != nil {
				a.settings = previousSettings
				a.status = forgetDeviceCleanupError
				return
			}
			a.Lock()
			a.path = DefaultVaultPath()
			a.confirmForgetDevice = false
			a.showSecretFallback = false
			a.onboarding = true
			a.create = false
			a.status = "已退出当前设备；磁盘上的 .ll 金库文件已完整保留"
		}}
	})
}

func (a *App) forgetDeviceConfirmView(c *ui.Context) {
	t := c.Theme()
	needsSecret := a.forgetDeviceNeedsSecret()
	ui.Column(c).FillWidth().Border(1, t.Danger).Radius(t.Radius).Background(t.Danger.Alpha(.06)).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "退出当前设备？").Bold().TextColor(t.Danger).Grow(1)
			oneui.Badge(c, "保留 .ll 文件", oneui.BadgeOptions{Tone: oneui.BadgeWarning})
		})
		oneui.Text(c, "退出后会删除此设备保存的 Secret Key、停用系统快捷解锁，并解除当前设备与该金库路径的绑定；磁盘上的 .ll 金库文件不会被删除。重新绑定此设备时需要使用应急文件中的 Secret Key。").
			FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		pwBox := oneui.TextBox(c, &a.forgetPassword, oneui.TextBoxOptions{}).
			Label("验证主密码").Placeholder("输入当前金库主密码以确认").Password().Disabled(a.busy)
		if needsSecret {
			oneui.TextBox(c, &a.secret, oneui.TextBoxOptions{}).
				Label("应急 Secret Key").Placeholder("LL1-…（此设备缺少本机 Secret Key）").Password().Disabled(a.busy).
				OnSubmit(a.forgetDeviceWithPassword)
		} else {
			pwBox.OnSubmit(a.forgetDeviceWithPassword)
		}
		confirmDisabled := a.busy || a.forgetPassword == "" || (needsSecret && strings.TrimSpace(a.secret) == "")
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "确认退出当前设备", oneui.ButtonOutline).
				TextColor(t.Danger).
				Disabled(confirmDisabled).
				OnClick(a.forgetDeviceWithPassword)
			oneui.Button(c, "取消退出", oneui.ButtonOutline).
				Disabled(a.busy).
				OnClick(func() {
					a.confirmForgetDevice = false
					a.forgetPassword = ""
					a.status = ""
				})
		})
	})
}
