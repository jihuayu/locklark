package desktop

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/passme/internal/osunlock"
	"github.com/jihuayu/passme/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
)

const (
	deviceSecretService      = "app.passme.device-secret-key.v1"
	forgetDeviceStatError    = "无法确认金库文件状态；已取消退出当前设备，未删除任何凭据。"
	forgetDeviceCleanupError = "退出当前设备未完成；本地凭据可能已部分移除，金库绑定仍保留，请检查权限后重试。磁盘上的 .pm 金库文件未被删除。"
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
	return "passme-secret-key/" + stringHex(sum[:])
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

func (a *App) invalidateDeviceSecretCache() {
	a.deviceSecretMu.Lock()
	a.deviceSecretCachePath = ""
	a.deviceSecretCached = false
	a.deviceSecretPresent = false
	a.deviceSecretMu.Unlock()
}

func (a *App) hasDeviceSecretCached(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || a.deviceSecrets == nil {
		return false
	}
	a.deviceSecretMu.Lock()
	if a.deviceSecretCached && a.deviceSecretCachePath == trimmed {
		present := a.deviceSecretPresent
		a.deviceSecretMu.Unlock()
		return present
	}
	a.deviceSecretMu.Unlock()

	_, err := a.loadDeviceSecret(trimmed)
	present := err == nil

	a.deviceSecretMu.Lock()
	a.deviceSecretCachePath = trimmed
	a.deviceSecretCached = true
	a.deviceSecretPresent = present
	a.deviceSecretMu.Unlock()
	return present
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
	err := a.deviceSecrets.Set(deviceSecretKey(path), []byte(secret))
	a.invalidateDeviceSecretCache()
	return err
}

func (a *App) deleteDeviceSecret(path string) error {
	if a.deviceSecrets == nil || strings.TrimSpace(path) == "" {
		return errors.New("device Secret Key store is unavailable")
	}
	err := a.deviceSecrets.Delete(deviceSecretKey(path))
	a.invalidateDeviceSecretCache()
	return err
}

func nextAvailableVaultPath(defaultPath string) string {
	trimmed := strings.TrimSpace(defaultPath)
	if trimmed == "" {
		return ""
	}
	if _, err := os.Stat(trimmed); errors.Is(err, os.ErrNotExist) {
		return trimmed
	}
	dir := filepath.Dir(trimmed)
	ext := filepath.Ext(trimmed)
	if ext == "" {
		ext = ".pm"
	}
	stem := strings.TrimSuffix(filepath.Base(trimmed), ext)
	for i := 2; i <= 100; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
	return trimmed
}

// forgetCurrentDevice unbinds this device after a two-step confirmation by
// removing quick unlock, the device Secret Key (if present), and VaultPath
// binding. The .pm vault file on disk is never deleted.
func (a *App) forgetCurrentDevice() {
	if a.busy {
		return
	}
	path := strings.TrimSpace(a.path)
	if path == "" {
		a.status = "当前没有绑定的金库文件"
		return
	}
	a.forgetPassword = ""
	if _, statErr := vaultFileExists(path); statErr != nil {
		a.status = forgetDeviceStatError
		return
	}
	sysStore := a.systemStore

	a.run(func() outcome {
		// Cleanup is ordered and intentionally not transactional. Remove quick
		// unlock first, then the device Secret Key, then the persisted binding.
		// This keeps the UI bound on every failure and preserves the local
		// Secret Key when quick-unlock removal fails. The .pm file is never touched.
		if sysStore != nil {
			// An already-absent quick-unlock item is a successful removal.
			if err := personal.DisableSystemUnlock(path, sysStore); err != nil && !errors.Is(err, osunlock.ErrNotFound) {
				return outcome{err: errForgetDeviceCleanup}
			}
		}
		if err := a.deleteDeviceSecret(path); err != nil && !errors.Is(err, mygo.ErrSecretNotFound) && !errors.Is(err, os.ErrNotExist) {
			return outcome{err: errForgetDeviceCleanup}
		}
		return outcome{apply: func() {
			// SetVaultPath changes in-memory settings before persisting. Restore
			// the old binding if the owned settings file cannot be saved so the
			// UI remains truthfully bound and the operation can be retried.
			previousSettings := a.settings
			prevExpired := a.systemUnlockExpired
			a.settings.SystemUnlockEnabled = false
			a.settings.SystemUnlockExpiresAt = 0
			a.systemUnlockExpired = false
			if err := a.SetVaultPath(""); err != nil {
				a.settings = previousSettings
				a.systemUnlockExpired = prevExpired
				a.status = forgetDeviceCleanupError
				return
			}
			a.Lock()
			a.invalidateDeviceSecretCache()
			a.path = nextAvailableVaultPath(DefaultVaultPath())
			a.confirmForgetDevice = false
			a.showSecretFallback = false
			a.onboarding = true
			a.create = false
			a.status = "已退出当前设备；磁盘上的 .pm 金库文件已完整保留"
		}}
	})
}

func (a *App) forgetDeviceConfirmView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Danger.Alpha(.45)).Radius(t.Radius * 1.25).Background(t.Danger.Alpha(.06)).
		Padding(t.Space(3.5)).Gap(t.Space(2.5)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "退出当前设备？").Bold().TextColor(t.Danger).Grow(1)
			onevraPill(c, "保留 .pm 文件", t.Warning)
		})
		oneui.Text(c, "确认后会移除此设备保存的 Secret Key、停用系统快捷解锁，并解除当前设备与该金库路径的绑定；磁盘上的 .pm 金库文件不会被删除。重新绑定此金库时需使用主密码与应急文件中的 Secret Key。").
			FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "确认退出当前设备", oneui.ButtonOutline).
				TextColor(t.Danger).
				Disabled(a.uiBusy(c)).
				OnClick(a.forgetCurrentDevice)
			oneui.Button(c, "取消退出", oneui.ButtonGhost).
				Disabled(a.uiBusy(c)).
				OnClick(func() {
					a.confirmForgetDevice = false
					a.forgetPassword = ""
					a.status = ""
				})
		})
	})
}
