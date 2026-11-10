package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// Settings holds the local, non-secret desktop preferences described by the
// 1Password 8 parity ledger (security.autolock.*, security.clipboard.*,
// privacy.* and appearance.*). Secrets are never written here.
//
// The JSON tags intentionally use the dotted preference keys from the
// reference desktop so an operator can audit or migrate the file without a
// translation table. Durations are exposed as convenience accessors; the
// persisted representation uses the reference integer units (minutes and
// seconds) to avoid ambiguous Go duration strings on disk.
type Settings struct {
	// AutoLockMinutes is security.autolock.minutes. 0 means "never".
	AutoLockMinutes int `json:"security.autolock.minutes"`
	// ClipboardClearSeconds is security.clipboard.clearAfterSeconds. 0 means
	// "never clear".
	ClipboardClearSeconds int `json:"security.clipboard.clearAfterSeconds"`
	// LockOnSleep is security.autolock.onSleep.
	LockOnSleep bool `json:"security.autolock.onSleep"`
	// LockOnScreenLock is security.autolock.onDeviceLock.
	LockOnScreenLock bool `json:"security.autolock.onDeviceLock"`
	// LockOnWindowClose is security.autolock.onWindowClose.
	LockOnWindowClose bool `json:"security.autolock.onWindowClose"`
	// RevealPasswords is security.revealPasswords.
	RevealPasswords bool `json:"security.revealPasswords"`
	// CheckHIBP is privacy.checkHibp. It is off unless explicitly enabled.
	CheckHIBP bool `json:"privacy.checkHibp"`
	// Theme is appearance.theme ("system", "light", "dark").
	Theme string `json:"appearance.theme"`
	// InterfaceDensity is appearance.interfaceDensity.
	InterfaceDensity string `json:"appearance.interfaceDensity"`
	// KeepInTray is app.keepInTray.
	KeepInTray bool `json:"app.keepInTray"`
	// DefaultVaultForSaving is app.defaultVaultForSaving.
	DefaultVaultForSaving string `json:"app.defaultVaultForSaving"`

	// IdleTimeout is an in-memory convenience view of AutoLockMinutes. It is
	// not persisted separately.
	IdleTimeout time.Duration `json:"-"`
	// ClipboardClearTimeout is an in-memory convenience view of
	// ClipboardClearSeconds. It is not persisted separately.
	ClipboardClearTimeout time.Duration `json:"-"`
}

// AutoLockPresets are the intervals offered by the reference desktop.
var AutoLockPresets = []int{0, 1, 2, 5, 10, 15, 30, 60, 240, 480}

// ClipboardClearPresets are the clipboard clear intervals offered by the
// reference desktop.
var ClipboardClearPresets = []int{0, 20, 30, 60, 90, 120}

// DefaultSettings returns the documented defaults: 5 minute idle auto-lock,
// 30 second clipboard clear, lock on sleep and device lock, no HIBP checks.
func DefaultSettings() Settings {
	s := Settings{
		AutoLockMinutes:       5,
		ClipboardClearSeconds: 30,
		LockOnSleep:           true,
		LockOnScreenLock:      true,
		LockOnWindowClose:     true,
		RevealPasswords:       false,
		CheckHIBP:             false,
		Theme:                 "system",
		InterfaceDensity:      "comfortable",
		KeepInTray:            true,
		DefaultVaultForSaving: "",
	}
	return s.normalized()
}

// SettingsPath returns the per-user non-secret settings path. The containing
// directory is created with 0700 and the file is written with 0600.
func SettingsPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "locklark", "settings.json")
}

// checkAutoLockMinutes validates security.autolock.minutes in its persisted
// integer unit before it is ever converted to a duration, so a negative or
// overflowing value can never be truncated or normalized into "never" (0).
func checkAutoLockMinutes(minutes int) error {
	if minutes < minAutoLockMinutes || minutes > maxAutoLockMinutes {
		return fmt.Errorf("desktop: autolock minutes %d is out of range [%d, %d]", minutes, minAutoLockMinutes, maxAutoLockMinutes)
	}
	return nil
}

// checkClipboardClearSeconds validates security.clipboard.clearAfterSeconds in
// seconds. Negative values are rejected rather than normalized to "never".
func checkClipboardClearSeconds(seconds int) error {
	if seconds < minClipboardClearSeconds || seconds > maxClipboardClearSeconds {
		return fmt.Errorf("desktop: clipboard clear seconds %d is out of range [%d, %d]", seconds, minClipboardClearSeconds, maxClipboardClearSeconds)
	}
	return nil
}

// minutesDuration and secondsDuration convert after validation only.
func (s Settings) minutesDuration() (time.Duration, error) {
	if err := checkAutoLockMinutes(s.AutoLockMinutes); err != nil {
		return 0, err
	}
	return time.Duration(s.AutoLockMinutes) * time.Minute, nil
}

func (s Settings) secondsDuration() (time.Duration, error) {
	if err := checkClipboardClearSeconds(s.ClipboardClearSeconds); err != nil {
		return 0, err
	}
	return time.Duration(s.ClipboardClearSeconds) * time.Second, nil
}

// normalize copies presentation defaults and the in-memory duration aliases
// into the canonical persisted units. It never repairs an out-of-range
// integer: ValidateSettings reports it, and a negative alias resolves to -1 in
// the persisted unit so it is rejected instead of becoming "never".
func (s Settings) normalized() Settings {
	if s.IdleTimeout != 0 {
		if s.IdleTimeout < 0 {
			s.AutoLockMinutes = -1
		} else {
			s.AutoLockMinutes = int(s.IdleTimeout / time.Minute)
		}
	}
	if s.ClipboardClearTimeout != 0 {
		if s.ClipboardClearTimeout < 0 {
			s.ClipboardClearSeconds = -1
		} else {
			s.ClipboardClearSeconds = int(s.ClipboardClearTimeout / time.Second)
		}
	}
	if s.Theme == "" {
		s.Theme = "system"
	}
	switch s.Theme {
	case "system", "light", "dark":
	default:
		s.Theme = "system"
	}
	if s.InterfaceDensity == "" {
		s.InterfaceDensity = "comfortable"
	}
	switch s.InterfaceDensity {
	case "comfortable", "compact":
	default:
		s.InterfaceDensity = "comfortable"
	}
	if d, err := s.minutesDuration(); err == nil {
		s.IdleTimeout = d
	} else {
		s.IdleTimeout = 0
	}
	if d, err := s.secondsDuration(); err == nil {
		s.ClipboardClearTimeout = d
	} else {
		s.ClipboardClearTimeout = 0
	}
	return s
}

// ValidateSettings enforces the bounded, documented preference values.
func ValidateSettings(s Settings) (Settings, error) {
	s = s.normalized()
	if err := checkAutoLockMinutes(s.AutoLockMinutes); err != nil {
		return Settings{}, err
	}
	if err := checkClipboardClearSeconds(s.ClipboardClearSeconds); err != nil {
		return Settings{}, err
	}
	switch s.InterfaceDensity {
	case "comfortable", "compact":
	default:
		return Settings{}, errors.New("desktop: invalid interface density")
	}
	switch s.Theme {
	case "system", "light", "dark":
	default:
		return Settings{}, errors.New("desktop: invalid theme")
	}
	return s, nil
}

// AutoLockDuration returns the idle timeout, or 0 when auto-lock is disabled.
func (s Settings) AutoLockDuration() time.Duration {
	d, err := s.minutesDuration()
	if err != nil {
		return 0
	}
	return d
}

// ClipboardClearDuration returns the owned clipboard lease duration, or 0
// when clipboard clearing is disabled.
func (s Settings) ClipboardClearDuration() time.Duration {
	d, err := s.secondsDuration()
	if err != nil {
		return 0
	}
	return d
}

// LoadSettings reads the settings file. A missing file returns the defaults
// without an error so a first launch is not an error path. Unknown fields are
// ignored for forward compatibility.
func LoadSettings(path string) (Settings, error) {
	if path == "" {
		path = SettingsPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultSettings(), nil
		}
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return Settings{}, fmt.Errorf("desktop: parse settings: %w", err)
	}
	s = s.normalized()
	if _, err := ValidateSettings(s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

// SaveSettings atomically writes the non-secret settings file with 0600
// permissions. The parent directory is created with 0700.
func SaveSettings(path string, s Settings) error {
	if path == "" {
		path = SettingsPath()
	}
	s = s.normalized()
	if _, err := ValidateSettings(s); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".settings-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// settings loads the current in-memory preferences, applying defaults to a
// zero App (useful in unit tests that construct App literals).
func (a *App) settingsSnapshot() Settings {
	s := a.settings
	if s.AutoLockMinutes == 0 && s.ClipboardClearSeconds == 0 && s.Theme == "" && !s.LockOnSleep && !s.LockOnScreenLock {
		// A zero value is distinguishable from an explicit "never" only by
		// intent. New uses DefaultSettings; a literal App gets defaults too.
		return DefaultSettings()
	}
	return s.normalized()
}

// ConfigureSettingsPath selects the settings file and loads it. It never
// makes unlock depend on a readable preferences file.
func (a *App) ConfigureSettingsPath(path string) error {
	a.settingsPath = path
	s, err := LoadSettings(path)
	if err != nil {
		a.settings = DefaultSettings()
		a.refreshClipboardClearSeconds(a.settings)
		return err
	}
	a.settings = s
	a.refreshClipboardClearSeconds(s)
	return nil
}

// LoadSettings loads the configured preferences file.
func (a *App) LoadSettings() error {
	return a.ConfigureSettingsPath(a.settingsPath)
}

// SaveSettings persists the current preferences with 0600 permissions.
func (a *App) SaveSettings() error {
	return SaveSettings(a.settingsPath, a.settings)
}

// SetAutoLockMinutes validates the raw integer, applies and persists the idle
// auto-lock interval. 0 disables idle locking; a negative or out-of-range value
// is rejected without touching the current settings.
func (a *App) SetAutoLockMinutes(minutes int) error {
	if err := checkAutoLockMinutes(minutes); err != nil {
		return err
	}
	s := a.settingsSnapshot()
	s.AutoLockMinutes = minutes
	s.IdleTimeout = time.Duration(minutes) * time.Minute // bounded by the check above
	s, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = s
	a.refreshClipboardClearSeconds(s)
	a.touchActivity()
	a.applyIdlePolicy()
	return a.SaveSettings()
}

// SetClipboardClearSeconds validates the raw integer, applies and persists the
// owned clipboard lease duration. 0 disables automatic clearing; a negative or
// out-of-range value is rejected without touching the current settings.
func (a *App) SetClipboardClearSeconds(seconds int) error {
	if err := checkClipboardClearSeconds(seconds); err != nil {
		return err
	}
	s := a.settingsSnapshot()
	s.ClipboardClearSeconds = seconds
	s.ClipboardClearTimeout = time.Duration(seconds) * time.Second // bounded above
	s, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = s
	a.refreshClipboardClearSeconds(s)
	return a.SaveSettings()
}

// SetLockOnSleep and SetLockOnScreenLock persist the OS integration toggles.
func (a *App) SetLockOnSleep(on bool) error {
	s := a.settingsSnapshot()
	s.LockOnSleep = on
	a.settings = s.normalized()
	a.refreshClipboardClearSeconds(a.settings)
	return a.SaveSettings()
}

func (a *App) SetLockOnScreenLock(on bool) error {
	s := a.settingsSnapshot()
	s.LockOnScreenLock = on
	a.settings = s.normalized()
	a.refreshClipboardClearSeconds(a.settings)
	return a.SaveSettings()
}

// SetLockOnWindowClose persists whether closing the window locks the vault.
func (a *App) SetLockOnWindowClose(on bool) error {
	s := a.settingsSnapshot()
	s.LockOnWindowClose = on
	a.settings = s.normalized()
	a.refreshClipboardClearSeconds(a.settings)
	return a.SaveSettings()
}

// SetRevealPasswords persists the default concealment preference. Turning it
// off immediately retracts any live default password disclosure.
func (a *App) SetRevealPasswords(on bool) error {
	s := a.settingsSnapshot()
	s.RevealPasswords = on
	a.settings = s.normalized()
	a.refreshClipboardClearSeconds(a.settings)
	if !on {
		a.defaultRevealAt = time.Time{}
		a.hideRevealed()
	}
	a.retractNarrowRevealIfDisabled()
	return a.SaveSettings()
}

// retractNarrowRevealIfDisabled hides an outstanding password-only disclosure
// when the preference is no longer active, e.g. after ApplySettings.
func (a *App) retractNarrowRevealIfDisabled() {
	if !a.settingsSnapshot().RevealPasswords {
		a.defaultRevealAt = time.Time{}
		if a.hideNarrowPassword() && !a.v2.revealUntil.IsZero() {
			a.v2.revealUntil = time.Time{}
		}
	}
}

// ApplySettings validates and applies an in-memory settings value, then
// persists it. It is the single entry point used by the settings view.
func (a *App) ApplySettings(s Settings) error {
	s, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = s
	a.refreshClipboardClearSeconds(s)
	a.touchActivity()
	a.applyIdlePolicy()
	if s.RevealPasswords && a.v2.detail != nil && a.defaultRevealAt.IsZero() && a.v2.narrowPassword.value == nil {
		a.defaultRevealAt = time.Now()
	}
	a.retractNarrowRevealIfDisabled()
	return a.SaveSettings()
}

// idleTimeout returns the effective idle timeout.
// An invalid preference fails closed to the documented default instead of
// silently becoming "never".
func (a *App) idleTimeout() time.Duration {
	d, err := a.settingsSnapshot().minutesDuration()
	if err != nil {
		return DefaultSettings().AutoLockDuration()
	}
	return d
}

// clipboardClearDuration is the non-blocking mirror of
// security.clipboard.clearAfterSeconds. Broker connection goroutines call it
// while holding no App state, so it never reads the UI settings struct. A
// negative result signals an invalid mirror and every caller fails closed
// instead of silently disabling cleanup.
func (a *App) clipboardClearDuration() time.Duration {
	seconds := a.clipboardClearSeconds.Load()
	if seconds < 0 || seconds > maxClipboardClearSeconds {
		return -1
	}
	return time.Duration(seconds) * time.Second
}

// refreshClipboardClearSeconds republishes the validated preference into the
// atomic mirror. Every settings mutation entry point and the UI start call it
// exactly once so an accepted broker connection always sees a live value.
func (a *App) refreshClipboardClearSeconds(s Settings) {
	seconds := int64(s.ClipboardClearSeconds)
	if seconds < 0 || seconds > maxClipboardClearSeconds {
		seconds = 0
	}
	a.clipboardClearSeconds.Store(seconds)
}

// Documented bounds for the persisted integer preference units.
const (
	minAutoLockMinutes       = 0
	maxAutoLockMinutes       = 480
	minClipboardClearSeconds = 0
	maxClipboardClearSeconds = 3600
)

// clipboardTimeout returns the effective clipboard lease duration.
// An invalid mirror never disables cleanup: it falls back to the default.
func (a *App) clipboardTimeout() time.Duration {
	d := a.clipboardClearDuration()
	if d < 0 {
		return DefaultSettings().ClipboardClearDuration()
	}
	return d
}

// touchActivity records an explicit user interaction for idle auto-lock.
// Passive redraws and background timer ticks deliberately do not call it.
func (a *App) touchActivity() {
	a.lastActivity = time.Now()
}

// checkIdle locks an unlocked session after the configured idle period.
func (a *App) checkIdle(now time.Time) bool {
	if a.session == nil || !a.session.Unlocked() {
		return false
	}
	timeout := a.idleTimeout()
	if timeout <= 0 {
		return false
	}
	if a.lastActivity.IsZero() {
		a.lastActivity = now
		return false
	}
	if now.Sub(a.lastActivity) < timeout {
		return false
	}
	a.Lock()
	return true
}

// backgroundTick is the single idempotent timer body. It runs from the
// independent ticker started by Run and may also be called by tests with a
// synthetic clock. It never assumes that View has rendered.
func (a *App) backgroundTick(now time.Time) {
	if a.settingsSnapshot().RevealPasswords && !a.narrowRevealPending && !a.v2.largeTypeOpen {
		if !a.defaultRevealAt.IsZero() && !now.Before(a.defaultRevealAt.Add(defaultRevealDelay)) {
			a.defaultRevealAt = time.Time{}
			a.requestPasswordReveal()
		}
	} else {
		a.defaultRevealAt = time.Time{}
	}
	if a.v2.narrowPassword.value != nil {
		d := a.v2.detail
		if d == nil || !a.v2.narrowPassword.current(d.ID, d.Revision, now) || d.Kind != string(vault.CategoryLogin) || !a.settingsSnapshot().RevealPasswords {
			a.hideNarrowPassword()
		}
	}
	a.checkOTPExposure(now)
	if !a.displayUntil.IsZero() && !now.Before(a.displayUntil) {
		a.display = ""
		a.displayUntil = time.Time{}
	}
	if !a.clipboardUntil.IsZero() && !now.Before(a.clipboardUntil) {
		a.clearClipboard()
	}
	if !a.v2.revealUntil.IsZero() && !now.Before(a.v2.revealUntil) {
		a.hideRevealed()
	}
	if a.v2.largeTypeOpen && a.session == nil {
		a.closeLargeType()
	}
	if a.session != nil && !a.session.Unlocked() {
		a.Lock()
		return
	}
	a.checkIdle(now)
}

// startBackgroundLoop starts the rendering-independent timer required by
// desktop bug #32. It is stopped by stopBackgroundLoop.
func (a *App) startBackgroundLoop() {
	if a.backgroundStop != nil {
		return
	}
	stop := make(chan struct{})
	a.backgroundStop = stop
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				a.dispatch(func() { a.backgroundTick(now) })
			}
		}
	}()
}

// stopBackgroundLoop stops the timer exactly once.
func (a *App) stopBackgroundLoop() {
	if a.backgroundStop != nil {
		close(a.backgroundStop)
		a.backgroundStop = nil
	}
}

// backgroundRunning is used by tests to assert teardown.
func (a *App) backgroundRunning() bool {
	return atomic.LoadUint32(&a.backgroundRunningFlag) == 1
}

// settingsView renders configurable security preferences. It is reachable
// from the top bar and is deliberately usable while a vault is unlocked.
func (a *App) settingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	ui.Column(c.Key("settings")).Role(ui.RoleGroup).Label("安全与偏好设置").FillWidth().MinWidth(0).Gap(t.Space(3)).Children(func() {
		// Header
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
			iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
				Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
			iconBox.Children(func() {
				oneui.Icon(c, lucide.Settings()).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
			})
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
				oneui.Text(c, "安全与偏好设置").FontSize(t.Rem(1.35)).Bold().SingleLine()
				oneui.Text(c, "管理本地自动锁定、剪贴板自动清理与系统级快捷解锁策略。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
			})
			oneui.Button(c, "关闭设置", oneui.ButtonOutline).OnClick(a.closeSettings)
		})

		// 1. Auto-Lock Card
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, "自动锁定").Bold().Grow(1)
				oneui.Badge(c, durationLabel(s.AutoLockDuration()), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
			})
			oneui.Text(c, "空闲自动锁定时间（分钟）— security.autolock.minutes").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
				for _, m := range AutoLockPresets {
					m := m
					label := fmt.Sprintf("%d 分钟", m)
					if m == 0 {
						label = "从不"
					}
					variant := oneui.ButtonOutline
					if s.AutoLockMinutes == m {
						variant = oneui.ButtonPrimary
					}
					oneui.Button(c, label, variant).OnClick(func() { _ = a.SetAutoLockMinutes(m) })
				}
			})
			oneui.Text(c, fmt.Sprintf("当前空闲自动锁定阈值：%s", durationLabel(s.AutoLockDuration()))).FontSize(t.Rem(.82)).TextColor(t.TextMuted)
			ui.Box(c).FillWidth().Height(1).Background(t.Border)
			sleep := s.LockOnSleep
			oneui.Checkbox(c, &sleep, "系统休眠时自动锁定").OnChange(func() { _ = a.SetLockOnSleep(sleep) })
			screen := s.LockOnScreenLock
			oneui.Checkbox(c, &screen, "屏幕锁定时自动锁定").OnChange(func() { _ = a.SetLockOnScreenLock(screen) })
			window := s.LockOnWindowClose
			oneui.Checkbox(c, &window, "关闭窗口时自动锁定").OnChange(func() { _ = a.SetLockOnWindowClose(window) })
		})

		// 2. Clipboard Protection Card
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, "剪贴板防护").Bold().Grow(1)
				oneui.Badge(c, durationLabel(s.ClipboardClearDuration()), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
			})
			oneui.Text(c, "复制敏感内容后尝试清理时间（秒）— security.clipboard.clearAfterSeconds").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
				for _, n := range ClipboardClearPresets {
					n := n
					label := fmt.Sprintf("%d 秒", n)
					if n == 0 {
						label = "从不"
					}
					variant := oneui.ButtonOutline
					if s.ClipboardClearSeconds == n {
						variant = oneui.ButtonPrimary
					}
					oneui.Button(c, label, variant).OnClick(func() { _ = a.SetClipboardClearSeconds(n) })
				}
			})
			oneui.Text(c, fmt.Sprintf("当前剪贴板清理策略：%s", durationLabel(s.ClipboardClearDuration()))).FontSize(t.Rem(.82)).TextColor(t.TextMuted)
			ui.Box(c).FillWidth().Height(1).Background(t.Border)
			reveal := s.RevealPasswords
			oneui.Checkbox(c, &reveal, "默认显示遮蔽字段").OnChange(func() { _ = a.SetRevealPasswords(reveal) })
		})

		// 3. System Quick Unlock & Shortcut Card
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				oneui.Text(c, "快捷解锁："+osunlock.Label()).Bold().Grow(1)
				oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.TextMuted)
			})
			oneui.Text(c, osunlock.Description()).FontSize(t.Rem(.82)).Wrap()
			oneui.Text(c, osunlock.Requirement()).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			oneui.Text(c, "首次或授权到期后需使用主密码与 Secret Key 完整解锁，再主动启用；系统验证失败时仍可通过完整凭据解锁。").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
				oneui.Button(c, "启用系统快捷解锁（有效期 24 小时）", oneui.ButtonSecondary).Disabled(a.busy || a.session == nil).OnClick(func() {
					sess, store := a.session, a.systemStore
					if sess == nil {
						return
					}
					a.run(func() outcome {
						return outcome{err: sess.EnableSystemUnlock(store), apply: func() { a.status = "系统快捷解锁已启用；现在可锁定并试用" }}
					})
				})
				oneui.Button(c, "停用系统快捷解锁", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
					path, store := a.path, a.systemStore
					a.run(func() outcome {
						return outcome{err: personal.DisableSystemUnlock(path, store), apply: func() { a.status = "系统快捷解锁已停用" }}
					})
				})
			})
			ui.Box(c).FillWidth().Height(1).Background(t.Border)
			oneui.Text(c, "快捷搜索："+quickSearchAcceleratorLabel()).FontSize(t.Rem(.84)).Bold()
			shortcut := a.quickShortcut
			if shortcut == "" {
				shortcut = "全局快捷键尚未提交注册；可使用窗口顶部的「快捷搜索」按钮。"
			}
			oneui.Text(c, shortcut).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		})

		// 4. Advanced Workspace Tools Card (when unlocked in v2 workspace)
		if a.v2Mode && a.session != nil {
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
				Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
				oneui.Text(c, "高级工作区工具").Bold()
				oneui.Text(c, "管理本地 SSH Agent 密钥、1Password 1PUX 迁移导入、KDBX 加密备份与安全审计记录。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
				ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
					oneui.Button(c, "SSH 密钥与 Agent", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
						a.v2.settingsOpen = false
						a.page = "ssh"
						a.refreshSSHKeys()
					})
					oneui.Button(c, "导入与导出", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
						a.v2.settingsOpen = false
						a.page = "transfer"
					})
					oneui.Button(c, "安全审计日志", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
						a.v2.settingsOpen = false
						a.page = "activity"
					})
				})
			})
		}

		oneui.Text(c, "非敏感偏好设置以 0600 权限保存于 "+a.settingsPath).FontSize(t.Rem(.75)).TextColor(t.TextMuted).Wrap()
	})
}

func durationLabel(d time.Duration) string {
	if d <= 0 {
		return "从不"
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return fmt.Sprintf("%d 秒", int(d/time.Second))
}

// normalizeThemeName is a small helper for future appearance controls and
// keeps the accepted values in one place.
func normalizeThemeName(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "light":
		return "light"
	case "dark":
		return "dark"
	default:
		return "system"
	}
}
