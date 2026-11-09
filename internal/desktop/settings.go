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

// normalize copies duration aliases into the canonical persisted units and
// applies defaults for missing presentation values.
func (s Settings) normalized() Settings {
	if s.IdleTimeout != 0 {
		s.AutoLockMinutes = int(s.IdleTimeout / time.Minute)
	}
	if s.IdleTimeout < 0 {
		s.AutoLockMinutes = 0
	}
	if s.ClipboardClearTimeout != 0 {
		s.ClipboardClearSeconds = int(s.ClipboardClearTimeout / time.Second)
	}
	if s.ClipboardClearTimeout < 0 {
		s.ClipboardClearSeconds = 0
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
	s.IdleTimeout = s.AutoLockDuration()
	s.ClipboardClearTimeout = s.ClipboardClearDuration()
	return s
}

// ValidateSettings enforces the bounded, documented preference values.
func ValidateSettings(s Settings) (Settings, error) {
	s = s.normalized()
	if s.AutoLockMinutes < 0 || s.AutoLockMinutes > 480 {
		return Settings{}, fmt.Errorf("desktop: autolock minutes %d is out of range", s.AutoLockMinutes)
	}
	if s.ClipboardClearSeconds < 0 || s.ClipboardClearSeconds > 3600 {
		return Settings{}, fmt.Errorf("desktop: clipboard clear seconds %d is out of range", s.ClipboardClearSeconds)
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
	return time.Duration(s.AutoLockMinutes) * time.Minute
}

// ClipboardClearDuration returns the owned clipboard lease duration, or 0
// when clipboard clearing is disabled.
func (s Settings) ClipboardClearDuration() time.Duration {
	return time.Duration(s.ClipboardClearSeconds) * time.Second
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

// SetAutoLockMinutes validates, applies and persists the idle auto-lock
// interval. 0 disables idle locking.
func (a *App) SetAutoLockMinutes(minutes int) error {
	s := a.settingsSnapshot()
	s.AutoLockMinutes = minutes
	s.IdleTimeout = time.Duration(minutes) * time.Minute
	s, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = s
	a.refreshClipboardClearSeconds(s)
	a.touchActivity()
	return a.SaveSettings()
}

// SetClipboardClearSeconds validates, applies and persists the owned
// clipboard lease duration. 0 disables automatic clearing.
func (a *App) SetClipboardClearSeconds(seconds int) error {
	s := a.settingsSnapshot()
	s.ClipboardClearSeconds = seconds
	s.ClipboardClearTimeout = time.Duration(seconds) * time.Second
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

// SetRevealPasswords persists the default concealment preference.
func (a *App) SetRevealPasswords(on bool) error {
	s := a.settingsSnapshot()
	s.RevealPasswords = on
	a.settings = s.normalized()
	a.refreshClipboardClearSeconds(a.settings)
	return a.SaveSettings()
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
	return a.SaveSettings()
}

// idleTimeout returns the effective idle timeout.
func (a *App) idleTimeout() time.Duration { return a.settingsSnapshot().AutoLockDuration() }

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

// maxClipboardClearSeconds is the documented upper bound for automatic
// clipboard clearing; ValidateSettings enforces the same range.
const maxClipboardClearSeconds = 3600

// clipboardTimeout returns the effective clipboard lease duration.
func (a *App) clipboardTimeout() time.Duration {
	return a.clipboardClearDuration()
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
	s := a.settingsSnapshot()
	ui.Scroll(c).Fill().Children(func() {
		ui.Column(c).Width(760).Gap(14).Children(func() {
			ui.Text(c, "Security Settings").FontSize(24).Bold()
			ui.Text(c, "Auto-lock").FontSize(18).Bold()
			ui.Text(c, "Idle auto-lock (minutes) — security.autolock.minutes")
			ui.Row(c).Gap(6).Children(func() {
				for _, m := range AutoLockPresets {
					m := m
					label := fmt.Sprintf("%d", m)
					if m == 0 {
						label = "Never"
					}
					button := ui.Button(c, "Auto-lock "+label)
					if s.AutoLockMinutes == m {
						button = ui.PrimaryButton(c, "Auto-lock "+label)
					}
					button.OnClick(func() { _ = a.SetAutoLockMinutes(m) })
				}
			})
			ui.Text(c, fmt.Sprintf("Current idle timeout: %s", durationLabel(s.AutoLockDuration())))
			sleep := s.LockOnSleep
			ui.Checkbox(c, &sleep, "Lock on sleep").OnChange(func() { _ = a.SetLockOnSleep(sleep) })
			screen := s.LockOnScreenLock
			ui.Checkbox(c, &screen, "Lock on screen lock").OnChange(func() { _ = a.SetLockOnScreenLock(screen) })
			ui.Text(c, "Clipboard").FontSize(18).Bold()
			ui.Text(c, "Clear copied secrets after (seconds) — security.clipboard.clearAfterSeconds")
			ui.Row(c).Gap(6).Children(func() {
				for _, n := range ClipboardClearPresets {
					n := n
					label := fmt.Sprintf("%d s", n)
					if n == 0 {
						label = "Never"
					}
					button := ui.Button(c, "Clipboard "+label)
					if s.ClipboardClearSeconds == n {
						button = ui.PrimaryButton(c, "Clipboard "+label)
					}
					button.OnClick(func() { _ = a.SetClipboardClearSeconds(n) })
				}
			})
			ui.Text(c, fmt.Sprintf("Current clipboard timeout: %s", durationLabel(s.ClipboardClearDuration())))
			reveal := s.RevealPasswords
			ui.Checkbox(c, &reveal, "Reveal concealed fields by default").OnChange(func() { _ = a.SetRevealPasswords(reveal) })
			ui.Text(c, "Settings are stored with 0600 permissions at "+a.settingsPath).FontSize(12)
			if a.status != "" {
				ui.Text(c, a.status)
			}
		})
	})
}

func durationLabel(d time.Duration) string {
	if d <= 0 {
		return "never"
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
	return fmt.Sprintf("%d seconds", int(d/time.Second))
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
