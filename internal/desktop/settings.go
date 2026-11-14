package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
	"github.com/oneo-me/onevra/source/theme"
)

const (
	settingsSectionGeneral     = "general"
	settingsSectionAppearance  = "appearance"
	settingsSectionSecurity    = "security"
	settingsSectionBrowser     = "browser"
	settingsSectionDeveloper   = "developer"
	settingsSectionSSH         = "ssh"
	settingsSectionCLI         = "cli"
	settingsSectionCLIActivity = "cli-activity"
	settingsSectionAudit       = "audit"
	settingsSectionTransfer    = "transfer"
	settingsSectionUpdates     = "updates"
	settingsSectionAbout       = "about"
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
	// VaultPath is app.vaultPath. Only the local .ll file path is stored here;
	// Secret Key and master passwords are never written to settings.
	VaultPath string `json:"app.vaultPath,omitempty"`

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

// UsageError reports invalid desktop command-line arguments. Its message is
// the fixed usage text and never includes the offending argument or path.
type UsageError struct{}

func (*UsageError) Error() string { return desktopSettingsUsage }

// desktopSettingsUsage is the only command-line syntax the desktop accepts.
const desktopSettingsUsage = "usage: locklark-desktop [--settings ABSOLUTE_PATH]"

// ErrSettingsPath is returned for an unusable explicit settings path. The
// error never includes the path itself.
var ErrSettingsPath = errors.New("desktop: settings path must be one absolute, clean file path")

// parseDesktopArgs parses the desktop command line. Only a single
// "--settings ABSOLUTE_PATH" option pair is accepted; no arguments means the
// default SettingsPath(). A "--settings=" form is rejected so the option has
// one spelling.
func parseDesktopArgs(args []string) (settingsPath string, err error) {
	switch {
	case len(args) == 0:
		return "", nil
	case len(args) == 2 && args[0] == "--settings":
		clean, err := validateSettingsFilePath(args[1])
		if err != nil {
			return "", err
		}
		return clean, nil
	default:
		return "", &UsageError{}
	}
}

// validateSettingsFilePath accepts exactly one absolute, clean path without
// NUL bytes. An existing path must be a regular file (checked with Lstat so a
// symlink or special file such as a FIFO or device cannot disguise a
// non-regular path); a path that does not exist yet is allowed.
func validateSettingsFilePath(path string) (string, error) {
	switch {
	case path == "" || strings.ContainsRune(path, 0):
		return "", ErrSettingsPath
	case !filepath.IsAbs(path):
		return "", ErrSettingsPath
	case filepath.Clean(path) != path:
		return "", ErrSettingsPath
	}
	if filepath.Dir(path) == path {
		// A filesystem root cannot be a settings file.
		return "", ErrSettingsPath
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return path, nil
	case err != nil:
		return "", ErrSettingsPath
	case !info.Mode().IsRegular():
		return "", ErrSettingsPath
	}
	return path, nil
}

// RunDesktopArgs validates the desktop command line and starts the
// application with the selected settings path. Invalid arguments return a
// *UsageError before any GUI state is created; no arguments run Run().
func RunDesktopArgs(args []string) error {
	path, err := parseDesktopArgs(args)
	if err != nil {
		return err
	}
	return RunWithSettingsPath(path)
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
	s.VaultPath = strings.TrimSpace(s.VaultPath)
	if s.VaultPath != "" {
		s.VaultPath = filepath.Clean(s.VaultPath)
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
	if strings.ContainsAny(s.VaultPath, "\x00\r\n") {
		return Settings{}, errors.New("desktop: invalid vault path")
	}
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

// SetTheme validates, applies and persists appearance.theme ("system", "light", "dark").
func (a *App) SetTheme(mode string) error {
	s := a.settingsSnapshot()
	s.Theme = normalizeThemeName(mode)
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	a.refreshClipboardClearSeconds(validated)
	a.applyAppearanceToRuntime()
	return a.SaveSettings()
}

// SetInterfaceDensity validates, applies and persists appearance.interfaceDensity.
func (a *App) SetInterfaceDensity(density string) error {
	s := a.settingsSnapshot()
	switch strings.ToLower(strings.TrimSpace(density)) {
	case "compact":
		s.InterfaceDensity = "compact"
	default:
		s.InterfaceDensity = "comfortable"
	}
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	a.refreshClipboardClearSeconds(validated)
	a.applyAppearanceToRuntime()
	return a.SaveSettings()
}

// SetDefaultVaultForSaving persists app.defaultVaultForSaving.
func (a *App) SetDefaultVaultForSaving(vaultID string) error {
	s := a.settingsSnapshot()
	s.DefaultVaultForSaving = strings.TrimSpace(vaultID)
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	return a.SaveSettings()
}

// SetVaultPath persists the currently bound local vault file path without secrets.
func (a *App) SetVaultPath(path string) error {
	s := a.settingsSnapshot()
	s.VaultPath = strings.TrimSpace(path)
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	return a.SaveSettings()
}

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
	out := *base
	if s.InterfaceDensity == "compact" {
		out.Spacing = 3.25
	}
	return &out
}

func (a *App) applyAppearanceToRuntime() {
	s := a.settingsSnapshot()
	if a.win != nil {
		switch s.Theme {
		case "light":
			mygo.Theme.SetSource(mygo.ThemeLight)
		case "dark":
			mygo.Theme.SetSource(mygo.ThemeDark)
		default:
			mygo.Theme.SetSource(mygo.ThemeSystem)
		}
		a.win.Invalidate()
	}
	if a.approvalWin != nil {
		a.approvalWin.Invalidate()
	}
}

func normalizeSettingsSection(section string) string {
	switch section {
	case settingsSectionGeneral,
		settingsSectionAppearance,
		settingsSectionSecurity,
		settingsSectionBrowser,
		settingsSectionDeveloper,
		settingsSectionSSH,
		settingsSectionCLI,
		settingsSectionCLIActivity,
		settingsSectionAudit,
		settingsSectionTransfer,
		settingsSectionUpdates,
		settingsSectionAbout:
		return section
	default:
		return settingsSectionSecurity
	}
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
	switch {
	case !a.settingsSnapshot().RevealPasswords || a.v2.largeTypeOpen:
		a.defaultRevealAt = time.Time{}
	case a.busy:
		// The single worker slot is taken, so run would return before the
		// read starts. Keep the schedule armed for a later tick.
	case !a.narrowRevealPending && !a.defaultRevealAt.IsZero() && !now.Before(a.defaultRevealAt.Add(defaultRevealDelay)):
		a.defaultRevealAt = time.Time{}
		a.requestPasswordReveal()
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

// settingsView renders the 12-section left-sidebar Settings workspace. It is
// reachable from the header gear and sidebar footer while unlocked.
func (a *App) settingsView(c *ui.Context) {
	t := c.Theme()
	section := normalizeSettingsSection(a.v2.settingsSection)
	a.v2.settingsSection = section

	ui.Row(c.Key("settings")).Role(ui.RoleGroup).Label("设置工作区").FillWidth().MinWidth(0).FillHeight().Gap(0).Children(func() {
		// Left 236px navigation rail
		ui.Column(c).Width(236).Shrink(0).FillHeight().Background(t.Surface).
			Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				btn := oneui.Button(c, "关闭设置", oneui.ButtonGhost).Grow(1)
				if btn.Clicked() {
					a.closeSettings()
				}
			})
			ui.Column(c).FillWidth().Padding(t.Space(1), t.Space(1.5)).Gap(t.Space(.25)).Children(func() {
				oneui.Text(c, "设置").FontSize(t.Rem(1.18)).Bold()
				oneui.Text(c, "仅保存非秘密偏好 · 0600 权限").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			oneui.ScrollView(c, oneui.ScrollViewOptions{}).Fill().Children(func() {
				oneui.Sidebar(c).Children(func() {
					oneui.SidebarSection(c, "本机", func() {
						a.onevraSidebarItem(c, "通用", lucide.SlidersHorizontal(), section == settingsSectionGeneral, 0, func() {
							a.selectSettingsSection(settingsSectionGeneral)
						})
						a.onevraSidebarItem(c, "外观", lucide.Palette(), section == settingsSectionAppearance, 0, func() {
							a.selectSettingsSection(settingsSectionAppearance)
						})
					})
					oneui.SidebarSection(c, "安全", func() {
						a.onevraSidebarItem(c, "安全与偏好", lucide.Shield(), section == settingsSectionSecurity, 0, func() {
							a.selectSettingsSection(settingsSectionSecurity)
						})
						a.onevraSidebarItem(c, "浏览与自动填充", lucide.Globe(), section == settingsSectionBrowser, 0, func() {
							a.selectSettingsSection(settingsSectionBrowser)
						})
					})
					oneui.SidebarSection(c, "开发者与集成", func() {
						a.onevraSidebarItem(c, "开发者", lucide.Code(), section == settingsSectionDeveloper, 0, func() {
							a.selectSettingsSection(settingsSectionDeveloper)
						})
						a.onevraSidebarItem(c, "SSH 与 Agent", lucide.KeyRound(), section == settingsSectionSSH, 0, func() {
							a.selectSettingsSection(settingsSectionSSH)
							a.refreshSSHKeys()
						})
						a.onevraSidebarItem(c, "CLI 集成", lucide.SquareTerminal(), section == settingsSectionCLI, len(a.cliSettings.store.Bindings), func() {
							a.selectSettingsSection(settingsSectionCLI)
						})
						a.onevraSidebarItem(c, "CLI 请求活动", lucide.ScrollText(), section == settingsSectionCLIActivity, 0, func() {
							a.selectSettingsSection(settingsSectionCLIActivity)
						})
						a.onevraSidebarItem(c, "活动审计", lucide.Activity(), section == settingsSectionAudit, 0, func() {
							a.selectSettingsSection(settingsSectionAudit)
						})
					})
					oneui.SidebarSection(c, "数据与设备", func() {
						a.onevraSidebarItem(c, "导入与导出", lucide.ArrowLeftRight(), section == settingsSectionTransfer, 0, func() {
							a.selectSettingsSection(settingsSectionTransfer)
						})
					})
					oneui.SidebarSection(c, "应用", func() {
						a.onevraSidebarItem(c, "更新", lucide.Download(), section == settingsSectionUpdates, 0, func() {
							a.selectSettingsSection(settingsSectionUpdates)
						})
						a.onevraSidebarItem(c, "关于 Locklark", lucide.Info(), section == settingsSectionAbout, 0, func() {
							a.selectSettingsSection(settingsSectionAbout)
						})
					})
				})
			})
		})

		ui.Box(c).Width(1).FillHeight().Background(t.Border)

		// Right scrollable content pane
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Grow(1).FillHeight().Children(func() {
			ui.Column(c.Key("settings-" + section)).FillWidth().MinWidth(0).MaxWidth(920).Padding(t.Space(5)).Gap(t.Space(3)).Children(func() {
				a.settingsSectionHeader(c, section)
				switch section {
				case settingsSectionGeneral:
					a.generalSettingsView(c)
				case settingsSectionAppearance:
					a.appearanceSettingsView(c)
				case settingsSectionBrowser:
					a.browserSettingsView(c)
				case settingsSectionDeveloper:
					a.developerSettingsView(c)
				case settingsSectionSSH:
					a.sshKeysContentView(c)
				case settingsSectionCLI:
					a.cliIntegrationsView(c)
				case settingsSectionCLIActivity:
					a.cliRequestActivityView(c)
				case settingsSectionAudit:
					a.activityContentView(c)
				case settingsSectionTransfer:
					a.transferSettingsView(c)
				case settingsSectionUpdates:
					a.updatesSettingsView(c)
				case settingsSectionAbout:
					a.aboutSettingsView(c)
				default:
					a.securitySettingsView(c)
				}
				oneui.Text(c, "非敏感偏好设置以 0600 权限保存于 "+a.settingsPath).FontSize(t.Rem(.75)).TextColor(t.TextMuted).Wrap()
			})
		})
	})
}

func (a *App) selectSettingsSection(section string) {
	a.v2.settingsSection = normalizeSettingsSection(section)
	a.touchActivity()
}

func (a *App) settingsSectionHeader(c *ui.Context, section string) {
	t := c.Theme()
	title, subtitle := "安全与偏好设置", "管理本地自动锁定、剪贴板自动清理与系统级快捷解锁策略。"
	icon := lucide.Shield()
	switch section {
	case settingsSectionGeneral:
		title, subtitle = "通用", "查看当前绑定的本地金库文件、默认保存位置与托盘后台策略。"
		icon = lucide.SlidersHorizontal()
	case settingsSectionAppearance:
		title, subtitle = "外观", "选择主题配色模式与界面信息密度；修改立即生效并保存。"
		icon = lucide.Palette()
	case settingsSectionBrowser:
		title, subtitle = "浏览与自动填充", "检查本机浏览器 IPC 桥接状态与按来源确认的自动填充边界。"
		icon = lucide.Globe()
	case settingsSectionDeveloper:
		title, subtitle = "开发者工具", "管理本机已经接通的 SSH、审计、导入导出和 CLI/MCP 工具入口。"
		icon = lucide.Code()
	case settingsSectionSSH:
		title, subtitle = "SSH 与 Agent", "管理 Ed25519 公钥并按次授权本机 SSH 签名请求。"
		icon = lucide.KeyRound()
	case settingsSectionCLI:
		title, subtitle = "CLI 集成配置", "查看已安装的命令行工具，并把金库字段绑定到受控的 CLI 配置。"
		icon = lucide.SquareTerminal()
	case settingsSectionCLIActivity:
		title, subtitle = "CLI 请求活动", "审计本机 CLI 凭据请求及其批准、拒绝和失败结果。"
		icon = lucide.ScrollText()
	case settingsSectionAudit:
		title, subtitle = "活动审计", "查看当前金库的离线签名审计事件账本。"
		icon = lucide.Activity()
	case settingsSectionTransfer:
		title, subtitle = "导入与导出", "从 1Password 1PUX 原子导入、导出加密 KDBX，或重新导出本机应急文件。"
		icon = lucide.ArrowLeftRight()
	case settingsSectionUpdates:
		title, subtitle = "更新", "查看应用版本与基于 Ed25519 公钥签名的离线/GitHub Releases 更新机制。"
		icon = lucide.Download()
	case settingsSectionAbout:
		title, subtitle = "关于 Locklark", "离线优先与零知识安全边界摘要及脱敏诊断信息。"
		icon = lucide.Info()
	}

	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2.5)).Children(func() {
		iconBox := ui.Box(c).Size(t.Space(10), t.Space(10)).Shrink(0).Radius(t.Space(2.5)).
			Background(t.Accent.Alpha(.12)).AlignItems(ui.Center).Justify(ui.Center)
		iconBox.Children(func() {
			oneui.Icon(c, icon).Size(t.Space(5), t.Space(5)).TextColor(t.Accent)
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			oneui.Text(c, title).FontSize(t.Rem(1.35)).Bold().SingleLine()
			oneui.Text(c, subtitle).FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		})
	})
}

func (a *App) generalSettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	// 1. Bound Vault & Device Lifecycle
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "本机绑定的金库").Bold().Grow(1)
			if a.path != "" {
				if _, err := a.loadDeviceSecret(a.path); err == nil {
					oneui.Badge(c.Key("vault-secret-saved"), "Secret Key 已存于本机", oneui.BadgeOptions{Tone: oneui.BadgeSuccess})
				} else {
					oneui.Badge(c.Key("vault-secret-needed"), "需应急恢复", oneui.BadgeOptions{Tone: oneui.BadgeWarning})
				}
			}
		})
		vaultName := vaultDisplayBaseName(a.path)
		if vaultName == "" {
			vaultName = "未绑定"
		}
		oneui.Text(c, vaultName+" · "+displayVaultLocation(a.path)).FontSize(t.Rem(.88)).Bold()
		if a.path != "" {
			oneui.Text(c, a.path).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
		}
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "查看首次创建流程", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
				a.Lock()
				a.onboarding = true
				a.create = false
				a.status = "已锁定并切换到首次创建引导概览"
			})
			oneui.Button(c, "退出当前设备…", oneui.ButtonOutline).Disabled(a.busy || a.path == "").OnClick(func() {
				a.confirmForgetDevice = true
				a.forgetPassword = ""
				a.status = "退出当前设备不会删除磁盘上的 .ll 金库文件"
			})
		})
		if a.confirmForgetDevice {
			a.forgetDeviceConfirmView(c)
		}
	})

	// 2. Window & Background Tray Policy (Fixed Background Execution)
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "关闭或最小化主窗口").Bold().Grow(1)
			oneui.Badge(c.Key("bg-pinned"), "固定后台运行", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		oneui.Text(c, "点击关闭或最小化按钮时立即锁定金库并隐藏到系统托盘，不弹出退出确认；本机浏览器扩展与 CLI 审批弹窗仍可及时响应。仅托盘菜单「退出」会结束进程。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
	})

	// 3. Default Vault for Saving & Quick Search
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, "保存与快捷访问").Bold()
		if len(a.v2.vaults) > 0 {
			selectedVault := s.DefaultVaultForSaving
			if selectedVault == "" {
				selectedVault = vault.DefaultVaultID
			}
			options := make([]oneui.NativeSelectOption[string], 0, len(a.v2.vaults))
			for _, v := range a.v2.vaults {
				options = append(options, oneui.NativeSelectOption[string]{Value: v.ID, Label: v.Name})
			}
			sel := oneui.NativeSelect(c, &selectedVault, options)
			sel.Trigger.Label("新建与自动保存默认保险库").Width(240)
			if sel.Changed() {
				if err := a.SetDefaultVaultForSaving(selectedVault); err != nil {
					a.status = "默认保险库设置保存失败"
				}
			}
		}
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		oneui.Text(c, "全局快捷搜索："+quickSearchAcceleratorLabel()).FontSize(t.Rem(.84)).Bold()
		shortcut := a.quickShortcut
		if shortcut == "" {
			shortcut = "全局快捷键尚未提交注册；可使用窗口顶部的「快捷搜索」按钮。"
		}
		oneui.Text(c, shortcut).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
	})
}

func (a *App) appearanceSettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	// Theme Selector Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "主题模式").Bold().Grow(1)
			oneui.Badge(c.Key("theme-badge-"+s.Theme), themeLabel(s.Theme), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(2)).Children(func() {
			for _, opt := range []struct {
				id, title, desc string
			}{
				{"system", "跟随系统", "自动匹配操作系统的浅色或深色模式"},
				{"light", "浅色", "暖白柔和对比度，适合日间与长时间阅读"},
				{"dark", "深色", "暖炭色低眩光表面，减少夜间视觉疲劳"},
			} {
				opt := opt
				selected := s.Theme == opt.id
				border := t.Border
				bg := t.Background
				if selected {
					border = t.Accent
					bg = t.Accent.Alpha(.08)
				}
				card := ui.ButtonBase(c.Key("theme-"+opt.id)).Label("主题："+opt.title).
					Grow(1).MinWidth(180).Border(1, border).Radius(t.Radius).Background(bg).
					Padding(t.Space(2.5))
				card.Children(func() {
					ui.Column(c).FillWidth().Gap(t.Space(.5)).Children(func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
							oneui.Text(c, opt.title).Bold().Grow(1)
							if selected {
								oneui.Badge(c, "当前", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
							}
						})
						oneui.Text(c, opt.desc).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
					})
				})
				if card.Clicked() {
					_ = a.SetTheme(opt.id)
					a.status = "主题已切换为：" + opt.title
				}
			}
		})
	})

	// Density Selector Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "界面密度").Bold().Grow(1)
			oneui.Badge(c.Key("density-badge-"+s.InterfaceDensity), densityLabel(s.InterfaceDensity), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
		})
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(2)).Children(func() {
			for _, opt := range []struct {
				id, title, desc string
			}{
				{"comfortable", "舒适", "标准内边距与列表行高，适合桌面端日常管理"},
				{"compact", "紧凑", "更紧凑的间距与列表密度，同屏显示更多凭据条目"},
			} {
				opt := opt
				selected := s.InterfaceDensity == opt.id
				border := t.Border
				bg := t.Background
				if selected {
					border = t.Accent
					bg = t.Accent.Alpha(.08)
				}
				card := ui.ButtonBase(c.Key("density-"+opt.id)).Label("密度："+opt.title).
					Grow(1).MinWidth(220).Border(1, border).Radius(t.Radius).Background(bg).
					Padding(t.Space(2.5))
				card.Children(func() {
					ui.Column(c).FillWidth().Gap(t.Space(.5)).Children(func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
							oneui.Text(c, opt.title).Bold().Grow(1)
							if selected {
								oneui.Badge(c, "当前", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
							}
						})
						oneui.Text(c, opt.desc).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
					})
				})
				if card.Clicked() {
					_ = a.SetInterfaceDensity(opt.id)
					a.status = "界面密度已切换为：" + opt.title
				}
			}
		})
	})

	// Live Mini Preview Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, "实时外观预览").FontSize(t.Rem(.82)).Bold().TextColor(t.TextMuted)
		ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).
			Padding(t.Space(2)).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Width(90).Padding(t.Space(1.5)).Radius(t.Radius * .75).Background(t.Surface).Gap(t.Space(1)).Children(func() {
				oneui.Text(c, "全部").FontSize(t.Rem(.72)).Bold().TextColor(t.Accent)
				oneui.Text(c, "收藏").FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			ui.Column(c).Grow(1).Gap(t.Space(.75)).Children(func() {
				oneui.Text(c, "GitHub Production Token").FontSize(t.Rem(.84)).Bold()
				oneui.Text(c, fmt.Sprintf("Spacing %.2f DIP · %s", t.Spacing, themeLabel(s.Theme))).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			oneui.Badge(c, "实时生效", oneui.BadgeOptions{Tone: oneui.BadgeSuccess})
		})
	})
}

func (a *App) securitySettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	// 1. Auto-Lock Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "自动锁定").Bold().Grow(1)
			oneui.Badge(c.Key("autolock-"+durationLabel(s.AutoLockDuration())), durationLabel(s.AutoLockDuration()), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		oneui.Text(c, "空闲自动锁定时间").FontSize(t.Rem(.76)).TextColor(t.TextMuted)
		minutes := s.AutoLockMinutes
		autoSelect := oneui.NativeSelect(c, &minutes, durationOptions(AutoLockPresets, minutes, "分钟"))
		autoSelect.Trigger.Label("自动锁定时间").Width(180)
		if autoSelect.Changed() {
			if err := a.SetAutoLockMinutes(minutes); err != nil {
				a.status = "自动锁定设置保存失败"
			}
		}
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		sleep := s.LockOnSleep
		oneui.Checkbox(c, &sleep, "系统休眠时自动锁定").OnChange(func() { _ = a.SetLockOnSleep(sleep) })
		screen := s.LockOnScreenLock
		oneui.Checkbox(c, &screen, "屏幕锁定时自动锁定").OnChange(func() { _ = a.SetLockOnScreenLock(screen) })
	})

	// 2. Clipboard Protection Card
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "剪贴板防护").Bold().Grow(1)
			oneui.Badge(c.Key("clip-"+durationLabel(s.ClipboardClearDuration())), durationLabel(s.ClipboardClearDuration()), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
		})
		oneui.Text(c, "复制后清理剪贴板").FontSize(t.Rem(.76)).TextColor(t.TextMuted)
		seconds := s.ClipboardClearSeconds
		clipboardSelect := oneui.NativeSelect(c, &seconds, durationOptions(ClipboardClearPresets, seconds, "秒"))
		clipboardSelect.Trigger.Label("剪贴板清理时间").Width(180)
		if clipboardSelect.Changed() {
			if err := a.SetClipboardClearSeconds(seconds); err != nil {
				a.status = "剪贴板设置保存失败"
			}
		}
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
	})

	// 4. Compact Updates Card (full updater view also lives in updates section)
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(1.5)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "应用更新").Bold().Grow(1)
			oneui.Badge(c, desktopVersionLabel(), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
		})
		oneui.Text(c, "安装版通过内置 Ed25519 公钥签名验证后才允许替换；不会上传金库内容。").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "检查更新…", oneui.ButtonSecondary).Disabled(a.busy).OnClick(updater.CheckForUpdates)
			oneui.Button(c, "查看更新详情", oneui.ButtonGhost).OnClick(func() {
				a.selectSettingsSection(settingsSectionUpdates)
			})
		})
	})
}

func (a *App) browserSettingsView(c *ui.Context) {
	t := c.Theme()

	a.brokerMu.Lock()
	running := a.broker != nil
	endpoint := a.brokerEndpoint
	a.brokerMu.Unlock()

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Text(c, "本机扩展 IPC 桥接").Bold().Grow(1)
			if running {
				oneui.Badge(c, "监听中", oneui.BadgeOptions{Tone: oneui.BadgeSuccess})
			} else {
				oneui.Badge(c, "未启动", oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
			}
		})
		if endpoint != "" {
			oneui.Text(c, "本机端点："+endpoint).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		}
		oneui.Text(c, "浏览器扩展只允许通过系统签名验证的 Native Messaging Host 连接到此桌面 IPC；所有填充、保存、TOTP 披露与 Passkey 操作都在本机弹出独立审批后再交付。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(1.5)).Children(func() {
		oneui.Text(c, "默认安全策略").Bold()
		for _, rule := range []struct{ name, policy string }{
			{"来源匹配边界", "按网站条目配置的 同源 / 同主机 / 同域名 / 精确 / 不填充 规则匹配"},
			{"跨源与 iframe 防护", "嵌入结账页或跨域敏感字段单独要求原主窗口明确授权"},
			{"剪贴板清理", fmt.Sprintf("扩展触发的安全复制遵循桌面清理时长（%s）", durationLabel(a.settingsSnapshot().ClipboardClearDuration()))},
		} {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(.5), 0).Children(func() {
				oneui.Text(c, rule.name).FontSize(t.Rem(.82)).Bold().Width(150)
				oneui.Text(c, rule.policy).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Grow(1).Wrap()
			})
		}
		ui.Row(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "查看活动审计", oneui.ButtonOutline).OnClick(func() {
				a.selectSettingsSection(settingsSectionAudit)
			})
		})
	})
}

func (a *App) developerSettingsView(c *ui.Context) {
	t := c.Theme()

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.Code()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
			oneui.Text(c, "开发者工具").Bold().Grow(1)
			oneui.Badge(c, "仅本机", oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
		})
		oneui.Text(c, "这里只显示 Locklark 已经实现并可验证的集成；不会把尚未接通的 SDK、远程执行或普通 MCP 客户端开关伪装成可用。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
			oneui.Text(c, "SSH Agent").Bold().Grow(1)
			if a.sshService == nil {
				oneui.Badge(c, "已停止", oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
			} else {
				oneui.Badge(c, "运行中", oneui.BadgeOptions{Tone: oneui.BadgeSuccess})
			}
		})
		oneui.Text(c, "使用金库中的 OpenSSH Ed25519 密钥提供 identities/sign 能力；不会接管系统 ssh-agent，也不会自动修改 shell 或 SSH 配置。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "打开 SSH 密钥与 Agent", oneui.ButtonSecondary).Disabled(a.busy).OnClick(func() {
				a.selectSettingsSection(settingsSectionSSH)
				a.refreshSSHKeys()
			})
			if a.sshService != nil {
				oneui.Button(c, "停止 SSH Agent", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
					a.stopSSHAgent()
					a.status = "SSH Agent 已撤销，正在关闭本地端点"
				})
			}
		})
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.SquareTerminal()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
			oneui.Text(c, "CLI 集成").Bold().Grow(1)
			oneui.Badge(c, "本机配置", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		oneui.Text(c, "GitHub CLI、Vercel、Git、AWS、Kubernetes、Docker 等内置配置使用金库字段作为短期凭据；配置只保存条目 ID、修订号、程序指纹和策略元数据。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
			for _, label := range []string{"GitHub CLI", "Vercel CLI", "Git", "AWS CLI", "kubectl", "Docker"} {
				oneui.Badge(c, label, oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
			}
		})
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "打开 CLI 配置", oneui.ButtonSecondary).OnClick(func() {
				a.selectSettingsSection(settingsSectionCLI)
			})
			oneui.Button(c, "查看 CLI 请求活动", oneui.ButtonOutline).OnClick(func() {
				a.selectSettingsSection(settingsSectionCLIActivity)
			})
		})
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.SquareTerminal()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
			oneui.Text(c, "命令行与自动化").Bold().Grow(1)
		})
		oneui.Text(c, "Locklark CLI 提供受控的建库、编辑、搜索、字段披露、导入导出和 SSH 密钥操作。敏感命令仍要求交互式双因素确认。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		oneui.Text(c, "locklark --help").FontSize(t.Rem(.78)).Bold().TextColor(t.Text).Wrap()
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "复制 CLI 命令", oneui.ButtonOutline).OnClick(func() {
				if err := a.writeClipboard([]byte("locklark --help"), time.Now().Add(30*time.Second), func() bool { return true }); err != nil {
					a.status = message(err)
					return
				}
				a.status = clipboardStatus(30 * time.Second)
			})
			oneui.Button(c, "安全审计日志", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
				a.selectSettingsSection(settingsSectionAudit)
			})
			oneui.Button(c, "打开导入与导出", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
				a.selectSettingsSection(settingsSectionTransfer)
			})
		})
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			oneui.Icon(c, lucide.Plug()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
			oneui.Text(c, "MCP / Agent 桥接").Bold().Grow(1)
			oneui.Badge(c, "受控配置", oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		oneui.Text(c, "MCP 只通过已登记、带独立会话密钥和固定模块摘要的 stdio 配置启动。桌面不会读取未知 MCP 配置，也不会向普通 Agent 暴露 Secret Key 或字段原值。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		oneui.Button(c, "查看开发者文档", oneui.ButtonOutline).OnClick(func() {
			c.OpenURLThen("https://github.com/jihuayu/locklark#用-mcp-提交申请并在重启后查状态", func(err error) {
				if err != nil {
					a.status = "开发者文档打开失败"
				}
			})
		})
	})
}

func (a *App) transferSettingsView(c *ui.Context) {
	t := c.Theme()
	a.transferView(c)

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "应急文件（Secret Key 备份）").Bold().Grow(1)
			oneui.Badge(c, "含明文 Secret Key", oneui.BadgeOptions{Tone: oneui.BadgeWarning})
		})
		oneui.Text(c, "更换电脑或重置本机系统凭据存储后，需要主密码和应急文件中的 Secret Key 才可重新授权设备。导出前需再次验证当前金库主密码。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		oneui.TextBox(c, &a.reexportPassword, oneui.TextBoxOptions{}).
			Label("当前金库主密码").Placeholder("输入当前主密码以确认导出").Password().Disabled(a.busy)
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "重新导出应急文件…", oneui.ButtonSecondary).
				Disabled(a.busy || a.path == "" || a.reexportPassword == "").
				OnClick(a.reexportEmergencyKit)
		})
		if a.kitSavedPath != "" {
			oneui.Text(c, "最近导出位置："+a.kitSavedPath).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
		}
	})
}

func (a *App) updatesSettingsView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			oneui.Text(c, "应用版本与更新检查").Bold().Grow(1)
			oneui.Badge(c, desktopVersionLabel(), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		oneui.Text(c, "安装版通过 GitHub Releases 检查更新；下载包必须通过内置 Ed25519 公钥签名验证后才能安装替换。日常运行和检查更新不会上传金库内容或遥测数据。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		if desktopCanSelfUpdate() {
			oneui.Text(c, "自动与手动更新均已就绪。").FontSize(t.Rem(.76)).TextColor(t.Success)
		} else {
			oneui.Text(c, "当前为开发构建（dev build），不会自动替换本机二进制文件。").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		}
		oneui.Button(c, "检查更新…", oneui.ButtonPrimary).Disabled(a.busy).OnClick(updater.CheckForUpdates)
	})
}

func (a *App) aboutSettingsView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3.5)).Gap(t.Space(2)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			mark := ui.Box(c).Size(t.Space(10), t.Space(10)).Radius(t.Space(2.5)).Background(t.Accent).
				AlignItems(ui.Center).Justify(ui.Center)
			mark.Children(func() {
				oneui.Icon(c, lucide.KeyRound()).Size(t.Space(5), t.Space(5)).TextColor(t.AccentText)
			})
			ui.Column(c).Grow(1).Gap(t.Space(.25)).Children(func() {
				oneui.Text(c, "Locklark").FontSize(t.Rem(1.15)).Bold()
				oneui.Text(c, "离线优先 · 零知识本地金库与开发者凭据运行时").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
			})
			oneui.Badge(c, desktopVersionLabel(), oneui.BadgeOptions{Tone: oneui.BadgeAccent})
		})
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		ui.Row(c).FillWidth().Wrap().Gap(t.Space(3)).Children(func() {
			for _, cell := range []struct{ k, v string }{
				{"当前版本", desktopVersionLabel()},
				{"运行平台", runtime.GOOS + " / " + runtime.GOARCH},
				{"Go 工具链", runtime.Version()},
			} {
				ui.Column(c).MinWidth(140).Gap(t.Space(.25)).Children(func() {
					oneui.Text(c, cell.k).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
					oneui.Text(c, cell.v).FontSize(t.Rem(.84)).Bold()
				})
			}
		})
		ui.Box(c).FillWidth().Height(1).Background(t.Border)
		oneui.Text(c, "隐私与安全承诺：没有账号体系、没有云同步、没有后台分析上报；所有金库加密与密钥派生都在本机完成。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		ui.Row(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "复制脱敏诊断摘要", oneui.ButtonOutline).OnClick(func() {
				summary := a.desensitizedDiagnosticSummary()
				if err := mygo.Clipboard.Write(transfer.TextData(summary)); err != nil {
					a.status = "诊断摘要复制未确认"
					return
				}
				a.status = "已复制脱敏诊断摘要（不含金库路径、用户名或密钥）"
			})
		})
	})
}

func (a *App) desensitizedDiagnosticSummary() string {
	s := a.settingsSnapshot()
	a.brokerMu.Lock()
	brokerRunning := a.broker != nil
	a.brokerMu.Unlock()
	return fmt.Sprintf(
		"Locklark Desktop %s (%s/%s)\ntheme=%s density=%s autolock_min=%d clipboard_sec=%d broker=%t ssh_agent=%t",
		desktopVersionLabel(), runtime.GOOS, runtime.GOARCH,
		s.Theme, s.InterfaceDensity, s.AutoLockMinutes, s.ClipboardClearSeconds,
		brokerRunning, a.sshService != nil,
	)
}

func themeLabel(mode string) string {
	switch mode {
	case "light":
		return "浅色"
	case "dark":
		return "深色"
	default:
		return "跟随系统"
	}
}

func densityLabel(density string) string {
	if density == "compact" {
		return "紧凑"
	}
	return "舒适"
}

func (a *App) openSettingsPage(page string) {
	a.v2.settingsOpen = false
	a.page = page
	a.touchActivity()
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

func durationOptions(presets []int, current int, unit string) []oneui.NativeSelectOption[int] {
	options := make([]oneui.NativeSelectOption[int], 0, len(presets)+1)
	found := false
	for _, value := range presets {
		label := fmt.Sprintf("%d %s", value, unit)
		if value == 0 {
			label = "从不"
		}
		options = append(options, oneui.NativeSelectOption[int]{Value: value, Label: label})
		found = found || value == current
	}
	if !found {
		options = append(options, oneui.NativeSelectOption[int]{Value: current, Label: fmt.Sprintf("%d %s", current, unit)})
	}
	return options
}
