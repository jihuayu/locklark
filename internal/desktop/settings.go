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
	"github.com/jihuayu/passme/internal/osunlock"
	"github.com/jihuayu/passme/internal/personal"
	"github.com/jihuayu/passme/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
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
	// Accent is appearance.accent: "terracotta" (default) or "teal".
	Accent string `json:"appearance.accent"`
	// InterfaceDensity is appearance.interfaceDensity.
	InterfaceDensity string `json:"appearance.interfaceDensity"`
	// KeepInTray is app.keepInTray.
	KeepInTray bool `json:"app.keepInTray"`
	// DefaultVaultForSaving is app.defaultVaultForSaving.
	DefaultVaultForSaving string `json:"app.defaultVaultForSaving"`
	// VaultPath is app.vaultPath. Only the local .pm file path is stored here;
	// Secret Key and master passwords are never written to settings.
	VaultPath string `json:"app.vaultPath,omitempty"`
	// SystemUnlockEnabled records whether OS quick unlock has been enrolled for
	// the bound vault on this device.
	SystemUnlockEnabled bool `json:"security.systemUnlock.enabled,omitempty"`
	// SystemUnlockExpiry selects the configured quick-unlock preset ID
	// ("24h", "7d", "14d", "30d", "90d", "never").
	SystemUnlockExpiry string `json:"security.systemUnlock.expiry,omitempty"`
	// SystemUnlockAutoRenew controls whether a full master-password unlock
	// renews an expiring or expired quick-unlock enrollment automatically.
	SystemUnlockAutoRenew bool `json:"security.systemUnlock.autoRenew"`
	// SystemUnlockExpiresAt is the Unix timestamp (seconds) when the current
	// timed quick-unlock enrollment expires; 0 means non-expiring or unset.
	SystemUnlockExpiresAt int64 `json:"security.systemUnlock.expiresAt,omitempty"`

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

type systemUnlockPreset struct {
	ID       string
	Label    string
	Duration time.Duration
}

// SystemUnlockExpiryPresets are the validity options offered for OS quick unlock.
var SystemUnlockExpiryPresets = []systemUnlockPreset{
	{ID: "24h", Label: "1 天（24 小时）", Duration: 24 * time.Hour},
	{ID: "7d", Label: "7 天", Duration: 7 * 24 * time.Hour},
	{ID: "14d", Label: "14 天（推荐）", Duration: 14 * 24 * time.Hour},
	{ID: "30d", Label: "30 天", Duration: 30 * 24 * time.Hour},
	{ID: "90d", Label: "90 天", Duration: 90 * 24 * time.Hour},
	{ID: "never", Label: "永不过期", Duration: personal.SystemUnlockNeverExpire},
}

func defaultSettingsBase() Settings {
	return Settings{
		AutoLockMinutes:       5,
		ClipboardClearSeconds: 30,
		LockOnSleep:           true,
		LockOnScreenLock:      true,
		LockOnWindowClose:     true,
		RevealPasswords:       false,
		CheckHIBP:             false,
		Theme:                 "system",
		InterfaceDensity:      "comfortable",
		Accent:                accentTerracotta,
		KeepInTray:            true,
		DefaultVaultForSaving: "",
		SystemUnlockExpiry:    "14d",
		SystemUnlockAutoRenew: true,
	}
}

// DefaultSettings returns the documented defaults: 5 minute idle auto-lock,
// 30 second clipboard clear, lock on sleep and device lock, no HIBP checks,
// 14-day quick unlock expiry with auto-renewal enabled.
func DefaultSettings() Settings {
	return defaultSettingsBase().normalized()
}

// UsageError reports invalid desktop command-line arguments. Its message is
// the fixed usage text and never includes the offending argument or path.
type UsageError struct{}

func (*UsageError) Error() string { return desktopSettingsUsage }

// desktopSettingsUsage is the only command-line syntax the desktop accepts.
const desktopSettingsUsage = "usage: passme-desktop [--settings ABSOLUTE_PATH]"

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
	return filepath.Join(dir, "passme", "settings.json")
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
	switch s.Accent {
	case accentTerracotta, accentTeal:
	default:
		s.Accent = accentTerracotta
	}
	s.VaultPath = strings.TrimSpace(s.VaultPath)
	if s.VaultPath != "" {
		s.VaultPath = filepath.Clean(s.VaultPath)
	}
	s.SystemUnlockExpiry = strings.ToLower(strings.TrimSpace(s.SystemUnlockExpiry))
	if s.SystemUnlockExpiry == "" {
		s.SystemUnlockExpiry = "14d"
	}
	if s.SystemUnlockExpiresAt < 0 {
		s.SystemUnlockExpiresAt = 0
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
	if _, ok := findSystemUnlockPreset(s.SystemUnlockExpiry); !ok {
		return Settings{}, errors.New("desktop: invalid system unlock expiry")
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

// SystemUnlockDuration returns the configured quick-unlock validity duration, or
// personal.SystemUnlockNeverExpire for non-expiring enrollments.
func (s Settings) SystemUnlockDuration() time.Duration {
	if p, ok := findSystemUnlockPreset(s.normalized().SystemUnlockExpiry); ok {
		return p.Duration
	}
	return 14 * 24 * time.Hour
}

// SystemUnlockNeedsRenewal reports whether an enabled quick-unlock enrollment
// should be renewed on a full master-password unlock at now.
func (s Settings) SystemUnlockNeedsRenewal(now time.Time) bool {
	if !s.SystemUnlockEnabled || !s.SystemUnlockAutoRenew {
		return false
	}
	ttl := s.SystemUnlockDuration()
	if ttl == personal.SystemUnlockNeverExpire {
		// Upgrade previously timed enrollments to non-expiring on next full unlock.
		return s.SystemUnlockExpiresAt > 0
	}
	if s.SystemUnlockExpiresAt <= 0 {
		return true
	}
	remaining := time.Unix(s.SystemUnlockExpiresAt, 0).Sub(now)
	return remaining <= ttl/2
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
	// Start from un-normalized defaults so IdleTimeout and ClipboardClearTimeout
	// stay zero and cannot overwrite unmarshaled integer fields in normalized().
	s := defaultSettingsBase()
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
	prev := s.VaultPath
	s.VaultPath = strings.TrimSpace(path)
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	if validated.VaultPath != prev {
		a.systemUnlockNotEnrolled = false
		a.enrollSystemUnlockOnUnlock = false
	}
	a.settings = validated
	return a.SaveSettings()
}

// SetSystemUnlockExpiry validates and persists security.systemUnlock.expiry.
func (a *App) SetSystemUnlockExpiry(expiry string) error {
	if _, ok := findSystemUnlockPreset(expiry); !ok {
		return errors.New("desktop: invalid system unlock expiry")
	}
	s := a.settingsSnapshot()
	s.SystemUnlockExpiry = strings.ToLower(strings.TrimSpace(expiry))
	validated, err := ValidateSettings(s)
	if err != nil {
		return err
	}
	a.settings = validated
	return a.SaveSettings()
}

// SetSystemUnlockAutoRenew persists security.systemUnlock.autoRenew.
func (a *App) SetSystemUnlockAutoRenew(on bool) error {
	s := a.settingsSnapshot()
	s.SystemUnlockAutoRenew = on
	a.settings = s.normalized()
	return a.SaveSettings()
}

func (a *App) markSystemUnlockEnrolled(ttl time.Duration, expiresAt time.Time) {
	s := a.settingsSnapshot()
	s.SystemUnlockEnabled = true
	if ttl == personal.SystemUnlockNeverExpire || expiresAt.IsZero() {
		s.SystemUnlockExpiresAt = 0
	} else {
		s.SystemUnlockExpiresAt = expiresAt.Unix()
	}
	a.settings = s.normalized()
	a.systemUnlockExpired = false
	_ = a.SaveSettings()
}

func (a *App) markSystemUnlockDisabled() {
	s := a.settingsSnapshot()
	s.SystemUnlockEnabled = false
	s.SystemUnlockExpiresAt = 0
	a.settings = s.normalized()
	a.systemUnlockExpired = false
	_ = a.SaveSettings()
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
// reachable from the header gear and sidebar tools while unlocked.
func (a *App) settingsView(c *ui.Context) {
	t := c.Theme()
	section := normalizeSettingsSection(a.v2.settingsSection)
	a.v2.settingsSection = section

	ui.Row(c.Key("settings")).Role(ui.RoleGroup).Label("设置工作区").FillWidth().MinWidth(0).FillHeight().Gap(0).Children(func() {
		// Left 224px navigation rail
		ui.Column(c).Width(224).Shrink(0).FillHeight().Background(onevraSidebarSurface(t)).
			Padding(t.Space(3), t.Space(2.5)).Gap(t.Space(2)).Children(func() {
			oneui.Button(c, "关闭设置", oneui.ButtonGhost).FillWidth().OnClick(a.closeSettings)
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
							a.ensureSSHKeysLoaded()
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
						a.onevraSidebarItem(c, "关于 Passme", lucide.Info(), section == settingsSectionAbout, 0, func() {
							a.selectSettingsSection(settingsSectionAbout)
						})
					})
				})
			})
		})

		ui.Box(c).Width(1).FillHeight().Background(t.Border)

		// Right scrollable content pane
		contentMaxW := float32(880)
		if section == settingsSectionCLI {
			contentMaxW = 1140
		}
		oneui.ScrollView(c, oneui.ScrollViewOptions{}).Grow(1).FillHeight().Children(func() {
			ui.Column(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Column(c.Key("settings-"+section)).FillWidth().MinWidth(0).MaxWidth(contentMaxW).Padding(t.Space(6), t.Space(7)).Gap(t.Space(4)).Children(func() {
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
					oneui.Text(c, "非敏感偏好设置以 0600 权限保存于 "+a.settingsPath).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
				})
			})
		})
	})
}

func (a *App) selectSettingsSection(section string) {
	a.v2.settingsSection = normalizeSettingsSection(section)
	a.touchActivity()
}

func (a *App) settingsSectionHeader(c *ui.Context, section string) {
	title, subtitle := "安全与偏好设置", "管理本地自动锁定、剪贴板自动清理与系统级快捷解锁策略。"
	switch section {
	case settingsSectionGeneral:
		title, subtitle = "通用", "查看当前绑定的本地金库文件、默认保存位置与托盘后台策略。"
	case settingsSectionAppearance:
		title, subtitle = "外观", "选择主题配色、明暗模式与界面密度；修改立即生效并保存。"
	case settingsSectionBrowser:
		title, subtitle = "浏览与自动填充", "检查本机浏览器 IPC 桥接状态与按来源确认的自动填充边界。"
	case settingsSectionDeveloper:
		title, subtitle = "开发者工具", "管理本机已经接通的 SSH、审计、导入导出和 CLI/MCP 工具入口。"
	case settingsSectionSSH:
		title, subtitle = "SSH 与 Agent", "管理 Ed25519 公钥并按次授权本机 SSH 签名请求。"
	case settingsSectionCLI:
		title, subtitle = "CLI 集成配置", "查看已安装的命令行工具，并把金库字段绑定到受控的 CLI 配置。"
	case settingsSectionCLIActivity:
		title, subtitle = "CLI 请求活动", "审计本机 CLI 凭据请求及其批准、拒绝和失败结果。"
	case settingsSectionAudit:
		title, subtitle = "活动审计", "查看当前金库的离线签名审计事件账本。"
	case settingsSectionTransfer:
		title, subtitle = "导入与导出", "从 1Password 1PUX 原子导入、导出加密 KDBX，或重新导出本机应急文件。"
	case settingsSectionUpdates:
		title, subtitle = "更新", "查看应用版本与基于 Ed25519 公钥签名的离线/GitHub Releases 更新机制。"
	case settingsSectionAbout:
		title, subtitle = "关于 Passme", "离线优先与零知识安全边界摘要及脱敏诊断信息。"
	}
	onevraPageHeader(c, title, subtitle)
}

func (a *App) generalSettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	vaultName := vaultDisplayBaseName(a.path)
	if vaultName == "" {
		vaultName = "未绑定"
	}

	onevraSettingsGroup(c, "本机绑定的金库", func(row func(string, string, func())) {
		row(vaultName+" · "+displayVaultLocation(a.path), a.path, func() {
			if a.path != "" {
				if a.hasDeviceSecretCached(a.path) {
					onevraPill(c.Key("vault-secret-saved"), "Secret Key 已存于本机", t.Success)
				} else {
					onevraPill(c.Key("vault-secret-needed"), "需应急恢复", t.Warning)
				}
			}
		})
		row("设备绑定管理", "可查看首次建库引导说明，或退出当前设备绑定（磁盘上的 .pm 文件会完整保留）。", func() {
			oneui.Button(c, "查看首次创建流程", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
				a.Lock()
				a.onboarding = true
				a.create = false
				a.status = "已锁定并切换到首次创建引导概览"
			})
			oneui.Button(c, "退出当前设备…", oneui.ButtonOutline).TextColor(t.Danger).Disabled(a.uiBusy(c) || a.path == "").OnClick(func() {
				a.confirmForgetDevice = true
				a.forgetPassword = ""
				a.status = "退出当前设备不会删除磁盘上的 .pm 金库文件"
			})
		})
	})
	if a.confirmForgetDevice {
		a.forgetDeviceConfirmView(c)
	}

	onevraSettingsGroup(c, "窗口与后台策略", func(row func(string, string, func())) {
		row("关闭或最小化主窗口", "立即锁定金库并隐藏到系统托盘，仅托盘菜单「退出」会结束进程；浏览器与 CLI 审批弹窗仍可及时响应。", func() {
			onevraPill(c.Key("bg-pinned"), "固定后台运行", t.Accent)
		})
	})

	onevraSettingsGroup(c, "保存与快捷访问", func(row func(string, string, func())) {
		if len(a.v2.vaults) > 0 {
			row("默认保存保险库", "新建或通过浏览器保存登录时的默认目标保险库。", func() {
				selectedVault := s.DefaultVaultForSaving
				if selectedVault == "" {
					selectedVault = vault.DefaultVaultID
				}
				options := make([]oneui.NativeSelectOption[string], 0, len(a.v2.vaults))
				for _, v := range a.v2.vaults {
					options = append(options, oneui.NativeSelectOption[string]{Value: v.ID, Label: v.Name})
				}
				sel := oneui.NativeSelect(c, &selectedVault, options)
				sel.Trigger.Label("新建与自动保存默认保险库").Width(200)
				if sel.Changed() {
					if err := a.SetDefaultVaultForSaving(selectedVault); err != nil {
						a.status = "默认保险库设置保存失败"
					}
				}
			})
		}
		shortcutDesc := a.quickShortcut
		if shortcutDesc == "" {
			shortcutDesc = "全局快捷键尚未注册；可使用标题栏的「快捷搜索」按钮。"
		}
		row("全局快捷搜索", shortcutDesc, func() {
			onevraKeyCap(c, quickSearchAcceleratorLabel())
		})
	})
}

func (a *App) appearanceSettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	onevraSettingsGroup(c, "主题配色", func(row func(string, string, func())) {
		row("强调色", "用于选中项、主按钮与焦点高亮，分别搭配暖纸白 / 沉稳石板中性色板。", func() {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				for _, opt := range []struct {
					id, label string
					color     ui.Color
				}{
					{accentTerracotta, "陶土橙", ui.Hex("#bd481b")},
					{accentTeal, "深青绿", ui.Hex("#1f7a68")},
				} {
					opt := opt
					selected := s.Accent == opt.id
					chip := ui.Row(c.Key("accent:"+opt.id)).AlignItems(ui.Center).Gap(t.Space(1.5)).
						Padding(t.Space(1.25), t.Space(2.5)).Radius(t.Radius).
						Border(1, t.Border).Cursor(ui.CursorPointer).
						Role(ui.RoleRadio).Label("强调色：" + opt.label).Focusable()
					if selected {
						chip.Border(2, opt.color).Background(opt.color.Alpha(.08))
					}
					chip.Children(func() {
						ui.Box(c).Size(t.Space(3.5), t.Space(3.5)).Radius(t.Space(1.75)).Background(opt.color)
						oneui.Text(c, opt.label).FontSize(t.Rem(.86))
					})
					if chip.Clicked() && !selected {
						_ = a.SetAccent(opt.id)
						a.status = "强调色已切换为：" + opt.label
					}
				}
			})
		})

		row("明暗模式", "切换跟随系统、浅色或深色外观；深色模式采用低眩光表面。", func() {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(.5)).Padding(t.Space(.5)).Radius(t.Radius).Background(t.Text.Alpha(.05)).Children(func() {
				for _, opt := range []struct{ id, title string }{
					{"system", "跟随系统"},
					{"light", "浅色"},
					{"dark", "深色"},
				} {
					opt := opt
					variant := oneui.ButtonGhost
					if s.Theme == opt.id {
						variant = oneui.ButtonSecondary
					}
					if oneui.Button(c.Key("theme-"+opt.id), opt.title, variant).Label("主题：" + opt.title).Clicked() {
						_ = a.SetTheme(opt.id)
						a.status = "主题已切换为：" + opt.title
					}
				}
			})
		})
	})

	onevraSettingsGroup(c, "布局", func(row func(string, string, func())) {
		row("界面密度", "紧凑模式减小列表行距与内边距，同屏展示更多条目。", func() {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(.5)).Padding(t.Space(.5)).Radius(t.Radius).Background(t.Text.Alpha(.05)).Children(func() {
				for _, opt := range []struct{ id, title string }{
					{"comfortable", "舒适"},
					{"compact", "紧凑"},
				} {
					opt := opt
					variant := oneui.ButtonGhost
					if s.InterfaceDensity == opt.id {
						variant = oneui.ButtonSecondary
					}
					if oneui.Button(c.Key("density-"+opt.id), opt.title, variant).Label("密度：" + opt.title).Clicked() {
						_ = a.SetInterfaceDensity(opt.id)
						a.status = "界面密度已切换为：" + opt.title
					}
				}
			})
		})
		row("当前渲染参数", fmt.Sprintf("Spacing %.2f DIP · %s", t.Spacing, themeLabel(s.Theme)), func() {
			onevraPill(c, "实时生效", t.Success)
		})
	})
}

func (a *App) securitySettingsView(c *ui.Context) {
	t := c.Theme()
	s := a.settingsSnapshot()

	onevraSettingsGroup(c, "自动锁定", func(row func(string, string, func())) {
		row("空闲自动锁定时间", "一段时间没有交互操作后自动锁定金库。", func() {
			minutes := s.AutoLockMinutes
			autoSelect := oneui.NativeSelect(c, &minutes, durationOptions(AutoLockPresets, minutes, "分钟"))
			autoSelect.Trigger.Label("自动锁定时间").Width(160)
			if autoSelect.Changed() {
				if err := a.SetAutoLockMinutes(minutes); err != nil {
					a.status = "自动锁定设置保存失败"
				}
			}
		})
		row("系统休眠时自动锁定", "", func() {
			if v, changed := onevraSwitch(c, "系统休眠时自动锁定", s.LockOnSleep); changed {
				_ = a.SetLockOnSleep(v)
			}
		})
		row("屏幕锁定时自动锁定", "", func() {
			if v, changed := onevraSwitch(c, "屏幕锁定时自动锁定", s.LockOnScreenLock); changed {
				_ = a.SetLockOnScreenLock(v)
			}
		})
	})

	onevraSettingsGroup(c, "剪贴板防护", func(row func(string, string, func())) {
		row("复制后清理剪贴板", "到期后仅清除仍由 Passme 写入的内容，不会覆盖你之后复制的其他内容。", func() {
			seconds := s.ClipboardClearSeconds
			clipboardSelect := oneui.NativeSelect(c, &seconds, durationOptions(ClipboardClearPresets, seconds, "秒"))
			clipboardSelect.Trigger.Label("剪贴板清理时间").Width(160)
			if clipboardSelect.Changed() {
				if err := a.SetClipboardClearSeconds(seconds); err != nil {
					a.status = "剪贴板设置保存失败"
				}
			}
		})
		row("默认显示遮蔽字段", "打开登录条目时自动展示密码；公共环境或共享屏幕时不建议开启。", func() {
			if v, changed := onevraSwitch(c, "默认显示遮蔽字段", s.RevealPasswords); changed {
				_ = a.SetRevealPasswords(v)
			}
		})
	})

	onevraSettingsGroup(c, "快捷解锁："+osunlock.Label(), func(row func(string, string, func())) {
		statusDesc := osunlock.Description() + " " + osunlock.Requirement()
		if a.session != nil && !a.session.CanEnableSystemUnlock() {
			statusDesc += " 当前通过快捷解锁进入；如需启用或重新授权，请先锁定并使用主密码完整解锁。"
		}
		row("系统级快捷解锁", statusDesc, func() {
			now := time.Now()
			if a.systemUnlockEnrolling {
				onevraPill(c, "等待系统验证…", t.Accent)
			} else if s.SystemUnlockEnabled {
				if a.systemUnlockExpired || (s.SystemUnlockExpiresAt > 0 && !now.Before(time.Unix(s.SystemUnlockExpiresAt, 0))) {
					onevraPill(c, "已过期", t.Warning)
				} else if s.SystemUnlockDuration() == personal.SystemUnlockNeverExpire {
					onevraPill(c, "已启用 · 永不过期", t.Success)
				} else if s.SystemUnlockExpiresAt > 0 {
					rem := time.Unix(s.SystemUnlockExpiresAt, 0).Sub(now)
					onevraPill(c, "已启用 · 剩余 "+systemUnlockRemainingLabel(rem), t.Success)
				} else {
					onevraPill(c, "已启用", t.Success)
				}
			} else {
				onevraPill(c, "未启用", t.TextMuted)
			}
			enableLabel := "启用系统快捷解锁"
			if s.SystemUnlockEnabled {
				enableLabel = "重新授权快捷解锁"
			}
			oneui.Button(c, enableLabel, oneui.ButtonSecondary).Disabled(a.uiBusy(c) || a.session == nil || !a.session.CanEnableSystemUnlock()).OnClick(func() {
				sess, store := a.session, a.systemStore
				if sess == nil || a.busy {
					return
				}
				ttl := s.SystemUnlockDuration()
				expiryLabel := systemUnlockExpiryLabel(s.SystemUnlockExpiry)
				a.systemUnlockEnrolling = true
				a.systemUnlockNotice = ""
				a.systemUnlockNoticeErr = false
				generation := a.generation
				a.runInteractive(func() outcome {
					if err := sess.EnableSystemUnlockFor(store, ttl); err != nil {
						a.dispatch(func() {
							if generation != a.generation {
								return
							}
							a.systemUnlockEnrolling = false
							a.systemUnlockNotice = message(err)
							a.systemUnlockNoticeErr = true
						})
						return outcome{err: err}
					}
					expiresAt := time.Now().Add(ttl)
					if ttl == personal.SystemUnlockNeverExpire {
						expiresAt = time.Time{}
					}
					return outcome{apply: func() {
						a.systemUnlockEnrolling = false
						a.systemUnlockExpired = false
						a.systemUnlockNotEnrolled = false
						a.enrollSystemUnlockOnUnlock = false
						a.markSystemUnlockEnrolled(ttl, expiresAt)
						msg := "系统快捷解锁已启用（" + expiryLabel + "）；现在可锁定并试用"
						a.status = msg
						a.systemUnlockNotice = msg
						a.systemUnlockNoticeErr = false
					}}
				})
			})
			oneui.Button(c, "停用系统快捷解锁", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
				if a.busy {
					return
				}
				path, store := a.path, a.systemStore
				a.systemUnlockEnrolling = false
				a.systemUnlockNotice = ""
				a.systemUnlockNoticeErr = false
				generation := a.generation
				a.runInteractive(func() outcome {
					err := personal.DisableSystemUnlock(path, store)
					if errors.Is(err, osunlock.ErrNotFound) {
						err = nil
					}
					if err != nil {
						a.dispatch(func() {
							if generation != a.generation {
								return
							}
							a.systemUnlockNotice = message(err)
							a.systemUnlockNoticeErr = true
						})
						return outcome{err: err}
					}
					return outcome{apply: func() {
						a.markSystemUnlockDisabled()
						a.status = "系统快捷解锁已停用"
						a.systemUnlockNotice = "系统快捷解锁已停用"
						a.systemUnlockNoticeErr = false
					}}
				})
			})
		})
		row("快捷解锁有效期", "限制免主密码快捷解锁的有效时长，超时后需重新验证主密码；“永不过期”请仅在受信任的个人设备上使用。", func() {
			expiry := s.SystemUnlockExpiry
			expirySelect := oneui.NativeSelect(c, &expiry, systemUnlockOptions(expiry))
			expirySelect.Trigger.Label("快捷解锁有效期").Width(180)
			if expirySelect.Changed() {
				if err := a.SetSystemUnlockExpiry(expiry); err != nil {
					a.status = "快捷解锁有效期保存失败"
				} else if s.SystemUnlockEnabled {
					a.status = "快捷解锁有效期已设为 " + systemUnlockExpiryLabel(expiry) + "；可重新授权或等待下次主密码自动续期"
				} else {
					a.status = "快捷解锁有效期已设为 " + systemUnlockExpiryLabel(expiry)
				}
			}
		})
		row("主密码完整解锁后自动续期", "启用快捷解锁后，当授权即将到期或已过期时，使用主密码完整解锁会自动按当前有效期续期。", func() {
			if v, changed := onevraSwitch(c, "主密码完整解锁后自动续期", s.SystemUnlockAutoRenew); changed {
				if err := a.SetSystemUnlockAutoRenew(v); err != nil {
					a.status = "自动续期设置保存失败"
				}
			}
		})
	})

	if a.systemUnlockEnrolling {
		onevraBanner(c, lucide.FingerprintPattern(), "正在等待 "+osunlock.Label()+" 验证：首次启用需在系统弹窗中依次完成「创建密钥」与「验证解密授权」两步确认。", t.Accent, nil)
	} else if a.systemUnlockNotice != "" {
		if a.systemUnlockNoticeErr {
			onevraBanner(c, lucide.TriangleAlert(), a.systemUnlockNotice, t.Warning, nil)
		} else {
			onevraBanner(c, lucide.CircleCheck(), a.systemUnlockNotice, t.Success, nil)
		}
	}

	onevraSettingsGroup(c, "应用更新", func(row func(string, string, func())) {
		row("安装版更新检查", "通过内置 Ed25519 公钥签名验证安装包；不上传任何金库内容。", func() {
			onevraPill(c, desktopVersionLabel(), t.TextMuted)
			oneui.Button(c, "检查更新…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(updater.CheckForUpdates)
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

	onevraSettingsGroup(c, "本机扩展 IPC 桥接", func(row func(string, string, func())) {
		desc := "浏览器扩展通过系统签名验证的 Native Messaging Host 连接到此桌面 IPC。"
		if endpoint != "" {
			desc = "本机端点：" + endpoint
		}
		row("连接状态", desc, func() {
			if running {
				onevraPill(c, "监听中", t.Success)
			} else {
				onevraPill(c, "未启动", t.TextMuted)
			}
		})
	})

	onevraSettingsGroup(c, "默认安全策略", func(row func(string, string, func())) {
		for _, rule := range []struct{ name, policy string }{
			{"来源匹配边界", "按网站条目配置的同源 / 同主机 / 同域名 / 精确 / 不填充规则匹配"},
			{"跨源与 iframe 防护", "嵌入结账页或跨域敏感字段单独要求原主窗口明确授权"},
			{"剪贴板清理", fmt.Sprintf("扩展触发的安全复制遵循桌面清理时长（%s）", durationLabel(a.settingsSnapshot().ClipboardClearDuration()))},
		} {
			rule := rule
			row(rule.name, rule.policy, nil)
		}
		row("审计日志", "查看扩展填充、保存与配对记录。", func() {
			oneui.Button(c, "查看活动审计", oneui.ButtonOutline).OnClick(func() {
				a.selectSettingsSection(settingsSectionAudit)
			})
		})
	})
}

func (a *App) developerSettingsView(c *ui.Context) {
	t := c.Theme()

	onevraGroup(c, "开发者工具", func(row func(func())) {
		row(func() {
			oneui.Icon(c, lucide.Code()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
			oneui.Text(c, "这里只显示 Passme 已经实现并可验证的本机集成，不渲染任何未接通的占位能力。").
				FontSize(t.Rem(.8)).TextColor(t.TextMuted).Grow(1).MinWidth(0).Wrap()
			onevraPill(c, "仅本机", t.TextMuted)
		})
	})

	onevraSettingsGroup(c, "SSH Agent", func(row func(string, string, func())) {
		row("OpenSSH Ed25519 Agent", "使用金库中的 Ed25519 密钥提供签名能力；不接管系统 ssh-agent，也不修改 shell 配置。", func() {
			if a.sshService == nil {
				onevraPill(c, "已停止", t.TextMuted)
			} else {
				onevraPill(c, "运行中", t.Success)
			}
			oneui.Button(c, "打开 SSH 密钥与 Agent", oneui.ButtonSecondary).Disabled(a.uiBusy(c)).OnClick(func() {
				a.selectSettingsSection(settingsSectionSSH)
				a.ensureSSHKeysLoaded()
			})
			if a.sshService != nil {
				oneui.Button(c, "停止 SSH Agent", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
					a.stopSSHAgent()
					a.status = "SSH Agent 已撤销，正在关闭本地端点"
				})
			}
		})
	})

	onevraGroup(c, "CLI 集成", func(row func(func())) {
		row(func() {
			oneui.Icon(c, lucide.SquareTerminal()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(1)).Children(func() {
				oneui.Text(c, "GitHub CLI、Vercel、Git、AWS、Kubernetes、Docker 等内置配置使用金库字段作为短期凭据，绑定文件仅保存非秘密引用元数据。").
					FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
				ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
					for _, label := range []string{"GitHub CLI", "Vercel CLI", "Git", "AWS CLI", "kubectl", "Docker"} {
						onevraPill(c, label, t.TextMuted)
					}
				})
			})
			onevraPill(c, "本机配置", t.Accent)
		})
		row(func() {
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
				oneui.Button(c, "打开 CLI 配置", oneui.ButtonSecondary).OnClick(func() {
					a.selectSettingsSection(settingsSectionCLI)
				})
				oneui.Button(c, "查看 CLI 请求活动", oneui.ButtonOutline).OnClick(func() {
					a.selectSettingsSection(settingsSectionCLIActivity)
				})
			})
		})
	})

	onevraSettingsGroup(c, "命令行与自动化", func(row func(string, string, func())) {
		row("Passme CLI", "支持受控的建库、编辑、搜索、字段披露与导入导出。可执行命令示例：passme --help", func() {
			onevraKeyCap(c, "passme --help")
			oneui.Button(c, "复制 CLI 命令", oneui.ButtonOutline).OnClick(func() {
				if err := a.writeClipboard([]byte("passme --help"), time.Now().Add(30*time.Second), func() bool { return true }); err != nil {
					a.status = message(err)
					return
				}
				a.status = clipboardStatus(30 * time.Second)
			})
		})
		row("相关工作区入口", "快速查看签名审计账本或迁移导入导出。", func() {
			oneui.Button(c, "安全审计日志", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
				a.selectSettingsSection(settingsSectionAudit)
			})
			oneui.Button(c, "打开导入与导出", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
				a.selectSettingsSection(settingsSectionTransfer)
			})
		})
	})

	onevraSettingsGroup(c, "MCP / Agent 桥接", func(row func(string, string, func())) {
		row("受控 stdio 桥接", "仅通过已登记、带独立会话密钥与固定模块摘要的 stdio 配置启动，绝不向普通 Agent 暴露 Secret Key 或字段原值。", func() {
			onevraPill(c, "受控配置", t.Accent)
			oneui.Button(c, "查看开发者文档", oneui.ButtonOutline).OnClick(func() {
				c.OpenURLThen("https://github.com/jihuayu/passme#用-mcp-提交申请并在重启后查状态", func(err error) {
					if err != nil {
						a.status = "开发者文档打开失败"
					}
				})
			})
		})
	})
}

func (a *App) transferSettingsView(c *ui.Context) {
	t := c.Theme()

	// 1. 1Password 1PUX Atomic Import (single-column stacked layout)
	onevraGroup(c, "1Password 1PUX 导入", func(row func(func())) {
		row(func() {
			ui.Column(c).FillWidth().Gap(t.Space(2)).Children(func() {
				oneui.Text(c, "默认导入登录与纯文本备注，可选完整类别；不支持的数据将整批原子拒绝，来源记录加密保留。").
					FontSize(t.Rem(.8)).TextColor(t.TextMuted).Wrap()
				ui.Row(c).FillWidth().AlignItems(ui.End).Wrap().Gap(t.Space(1.5)).Children(func() {
					oneui.TextBox(c, &a.source, oneui.TextBoxOptions{}).
						Label("1PUX 文件").Placeholder("1PUX 归档完整路径").Grow(1).Disabled(a.uiBusy(c))
					oneui.Button(c, "选择 1PUX 文件…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
						win := a.win
						a.runInteractive(func() outcome {
							paths, e := mygo.Dialog.Open(mygo.OpenDialogOptions{
								Parent:      win,
								Title:       "选择 1Password 1PUX",
								DefaultPath: importDirectory(),
								Filters:     []mygo.FileFilter{{Name: "1Password 1PUX", Extensions: []string{"1pux"}}},
							})
							return outcome{err: e, apply: func() {
								if len(paths) == 1 {
									a.source = paths[0]
									a.planDigest = ""
									a.report = ""
								}
							}}
						})
					})
					oneui.Button(c, "打开 1Password 导出…", oneui.ButtonGhost).Disabled(a.uiBusy(c)).OnClick(func() {
						c.OpenURLThen("onepassword://", func(err error) {
							a.dispatch(func() {
								if err != nil {
									a.status = "无法自动打开 1Password，请手动启动并导出 .1pux"
									return
								}
								a.status = "已打开 1Password；请选择金库 → 导出 → 1PUX，再把文件拖回此页"
							})
						})
					})
				})
				drop := ui.Row(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).
					Padding(t.Space(2), t.Space(3)).AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
					oneui.Icon(c, lucide.Download()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
					oneui.Text(c, "或把 .1pux 文件拖到这里").FontSize(t.Rem(.84)).Bold().TextColor(t.Accent)
					ui.Spacer(c)
					oneui.Text(c, "仅支持 .1pux 导出包（1PUX 为未加密文件，导入后请安全删除）").FontSize(t.Rem(.72)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
				})
				if !a.busy {
					if d, ok := ui.DropData(drop, transfer.DropOptions{Formats: []transfer.Format{transfer.FileList, transfer.URIList}, Operations: transfer.Copy}); ok {
						files, e := d.Data.Files()
						switch {
						case e != nil:
							a.status = "无法读取拖入的文件"
						case len(files) != 1:
							a.status = "一次只能拖入一个 .1pux 文件"
						case !strings.EqualFold(filepath.Ext(files[0]), ".1pux"):
							a.status = "请拖入 1Password 导出的 .1pux 文件"
						default:
							a.source, a.planDigest, a.report = files[0], "", ""
							a.status = "已选择 1PUX，请生成导入计划"
						}
					}
				}
			})
		})
		row(func() {
			onevraSettingRow(c, "完整类别（含卡片/身份/笔记，实验）", "关闭时仅导入登录与纯文本备注；Passme 不接收 1Password 主密码或 Secret Key。", func() {
				if v, changed := onevraSwitch(c, "完整类别", a.importFull); changed && !a.busy {
					a.importFull = v
					a.planDigest = ""
					a.report = ""
				}
			})
		})
		if a.report != "" {
			row(func() {
				onevraBanner(c, lucide.FileText(), a.report, t.Accent, nil)
			})
		}
		row(func() {
			ui.Row(c).FillWidth().Wrap().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
				oneui.Button(c, "生成导入计划", oneui.ButtonOutline).Disabled(a.uiBusy(c) || strings.TrimSpace(a.source) == "").OnClick(func() {
					s, source, full := a.session, a.source, a.importFull
					a.planDigest = ""
					a.runInteractive(func() outcome {
						var r personal.ImportReceipt
						var e error
						if full {
							r, e = s.PlanImportV2(source)
						} else {
							r, e = s.PlanImport(source)
						}
						return outcome{err: e, apply: func() {
							a.planDigest = r.Report.SourceDigest
							mode := "登录与备注"
							if full {
								mode = "完整类别"
							}
							a.report = fmt.Sprintf("%s：待导入 %d 条，归档 %d 条", mode, r.Report.Items, r.Report.Archived)
						}}
					})
				})
				oneui.Button(c, "确认整批导入", oneui.ButtonPrimary).Disabled(a.uiBusy(c) || a.planDigest == "").OnClick(func() {
					s, source, digest, full := a.session, a.source, a.planDigest, a.importFull
					a.planDigest = ""
					a.runInteractive(func() outcome {
						var e error
						if full {
							_, e = s.ImportV2(source, digest)
						} else {
							_, e = s.Import(source, digest)
						}
						return outcome{err: e, apply: func() { a.status = "导入完成，请到金库刷新" }}
					})
				})
			})
		})
	})

	// 2. Encrypted KDBX Export
	onevraGroup(c, "KDBX 加密导出", func(row func(func())) {
		row(func() {
			ui.Row(c).FillWidth().AlignItems(ui.End).Wrap().Gap(t.Space(1.5)).Children(func() {
				oneui.TextBox(c, &a.exportPath, oneui.TextBoxOptions{}).
					Label("导出路径").Placeholder("新的 .kdbx 完整路径").Grow(1).Disabled(a.uiBusy(c))
				oneui.Button(c, "选择导出位置…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
					win := a.win
					a.runInteractive(func() outcome {
						path, e := mygo.Dialog.Save(mygo.SaveDialogOptions{
							Parent:      win,
							Title:       "导出加密 KDBX",
							DefaultPath: "passme-export.kdbx",
							Filters:     []mygo.FileFilter{{Name: "KeePass KDBX", Extensions: []string{"kdbx"}}},
						})
						return outcome{err: e, apply: func() {
							if strings.TrimSpace(path) != "" {
								a.exportPath = path
							}
						}}
					})
				})
			})
		})
		row(func() {
			oneui.TextBox(c, &a.exportPassword, oneui.TextBoxOptions{}).
				Label("独立导出密码").Placeholder("至少 12 字符的独立导出密码").Password().FillWidth().Disabled(a.uiBusy(c))
		})
		row(func() {
			onevraSettingRow(c, "导出全量加密档案", "导出所有状态条目及来源元数据，并使用上方独立密码加密。", func() {
				oneui.Button(c, "确认加密导出", oneui.ButtonSecondary).
					Disabled(a.uiBusy(c) || strings.TrimSpace(a.exportPath) == "" || len(a.exportPassword) < 12).
					OnClick(func() {
						s, path, password := a.session, a.exportPath, a.exportPassword
						a.exportPassword = ""
						a.runInteractive(func() outcome { return outcome{err: s.Export(password, path)} })
					})
			})
		})
	})

	// 3. Emergency Kit Re-Export
	onevraGroup(c, "应急文件（Secret Key 备份）", func(row func(func())) {
		row(func() {
			onevraSettingRow(c, "包含明文 Secret Key 的离线恢复文档", "更换电脑或重置本机系统凭据存储后，需主密码和应急文件中的 Secret Key 重新授权设备。", func() {
				onevraPill(c, "含明文 Secret Key", t.Warning)
			})
		})
		row(func() {
			ui.Row(c).FillWidth().AlignItems(ui.End).Wrap().Gap(t.Space(1.5)).Children(func() {
				oneui.TextBox(c, &a.reexportPassword, oneui.TextBoxOptions{}).
					Label("当前金库主密码").Placeholder("输入当前主密码以确认导出").Password().Grow(1).Disabled(a.uiBusy(c)).
					OnSubmit(a.reexportEmergencyKit)
				oneui.Button(c, "重新导出应急文件…", oneui.ButtonSecondary).
					Disabled(a.uiBusy(c) || a.path == "" || a.reexportPassword == "").
					OnClick(a.reexportEmergencyKit)
			})
		})
		if a.kitSavedPath != "" {
			row(func() {
				oneui.Text(c, "最近导出位置："+a.kitSavedPath).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
			})
		}
	})
}

func (a *App) updatesSettingsView(c *ui.Context) {
	t := c.Theme()
	onevraSettingsGroup(c, "版本与更新机制", func(row func(string, string, func())) {
		row("当前版本", "通过 GitHub Releases 检查更新，下载包需通过内置 Ed25519 公钥签名验证；不上传金库内容或遥测数据。", func() {
			onevraPill(c, desktopVersionLabel(), t.Accent)
		})
		statusDesc := "当前为开发构建（dev build），不会自动替换本机二进制文件。"
		if desktopCanSelfUpdate() {
			statusDesc = "自动与手动更新均已就绪。"
		}
		row("检查更新", statusDesc, func() {
			oneui.Button(c, "检查更新…", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).OnClick(updater.CheckForUpdates)
		})
	})
}

func (a *App) aboutSettingsView(c *ui.Context) {
	t := c.Theme()
	onevraGroup(c, "", func(row func(func())) {
		row(func() {
			mark := ui.Box(c).Size(t.Space(10), t.Space(10)).Radius(t.Space(2.5)).Background(t.Accent).
				AlignItems(ui.Center).Justify(ui.Center)
			mark.Children(func() {
				oneui.Icon(c, lucide.KeyRound()).Size(t.Space(5), t.Space(5)).TextColor(t.AccentText)
			})
			ui.Column(c).Grow(1).Gap(t.Space(.25)).Children(func() {
				oneui.Text(c, "Passme").FontSize(t.Rem(1.12)).Bold()
				oneui.Text(c, "离线优先 · 零知识本地金库与开发者凭据运行时").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
			})
			onevraPill(c, desktopVersionLabel(), t.Accent)
		})
		row(func() {
			ui.Row(c).FillWidth().Wrap().Gap(t.Space(4)).Children(func() {
				for _, cell := range []struct{ k, v string }{
					{"当前版本", desktopVersionLabel()},
					{"运行平台", runtime.GOOS + " / " + runtime.GOARCH},
					{"Go 工具链", runtime.Version()},
				} {
					ui.Column(c).MinWidth(130).Gap(t.Space(.25)).Children(func() {
						oneui.Text(c, cell.k).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
						oneui.Text(c, cell.v).FontSize(t.Rem(.84)).Bold()
					})
				}
			})
		})
		row(func() {
			onevraSettingRow(c, "隐私与安全承诺", "没有账号体系、没有云同步、没有后台分析上报；所有金库加密与密钥派生都在本机完成。", func() {
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
	})
}

func (a *App) desensitizedDiagnosticSummary() string {
	s := a.settingsSnapshot()
	a.brokerMu.Lock()
	brokerRunning := a.broker != nil
	a.brokerMu.Unlock()
	return fmt.Sprintf(
		"Passme Desktop %s (%s/%s)\ntheme=%s density=%s autolock_min=%d clipboard_sec=%d broker=%t ssh_agent=%t",
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

func findSystemUnlockPreset(id string) (systemUnlockPreset, bool) {
	key := strings.ToLower(strings.TrimSpace(id))
	for _, preset := range SystemUnlockExpiryPresets {
		if preset.ID == key {
			return preset, true
		}
	}
	return systemUnlockPreset{}, false
}

func systemUnlockExpiryLabel(id string) string {
	if preset, ok := findSystemUnlockPreset(id); ok {
		return preset.Label
	}
	return "14 天（推荐）"
}

func systemUnlockRemainingLabel(d time.Duration) string {
	if d <= 0 {
		return "即将到期"
	}
	if d >= 24*time.Hour {
		return fmt.Sprintf("约 %d 天", int((d+12*time.Hour)/(24*time.Hour)))
	}
	if d >= time.Hour {
		return fmt.Sprintf("约 %d 小时", int((d+30*time.Minute)/time.Hour))
	}
	return "不足 1 小时"
}

func systemUnlockOptions(current string) []oneui.NativeSelectOption[string] {
	options := make([]oneui.NativeSelectOption[string], 0, len(SystemUnlockExpiryPresets))
	for _, preset := range SystemUnlockExpiryPresets {
		options = append(options, oneui.NativeSelectOption[string]{
			Value: preset.ID,
			Label: preset.Label,
		})
	}
	return options
}
