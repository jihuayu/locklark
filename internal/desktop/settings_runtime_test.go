package desktop

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// runtimeSettingsFixture keeps every settings mutation inside the temporary
// directory so the tests can use the real setter/persist path without touching
// the operator's settings file.
func runtimeSettingsFixture(t *testing.T) *App {
	t.Helper()
	a := dailyAppFixture(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.launch = func(f func()) { f() }
	a.dispatch = func(f func()) { f() }
	return a
}

func TestAutoLockMinutesAppliesToLiveSession(t *testing.T) {
	a := runtimeSettingsFixture(t)
	if err := a.SetAutoLockMinutes(30); err != nil {
		t.Fatal(err)
	}
	deadline, ok := a.session.IdleDeadline()
	if !ok || time.Until(deadline) < 29*time.Minute {
		t.Fatalf("session idle deadline=%v ok=%v, want the configured 30 minutes", deadline, ok)
	}
	// The old hardcoded five-minute Session idle would have expired here.
	a.touchActivity()
	a.backgroundTick(time.Now().Add(6 * time.Minute))
	if a.session == nil || !a.session.Unlocked() {
		t.Fatal("a 30-minute preference was still locked by the old five-minute session idle")
	}
	// The configured threshold itself must still lock.
	a.lastActivity = time.Now().Add(-31 * time.Minute)
	a.backgroundTick(time.Now())
	if a.session != nil {
		t.Fatal("configured 30-minute auto-lock did not fire")
	}
}

func TestAutoLockNeverDisablesIdleLocking(t *testing.T) {
	a := runtimeSettingsFixture(t)
	if err := a.SetAutoLockMinutes(0); err != nil {
		t.Fatal(err)
	}
	if a.idleTimer != nil {
		t.Fatal("disabled auto-lock left an armed idle timer")
	}
	deadline, ok := a.session.IdleDeadline()
	if !ok || !deadline.IsZero() {
		t.Fatalf("session with disabled auto-lock reports deadline=%v ok=%v", deadline, ok)
	}
	a.lastActivity = time.Now().Add(-24 * time.Hour)
	a.backgroundTick(time.Now())
	if a.session == nil || !a.session.Unlocked() {
		t.Fatal("AutoLockMinutes=0 still expired the session")
	}
	// Explicit locking keeps working.
	a.Lock()
	if a.session != nil {
		t.Fatal("explicit lock was ignored")
	}
}

func TestAutoLockTimeoutSurvivesSystemUnlock(t *testing.T) {
	// The unlock entry points must read AutoLockMinutes instead of the old
	// five-minute literal. A 10-minute preference is below Session's documented
	// maximum and must be visible in the created session.
	path := filepath.Join(t.TempDir(), "unlock.ll")
	key := make([]byte, 16)
	for i := range key {
		key[i] = 6
	}
	if err := personal.Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.settings.AutoLockMinutes = 10
	a.settings.IdleTimeout = 10 * time.Minute
	a.path = path
	a.password = "fixture"
	a.secret = personal.FormatSecret(key)
	a.launch = func(f func()) { f() }
	a.dispatch = func(f func()) { f() }
	a.unlock()
	if a.session == nil {
		t.Fatal("unlock did not create a session")
	}
	defer a.Lock()
	deadline, ok := a.session.IdleDeadline()
	if !ok || time.Until(deadline) < 9*time.Minute {
		t.Fatalf("unlock ignored AutoLockMinutes: deadline=%v ok=%v", deadline, ok)
	}
}

func TestLockPreferencesGateSleepScreenLockAndWindowClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		off  func(*App) error
		fire func(*App)
	}{
		{"sleep", func(a *App) error { return a.SetLockOnSleep(false) }, func(a *App) { a.suspendEvent() }},
		{"screen-lock", func(a *App) error { return a.SetLockOnScreenLock(false) }, func(a *App) { a.screenLockEvent() }},
		{"window-close", func(a *App) error { return a.SetLockOnWindowClose(false) }, func(a *App) { a.windowClose(&mygo.CloseEvent{}) }},
	} {
		t.Run(tc.name+" disabled", func(t *testing.T) {
			a := runtimeSettingsFixture(t)
			if err := tc.off(a); err != nil {
				t.Fatal(err)
			}
			tc.fire(a)
			if a.session == nil || !a.session.Unlocked() {
				t.Fatal("disabled lock preference still locked the vault")
			}
		})
	}
	for _, tc := range []struct {
		name string
		fire func(*App)
	}{
		{"sleep", func(a *App) { a.suspendEvent() }},
		{"screen-lock", func(a *App) { a.screenLockEvent() }},
		{"window-close", func(a *App) { a.windowClose(nil) }},
	} {
		t.Run(tc.name+" enabled", func(t *testing.T) {
			a := runtimeSettingsFixture(t)
			tc.fire(a)
			if a.session != nil {
				t.Fatal("enabled lock preference did not lock the vault")
			}
		})
	}
}

func TestClipboardClearSecondsAppliesToNativeDisclosure(t *testing.T) {
	a := runtimeSettingsFixture(t)
	clipboard := attachFakeClipboard(a)
	id, err := a.session.AddLogin("clipboard target", "user", "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.session.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("clipboard fixture list=%v err=%v", rows, err)
	}
	a.selected = &rows[0]
	if err := a.SetClipboardClearSeconds(90); err != nil {
		t.Fatal(err)
	}
	a.disclose("password", "copy")
	if clipboard.value != "secret-value" {
		t.Fatalf("clipboard value=%q", clipboard.value)
	}
	if d := time.Until(a.clipboardUntil); d < 85*time.Second || d > 95*time.Second {
		t.Fatalf("clipboard lease=%v, want the configured 90 seconds", d)
	}
	a.backgroundTick(a.clipboardUntil.Add(time.Second))
	if clipboard.value != "" {
		t.Fatal("configured clipboard deadline did not clear the owned value")
	}
}

func TestClipboardClearNeverKeepsConfiguredLease(t *testing.T) {
	a := runtimeSettingsFixture(t)
	clipboard := attachFakeClipboard(a)
	id, err := a.session.AddLogin("clipboard never", "user", "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.session.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("clipboard fixture list=%v err=%v", rows, err)
	}
	a.selected = &rows[0]
	if err := a.SetClipboardClearSeconds(0); err != nil {
		t.Fatal(err)
	}
	a.disclose("password", "copy")
	if clipboard.value != "secret-value" {
		t.Fatalf("clipboard value=%q", clipboard.value)
	}
	if d := time.Until(a.clipboardUntil); d < 24*time.Hour {
		t.Fatalf("clipboard lease=%v, want no automatic clearing", d)
	}
	a.backgroundTick(time.Now().Add(time.Hour))
	if clipboard.value == "" {
		t.Fatal("AutoClear=0 still cleared the clipboard")
	}
	a.Lock()
	if clipboard.value != "" {
		t.Fatal("lock did not clear the owned clipboard")
	}
}

// revealRuntimeFixture selects a fresh item through the production selection
// path with a synchronous worker, so the settings behaviour is observable
// without a rendered frame.
func revealRuntimeFixture(t *testing.T, item vault.Item) (*App, string) {
	t.Helper()
	a := runtimeSettingsFixture(t)
	a.EnableV2()
	// One gate owns one native mutation.
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := a.session.RegisterMutation(g); err != nil {
		t.Fatal(err)
	}
	id, rev, err := a.session.AddItem(item, g)
	if err != nil {
		t.Fatal(err)
	}
	a.reloadV2(false)
	for _, row := range a.v2.rows {
		if row.ID == id {
			rev = row.Revision
		}
	}
	if rev == "" {
		t.Fatal("fixture item missing from the V2 list")
	}
	return a, rev
}

// applyDue runs the debounced default reveal exactly as an idle background
// tick would once the delay has elapsed.
func applyDue(t *testing.T, a *App) {
	t.Helper()
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
}

func TestRevealPasswordsPreferenceControlsDefaultDisclosure(t *testing.T) {
	a, revision := revealRuntimeFixture(t, vault.Item{Kind: "login", Category: vault.CategoryLogin, Title: "reveal target", Username: "user", Password: "secret-value", Notes: "private-note"})
	id := a.v2.rows[0].ID

	// Defaults keep the current concealment: selecting metadata never fetches
	// or shows the password.
	a.selectItem(id, revision)
	applyDue(t, a)
	if a.v2.revealed["password"] || a.v2.detailPlain != nil || a.v2.narrowPassword.value != nil {
		t.Fatal("default settings revealed the password on selection")
	}
	view := ui.NewTester(a.View, 1200, 1400)
	if view.HasText("secret-value") {
		t.Fatal("detail pane exposed the unrevealed password")
	}

	if err := a.SetRevealPasswords(true); err != nil {
		t.Fatal(err)
	}
	a.selectItem(id, revision)
	applyDue(t, a)
	if a.v2.detailPlain != nil {
		t.Fatal("RevealPasswords cached a full plaintext detail")
	}
	if !a.v2.narrowPassword.current(id, revision, time.Now()) {
		t.Fatal("RevealPasswords did not reveal the selected password")
	}
	if a.v2.revealed["notes"] || a.v2.revealed["otp"] || a.v2.revealed["password"] {
		t.Fatal("RevealPasswords expanded disclosure beyond the password")
	}
	view = ui.NewTester(a.View, 1200, 1400)
	if !view.HasText("secret-value") {
		t.Fatal("detail pane did not render the default-revealed password")
	}
	if view.HasText("private-note") {
		t.Fatal("RevealPasswords rendered the notes it must not disclose")
	}

	// The same bounded reveal window still clears the value.
	a.backgroundTick(time.Now().Add(16 * time.Second))
	if a.v2.detailPlain != nil || len(a.v2.revealed) != 0 || a.v2.narrowPassword.value != nil {
		t.Fatal("default reveal outlived the bounded display window")
	}
	if view := ui.NewTester(a.View, 1200, 1400); view.HasText("secret-value") {
		t.Fatal("cleared default reveal remained visible")
	}
}

func TestRevealPasswordsTurnsOffImmediately(t *testing.T) {
	a, revision := revealRuntimeFixture(t, vault.Item{Kind: "login", Category: vault.CategoryLogin, Title: "toggle target", Password: "secret-value"})
	id := a.v2.rows[0].ID
	if err := a.SetRevealPasswords(true); err != nil {
		t.Fatal(err)
	}
	a.selectItem(id, revision)
	applyDue(t, a)
	if view := ui.NewTester(a.View, 1200, 1400); !view.HasText("secret-value") {
		t.Fatal("precondition: password was not revealed")
	}
	if err := a.SetRevealPasswords(false); err != nil {
		t.Fatal(err)
	}
	if a.v2.narrowPassword.value != nil || a.v2.revealUntil != (time.Time{}) || !a.defaultRevealAt.IsZero() {
		t.Fatal("turning RevealPasswords off left the disclosure armed")
	}
	applyDue(t, a)
	if view := ui.NewTester(a.View, 1200, 1400); view.HasText("secret-value") {
		t.Fatal("turning RevealPasswords off did not hide the password immediately")
	}
}

func TestRevealPasswordsRechecksSettingWhenResultArrives(t *testing.T) {
	a, revision := revealRuntimeFixture(t, vault.Item{Kind: "login", Category: vault.CategoryLogin, Title: "late target", Password: "secret-value"})
	id := a.v2.rows[0].ID
	if err := a.SetRevealPasswords(true); err != nil {
		t.Fatal(err)
	}
	a.selectItem(id, revision)
	var pending []func()
	a.dispatch = func(fn func()) { pending = append(pending, fn) }
	a.backgroundTick(time.Now().Add(defaultRevealDelay))
	if !a.busy || len(pending) == 0 {
		t.Fatal("precondition: disclosure read was not started")
	}
	// The preference is disabled before the asynchronous result is applied,
	// and a direct setter path bypasses the prompt retraction hook.
	a.settings.RevealPasswords = false
	for len(pending) > 0 {
		next := pending[0]
		pending = pending[1:]
		next()
	}
	if a.v2.narrowPassword.value != nil || !a.v2.revealUntil.IsZero() {
		t.Fatal("in-flight disclosure was applied after the setting was disabled")
	}
	if view := ui.NewTester(a.View, 1200, 1400); view.HasText("secret-value") {
		t.Fatal("stale disclosure remained visible")
	}
}

func TestRevealPasswordsOnlyDisclosesLoginPasswords(t *testing.T) {
	for _, item := range []vault.Item{
		{Kind: "secure_note", Category: vault.CategorySecureNote, Title: "note", Notes: "private-note"},
		{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "card", CreditCard: &vault.CreditCardDetails{CardholderName: "Holder", Type: "visa", Number: "4242424242424242", Verification: "123"}},
		{Kind: "login", Category: vault.CategoryLogin, Title: "no password"},
	} {
		t.Run(string(item.Category)+item.Title, func(t *testing.T) {
			a, revision := revealRuntimeFixture(t, item)
			id := a.v2.rows[0].ID
			if err := a.SetRevealPasswords(true); err != nil {
				t.Fatal(err)
			}
			a.selectItem(id, revision)
			applyDue(t, a)
			if a.v2.narrowPassword.value != nil || len(a.v2.revealed) != 0 || a.v2.detailPlain != nil || !a.v2.revealUntil.IsZero() {
				t.Fatal("RevealPasswords disclosed a non-login item or a missing password")
			}
			if a.revealPasswordValue() != "" {
				t.Fatal("narrow password lookup returned a value for a non-login item")
			}
			view := newOnevraTestTester(a)
			if view.HasText("private-note") || view.HasText("4242424242424242") {
				t.Fatal("RevealPasswords rendered notes or card values")
			}
			if item.Title != "no password" && !view.HasText(v2MaskedValue) {
				t.Fatal("password field stopped being masked")
			}
		})
	}
}

func TestSettingsRejectsNegativeAndOutOfRangeIntegers(t *testing.T) {
	a := runtimeSettingsFixture(t)
	before := a.settingsSnapshot()
	for _, minutes := range []int{-1, -5, math.MaxInt, math.MinInt, 481} {
		if err := a.SetAutoLockMinutes(minutes); err == nil {
			t.Fatalf("SetAutoLockMinutes(%d) was accepted", minutes)
		}
		if a.settingsSnapshot().AutoLockMinutes != before.AutoLockMinutes {
			t.Fatalf("SetAutoLockMinutes(%d) mutated settings to %d", minutes, a.settingsSnapshot().AutoLockMinutes)
		}
	}
	for _, seconds := range []int{-1, -30, math.MaxInt, math.MinInt, 3601} {
		if err := a.SetClipboardClearSeconds(seconds); err == nil {
			t.Fatalf("SetClipboardClearSeconds(%d) was accepted", seconds)
		}
		if a.settingsSnapshot().ClipboardClearSeconds != before.ClipboardClearSeconds || a.clipboardClearDuration() != 30*time.Second {
			t.Fatalf("SetClipboardClearSeconds(%d) mutated the clipboard configuration", seconds)
		}
	}
	for _, s := range []Settings{
		{AutoLockMinutes: -1, Theme: "system", InterfaceDensity: "comfortable"},
		{ClipboardClearSeconds: -1, Theme: "system", InterfaceDensity: "comfortable"},
		{AutoLockMinutes: 5, IdleTimeout: -time.Minute, Theme: "system", InterfaceDensity: "comfortable"},
		{AutoLockMinutes: 5, ClipboardClearTimeout: -time.Second, Theme: "system", InterfaceDensity: "comfortable"},
		{AutoLockMinutes: 5, ClipboardClearSeconds: 60, IdleTimeout: -time.Second, Theme: "dark", InterfaceDensity: "compact"},
	} {
		if _, err := ValidateSettings(s); err == nil {
			t.Fatalf("ValidateSettings accepted %+v", s)
		}
		if err := a.ApplySettings(s); err == nil {
			t.Fatalf("ApplySettings accepted %+v", s)
		}
	}
	// The explicit "never" value stays valid and keeps its exact meaning.
	if err := a.SetAutoLockMinutes(0); err != nil {
		t.Fatal(err)
	}
	if err := a.SetAutoLockMinutes(480); err != nil {
		t.Fatal(err)
	}
	if a.idleTimeout() != 480*time.Minute {
		t.Fatalf("480 minutes became %v", a.idleTimeout())
	}
	if err := a.SetClipboardClearSeconds(3600); err != nil {
		t.Fatal(err)
	}
}

func TestOTPClipboardDeadlineHonoursBothCaps(t *testing.T) {
	now := time.Now()
	otpExpiry := now.Add(40 * time.Second)
	for _, tc := range []struct {
		name  string
		clear time.Duration
		want  time.Time
	}{
		{"zero keeps otp validity", 0, otpExpiry},
		{"longer config capped by otp", time.Minute, otpExpiry},
		{"shorter config wins", 20 * time.Second, now.Add(20 * time.Second)},
		{"negative behaves like unset", -time.Second, otpExpiry},
	} {
		if got := otpClipboardDeadline(otpExpiry, tc.clear, now); !got.Equal(tc.want) {
			t.Fatalf("%s: deadline=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOTPCopyUsesConfiguredAndCodeValidityDeadline(t *testing.T) {
	a := runtimeSettingsFixture(t)
	id, err := a.session.AddLogin("otp copy", "user", "private-password")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.session.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("otp fixture list=%v err=%v", rows, err)
	}
	rev := rows[0].Revision
	// A one-hour TOTP period makes the code outlive every clipboard preset.
	rev, err = a.session.Edit(personal.Edit{ID: id, Revision: rev, Field: "otp", Value: "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=3600"})
	if err != nil {
		t.Fatal(err)
	}
	a.selected = &personal.Row{ID: id, Revision: rev, Title: "otp copy", State: "active"}
	clipboard := attachFakeClipboard(a)
	a.dispatch = func(fn func()) { fn() }
	a.launch = func(fn func()) { fn() }
	defer a.clearClipboard()

	if err := a.SetClipboardClearSeconds(20); err != nil {
		t.Fatal(err)
	}
	a.requestOTP("copy")
	if d := time.Until(a.clipboardUntil); d < 15*time.Second || d > 21*time.Second {
		t.Fatalf("OTP copy lease=%v, want the configured 20 seconds", d)
	}
	if a.otpClipboard == nil || !a.clipboardUntil.Before(a.otpClipboard.Deadline.Add(time.Second)) {
		t.Fatal("OTP copy was not capped by the code validity")
	}
	a.backgroundTick(a.clipboardUntil.Add(time.Second))
	if clipboard.value != "" {
		t.Fatal("configured OTP copy deadline did not clear the code")
	}

	// Auto-clear "never" still ends with the code validity.
	if err := a.SetClipboardClearSeconds(0); err != nil {
		t.Fatal(err)
	}
	a.requestOTP("copy")
	if a.otpClipboard == nil {
		t.Fatal("OTP copy was not prepared")
	}
	expiry := a.otpClipboard.Deadline
	if !a.clipboardUntil.Equal(expiry) {
		t.Fatalf("OTP copy lease=%v, want the code deadline %v", a.clipboardUntil, expiry)
	}
	a.backgroundTick(expiry.Add(time.Second))
	if clipboard.value != "" {
		t.Fatal("expired one-time code was retained with auto-clear disabled")
	}
}

func TestRevealPasswordsDoesNotFetchSecretsOnListing(t *testing.T) {
	a := runtimeSettingsFixture(t)
	a.EnableV2()
	id, err := a.session.AddLogin("metadata only", "user", "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetRevealPasswords(true); err != nil {
		t.Fatal(err)
	}
	a.reloadV2(false)
	if a.v2.detailPlain != nil || len(a.v2.revealed) != 0 {
		t.Fatal("metadata listing fetched plaintext")
	}
	if a.v2.rows[0].ID != id || strings.Contains(a.status, "secret-value") {
		t.Fatal("listing changed or disclosed the item")
	}
}
