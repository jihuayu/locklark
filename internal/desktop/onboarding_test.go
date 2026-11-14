package desktop

import (
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreationSecretCanBeCopiedAndSaved(t *testing.T) {
	a := New()
	a.create = true
	a.issued = "LL1-SYNTHETIC-KEY"
	clip := attachFakeClipboard(a)
	tester := ui.NewTester(a.View, 1100, 760)
	for _, label := range []string{"复制 Secret Key", "保存应急文件…"} {
		if !tester.HasText(label) {
			t.Fatalf("missing %s", label)
		}
	}
	if err := tester.Click("复制 Secret Key"); err != nil {
		t.Fatal(err)
	}
	if clip.value != a.issued {
		t.Fatal("copied value differs from issued key")
	}
	if a.clipboardUntil.IsZero() {
		t.Fatal("sensitive clipboard copy has no expiry")
	}
	target := filepath.Join(t.TempDir(), "emergency.txt")
	if err := saveEmergencyKit(target, a.issued); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), a.issued) || !strings.Contains(string(data), "主密码") {
		t.Fatal("emergency file lacks key or instructions")
	}
	if err := saveEmergencyKit(target, "different"); err == nil {
		t.Fatal("overwrote existing file")
	}
	again, err := os.ReadFile(target)
	if err != nil || string(again) != string(data) {
		t.Fatal("existing file changed")
	}
	a.Lock()
	if clip.value != "" {
		t.Fatal("lock retained secret key on clipboard")
	}
}

func TestUnlockOnboardingUsesTheWideDesktopWorkspace(t *testing.T) {
	t.Run("default-centered-card", func(t *testing.T) {
		t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "")
		a := New()
		a.path = filepath.Join(t.TempDir(), "personal.ll")
		tester := ui.NewTester(a.lockView, 1600, 900)
		card, ok := tester.Find("解锁当前设备金库")
		if !ok {
			t.Fatal("default unlock card is missing accessible surface")
		}
		if card.W > 520 {
			t.Fatalf("default unlock card exceeded single-card width: width=%g", card.W)
		}
		for _, label := range []string{"解锁金库", "解锁", "使用" + osunlock.Label() + "解锁", "使用应急资料…", "打开其他金库…", "退出当前设备…"} {
			if !tester.HasText(label) {
				t.Fatalf("default unlock card missing %q", label)
			}
		}
		for _, forbidden := range []string{"创建新金库", "选择金库位置…"} {
			if tester.HasText(forbidden) {
				t.Fatalf("default unlock card should not expose %q", forbidden)
			}
		}
	})

	t.Run("classic", func(t *testing.T) {
		t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "classic")
		a := New()
		tester := ui.NewTester(a.lockView, 1600, 900)
		workspace, ok := tester.Find("解锁与本地安全")
		if !ok {
			t.Fatal("wide onboarding workspace has no identifiable surface")
		}
		if workspace.W < 900 {
			t.Fatalf("wide onboarding remained a small centered form: width=%g", workspace.W)
		}
		for _, label := range []string{"解锁金库", "解锁", "创建新金库", "使用应急资料…"} {
			if !tester.HasText(label) {
				t.Fatalf("wide onboarding missing %q", label)
			}
		}
	})
}

func TestOnboardingSnapshot(t *testing.T) {
	dir := os.Getenv("LOCKLARK_ONBOARDING_SNAPSHOT")
	if dir == "" {
		t.Skip("set LOCKLARK_ONBOARDING_SNAPSHOT to render onboarding")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		width, height int
		onboarding    bool
		create        bool
	}{
		{"onboarding", 1240, 860, true, false},
		{"create", 1100, 820, false, true},
		{"unlock", 1240, 820, false, false},
	} {
		a := New()
		a.path = filepath.Join(dir, "personal.ll")
		a.onboarding = tc.onboarding
		a.create = tc.create
		if tc.create {
			a.issued = "LL1-EXAMPLEEXAMPLEEXAMPLEEXAMPL"
		}
		tester := ui.NewTester(a.View, tc.width, tc.height)
		if tc.create && !tester.HasText("保存应急文件…") {
			t.Fatal("missing save action")
		}
		f, err := os.Create(filepath.Join(dir, tc.name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, tester.Image())
		closeErr := f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}

func TestStreamlinedCreationAutoSavesEmergencyKitWithoutSecretReentry(t *testing.T) {
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "")
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)

	a := New()
	a.launch = func(f func()) { f() }
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.deviceSecrets = newFakeDeviceSecretStore()

	vaultDir := t.TempDir()
	a.path = filepath.Join(vaultDir, "personal.ll")
	existingKit := filepath.Join(vaultDir, emergencyKitFileName)
	if err := os.WriteFile(existingKit, []byte("existing-kit"), 0o600); err != nil {
		t.Fatal(err)
	}

	a.startCreateVault()
	if !a.create || a.onboarding || a.issued == "" || a.secret != "" {
		t.Fatalf("unexpected create state: create=%v onboarding=%v issued=%v secret=%q", a.create, a.onboarding, a.issued != "", a.secret)
	}

	a.password = "fixture-password"
	a.confirmation = "fixture-password"
	a.createVaultFile()
	if a.session == nil {
		t.Fatalf("streamlined vault creation failed without secret re-entry: %s", a.status)
	}
	defer a.Lock()

	if a.settingsSnapshot().VaultPath != a.path {
		t.Fatalf("Settings.VaultPath = %q, want %q", a.settingsSnapshot().VaultPath, a.path)
	}
	wantKit := filepath.Join(vaultDir, "Locklark-Emergency-Kit-2.txt")
	if a.kitSavedPath != wantKit {
		t.Fatalf("kitSavedPath = %q, want %q", a.kitSavedPath, wantKit)
	}
	existingData, err := os.ReadFile(existingKit)
	if err != nil || string(existingData) != "existing-kit" {
		t.Fatalf("existing Emergency Kit was modified: %q err=%v", string(existingData), err)
	}
	kitData, err := os.ReadFile(wantKit)
	if err != nil || !strings.Contains(string(kitData), "Secret Key:") {
		t.Fatalf("auto-saved Emergency Kit missing Secret Key: err=%v data=%q", err, string(kitData))
	}
	if _, err := a.loadDeviceSecret(a.path); err != nil {
		t.Fatalf("device Secret Key was not persisted: %v", err)
	}
}

func TestClassicCreationStillRequiresMatchingSavedSecret(t *testing.T) {
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "classic")
	a := New()
	a.launch = func(f func()) { f() }
	a.create = true
	a.path = filepath.Join(t.TempDir(), "vault.ll")
	key, err := personal.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	a.issued = personal.FormatSecret(key)
	a.password, a.confirmation, a.secret = "fixture-password", "fixture-password", "wrong"
	a.createVaultFile()
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatal("created vault with mismatched key")
	}
	a.secret = a.issued
	a.createVaultFile()
	if a.session == nil {
		t.Fatalf("could not create vault with confirmed key: %s", a.status)
	}
	defer a.Lock()
	if _, err := os.Stat(a.path); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsUseMenusAndDesktopOmitsWatchtower(t *testing.T) {
	a := newOnevraTestApp()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	tester := newOnevraTestTesterSize(a, 1280, 1000)
	if tester.HasText("Watchtower 安全体检") {
		t.Fatal("desktop still exposes Watchtower")
	}
	a.openSettings()
	tester.Frame()
	if err := tester.Click("自动锁定时间"); err != nil {
		t.Fatal(err)
	}
	if err := tester.ChooseMenuItem("10 分钟"); err != nil {
		t.Fatal(err)
	}
	if a.settingsSnapshot().AutoLockMinutes != 10 {
		t.Fatal("auto lock selection not applied")
	}
	if err := tester.Click("剪贴板清理时间"); err != nil {
		t.Fatal(err)
	}
	if err := tester.ChooseMenuItem("60 秒"); err != nil {
		t.Fatal(err)
	}
	if a.settingsSnapshot().ClipboardClearSeconds != 60 {
		t.Fatal("clipboard selection not applied")
	}
}

func TestSettingsCustomValuesRemainSelectable(t *testing.T) {
	opts := durationOptions(AutoLockPresets, 7, "分钟")
	found := false
	for _, option := range opts {
		if option.Value == 7 && option.Label == "7 分钟" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom persisted setting missing from menu")
	}
}

func TestFirstLaunchShowsOnboardingGuideWithoutCreatingVault(t *testing.T) {
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "")
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)

	a := New()
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.syncInitialVaultState()
	if !a.onboarding || a.create {
		t.Fatalf("expected onboarding guide on uninitialized launch, got onboarding=%v create=%v", a.onboarding, a.create)
	}
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatalf("syncInitialVaultState unexpectedly created file on disk: err=%v", err)
	}

	tester := ui.NewTester(a.View, 1240, 860)
	for _, want := range []string{
		"欢迎使用 Locklark 本地金库",
		"1. 主密码（仅你记忆）",
		"2. Secret Key（本机系统凭据保护）",
		"3. 双因素派生与零知识加密",
		"4. Emergency Kit（跨设备/重装离线恢复）",
		"创建金库",
		"打开已有金库…",
	} {
		if !tester.HasText(want) {
			t.Fatalf("onboarding guide missing %q", want)
		}
	}
	if err := tester.Click("创建金库"); err != nil {
		t.Fatal(err)
	}
	if !a.create || a.onboarding || a.issued == "" {
		t.Fatalf("clicking 创建金库 did not enter create view cleanly: create=%v onboarding=%v issued=%v", a.create, a.onboarding, a.issued != "")
	}
}

func TestForgetDeviceRequiresMasterPasswordAndKeepsVaultFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)

	a, password, secret := createDeviceSecretTestVault(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.deviceSecrets = newFakeDeviceSecretStore()
	system := newFakeSystemUnlockStore()
	a.systemStore = system
	if err := a.storeDeviceSecret(a.path, secret); err != nil {
		t.Fatal(err)
	}
	if err := a.SetVaultPath(a.path); err != nil {
		t.Fatal(err)
	}
	vaultPath := a.path

	a.forgetPassword = "wrong-password"
	a.forgetDeviceWithPassword()
	if a.onboarding {
		t.Fatal("forgetDeviceWithPassword proceeded with wrong master password")
	}
	if _, err := a.loadDeviceSecret(vaultPath); err != nil {
		t.Fatalf("device secret deleted despite wrong password: %v", err)
	}
	if a.settingsSnapshot().VaultPath != vaultPath {
		t.Fatalf("VaultPath cleared despite wrong password: %q", a.settingsSnapshot().VaultPath)
	}
	if system.deleteCalls != 0 {
		t.Fatalf("system unlock deleted despite wrong password: %d", system.deleteCalls)
	}

	a.forgetPassword = password
	a.forgetDeviceWithPassword()
	if !a.onboarding {
		t.Fatalf("forgetDeviceWithPassword did not return to onboarding: %s", a.status)
	}
	if a.settingsSnapshot().VaultPath != "" {
		t.Fatalf("VaultPath was not cleared after forget device: %q", a.settingsSnapshot().VaultPath)
	}
	if system.deleteCalls != 1 {
		t.Fatalf("system unlock cleanup calls = %d, want 1", system.deleteCalls)
	}
	if _, err := a.loadDeviceSecret(vaultPath); err == nil {
		t.Fatal("device secret remained after forget device")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("forget device deleted .ll vault file: %v", err)
	}
}

func TestSettingsReexportEmergencyKitRequiresMasterPassword(t *testing.T) {
	a, password, secret := createDeviceSecretTestVault(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.deviceSecrets = newFakeDeviceSecretStore()
	if err := a.storeDeviceSecret(a.path, secret); err != nil {
		t.Fatal(err)
	}

	a.reexportPassword = "wrong-password"
	a.reexportEmergencyKit()
	if a.kitSavedPath != "" {
		t.Fatalf("re-exported Emergency Kit with wrong password: %q", a.kitSavedPath)
	}

	a.reexportPassword = password
	a.reexportEmergencyKit()
	if a.kitSavedPath == "" {
		t.Fatalf("re-export failed with valid password: %s", a.status)
	}
	data, err := os.ReadFile(a.kitSavedPath)
	if err != nil || !strings.Contains(string(data), secret) {
		t.Fatalf("re-exported Emergency Kit missing Secret Key: err=%v", err)
	}
}

func TestSettingsSnapshot(t *testing.T) {
	dir := os.Getenv("LOCKLARK_ONBOARDING_SNAPSHOT")
	if dir == "" {
		t.Skip("set LOCKLARK_ONBOARDING_SNAPSHOT to render settings")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	a := newOnevraTestApp()
	a.session = &personal.Session{}
	a.launch = func(func()) {}
	a.v2Mode = true
	a.settingsPath = filepath.Join(dir, "settings.json")
	a.openSettings()
	tester := newOnevraTestTesterSize(a, 1280, 1000)

	for _, tc := range []struct {
		name    string
		section string
	}{
		{"settings", settingsSectionSecurity},
		{"settings-general", settingsSectionGeneral},
		{"settings-appearance", settingsSectionAppearance},
		{"settings-developer", settingsSectionDeveloper},
		{"settings-cli", settingsSectionCLI},
		{"settings-cli-activity", settingsSectionCLIActivity},
		{"settings-about", settingsSectionAbout},
	} {
		a.v2.settingsSection = tc.section
		tester.Frame()
		f, err := os.Create(filepath.Join(dir, tc.name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, tester.Image())
		closeErr := f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}
