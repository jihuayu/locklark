package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
)

type fakeDeviceSecretStore struct {
	values             map[string][]byte
	setCalls, getCalls int
	deleteCalls        int
}

type fakeSystemUnlockStore struct {
	values      map[string][]byte
	deleteCalls int
	deleteErr   error
}

func newFakeDeviceSecretStore() *fakeDeviceSecretStore {
	return &fakeDeviceSecretStore{values: map[string][]byte{}}
}

func newFakeSystemUnlockStore() *fakeSystemUnlockStore {
	return &fakeSystemUnlockStore{values: map[string][]byte{}}
}

func TestDeviceSecretKeyIsCompactAndDoesNotExposeVaultPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-vault-name.ll")
	key := deviceSecretKey(path)

	if len(key) > 256 {
		t.Fatalf("credential key is %d bytes; Windows accepts at most 256", len(key))
	}
	if strings.Contains(strings.ToLower(key), strings.ToLower(filepath.Base(path))) {
		t.Fatalf("credential key exposes the vault file name: %q", key)
	}
	if again := deviceSecretKey(path); again != key {
		t.Fatalf("credential key is not stable: %q != %q", key, again)
	}
}

func (s *fakeDeviceSecretStore) Set(key string, value []byte) error {
	s.setCalls++
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *fakeDeviceSecretStore) Get(key string) ([]byte, error) {
	s.getCalls++
	value, ok := s.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func (s *fakeDeviceSecretStore) Delete(key string) error {
	s.deleteCalls++
	delete(s.values, key)
	return nil
}

func (s *fakeSystemUnlockStore) Store(key string, value []byte) error {
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *fakeSystemUnlockStore) Load(key string) ([]byte, error) {
	value, ok := s.values[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func (s *fakeSystemUnlockStore) Delete(key string) error {
	s.deleteCalls++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.values, key)
	return nil
}

func TestLockedViewHidesSecretKeyWhenSavedForThisDevice(t *testing.T) {
	a := New()
	a.path = filepath.Join(t.TempDir(), "owner.ll")
	a.deviceSecrets = newFakeDeviceSecretStore()
	a.showSecretFallback = false

	tester := ui.NewTester(a.lockView, 640, 600)
	if _, ok := tester.Find("主密码"); !ok {
		t.Fatal("normal unlock did not ask for the master password")
	}
	if _, ok := tester.Find("Secret Key"); ok {
		t.Fatal("normal unlock still asked for a Secret Key stored on this device")
	}
	for _, label := range []string{"使用应急资料…", "退出当前设备…"} {
		if _, ok := tester.Find(label); !ok {
			t.Fatalf("normal unlock missing %q", label)
		}
	}
}

func TestUnlockUsesSecretStoredForThisDevice(t *testing.T) {
	a, password, secret := createDeviceSecretTestVault(t)
	store := newFakeDeviceSecretStore()
	if err := store.Set(deviceSecretKey(a.path), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	a.deviceSecrets = store
	a.password = password
	a.secret = ""
	a.showSecretFallback = false

	a.unlock()
	if a.session == nil {
		t.Fatalf("password-only unlock failed: %s", a.status)
	}
	defer a.Lock()
}

func TestUnlockWithoutSavedSecretRevealsEmergencyFallback(t *testing.T) {
	a, password, _ := createDeviceSecretTestVault(t)
	a.deviceSecrets = newFakeDeviceSecretStore()
	a.password = password
	a.secret = ""
	a.showSecretFallback = false

	a.unlock()
	if a.session != nil {
		t.Fatal("unlock accepted a missing device Secret Key")
	}
	if !a.showSecretFallback {
		t.Fatal("missing device Secret Key did not reveal the emergency fallback")
	}
}

func TestForgetDeviceStatFailureAbortsBeforeDestructiveCalls(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"permission", &os.PathError{Op: "stat", Path: "vault.ll", Err: os.ErrPermission}},
		{"io", &os.PathError{Op: "stat", Path: "vault.ll", Err: syscall.EIO}},
		{"not-a-directory", &os.PathError{Op: "stat", Path: "vault.ll", Err: syscall.ENOTDIR}},
		{"unknown", errors.New("unexpected stat failure")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, os.ErrNotExist) {
				t.Skip("this platform classifies the stat error as not-exist")
			}
			a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)
			previousStat := statVaultFile
			statVaultFile = func(string) (os.FileInfo, error) { return nil, tc.err }
			t.Cleanup(func() { statVaultFile = previousStat })

			a.confirmForgetDevice = true
			a.showSecretFallback = true
			a.forgetPassword = password
			a.forgetDeviceWithPassword()

			if a.status != forgetDeviceStatError {
				t.Fatalf("status = %q, want fixed stat error", a.status)
			}
			if secrets.deleteCalls != 0 || system.deleteCalls != 0 {
				t.Fatalf("stat error deleted credentials: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
			}
			if secrets.getCalls != 0 {
				t.Fatalf("stat error read the device Secret Key %d time(s)", secrets.getCalls)
			}
			if got := a.settingsSnapshot().VaultPath; got != vaultPath {
				t.Fatalf("stat error changed VaultPath binding: %q", got)
			}
			if a.path != vaultPath {
				t.Fatalf("stat error changed active vault path: %q", a.path)
			}
			if _, ok := secrets.values[deviceSecretKey(vaultPath)]; !ok {
				t.Fatal("stat error removed the device Secret Key")
			}
			if !a.confirmForgetDevice || !a.showSecretFallback || a.onboarding || a.busy {
				t.Fatalf("stat error changed UI state: confirm=%v fallback=%v onboarding=%v busy=%v", a.confirmForgetDevice, a.showSecretFallback, a.onboarding, a.busy)
			}
			if !a.forgetDeviceNeedsSecret() {
				t.Fatal("stat error was treated as an absent vault")
			}
			if secrets.getCalls != 0 {
				t.Fatal("forgetDeviceNeedsSecret read credentials after a stat error")
			}
		})
	}
}

func TestForgetDeviceSystemUnlockDeleteFailureKeepsDeviceKeyAndBinding(t *testing.T) {
	a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)
	a.password = password
	a.secret = ""
	a.showSecretFallback = false
	a.unlock()
	if a.session == nil {
		t.Fatalf("setup unlock failed: %s", a.status)
	}
	defer a.Lock()

	system.deleteErr = errors.New("system store delete denied")
	a.confirmForgetDevice = true
	a.forgetPassword = password
	a.forgetDeviceWithPassword()

	if a.status != forgetDeviceCleanupError {
		t.Fatalf("status = %q, want fixed cleanup failure", a.status)
	}
	if system.deleteCalls != 1 {
		t.Fatalf("system delete calls = %d, want 1", system.deleteCalls)
	}
	if secrets.deleteCalls != 0 {
		t.Fatalf("device Secret Key was deleted after quick-unlock removal failed: %d", secrets.deleteCalls)
	}
	if _, ok := secrets.values[deviceSecretKey(vaultPath)]; !ok {
		t.Fatal("quick-unlock failure removed the last local recovery material")
	}
	if got := a.settingsSnapshot().VaultPath; got != vaultPath {
		t.Fatalf("quick-unlock failure changed VaultPath binding: %q", got)
	}
	if a.path != vaultPath || a.onboarding || !a.confirmForgetDevice {
		t.Fatalf("quick-unlock failure changed bound UI: path=%q onboarding=%v confirm=%v", a.path, a.onboarding, a.confirmForgetDevice)
	}
	if a.session == nil || !a.session.Unlocked() {
		t.Fatal("quick-unlock failure lost the existing unlocked session")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("quick-unlock failure altered the .ll vault file: %v", err)
	}
}

func TestForgetDeviceAbsentQuickUnlockStillCompletes(t *testing.T) {
	a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)
	system.deleteErr = osunlock.ErrNotFound
	a.forgetPassword = password
	a.forgetDeviceWithPassword()

	if a.status != "已退出当前设备；磁盘上的 .ll 金库文件已完整保留" {
		t.Fatalf("already-absent quick unlock blocked logout: %q", a.status)
	}
	if secrets.deleteCalls != 1 || system.deleteCalls != 1 {
		t.Fatalf("already-absent quick unlock skipped cleanup: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if got := a.settingsSnapshot().VaultPath; got != "" {
		t.Fatalf("already-absent quick unlock retained VaultPath binding: %q", got)
	}
	if !a.onboarding {
		t.Fatal("already-absent quick unlock did not return to onboarding")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("already-absent quick unlock altered the .ll vault file: %v", err)
	}
}

func TestForgetDeviceSettingsSaveFailureKeepsBoundUI(t *testing.T) {
	a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)
	boundSettings := a.settingsPath
	blocker := filepath.Join(t.TempDir(), "settings-parent-is-a-file")
	if err := os.WriteFile(blocker, []byte("owned test blocker"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.settingsPath = filepath.Join(blocker, "settings.json")
	a.confirmForgetDevice = true
	a.forgetPassword = password
	a.forgetDeviceWithPassword()

	if a.status != forgetDeviceCleanupError {
		t.Fatalf("status = %q, want fixed cleanup failure", a.status)
	}
	if system.deleteCalls != 1 || secrets.deleteCalls != 1 {
		t.Fatalf("cleanup did not reach the binding step: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if _, ok := secrets.values[deviceSecretKey(vaultPath)]; ok {
		t.Fatal("settings failure restored the already-deleted device Secret Key")
	}
	if got := a.settingsSnapshot().VaultPath; got != vaultPath {
		t.Fatalf("settings failure lost in-memory VaultPath binding: %q", got)
	}
	if a.path != vaultPath || a.onboarding || !a.confirmForgetDevice {
		t.Fatalf("settings failure changed bound UI: path=%q onboarding=%v confirm=%v", a.path, a.onboarding, a.confirmForgetDevice)
	}
	persisted, err := LoadSettings(boundSettings)
	if err != nil {
		t.Fatalf("load original settings: %v", err)
	}
	if persisted.VaultPath != vaultPath {
		t.Fatalf("settings failure lost persisted VaultPath binding: %q", persisted.VaultPath)
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("settings failure altered the .ll vault file: %v", err)
	}
}

func TestClassicForgetDeviceUsesSharedVerifiedConfirmation(t *testing.T) {
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "classic")
	a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)
	// Exercise the emergency-key branch for an existing owned vault.
	secret := string(secrets.values[deviceSecretKey(vaultPath)])
	delete(secrets.values, deviceSecretKey(vaultPath))
	boundSettings := a.settingsPath

	tester := ui.NewTester(a.lockView, 1600, 900)
	if err := tester.Click("退出当前设备…"); err != nil {
		t.Fatal(err)
	}
	if !a.confirmForgetDevice || a.forgetPassword != "" {
		t.Fatalf("classic exit did not open an empty confirmation: confirm=%v password=%q", a.confirmForgetDevice, a.forgetPassword)
	}
	if system.deleteCalls != 0 || secrets.deleteCalls != 0 {
		t.Fatalf("classic route deleted credentials before confirmation: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if a.settingsSnapshot().VaultPath != vaultPath || a.onboarding {
		t.Fatalf("classic route changed binding before confirmation: path=%q onboarding=%v", a.settingsSnapshot().VaultPath, a.onboarding)
	}

	tester.Frame()
	for _, want := range []string{"验证主密码", "应急 Secret Key", "确认退出当前设备", "取消退出", "保留 .ll 文件"} {
		if !tester.HasText(want) {
			t.Fatalf("classic confirmation missing %q", want)
		}
	}

	a.forgetPassword = "wrong-password"
	a.secret = secret
	tester.Frame()
	if err := tester.Click("确认退出当前设备"); err != nil {
		t.Fatal(err)
	}
	if a.status == "已退出当前设备；磁盘上的 .ll 金库文件已完整保留" || a.onboarding {
		t.Fatalf("classic route succeeded with a wrong password: status=%q onboarding=%v", a.status, a.onboarding)
	}
	if system.deleteCalls != 0 || secrets.deleteCalls != 0 {
		t.Fatalf("wrong password deleted credentials: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if got := a.settingsSnapshot().VaultPath; got != vaultPath {
		t.Fatalf("wrong password changed VaultPath binding: %q", got)
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("wrong password altered the .ll vault file: %v", err)
	}

	a.forgetPassword = password
	tester.Frame()
	if err := tester.Click("确认退出当前设备"); err != nil {
		t.Fatal(err)
	}
	if a.status != "已退出当前设备；磁盘上的 .ll 金库文件已完整保留" {
		t.Fatalf("classic verified route did not finish forget-device: %q", a.status)
	}
	if system.deleteCalls != 1 || secrets.deleteCalls != 1 {
		t.Fatalf("classic verified route did not complete cleanup: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if _, ok := secrets.values[deviceSecretKey(vaultPath)]; ok {
		t.Fatal("classic verified route retained the device Secret Key")
	}
	if got := a.settingsSnapshot().VaultPath; got != "" {
		t.Fatalf("classic verified route retained VaultPath binding: %q", got)
	}
	persisted, err := LoadSettings(boundSettings)
	if err != nil {
		t.Fatalf("load settings after classic forget: %v", err)
	}
	if persisted.VaultPath != "" {
		t.Fatalf("classic verified route retained persisted VaultPath binding: %q", persisted.VaultPath)
	}
	if !a.onboarding {
		t.Fatal("classic verified route did not return to onboarding")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("classic verified route altered the .ll vault file: %v", err)
	}
}

func TestForgetDeviceExplicitMissingVaultTakesAbsentPath(t *testing.T) {
	a, _, vaultPath, secrets, system := prepareForgetDeviceTest(t)
	if err := os.Remove(vaultPath); err != nil {
		t.Fatal(err)
	}
	if a.forgetDeviceNeedsSecret() {
		t.Fatal("explicitly missing vault still required a Secret Key")
	}
	a.forgetPassword = ""
	a.forgetDeviceWithPassword()

	if a.status != "已退出当前设备；磁盘上的 .ll 金库文件已完整保留" {
		t.Fatalf("unexpected missing-vault status: %q", a.status)
	}
	if secrets.deleteCalls != 1 || system.deleteCalls != 1 {
		t.Fatalf("missing vault did not take the absent path: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if _, ok := secrets.values[deviceSecretKey(vaultPath)]; ok {
		t.Fatal("missing-vault path retained the device Secret Key")
	}
	if got := a.settingsSnapshot().VaultPath; got != "" {
		t.Fatalf("missing-vault path retained VaultPath binding: %q", got)
	}
	if !a.onboarding {
		t.Fatal("missing-vault path did not return to onboarding")
	}
	if _, err := os.Stat(vaultPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-vault path created or retained a vault file: %v", err)
	}
}

func TestForgetDeviceVerifiedPasswordDeletesCredentialsAndBinding(t *testing.T) {
	a, password, vaultPath, secrets, system := prepareForgetDeviceTest(t)

	a.forgetPassword = "wrong-password"
	a.forgetDeviceWithPassword()
	if secrets.deleteCalls != 0 || system.deleteCalls != 0 {
		t.Fatalf("wrong password deleted credentials: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if got := a.settingsSnapshot().VaultPath; got != vaultPath {
		t.Fatalf("wrong password changed VaultPath binding: %q", got)
	}
	if a.onboarding {
		t.Fatal("wrong password returned to onboarding")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("wrong password altered the vault file: %v", err)
	}

	a.forgetPassword = password
	a.forgetDeviceWithPassword()
	if a.status != "已退出当前设备；磁盘上的 .ll 金库文件已完整保留" {
		t.Fatalf("verified password did not finish forget-device: %q", a.status)
	}
	if secrets.deleteCalls != 1 || system.deleteCalls != 1 {
		t.Fatalf("verified password did not delete credentials: device=%d system=%d", secrets.deleteCalls, system.deleteCalls)
	}
	if _, ok := secrets.values[deviceSecretKey(vaultPath)]; ok {
		t.Fatal("verified password retained the device Secret Key")
	}
	if got := a.settingsSnapshot().VaultPath; got != "" {
		t.Fatalf("verified password retained VaultPath binding: %q", got)
	}
	persisted, err := LoadSettings(a.settingsPath)
	if err != nil {
		t.Fatalf("load settings after verified forget: %v", err)
	}
	if persisted.VaultPath != "" {
		t.Fatalf("verified password retained persisted VaultPath binding: %q", persisted.VaultPath)
	}
	if !a.onboarding {
		t.Fatal("verified password did not return to onboarding")
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("verified password deleted the .ll vault file: %v", err)
	}
}

func prepareForgetDeviceTest(t *testing.T) (*App, string, string, *fakeDeviceSecretStore, *fakeSystemUnlockStore) {
	t.Helper()
	a, password, secret := createDeviceSecretTestVault(t)
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	secrets := newFakeDeviceSecretStore()
	a.deviceSecrets = secrets
	if err := a.storeDeviceSecret(a.path, secret); err != nil {
		t.Fatal(err)
	}
	system := newFakeSystemUnlockStore()
	a.systemStore = system
	vaultPath := a.path
	if err := a.SetVaultPath(vaultPath); err != nil {
		t.Fatal(err)
	}
	return a, password, vaultPath, secrets, system
}

func createDeviceSecretTestVault(t *testing.T) (*App, string, string) {
	t.Helper()
	a := New()
	a.launch = func(fn func()) { fn() }
	a.path = filepath.Join(t.TempDir(), "owner.ll")
	key, err := personal.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := personal.Create(a.path, "fixture-password", key); err != nil {
		t.Fatal(err)
	}
	return a, "fixture-password", personal.FormatSecret(key)
}
