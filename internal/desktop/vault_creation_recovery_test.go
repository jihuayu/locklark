package desktop

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

type creationInvariantStore struct {
	values   map[string][]byte
	setCalls int
	setErr   error
}

func newCreationInvariantStore() *creationInvariantStore {
	return &creationInvariantStore{values: map[string][]byte{}}
}

func (s *creationInvariantStore) Set(key string, value []byte) error {
	s.setCalls++
	if s.setErr != nil {
		return s.setErr
	}
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *creationInvariantStore) Get(key string) ([]byte, error) {
	value, ok := s.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func (s *creationInvariantStore) Delete(key string) error {
	delete(s.values, key)
	return nil
}

func newCreationInvariantApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("LOCKLARK_DESKTOP_LAYOUT", "")
	a := New()
	a.launch = func(fn func()) { fn() }
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	return a
}

func emergencyKitSecret(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Emergency Kit: %v", err)
	}
	const marker = "Secret Key: "
	index := strings.Index(string(data), marker)
	if index < 0 {
		t.Fatal("Emergency Kit has no Secret Key")
	}
	secret := string(data)[index+len(marker):]
	if end := strings.IndexAny(secret, "\r\n"); end >= 0 {
		secret = secret[:end]
	}
	secret = strings.TrimSpace(secret)
	if _, err := personal.ParseSecret(secret); err != nil {
		t.Fatal("Emergency Kit Secret Key is invalid")
	}
	return secret
}

func vaultDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	return sha256.Sum256(data)
}

func TestGeneratedKeyCreationRequiresDurableKitBeforeVault(t *testing.T) {
	a := newCreationInvariantApp(t)
	vaultDir := filepath.Join(t.TempDir(), "read-only-vault")
	if err := os.Mkdir(vaultDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vaultDir, 0700) })

	// The owned temp directory normally enforces the real write failure. If
	// the environment bypasses permissions, keep the same contract with an
	// injected kit failure.
	probe := filepath.Join(vaultDir, "write-probe")
	if f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		_ = f.Close()
		_ = os.Remove(probe)
		a.autoSaveKit = func(string, string) (string, error) {
			return "", errors.New("injected Emergency Kit failure")
		}
	}

	store := newCreationInvariantStore()
	a.deviceSecrets = store
	a.path = filepath.Join(vaultDir, "personal.ll")
	a.startCreateVault()
	issued := a.issued
	if issued == "" {
		t.Fatal("creation wizard did not issue a key")
	}

	password := "fixture-password"
	a.password, a.confirmation = password, password
	a.createVaultFile()

	if _, err := os.Stat(a.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a .ll without a durable kit: %v", err)
	}
	if store.setCalls != 0 {
		t.Fatalf("device store was touched before a durable kit: %d calls", store.setCalls)
	}
	if a.issued != issued || !a.create {
		t.Fatal("wizard key was not retained for retry after kit failure")
	}
	if a.session != nil {
		t.Fatal("kit failure still produced an unlocked vault")
	}
	if !strings.Contains(a.status, "未创建金库") {
		t.Fatalf("kit failure did not report a closed creation: %q", a.status)
	}
}

func TestSavedKitRecoversCreatedVaultAfterLockWhenDeviceStoreFails(t *testing.T) {
	a := newCreationInvariantApp(t)
	vaultDir := t.TempDir()
	a.path = filepath.Join(vaultDir, "personal.ll")
	store := newCreationInvariantStore()
	store.setErr = errors.New("injected device store failure")
	a.deviceSecrets = store

	a.startCreateVault()
	issued := a.issued
	if issued == "" {
		t.Fatal("creation wizard did not issue a key")
	}

	password := "fixture-password"
	a.password, a.confirmation = password, password
	a.createVaultFile()

	if a.session == nil {
		t.Fatalf("vault creation failed despite a durable kit: %q", a.status)
	}
	if a.kitSavedPath == "" {
		t.Fatal("durable Emergency Kit was not saved")
	}
	if got := emergencyKitSecret(t, a.kitSavedPath); got != issued {
		t.Fatal("saved Emergency Kit does not contain the created vault key")
	}
	if a.issued != "" || a.secret != "" {
		t.Fatal("creation key remained in the app after a durable kit was saved")
	}
	if settingsData, err := os.ReadFile(a.settingsPath); err == nil && bytes.Contains(settingsData, []byte(issued)) {
		t.Fatal("settings persisted the generated Secret Key")
	}
	if _, err := os.Stat(a.path); err != nil {
		t.Fatalf("created .ll is missing: %v", err)
	}
	if store.setCalls != 1 {
		t.Fatalf("device store attempts = %d, want one optional attempt", store.setCalls)
	}
	if !strings.Contains(a.status, "应急文件已自动保存") || !strings.Contains(a.status, "未能保存 Secret Key") {
		t.Fatalf("creation status hid the kit/device outcome: %q", a.status)
	}

	before := vaultDigest(t, a.path)
	a.Lock()
	if a.issued != "" || a.secret != "" {
		t.Fatal("lock retained a creation key in the app")
	}
	if after := vaultDigest(t, a.path); after != before {
		t.Fatal("lock modified the created .ll")
	}

	a.password = password
	a.secret = issued
	a.showSecretFallback = true
	a.unlock()
	if a.session == nil {
		t.Fatalf("kit key could not unlock the created vault after lock: %q", a.status)
	}
	if _, err := os.Stat(a.path); err != nil {
		t.Fatalf("created .ll disappeared after recovery unlock: %v", err)
	}
	a.Lock()
}

func TestCreateRefusalPreservesExistingVaultAndDeviceBinding(t *testing.T) {
	a := newCreationInvariantApp(t)
	vaultDir := t.TempDir()
	a.path = filepath.Join(vaultDir, "existing.ll")
	password := "fixture-password"

	oldKey, err := personal.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldKey)
	if err := personal.Create(a.path, password, oldKey); err != nil {
		t.Fatal(err)
	}
	oldSecret := personal.FormatSecret(oldKey)
	store := newCreationInvariantStore()
	store.values[deviceSecretKey(a.path)] = []byte(oldSecret)
	a.deviceSecrets = store

	before := vaultDigest(t, a.path)
	a.startCreateVault()
	if a.issued == "" || a.issued == oldSecret {
		t.Fatal("creation wizard did not issue a distinct key")
	}
	a.password, a.confirmation = password, password
	a.createVaultFile()

	if a.session != nil {
		t.Fatal("create overwrote or unlocked an existing vault")
	}
	if after := vaultDigest(t, a.path); after != before {
		t.Fatal("create refusal modified the existing .ll")
	}
	if store.setCalls != 0 {
		t.Fatalf("device binding touched before exclusive create: %d calls", store.setCalls)
	}
	bound, err := store.Get(deviceSecretKey(a.path))
	if err != nil || string(bound) != oldSecret {
		t.Fatal("existing device Secret Key binding changed on create refusal")
	}
	if _, err := os.Stat(filepath.Join(vaultDir, emergencyKitFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("create refusal wrote an Emergency Kit: %v", err)
	}

	key, err := personal.ParseSecret(oldSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	s, err := personal.UnlockSession(a.path, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatalf("existing vault no longer unlocks with its original key: %v", err)
	}
	s.Lock()
}
