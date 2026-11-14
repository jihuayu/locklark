package desktop

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

type fakeDeviceSecretStore struct {
	values map[string][]byte
}

func newFakeDeviceSecretStore() *fakeDeviceSecretStore {
	return &fakeDeviceSecretStore{values: map[string][]byte{}}
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
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *fakeDeviceSecretStore) Get(key string) ([]byte, error) {
	value, ok := s.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func (s *fakeDeviceSecretStore) Delete(key string) error {
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
