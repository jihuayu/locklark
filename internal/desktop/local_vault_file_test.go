package desktop

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func TestDesktopIndependentFileNavigationUsesOnePersonalAndWorkspace(t *testing.T) {
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	key := []byte("1234567890abcdef")
	if err := personal.Create(personalPath, "navigation-factor", key); err != nil {
		t.Fatal("LOCAL_NAV_PROFILE_CREATE_FAILED")
	}
	profileDir, backendRoot := localVaultFilePaths(settingsPath, personalPath)
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		t.Fatal("LOCAL_NAV_PRIVATE_DIRECTORY_FAILED")
	}
	journalDir := filepath.Join(root, "journals")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("LOCAL_NAV_JOURNAL_DIRECTORY_FAILED")
	}
	for _, name := range []string{"alpha", "beta"} {
		proposal := vaultfileclient.Manifest{Version: 1, Kind: vaultfileclient.CreateKind,
			PersonalFile: personalPath, BackendRoot: backendRoot, Name: name,
			Journal: filepath.Join(journalDir, name+".journal"), Archive: filepath.Join(root, name+".llb")}
		if _, err := vaultfileclient.ReserveManifest(filepath.Join(profileDir, name+".json"), proposal); err != nil {
			t.Fatal("LOCAL_NAV_SELECTOR_RESERVATION_FAILED")
		}
	}
	s, err := personal.UnlockSession(personalPath, []byte("navigation-factor"), key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_NAV_PROFILE_UNLOCK_FAILED")
	}
	defer s.Lock()
	a := New()
	a.settingsPath = settingsPath
	a.path, a.session = personalPath, s
	a.launch = func(fn func()) { fn() }
	a.refreshLocalVaultFiles()
	if len(a.localVaultFiles.refs) != 2 || a.localVaultFiles.refs[0].vaultID == "" ||
		a.localVaultFiles.refs[0].vaultID == a.localVaultFiles.refs[1].vaultID {
		t.Fatal("LOCAL_NAV_REFS_NOT_INDEPENDENT")
	}
	if a.localVaultFiles.refs[0].path == a.localVaultFiles.refs[1].path {
		t.Fatal("LOCAL_NAV_CONFIG_PATH_REUSED")
	}
	a.Lock()
	if a.localVaultFiles.selected != "" || len(a.localVaultFiles.refs) != 0 {
		t.Fatal("LOCAL_NAV_ACCOUNT_LOCK_RETAINED_REFS")
	}
}
