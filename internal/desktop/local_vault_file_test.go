package desktop

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/theme"
)

func TestDesktopIndependentFileNavigationUsesOnePersonalAndWorkspace(t *testing.T) {
	root := desktopPrivateTestRoot(t)
	settingsDir := filepath.Join(root, "settings")
	if err := teamfiles.EnsurePrivateWorkspace(settingsDir); err != nil {
		t.Fatal("LOCAL_NAV_PRIVATE_ROOT_FAILED")
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	personalPath := filepath.Join(settingsDir, "personal.ll")
	key := []byte("1234567890abcdef")
	if err := personal.Create(personalPath, "navigation-factor", key); err != nil {
		t.Fatal("LOCAL_NAV_PROFILE_CREATE_FAILED")
	}
	if err := teamfiles.ValidatePrivateFile(personalPath); err != nil {
		t.Fatal("LOCAL_NAV_PRIVATE_PROFILE_FAILED")
	}
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("LOCAL_NAV_PRIVATE_WORKSPACE_FAILED")
	}
	journalDir := filepath.Join(settingsDir, "journals")
	if err := teamfiles.EnsurePrivateWorkspace(journalDir); err != nil {
		t.Fatal("LOCAL_NAV_JOURNAL_DIRECTORY_FAILED")
	}
	for _, name := range []string{"alpha", "beta"} {
		proposal := vaultfileclient.Manifest{Version: 1, Kind: vaultfileclient.CreateKind,
			PersonalFile: personalPath, BackendRoot: backendRoot, Name: name,
			Journal: filepath.Join(journalDir, name+".journal"), Archive: filepath.Join(settingsDir, name+".llb")}
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
	if !a.session.Unlocked() {
		t.Fatal("LOCAL_NAV_REVIEW_SESSION_NOT_UNLOCKED")
	}
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

func TestDesktopIndependentFileDuplicateReviewRowsKeepSelectionSeparate(t *testing.T) {
	a := newOnevraTestApp()
	personalPath := filepath.Join(t.TempDir(), "personal.ll")
	key := []byte("1234567890abcdef")
	if personal.Create(personalPath, "review-factor", key) != nil {
		t.Fatal("LOCAL_NAV_REVIEW_PROFILE_CREATE_FAILED")
	}
	s, err := personal.UnlockSession(personalPath, []byte("review-factor"), key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_NAV_REVIEW_PROFILE_UNLOCK_FAILED")
	}
	defer s.Lock()
	a.path, a.session = personalPath, s
	first := localVaultFileRef{path: filepath.Join(t.TempDir(), "first.json"), name: "待核查文件"}
	second := localVaultFileRef{path: filepath.Join(t.TempDir(), "second.json"), name: "待核查文件"}
	a.localVaultFiles.refs = []localVaultFileRef{first, second}
	tester := ui.NewTester(func(c *ui.Context) {
		c.SetTheme(theme.Onevra(c))
		oneui.Sidebar(c).Children(func() { a.onevraLocalVaultFileSidebar(c) })
	}, 480, 500)
	if err := tester.Click("待核查文件"); err != nil || a.localVaultFiles.selected != first.path {
		t.Fatal("LOCAL_NAV_FIRST_REVIEW_ROW_NOT_SELECTED")
	}
	tester.Key(0, ui.KeyTab)
	tester.Key(0, ui.KeyEnter)
	if a.localVaultFiles.selected != second.path {
		t.Fatal("LOCAL_NAV_SECOND_REVIEW_ROW_FOCUS_COLLIDED")
	}
}
