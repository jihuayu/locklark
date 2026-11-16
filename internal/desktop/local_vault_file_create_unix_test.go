//go:build darwin || linux

package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func TestDesktopCreateTwoIndependentFilesWithConfirmedRecovery(t *testing.T) {
	root := t.TempDir()
	personalPath := filepath.Join(root, "personal.ll")
	password := "desktop-create-factor"
	key := []byte("1234567890abcdef")
	secret := personal.FormatSecret(key)
	if personal.Create(personalPath, password, key) != nil {
		t.Fatal("DESKTOP_CREATE_PROFILE_FAILED")
	}
	s, err := personal.UnlockSession(personalPath, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_PROFILE_UNLOCK_FAILED")
	}
	defer s.Lock()
	a := New()
	a.path, a.session = personalPath, s
	settingsDir := filepath.Join(root, "settings")
	if err := os.Mkdir(settingsDir, 0700); err != nil {
		t.Fatal("DESKTOP_CREATE_SETTINGS_DIRECTORY_FAILED")
	}
	a.settingsPath = filepath.Join(settingsDir, "settings.json")
	a.launch = func(fn func()) { fn() }
	profileDir, backendRoot, workspaceErr := ensureLocalVaultFileWorkspace(a.settingsPath, personalPath)
	if workspaceErr != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_PREPARATION_FAILED")
	}
	_, probe, probeErr := newLocalVaultFileProposal(profileDir, backendRoot, personalPath)
	if probeErr != nil || !vaultfileclient.ValidManifestPhase(filepath.Join(profileDir, "probe.json"), probe, false, true) {
		t.Fatal("DESKTOP_CREATE_PROPOSAL_INVALID")
	}

	var manifests []vaultfileclient.Manifest
	var companions []vaultfileclient.Companion
	for range 2 {
		a.openLocalVaultFileCreate("")
		a.localCreate.password, a.localCreate.secret = password, secret
		a.localCreatePrepare()
		if a.localCreate.phase != "confirm" || a.localCreate.backup == nil || a.localCreate.issued == "" {
			t.Fatalf("DESKTOP_CREATE_BACKUP_CONFIRMATION_MISSING phase=%s status=%s", a.localCreate.phase, a.localCreate.status)
		}
		configPath := a.localCreate.configPath
		manifest, exists, err := vaultfileclient.ReadManifest(configPath)
		if err != nil || !exists {
			t.Fatal("DESKTOP_CREATE_DURABLE_SELECTOR_MISSING")
		}
		if _, err := os.Lstat(manifest.Archive); !os.IsNotExist(err) {
			t.Fatal("DESKTOP_CREATE_UNCONFIRMED_ARCHIVE_PUBLISHED")
		}
		kit := a.localCreate.issued
		a.localCreate.confirm = "incorrect-recovery"
		a.localCreatePublishBackup()
		if a.localCreate.phase != "confirm" || a.localCreate.backup == nil {
			t.Fatal("DESKTOP_CREATE_WRONG_CONFIRMATION_ADVANCED")
		}
		a.localCreate.confirm = kit
		a.localCreatePublishBackup()
		if a.localCreate.phase != "complete" || a.localCreate.backup != nil || a.localCreate.issued != "" {
			t.Fatal("DESKTOP_CREATE_CONFIRMED_BACKUP_NOT_PUBLISHED")
		}
		a.localCreate.password, a.localCreate.secret, a.localCreate.kit = password, secret, kit
		a.localCreateComplete()
		if a.localCreate.open || a.localVaultFiles.selected != configPath ||
			a.localVaultFiles.status != "已验证本地初始版本 · 远端状态未核实" ||
			a.localCreate.issued != "" || a.localCreate.confirm != "" || a.localCreate.password != "" ||
			a.localCreate.secret != "" || a.localCreate.kit != "" || a.localCreate.backup != nil ||
			a.localCreate.publish != nil {
			t.Fatal("DESKTOP_CREATE_LOCAL_BASELINE_NOT_SELECTED")
		}
		companion, exists, err := vaultfileclient.ReadCompanion(configPath, manifest)
		if err != nil || !exists {
			t.Fatal("DESKTOP_CREATE_COMPANION_MISSING")
		}
		manifests = append(manifests, manifest)
		companions = append(companions, companion)
	}
	if manifests[0].VaultID == manifests[1].VaultID || manifests[0].Name == manifests[1].Name ||
		manifests[0].PersonalFile != manifests[1].PersonalFile ||
		manifests[0].BackendRoot != manifests[1].BackendRoot ||
		companions[0].GenesisSHA256 == companions[1].GenesisSHA256 || len(a.localVaultFiles.refs) != 2 {
		t.Fatal("DESKTOP_CREATE_FILES_NOT_INDEPENDENT")
	}
	backend, err := vaultfilebackend.OpenExistingDir(manifests[0].BackendRoot)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_BACKEND_OPEN_FAILED")
	}
	defer backend.Close()
	for i, manifest := range manifests {
		read, err := backend.Read(context.Background(), manifest.Name)
		if err != nil || read.Revision.Zero() {
			t.Fatal("DESKTOP_CREATE_BACKEND_FILE_MISSING")
		}
		hash := sha256.Sum256(read.Bytes)
		clear(read.Bytes)
		if hex.EncodeToString(hash[:]) != companions[i].GenesisSHA256 {
			t.Fatal("DESKTOP_CREATE_BACKEND_FILE_NOT_BOUND_TO_GENESIS")
		}
	}
	a.Lock()
	if a.localVaultFiles.selected != "" || len(a.localVaultFiles.refs) != 0 || a.localCreate.issued != "" {
		t.Fatal("DESKTOP_CREATE_LOCK_RETAINED_LOCAL_VIEWS")
	}
}

func TestDesktopCreateWorkspaceFirstUseMissingSettingsDir(t *testing.T) {
	root := t.TempDir()
	parentBefore, err := os.Lstat(root)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_FIRST_USE_PARENT_MISSING")
	}
	settingsDir := filepath.Join(root, "locklark")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_FIRST_USE_FAILED")
	}
	base := filepath.Dir(filepath.Dir(profileDir))
	for _, path := range []string{settingsDir, base, filepath.Dir(profileDir), profileDir, backendRoot} {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			t.Fatal("DESKTOP_CREATE_WORKSPACE_FIRST_USE_MODE_INVALID")
		}
	}
	parentAfter, err := os.Lstat(root)
	if err != nil || parentAfter.Mode().Perm() != parentBefore.Mode().Perm() {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_FIRST_USE_PARENT_CHANGED")
	}
	againProfile, againBackend, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil || againProfile != profileDir || againBackend != backendRoot {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_FIRST_USE_NOT_IDEMPOTENT")
	}
}

func TestDesktopCreateWorkspaceRejectsExisting0755SettingsDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_0755_SETUP_FAILED")
	}
	settingsPath := filepath.Join(root, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	if _, _, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath); !errors.Is(err, vaultfileclient.ErrLocalReview) {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_0755_NOT_REJECTED")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_0755_CHANGED")
	}
	if _, err := os.Lstat(filepath.Join(root, "vaultfile-workspace")); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_0755_CREATED_WORKSPACE")
	}
}

func TestDesktopCreateWorkspaceRejectsSymlinkSettingsDir(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_SETUP_FAILED")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_SETUP_FAILED")
	}
	settingsPath := filepath.Join(link, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	if _, _, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath); !errors.Is(err, vaultfileclient.ErrLocalReview) {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_NOT_REJECTED")
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_CHANGED")
	}
	target, err := os.Lstat(realDir)
	if err != nil || target.Mode().Perm() != 0700 {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_TARGET_CHANGED")
	}
	if _, err := os.Lstat(filepath.Join(realDir, "vaultfile-workspace")); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_WORKSPACE_SYMLINK_CREATED_WORKSPACE")
	}
}

type desktopCreateResumeFixture struct {
	app                            *App
	root, profileDir, backendRoot  string
	personalPath, password, secret string
	key                            []byte
}

func newDesktopCreateResumeFixture(t *testing.T) *desktopCreateResumeFixture {
	t.Helper()
	root := t.TempDir()
	settingsDir := filepath.Join(root, "settings")
	if err := os.Mkdir(settingsDir, 0700); err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_SETTINGS_DIRECTORY_FAILED")
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	password := "desktop-resume-factor"
	key := []byte("1234567890abcdef")
	if personal.Create(personalPath, password, key) != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_PROFILE_FAILED")
	}
	session, err := personal.UnlockSession(personalPath, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_PROFILE_UNLOCK_FAILED")
	}
	a := New()
	a.path, a.session = personalPath, session
	a.settingsPath = settingsPath
	a.launch = func(fn func()) { fn() }
	t.Cleanup(session.Lock)
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_WORKSPACE_FAILED")
	}
	return &desktopCreateResumeFixture{
		app: a, root: root, profileDir: profileDir, backendRoot: backendRoot,
		personalPath: personalPath, password: password, secret: personal.FormatSecret(key), key: key,
	}
}

func (f *desktopCreateResumeFixture) reserve(t *testing.T, name string, proposal vaultfileclient.Manifest) string {
	t.Helper()
	path := filepath.Join(f.profileDir, name+".json")
	if _, err := vaultfileclient.ReserveManifest(path, proposal); err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_MANIFEST_RESERVE_FAILED")
	}
	return path
}

func (f *desktopCreateResumeFixture) seedWrongBackendArchive(t *testing.T) (string, vaultfileclient.Manifest) {
	t.Helper()
	wrongBackend := filepath.Join(f.root, "wrong-backend")
	if err := os.Mkdir(wrongBackend, 0700); err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_WRONG_BACKEND_SETUP_FAILED")
	}
	if err := os.WriteFile(filepath.Join(wrongBackend, "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_WRONG_BACKEND_SETUP_FAILED")
	}
	proposal := vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind,
		PersonalFile: f.personalPath, BackendRoot: wrongBackend,
		Name:    "wrong-backend.llv",
		Journal: filepath.Join(f.profileDir, "wrong-backend.journal"),
		Archive: filepath.Join(f.profileDir, "wrong-backend.llb"),
	}
	if err := os.WriteFile(proposal.Archive, []byte("existing-archive"), 0600); err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_ARCHIVE_SETUP_FAILED")
	}
	return f.reserve(t, "wrong-backend", proposal), proposal
}

type desktopCreateFileSnapshot struct {
	digest string
	mode   os.FileMode
	uid    uint32
	gid    uint32
}

func desktopCreateSnapshotFile(t *testing.T, path string) desktopCreateFileSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_FILE_READ_FAILED")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_FILE_STAT_FAILED")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("DESKTOP_CREATE_RESUME_FILE_OWNER_UNAVAILABLE")
	}
	sum := sha256.Sum256(raw)
	return desktopCreateFileSnapshot{digest: hex.EncodeToString(sum[:]), mode: info.Mode(), uid: stat.Uid, gid: stat.Gid}
}

func (s desktopCreateFileSnapshot) assertUnchanged(t *testing.T, path, code string) {
	t.Helper()
	if desktopCreateSnapshotFile(t, path) != s {
		t.Fatal(code)
	}
}

func desktopCreateDirDigest(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_RESUME_DIRECTORY_READ_FAILED")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return strings.Join(names, "\n")
}

func TestDesktopCreatePrepareRejectsForeignPersonalManifest(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	foreignPath := filepath.Join(f.root, "foreign.ll")
	if personal.Create(foreignPath, f.password, f.key) != nil {
		t.Fatal("DESKTOP_CREATE_FOREIGN_PERSONAL_FIXTURE_FAILED")
	}
	probe, err := personal.UnlockSession(foreignPath, []byte(f.password), f.key, time.Minute)
	if err != nil {
		t.Fatal("DESKTOP_CREATE_FOREIGN_PERSONAL_FIXTURE_UNLOCK_FAILED")
	}
	probe.Lock()
	proposal := vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind,
		PersonalFile: foreignPath, BackendRoot: f.backendRoot,
		Name:    "foreign-personal.llv",
		Journal: filepath.Join(f.profileDir, "foreign-personal.journal"),
		Archive: filepath.Join(f.profileDir, "foreign-personal.llb"),
	}
	configPath := f.reserve(t, "foreign-personal", proposal)
	foreign := desktopCreateSnapshotFile(t, foreignPath)
	manifest := desktopCreateSnapshotFile(t, configPath)
	backend := desktopCreateDirDigest(t, f.backendRoot)

	f.app.openLocalVaultFileCreate(configPath)
	f.app.localCreate.password, f.app.localCreate.secret = f.password, f.secret
	f.app.localCreatePrepare()

	if f.app.localCreate.phase != "prepare" || f.app.localCreate.configPath != configPath ||
		f.app.localCreate.backup != nil || f.app.localCreate.issued != "" ||
		f.app.localCreate.status != "准备失败；请核查本地状态" {
		t.Fatal("DESKTOP_CREATE_FOREIGN_PERSONAL_INTENT_CHANGED")
	}
	foreign.assertUnchanged(t, foreignPath, "DESKTOP_CREATE_FOREIGN_PERSONAL_CHANGED")
	manifest.assertUnchanged(t, configPath, "DESKTOP_CREATE_FOREIGN_MANIFEST_CHANGED")
	if desktopCreateDirDigest(t, f.backendRoot) != backend {
		t.Fatal("DESKTOP_CREATE_FOREIGN_BACKEND_CHANGED")
	}
	if _, err := os.Lstat(proposal.Archive); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_FOREIGN_ARCHIVE_CREATED")
	}
}

func TestDesktopCreateResumeRejectsWrongBackendWithExistingArchive(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	configPath, proposal := f.seedWrongBackendArchive(t)
	personal := desktopCreateSnapshotFile(t, f.personalPath)
	archive := desktopCreateSnapshotFile(t, proposal.Archive)
	manifest := desktopCreateSnapshotFile(t, configPath)
	wrongBackend := desktopCreateDirDigest(t, proposal.BackendRoot)
	correctBackend := desktopCreateDirDigest(t, f.backendRoot)

	f.app.openLocalVaultFileCreate(configPath)
	f.app.localCreate.password, f.app.localCreate.secret = f.password, f.secret
	f.app.localCreatePrepare()

	if f.app.localCreate.phase != "prepare" || f.app.localCreate.configPath != configPath ||
		f.app.localCreate.backup != nil || f.app.localCreate.issued != "" ||
		f.app.localCreate.status != "准备失败；请核查本地状态" {
		t.Fatal("DESKTOP_CREATE_WRONG_BACKEND_INTENT_CHANGED")
	}
	personal.assertUnchanged(t, f.personalPath, "DESKTOP_CREATE_WRONG_BACKEND_PERSONAL_CHANGED")
	archive.assertUnchanged(t, proposal.Archive, "DESKTOP_CREATE_WRONG_BACKEND_ARCHIVE_CHANGED")
	manifest.assertUnchanged(t, configPath, "DESKTOP_CREATE_WRONG_BACKEND_MANIFEST_CHANGED")
	if desktopCreateDirDigest(t, proposal.BackendRoot) != wrongBackend {
		t.Fatal("DESKTOP_CREATE_WRONG_BACKEND_OBJECTS_CHANGED")
	}
	if desktopCreateDirDigest(t, f.backendRoot) != correctBackend {
		t.Fatal("DESKTOP_CREATE_WRONG_BACKEND_CORRECT_ROOT_CHANGED")
	}
}

func TestDesktopCreateCompleteRejectsWrongBackendBeforePublish(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	configPath, proposal := f.seedWrongBackendArchive(t)
	personal := desktopCreateSnapshotFile(t, f.personalPath)
	archive := desktopCreateSnapshotFile(t, proposal.Archive)
	manifest := desktopCreateSnapshotFile(t, configPath)
	wrongBackend := desktopCreateDirDigest(t, proposal.BackendRoot)
	correctBackend := desktopCreateDirDigest(t, f.backendRoot)

	f.app.openLocalVaultFileCreate(configPath)
	f.app.localCreate.phase = "complete"
	f.app.localCreate.password, f.app.localCreate.secret = f.password, f.secret
	f.app.localCreate.kit = "unused-kit"
	f.app.localCreateComplete()

	if f.app.localCreate.phase != "complete" || f.app.localCreate.configPath != configPath ||
		f.app.localCreate.backup != nil || f.app.localCreate.issued != "" ||
		f.app.localCreate.status != "创建未完成；请核查本地状态" {
		t.Fatal("DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_INTENT_CHANGED")
	}
	personal.assertUnchanged(t, f.personalPath, "DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_PERSONAL_CHANGED")
	archive.assertUnchanged(t, proposal.Archive, "DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_ARCHIVE_CHANGED")
	manifest.assertUnchanged(t, configPath, "DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_MANIFEST_CHANGED")
	if desktopCreateDirDigest(t, proposal.BackendRoot) != wrongBackend {
		t.Fatal("DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_OBJECTS_CHANGED")
	}
	if desktopCreateDirDigest(t, f.backendRoot) != correctBackend {
		t.Fatal("DESKTOP_CREATE_COMPLETE_WRONG_BACKEND_CORRECT_ROOT_CHANGED")
	}
}

func TestDesktopCreatePublishCancelBeforeStartDoesNotPublish(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	var queued []func()
	f.app.launch = func(fn func()) { queued = append(queued, fn) }
	runNext := func() {
		fn := queued[0]
		queued = queued[1:]
		fn()
	}
	f.app.openLocalVaultFileCreate("")
	f.app.localCreate.password, f.app.localCreate.secret = f.password, f.secret
	f.app.localCreatePrepare()
	if len(queued) != 1 {
		t.Fatal("DESKTOP_CREATE_PUBLISH_PREPARE_NOT_QUEUED")
	}
	runNext()
	if f.app.localCreate.phase != "confirm" || f.app.localCreate.backup == nil || f.app.localCreate.issued == "" {
		t.Fatal("DESKTOP_CREATE_PUBLISH_CONFIRM_SETUP_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(f.app.localCreate.configPath)
	if err != nil || !exists {
		t.Fatal("DESKTOP_CREATE_PUBLISH_MANIFEST_MISSING")
	}
	archive := manifest.Archive
	f.app.localCreate.confirm = f.app.localCreate.issued
	f.app.localCreatePublishBackup()
	if f.app.localCreate.publish == nil || f.app.localCreate.backup != nil {
		t.Fatal("DESKTOP_CREATE_PUBLISH_GATE_NOT_QUEUED")
	}
	if len(queued) != 2 {
		t.Fatal("DESKTOP_CREATE_PUBLISH_WORKER_NOT_QUEUED")
	}
	f.app.cancelLocalVaultFileCreate()
	if f.app.localCreate.open || f.app.localCreate.phase != "" || f.app.localCreate.configPath != "" ||
		f.app.localCreate.issued != "" || f.app.localCreate.confirm != "" ||
		f.app.localCreate.password != "" || f.app.localCreate.secret != "" || f.app.localCreate.kit != "" ||
		f.app.localCreate.backup != nil || f.app.localCreate.publish != nil {
		t.Fatal("DESKTOP_CREATE_PUBLISH_CANCEL_RETAINED_STATE")
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_PUBLISH_ARCHIVE_PUBLISHED_BEFORE_START")
	}
	if temps, _ := filepath.Glob(filepath.Join(f.profileDir, ".locklark-backup-*")); len(temps) != 0 {
		t.Fatal("DESKTOP_CREATE_PUBLISH_TEMP_RETAINED")
	}
	for len(queued) > 0 {
		runNext()
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_PUBLISH_ARCHIVE_PUBLISHED_AFTER_CANCEL")
	}
}

func TestDesktopCreateDialogExplicitCancelClearsConfirmState(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	f.app.openLocalVaultFileCreate("")
	f.app.localCreate.password, f.app.localCreate.secret = f.password, f.secret
	f.app.localCreatePrepare()
	if f.app.localCreate.phase != "confirm" || f.app.localCreate.backup == nil || f.app.localCreate.issued == "" {
		t.Fatal("DESKTOP_CREATE_DIALOG_CONFIRM_SETUP_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(f.app.localCreate.configPath)
	if err != nil || !exists {
		t.Fatal("DESKTOP_CREATE_DIALOG_MANIFEST_MISSING")
	}
	archive := manifest.Archive
	tester := ui.NewTester(func(c *ui.Context) {
		f.app.onevraLocalVaultFileCreateDialog(c)
	}, 600, 500)
	tester.SetPreferences(ui.Preferences{ReduceMotion: true})
	tester.Frame()
	tester.ClickAt(2, 2)
	tester.Key(0, ui.KeyEscape)
	tester.Frame()
	if !f.app.localCreate.open || f.app.localCreate.phase != "confirm" ||
		f.app.localCreate.backup == nil || f.app.localCreate.issued == "" {
		t.Fatal("DESKTOP_CREATE_DIALOG_IMPLICIT_CLOSE_BYPASSED_CLEANUP")
	}
	if err := tester.Click("取消"); err != nil {
		t.Fatal(err)
	}
	if f.app.localCreate.open || f.app.localCreate.phase != "" || f.app.localCreate.configPath != "" ||
		f.app.localCreate.issued != "" || f.app.localCreate.confirm != "" ||
		f.app.localCreate.password != "" || f.app.localCreate.secret != "" || f.app.localCreate.kit != "" ||
		f.app.localCreate.backup != nil || f.app.localCreate.publish != nil {
		t.Fatal("DESKTOP_CREATE_DIALOG_CANCEL_RETAINED_STATE")
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Fatal("DESKTOP_CREATE_DIALOG_CANCEL_PUBLISHED_ARCHIVE")
	}
	if temps, _ := filepath.Glob(filepath.Join(f.profileDir, ".locklark-backup-*")); len(temps) != 0 {
		t.Fatal("DESKTOP_CREATE_DIALOG_CANCEL_RETAINED_TEMP")
	}
}
