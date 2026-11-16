//go:build darwin || linux

package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
			a.localVaultFiles.status != "已验证本地初始版本 · 远端状态未核实" {
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
