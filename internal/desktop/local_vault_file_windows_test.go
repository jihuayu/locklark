//go:build windows

package desktop

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"golang.org/x/sys/windows"
)

func desktopWindowsUserSID(t *testing.T) *windows.SID {
	t.Helper()
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_USER_UNAVAILABLE")
	}
	return token.User.Sid
}

func desktopWindowsSD(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_SD_FIXTURE_FAILED")
	}
	return sd
}

func desktopWindowsCreateDir(t *testing.T, path, sddl string) {
	t.Helper()
	sd := desktopWindowsSD(t, sddl)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PATH_FIXTURE_FAILED")
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_DIRECTORY_FIXTURE_FAILED")
	}
}

func desktopWindowsSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_NAMED_SD_FAILED")
	}
	return sd.String()
}

func desktopWindowsBroadDirectory(t *testing.T, path string) string {
	t.Helper()
	sid := desktopWindowsUserSID(t).String()
	sddl := "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;GR;;;WD)"
	desktopWindowsCreateDir(t, path, sddl)
	return sddl
}

func TestDesktopWindowsPrivateReserveAndTwoIndependentRefs(t *testing.T) {
	root := t.TempDir()
	settingsDir := filepath.Join(root, "settings")
	if err := teamfiles.EnsurePrivateWorkspace(settingsDir); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_FAILED")
	}
	personalPath := filepath.Join(settingsDir, "personal.ll")
	key := []byte("1234567890abcdef")
	if err := personal.Create(personalPath, "navigation-factor", key); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PROFILE_CREATE_FAILED")
	}
	if err := teamfiles.ValidatePrivateFile(personalPath); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PROFILE_NOT_PRIVATE")
	}
	journalDir := filepath.Join(settingsDir, "journals")
	if err := teamfiles.EnsurePrivateWorkspace(journalDir); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_JOURNAL_DIRECTORY_FAILED")
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_WORKSPACE_FAILED")
	}
	for _, path := range []string{settingsDir, profileDir, backendRoot} {
		if err := teamfiles.ValidatePrivateWorkspace(path); err != nil {
			t.Fatal("LOCAL_NAV_WINDOWS_WORKSPACE_NOT_PRIVATE")
		}
	}
	if !strings.Contains(desktopWindowsSDDL(t, settingsDir), "D:P") {
		t.Fatal("LOCAL_NAV_WINDOWS_WORKSPACE_DACL_NOT_PROTECTED")
	}
	for _, name := range []string{"alpha", "beta"} {
		proposal := vaultfileclient.Manifest{Version: 1, Kind: vaultfileclient.CreateKind,
			PersonalFile: personalPath, BackendRoot: backendRoot, Name: name,
			Journal: filepath.Join(journalDir, name+".journal"), Archive: filepath.Join(settingsDir, name+".llb")}
		manifest, err := vaultfileclient.ReserveManifest(filepath.Join(profileDir, name+".json"), proposal)
		if err != nil {
			t.Fatal("LOCAL_NAV_WINDOWS_SELECTOR_RESERVATION_FAILED")
		}
		read, exists, err := vaultfileclient.ReadManifest(filepath.Join(profileDir, name+".json"))
		if err != nil || !exists || read.VaultID != manifest.VaultID {
			t.Fatal("LOCAL_NAV_WINDOWS_MANIFEST_READ_FAILED")
		}
	}
	refs, err := listLocalVaultFileRefs(profileDir, backendRoot, personalPath)
	if err != nil || len(refs) != 2 || refs[0].vaultID == "" || refs[0].vaultID == refs[1].vaultID ||
		refs[0].path == refs[1].path {
		t.Fatal("LOCAL_NAV_WINDOWS_REFS_NOT_INDEPENDENT")
	}
}

func TestDesktopWindowsRejectsBroadExistingSettingsWithoutRewrite(t *testing.T) {
	root := t.TempDir()
	settingsDir := filepath.Join(root, "settings")
	desktopWindowsBroadDirectory(t, settingsDir)
	before := desktopWindowsSDDL(t, settingsDir)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if _, _, err := ensureLocalVaultFileWorkspace(settingsPath, filepath.Join(root, "personal.ll")); err == nil {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_SETTINGS_ACCEPTED")
	}
	if after := desktopWindowsSDDL(t, settingsDir); after != before {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_SETTINGS_REWRITTEN")
	}
	if _, err := os.Lstat(filepath.Join(settingsDir, "vaultfile-workspace")); !os.IsNotExist(err) {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_SETTINGS_CREATED_WORKSPACE")
	}
}

func TestDesktopWindowsRejectsBroadExistingProfileWithoutRewrite(t *testing.T) {
	root := t.TempDir()
	settingsDir := filepath.Join(root, "settings")
	if err := teamfiles.EnsurePrivateWorkspace(settingsDir); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_FAILED")
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	personalPath := filepath.Join(settingsDir, "personal.ll")
	key := []byte("1234567890abcdef")
	if err := personal.Create(personalPath, "navigation-factor", key); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PROFILE_CREATE_FAILED")
	}
	_, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_WORKSPACE_FAILED")
	}
	profileDir := filepath.Join(settingsDir, "vaultfile-workspace", "profiles", "broad")
	desktopWindowsBroadDirectory(t, profileDir)
	before := desktopWindowsSDDL(t, profileDir)
	if _, err := listLocalVaultFileRefs(profileDir, backendRoot, personalPath); err == nil {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_ACCEPTED")
	}
	if after := desktopWindowsSDDL(t, profileDir); after != before {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_REWRITTEN")
	}
}

func TestDesktopWindowsRejectsBroadExistingPersonalWithoutChange(t *testing.T) {
	root := t.TempDir()
	settingsDir := filepath.Join(root, "settings")
	if err := teamfiles.EnsurePrivateWorkspace(settingsDir); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_FAILED")
	}
	broadDir := filepath.Join(root, "broad")
	desktopWindowsBroadDirectory(t, broadDir)
	personalPath := filepath.Join(broadDir, "personal.ll")
	key := []byte("1234567890abcdef")
	if err := personal.Create(personalPath, "navigation-factor", key); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_CREATE_FAILED")
	}
	if err := teamfiles.ValidatePrivateFile(personalPath); err == nil {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_ACCEPTED_BY_HELPER")
	}
	beforeBytes, err := os.ReadFile(personalPath)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_READ_FAILED")
	}
	beforeACL := desktopWindowsSDDL(t, personalPath)
	settingsPath := filepath.Join(settingsDir, "settings.json")
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_WORKSPACE_FAILED")
	}
	journalDir := filepath.Join(settingsDir, "journals")
	if err := teamfiles.EnsurePrivateWorkspace(journalDir); err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_JOURNAL_DIRECTORY_FAILED")
	}
	configPath := filepath.Join(profileDir, "broad-personal.json")
	proposal := vaultfileclient.Manifest{Version: 1, Kind: vaultfileclient.CreateKind,
		PersonalFile: personalPath, BackendRoot: backendRoot, Name: "broad-personal",
		Journal: filepath.Join(journalDir, "broad-personal.journal"), Archive: filepath.Join(settingsDir, "broad-personal.llb")}
	if _, err := vaultfileclient.ReserveManifest(configPath, proposal); !errors.Is(err, vaultfileclient.ErrConfig) {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_NOT_REJECTED")
	}
	afterBytes, err := os.ReadFile(personalPath)
	if err != nil || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_CHANGED")
	}
	if afterACL := desktopWindowsSDDL(t, personalPath); afterACL != beforeACL {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_ACL_REWRITTEN")
	}
	if _, err := os.Lstat(configPath); !os.IsNotExist(err) {
		t.Fatal("LOCAL_NAV_WINDOWS_BROAD_PROFILE_WROTE_MANIFEST")
	}
}
