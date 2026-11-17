//go:build windows

package desktop

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/jihuayu/locklark/internal/teamfiles"
	"golang.org/x/sys/windows"
)

func desktopPrivateTestRoot(t *testing.T) string {
	t.Helper()
	public, err := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_FOLDER_FAILED")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_USER_FAILED")
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_SD_FAILED")
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_RANDOM_FAILED")
		}
		root := filepath.Join(public, "locklark-desktop-test-"+hex.EncodeToString(suffix[:]))
		name, err := windows.UTF16PtrFromString(root)
		if err != nil {
			t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_PATH_FAILED")
		}
		switch err = windows.CreateDirectory(name, &attributes); {
		case errors.Is(err, windows.ERROR_ALREADY_EXISTS), errors.Is(err, windows.ERROR_FILE_EXISTS):
			continue
		case err != nil:
			t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_CREATE_FAILED")
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(root); err != nil {
				t.Errorf("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_CLEANUP_FAILED")
			}
		})
		if err := teamfiles.ValidatePrivateWorkspace(root); err != nil {
			t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_NOT_PRIVATE")
		}
		return root
	}
	t.Fatal("LOCAL_NAV_WINDOWS_PRIVATE_ROOT_COLLISION")
	return ""
}
