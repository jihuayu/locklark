//go:build windows

package desktop

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// newPrivateCLIConfigDir creates a directory whose ACL satisfies the same
// trust checks as a real user profile while surviving the host's broad TEMP
// ACL.
func newPrivateCLIConfigDir(t *testing.T) string {
	t.Helper()
	parent, err := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "locklark-desktop-test-"+hex.EncodeToString(suffix[:]))
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		err = windows.CreateDirectory(wide, &attributes)
		if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_FILE_EXISTS {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(path); err != nil {
				t.Errorf("remove private CLI test directory: %v", err)
			}
		})
		return path
	}
	t.Fatal("private CLI test directory name collision")
	return ""
}
