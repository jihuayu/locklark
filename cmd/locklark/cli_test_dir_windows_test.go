//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// newPrivateCLITestDir places the binding fixture below a stable Windows
// system directory whose ancestors grant ordinary users creation without
// granting replacement, ACL, owner, or metadata rights on existing children.
// The directory itself has a protected current-user-only DACL, so tests
// exercise the production trust chain rather than relying on a potentially
// shared host TEMP directory.
func newPrivateCLITestDir(t *testing.T) string {
	t.Helper()
	parent, err := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if err != nil {
		t.Fatal("Windows public directory unavailable:", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("Windows user unavailable:", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal("private test ACL unavailable:", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err = rand.Read(suffix[:]); err != nil {
			t.Fatal("private test name unavailable:", err)
		}
		path := filepath.Join(parent, "locklark-cli-test-"+hex.EncodeToString(suffix[:]))
		wide, e := windows.UTF16PtrFromString(path)
		if e != nil {
			t.Fatal("private test path unavailable:", e)
		}
		e = windows.CreateDirectory(wide, &attributes)
		if e == windows.ERROR_ALREADY_EXISTS || e == windows.ERROR_FILE_EXISTS {
			continue
		}
		if e != nil {
			t.Fatal("private test directory unavailable:", e)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(path); err != nil {
				t.Error("private test cleanup failed:", err)
			}
		})
		return path
	}
	t.Fatal("private test directory name collision")
	return ""
}
