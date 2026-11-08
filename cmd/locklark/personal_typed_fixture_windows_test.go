//go:build windows

package main

// OS-specific creation of the private typed-input fixture.
//
// Windows cannot make a file private through os.WriteFile/os.Chmod: those only
// map to the read-only attribute and leave the inherited DACL in place, which
// grants SYSTEM, Administrators and often other principals access. The typed
// input reader correctly refuses such a file, so the fixture must instead
// create the file with an explicit owner and a protected owner-only DACL.

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func writePrivateTypedFixture(t *testing.T, path string, content []byte) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	sid := user.User.Sid.String()
	// O: names the owner explicitly instead of letting the filesystem default
	// it, and D:P grants full access only to that SID with no inherited ACEs.
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatalf("private input security descriptor: %v", err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("private input path: %v", err)
	}
	// CREATE_NEW keeps the creation security descriptor authoritative; the
	// complete write and close happen before any reader can open the path.
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("create private input: %v", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		t.Fatalf("create private input: invalid file handle")
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		t.Fatalf("write private input: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close private input: %v", err)
	}
}
