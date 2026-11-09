//go:build windows

package main

// Windows private-root fixtures for TestPrivateRoot.
//
// os.Chmod cannot make a directory private on Windows, so the positive fixture
// is created with an explicit current-user owner and a protected owner-only
// DACL, and the negative fixture installs a real Everyone read ACE. That is the
// same native class privateRoot checks in root_windows.go.

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func passkeyTransferCurrentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	return user.User.Sid.String()
}

func passkeyTransferPrivateRootFixture(t *testing.T) string {
	t.Helper()
	sid := passkeyTransferCurrentUserSID(t)
	root := filepath.Join(t.TempDir(), "root")
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		t.Fatalf("private root descriptor: %v", err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatalf("private root path: %v", err)
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatalf("create private root: %v", err)
	}
	return root
}

func passkeyTransferMakeRootShared(t *testing.T, root string) {
	t.Helper()
	sid := passkeyTransferCurrentUserSID(t)
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatalf("shared root descriptor: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("shared root DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("install shared root DACL: %v", err)
	}
}
