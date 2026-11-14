//go:build windows

package vaultfileinspect

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateOutput(t *testing.T, path string) *os.File {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatal("private output user lookup failed")
	}
	// D:P is a protected DACL; only the current user receives file-all. No
	// world, Users, or Authenticated Users ACE is present or inherited.
	sd, err := windows.SecurityDescriptorFromString(
		"O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")",
	)
	if err != nil {
		t.Fatal("private output descriptor failed")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("private output path failed")
	}
	attrs := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		&attrs,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatal("private output creation failed")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("private output handle failed")
	}
	return file
}

func assertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatal("private output user lookup failed")
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		t.Fatal("private output descriptor read failed")
	}
	owner, defaulted, err := sd.Owner()
	if err != nil || defaulted || owner == nil || !owner.Equals(user.User.Sid) {
		t.Fatal("private output owner is not the current user")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("private output DACL is not present/protected")
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil || dacl.AceCount != 1 {
		t.Fatal("private output DACL is not owner-only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil {
		t.Fatal("private output ACE read failed")
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERIT_ONLY_ACE|windows.NO_PROPAGATE_INHERIT_ACE|windows.INHERITED_ACE) != 0 {
		t.Fatal("private output ACE is inheritable or not allow-only")
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Fatal("private output ACE is not the current user")
	}
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid, windows.WinBuiltinUsersSid, windows.WinAuthenticatedUserSid,
	} {
		forbidden, err := windows.CreateWellKnownSid(kind)
		if err != nil || forbidden == nil {
			t.Fatal("private output well-known SID lookup failed")
		}
		if sid.Equals(forbidden) {
			t.Fatal("private output ACE grants a non-owner SID")
		}
	}
}
