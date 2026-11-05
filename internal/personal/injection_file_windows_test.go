package personal

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestInjectionWindowsPrivateACLFromCreation(t *testing.T) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	check := func(sd *windows.SECURITY_DESCRIPTOR) {
		t.Helper()
		control, _, e := sd.Control()
		if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("DACL inherits parent permissions", e)
		}
		acl, _, e := sd.DACL()
		if e != nil || acl == nil || acl.AceCount != 1 {
			t.Fatal("unexpected grants", e)
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, 0, &ace); e != nil {
			t.Fatal(e)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !sid.Equals(user.User.Sid) || ace.Mask&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ {
			t.Fatal("ACL does not restrict read access to current account")
		}
	}
	dir := t.TempDir()
	file, e := createInjectionTemp(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	sd, e := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	check(sd)
	if _, e = file.Write([]byte("synthetic-private")); e != nil {
		t.Fatal(e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(dir, "published.json")
	if e = publish(file.Name(), dest); e != nil {
		t.Fatal(e)
	}
	sd, e = windows.GetNamedSecurityInfo(dest, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	check(sd)
}
